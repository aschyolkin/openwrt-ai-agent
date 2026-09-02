from __future__ import annotations

import hashlib
import html
import json
import logging
import re
import threading
from typing import Any, Callable

from .telegram import TelegramClient, TelegramError
from .telegram_security import TelegramUpdateGuard, markdown_to_telegram_chunks
from .telegram_state import TelegramOffsetStore


LOG = logging.getLogger("ai-agent.telegram")

TYPING_REFRESH_SECONDS = 4.0  # Telegram's "typing" status auto-expires after ~5s.


def _sentence(text: str) -> str:
    value = str(text or "").strip()
    if value and value[-1] not in ".!?":
        value += "."
    return value


def human_response(response: dict[str, Any]) -> str:
    """Render Core API data for a person; never expose internal JSON in Telegram."""
    state = str(response.get("state") or "")
    message = str(response.get("message") or "").strip()
    verification = response.get("verification")
    verified_message = str(verification.get("message") or "").strip() if isinstance(verification, dict) else ""
    detail = message or verified_message
    if state == "verified":
        return "Готово. " + (_sentence(detail) or "Действие выполнено и проверено.")
    if state == "cancelled":
        return "Действие отменено."
    if state == "rolled_back":
        return "Готово. " + (_sentence(detail) or "Откат выполнен.")
    if state == "rollback_declined":
        return "Откат отменён."
    if detail:
        return detail
    if response.get("ok"):
        return "Готово."
    return "Не удалось выполнить запрос. Подробности сохранены в журнале агента."


class TelegramWorker:
    def __init__(
        self,
        client: TelegramClient,
        core_request: Callable[[str, dict[str, Any]], dict[str, Any]],
        allowed_chat_ids: frozenset[int],
        offset_path: str | None = None,
    ):
        self.client = client
        self.core_request = core_request
        self.guard = TelegramUpdateGuard(allowed_chat_ids)
        self.offset_store = TelegramOffsetStore(offset_path) if offset_path else None
        if self.offset_store is not None:
            # Fail at startup if durable state cannot be written, instead of
            # discovering that only after an expensive Core/LLM call.
            self.offset_store.initialize()
        state = self.offset_store.load_state() if self.offset_store else {
            "offset": None, "pending": None,
        }
        self.offset: int | None = state["offset"]
        self._pending_core: dict[str, Any] | None = state["pending"]
        self._active_update_id: int | None = None
        self._delivery_sequence = 0

    @staticmethod
    def _core_cache_key(method: str, params: dict[str, Any]) -> str:
        encoded = json.dumps(
            {"method": method, "params": params},
            ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _delivery_cache_key(
        chat_id: int,
        parts: list[str],
        kwargs: dict[str, Any],
        sequence: int = 0,
    ) -> str:
        encoded = json.dumps(
            {
                "chat_id": chat_id,
                "parse_mode": "HTML",
                "parts": parts,
                "kwargs": kwargs,
                "sequence": sequence,
            },
            ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _persist_pending(self) -> None:
        pending = self._pending_core
        if self.offset_store is None or not isinstance(pending, dict):
            return
        self.offset_store.save_pending(
            self.offset,
            int(pending["update_id"]),
            str(pending["key"]),
            pending["response"],
            pending.get("deliveries"),
        )

    def _call_core(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        key = self._core_cache_key(method, params)
        pending = self._pending_core
        if (
            self._active_update_id is not None
            and isinstance(pending, dict)
            and pending.get("update_id") == self._active_update_id
            and pending.get("key") == key
            and isinstance(pending.get("response"), dict)
        ):
            return pending["response"]
        response = self.core_request(method, params)
        if not isinstance(response, dict):
            raise TypeError("Core API response is not an object")
        if self._active_update_id is not None:
            pending = {
                "update_id": self._active_update_id,
                "key": key,
                "response": response,
            }
            self._pending_core = pending
            self._persist_pending()
        return response

    def _send(self, chat_id: int, text: str, **kwargs: Any) -> None:
        parts = markdown_to_telegram_chunks(text)
        sequence = self._delivery_sequence
        self._delivery_sequence += 1
        delivery_key = self._delivery_cache_key(chat_id, parts, kwargs, sequence)
        start = 0
        pending = self._pending_core
        if self._active_update_id is not None and isinstance(pending, dict):
            deliveries = pending.setdefault("deliveries", {})
            if not isinstance(deliveries, dict):
                deliveries = {}
                pending["deliveries"] = deliveries
            try:
                start = max(0, min(int(deliveries.get(delivery_key, 0)), len(parts)))
            except (TypeError, ValueError):
                start = 0
            if delivery_key not in deliveries:
                deliveries[delivery_key] = 0
                self._persist_pending()

        for index, part in enumerate(parts):
            if index < start:
                continue
            try:
                self.client.send_message(chat_id, part, parse_mode="HTML", **kwargs)
            except TelegramError as exc:
                # Only a definitive HTTP 400 means Telegram rejected our HTML.
                # Transport/429/5xx failures may be ambiguous; immediately sending
                # again could duplicate a message accepted before disconnect.
                if exc.status_code != 400:
                    raise
                LOG.warning("Telegram rejected HTML; retrying this chunk as plain text")
                plain = html.unescape(re.sub(r"<[^>]+>", "", part))
                self.client.send_message(chat_id, plain, **kwargs)
            if self._active_update_id is not None and isinstance(pending, dict):
                pending["deliveries"][delivery_key] = index + 1
                self._persist_pending()

    def _request_with_typing(self, chat_id: int, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """Show a live "typing" indicator for the whole (potentially slow, LLM-bound)
        Core API call instead of leaving the chat silent until the answer lands."""
        stop = threading.Event()

        def _keep_typing() -> None:
            while not stop.is_set():
                try:
                    self.client.send_chat_action(chat_id, "typing")
                except Exception:
                    pass
                stop.wait(TYPING_REFRESH_SECONDS)

        thread = threading.Thread(target=_keep_typing, daemon=True)
        thread.start()
        try:
            return self._call_core(method, params)
        finally:
            stop.set()
            thread.join(timeout=1)

    def _buttons(self, action_id: str) -> dict[str, Any]:
        return {"inline_keyboard": [[
            {"text": "Подтвердить", "callback_data": f"confirm:{action_id}:yes"},
            {"text": "Отменить", "callback_data": f"confirm:{action_id}:no"},
        ]]}

    def _recovery_buttons(self, action_id: str) -> dict[str, Any]:
        return {"inline_keyboard": [
            [{"text": "Проверить снова", "callback_data": f"reverify:{action_id}:yes"}],
            [
                {"text": "Откатить", "callback_data": f"rollback:{action_id}:yes"},
                {"text": "Оставить", "callback_data": f"rollback:{action_id}:no"},
            ],
        ]}

    def _deliver(self, chat_id: int, response: dict[str, Any]) -> None:
        """Send a Core chat response: a confirmation prompt with buttons, or text."""
        if response.get("status") == "awaiting_confirmation" and response.get("action_id"):
            plan = response.get("plan", {})
            summary = response.get("message") or plan.get("summary") or "Выполнить запрошенное действие"
            body = "Подтвердите действие:\n" + _sentence(str(summary))
            self._send(chat_id, body, reply_markup=self._buttons(str(response["action_id"])))
            return
        self._send(chat_id, human_response(response))

    def handle_update(self, update: dict[str, Any]) -> str:
        accepted, reason, chat_id = self.guard.accept(update)
        if not accepted:
            return reason
        assert chat_id is not None
        if isinstance(update.get("message"), dict):
            text = update["message"].get("text")
            if not isinstance(text, str):
                return "ignored"
            response = self._request_with_typing(chat_id, "chat", {"session_id": self.guard.session_id(chat_id), "message": text})
            self._deliver(chat_id, response)
            return "message"
        callback = update.get("callback_query")
        if isinstance(callback, dict):
            data = str(callback.get("data", ""))
            parts = data.split(":")
            if (
                len(parts) != 3
                or parts[0] not in {"confirm", "rollback", "reverify"}
                or parts[2] not in {"yes", "no"}
                or (parts[0] == "reverify" and parts[2] != "yes")
            ):
                self.client.answer_callback(str(callback.get("id", "")), text="Некорректная команда")
                return "invalid_callback"
            method = parts[0]
            params = {"session_id": self.guard.session_id(chat_id), "action_id": parts[1]}
            if method != "reverify":
                params["approve"] = parts[2] == "yes"
            response = self._call_core(method, params)
            try:
                self.client.answer_callback(str(callback.get("id", "")), text="Запрос обработан")
            except TelegramError:
                # Callback acknowledgement is cosmetic and expires quickly.
                # The actual result below is still useful and must be delivered.
                LOG.warning("Telegram callback acknowledgement failed")
            kwargs = {}
            if response.get("state") == "rollback_pending" and response.get("action_id"):
                kwargs["reply_markup"] = self._recovery_buttons(str(response["action_id"]))
            self._send(chat_id, human_response(response), **kwargs)
            # A confirmed action may leave part of the user's request undone;
            # Core takes one more turn and returns it here, so the next step of
            # a multi-step request reaches the chat instead of being dropped.
            follow_up = response.get("follow_up")
            if isinstance(follow_up, dict):
                self._deliver(chat_id, follow_up)
            return "callback"
        return "ignored"

    def run_once(self, timeout: int = 25) -> int:
        count = 0
        for update in self.client.get_updates(self.offset, timeout):
            try:
                update_id = int(update["update_id"])
                if self.offset is not None and update_id < self.offset:
                    continue
                self._active_update_id = update_id
                self._delivery_sequence = 0
                self.handle_update(update)
                next_offset = update_id + 1
                if self.offset_store is not None:
                    self.offset_store.save(next_offset)
                self.offset = next_offset
                self._pending_core = None
                self._active_update_id = None
                count += 1
            except Exception:
                if isinstance(update, dict):
                    self.guard.release(update)
                LOG.warning("Telegram update failed; offset was not advanced")
                # Stop at the first failure: acknowledging a later update would
                # permanently skip the failed one.
                raise
        return count
