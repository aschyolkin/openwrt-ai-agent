from __future__ import annotations

import html
import logging
import re
import threading
from typing import Any, Callable

from .telegram import TelegramClient, TelegramError
from .telegram_security import TelegramUpdateGuard, markdown_to_telegram_chunks


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
    def __init__(self, client: TelegramClient, core_request: Callable[[str, dict[str, Any]], dict[str, Any]], allowed_chat_ids: frozenset[int]):
        self.client = client
        self.core_request = core_request
        self.guard = TelegramUpdateGuard(allowed_chat_ids)
        self.offset: int | None = None

    def _send(self, chat_id: int, text: str, **kwargs: Any) -> None:
        for part in markdown_to_telegram_chunks(text):
            try:
                self.client.send_message(chat_id, part, parse_mode="HTML", **kwargs)
            except TelegramError:
                # Any remaining HTML edge case (unexpected tag rejected by the Bot
                # API, etc.) should degrade to a plain reply rather than leave the
                # user with silence — never let formatting bugs eat the answer.
                LOG.exception("HTML send failed, retrying as plain text")
                plain = html.unescape(re.sub(r"<[^>]+>", "", part))
                self.client.send_message(chat_id, plain, **kwargs)

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
            return self.core_request(method, params)
        finally:
            stop.set()
            thread.join(timeout=1)

    def _buttons(self, action_id: str) -> dict[str, Any]:
        return {"inline_keyboard": [[
            {"text": "Подтвердить", "callback_data": f"confirm:{action_id}:yes"},
            {"text": "Отменить", "callback_data": f"confirm:{action_id}:no"},
        ], [{"text": "Откатить", "callback_data": f"rollback:{action_id}:yes"}] ]}

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
            if response.get("status") == "awaiting_confirmation" and response.get("action_id"):
                plan = response.get("plan", {})
                summary = response.get("message") or plan.get("summary") or "Выполнить запрошенное действие"
                body = "Подтвердите действие:\n" + _sentence(str(summary))
                self._send(chat_id, body, reply_markup=self._buttons(str(response["action_id"])))
            else:
                self._send(chat_id, human_response(response))
            return "message"
        callback = update.get("callback_query")
        if isinstance(callback, dict):
            data = str(callback.get("data", ""))
            parts = data.split(":")
            if len(parts) != 3 or parts[0] not in {"confirm", "rollback"} or parts[2] not in {"yes", "no"}:
                self.client.answer_callback(str(callback.get("id", "")), text="Некорректная команда")
                return "invalid_callback"
            method = "confirm" if parts[0] == "confirm" else "rollback"
            response = self.core_request(method, {"session_id": self.guard.session_id(chat_id), "action_id": parts[1], "approve": parts[2] == "yes"})
            self.client.answer_callback(str(callback.get("id", "")), text="Готово")
            self._send(chat_id, human_response(response))
            return "callback"
        return "ignored"

    def run_once(self, timeout: int = 25) -> int:
        count = 0
        for update in self.client.get_updates(self.offset, timeout):
            try:
                update_id = int(update["update_id"])
                self.offset = update_id + 1
                self.handle_update(update)
                count += 1
            except Exception:
                LOG.exception("telegram update failed")
        return count
