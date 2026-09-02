from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

import requests



DEFAULT_TELEGRAM_PROXY = "http://10.110.112.1:2080"

class TelegramError(RuntimeError):
    """Safe Bot API error; never include the bot token in its message."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        retry_after: int | None = None,
    ):
        super().__init__(message)
        self.status_code = status_code
        self.retry_after = retry_after


class TelegramClient(Protocol):
    def send_message(self, chat_id: int, text: str, **kwargs: Any) -> dict[str, Any]: ...
    def edit_message(self, chat_id: int, message_id: int, text: str, **kwargs: Any) -> dict[str, Any]: ...
    def answer_callback(self, callback_query_id: str, **kwargs: Any) -> dict[str, Any]: ...
    def send_chat_action(self, chat_id: int, action: str = "typing") -> dict[str, Any]: ...
    def get_updates(self, offset: int | None = None, timeout: int = 25) -> list[dict[str, Any]]: ...


class TelegramBotClient:
    def __init__(self, token: str, timeout: int = 35, session: requests.Session | None = None, proxy: str | None = None):
        if not token or any(ch.isspace() for ch in token):
            raise ValueError("invalid Telegram bot token")
        self._token = token
        self.timeout = max(5, min(int(timeout), 60))
        self.session = session or requests.Session()
        if proxy:
            self.session.proxies.update({"http": proxy, "https": proxy})
        self.base_url = f"https://api.telegram.org/bot{token}"

    def _call(self, method: str, payload: dict[str, Any]) -> dict[str, Any]:
        request_timeout = self.timeout
        if method == "getUpdates":
            try:
                request_timeout = max(self.timeout, min(int(payload.get("timeout", 0)) + 10, 60))
            except (TypeError, ValueError):
                pass
        try:
            response = self.session.post(self.base_url + "/" + method, json=payload, timeout=request_timeout)
            data = response.json()
        except (requests.RequestException, ValueError, TypeError):
            # requests exceptions include the request URL. Telegram puts the
            # bot token in that URL, so retaining the exception chain would
            # leak the token whenever callers log this safe wrapper error.
            raise TelegramError("Telegram Bot API unavailable") from None
        if not isinstance(data, dict):
            raise TelegramError("Telegram Bot API returned malformed data")
        if response.status_code >= 400 or not data.get("ok"):
            description = data.get("description")
            parameters = data.get("parameters")
            retry_after = None
            if isinstance(parameters, dict):
                try:
                    retry_after = max(1, min(int(parameters.get("retry_after")), 300))
                except (TypeError, ValueError):
                    pass
            raise TelegramError(
                f"Telegram Bot API error: {str(description or response.status_code)[:200]}",
                status_code=int(response.status_code),
                retry_after=retry_after,
            )
        return data

    def send_message(self, chat_id: int, text: str, **kwargs: Any) -> dict[str, Any]:
        return self._call("sendMessage", {"chat_id": chat_id, "text": text, **kwargs})

    def edit_message(self, chat_id: int, message_id: int, text: str, **kwargs: Any) -> dict[str, Any]:
        return self._call("editMessageText", {"chat_id": chat_id, "message_id": message_id, "text": text, **kwargs})

    def answer_callback(self, callback_query_id: str, **kwargs: Any) -> dict[str, Any]:
        return self._call("answerCallbackQuery", {"callback_query_id": callback_query_id, **kwargs})

    def send_chat_action(self, chat_id: int, action: str = "typing") -> dict[str, Any]:
        return self._call("sendChatAction", {"chat_id": chat_id, "action": action})

    def get_updates(self, offset: int | None = None, timeout: int = 25) -> list[dict[str, Any]]:
        payload: dict[str, Any] = {"timeout": max(0, min(int(timeout), 50)), "allowed_updates": ["message", "callback_query"]}
        if offset is not None:
            payload["offset"] = int(offset)
        result = self._call("getUpdates", payload)
        updates = result.get("result", [])
        if not isinstance(updates, list):
            raise TelegramError("Telegram Bot API returned malformed updates")
        return updates


@dataclass
class FakeTelegramClient:
    sent: list[dict[str, Any]] = field(default_factory=list)
    edited: list[dict[str, Any]] = field(default_factory=list)
    callbacks: list[dict[str, Any]] = field(default_factory=list)
    actions: list[dict[str, Any]] = field(default_factory=list)
    updates: list[dict[str, Any]] = field(default_factory=list)

    def send_message(self, chat_id: int, text: str, **kwargs: Any) -> dict[str, Any]:
        item = {"chat_id": chat_id, "text": text, **kwargs}
        self.sent.append(item)
        return {"ok": True, "result": {"message_id": len(self.sent), **item}}

    def edit_message(self, chat_id: int, message_id: int, text: str, **kwargs: Any) -> dict[str, Any]:
        item = {"chat_id": chat_id, "message_id": message_id, "text": text, **kwargs}
        self.edited.append(item)
        return {"ok": True, "result": item}

    def answer_callback(self, callback_query_id: str, **kwargs: Any) -> dict[str, Any]:
        item = {"callback_query_id": callback_query_id, **kwargs}
        self.callbacks.append(item)
        return {"ok": True, "result": True}

    def send_chat_action(self, chat_id: int, action: str = "typing") -> dict[str, Any]:
        item = {"chat_id": chat_id, "action": action}
        self.actions.append(item)
        return {"ok": True, "result": True}

    def get_updates(self, offset: int | None = None, timeout: int = 25) -> list[dict[str, Any]]:
        del offset, timeout
        updates, self.updates = self.updates, []
        return updates
