from __future__ import annotations

import json
import logging
import os
import socket
import time
from typing import Any

from .redaction import redact_text
from .telegram import TelegramBotClient, TelegramError
from .telegram_state import (
    DEFAULT_TELEGRAM_HEALTH_PATH,
    DEFAULT_TELEGRAM_OFFSET_PATH,
    write_telegram_health,
)
from .telegram_worker import TelegramWorker


LOG = logging.getLogger("ai-agent.telegram.main")
MAX_CORE_RESPONSE_BYTES = 2 * 1024 * 1024


def _env(path: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in open(path, encoding="utf-8"):
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def _read_core_response(client: socket.socket, maximum: int = MAX_CORE_RESPONSE_BYTES) -> dict[str, Any]:
    data = bytearray()
    while True:
        remaining = maximum + 1 - len(data)
        if remaining <= 0:
            raise ValueError("Core API response exceeds limit")
        chunk = client.recv(min(65536, remaining))
        if not chunk:
            break
        data.extend(chunk)
        newline = data.find(b"\n")
        if newline >= 0:
            del data[newline + 1:]
            break
        if len(data) > maximum:
            raise ValueError("Core API response exceeds limit")
    if not data:
        raise ValueError("Core API returned an empty response")
    if len(data) > maximum:
        raise ValueError("Core API response exceeds limit")
    payload = json.loads(bytes(data).split(b"\n", 1)[0].decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Core API response is not an object")
    return payload


def _core_request(socket_path: str, method: str, params: dict) -> dict:
    payload = (json.dumps({"method": method, "params": params}, ensure_ascii=False) + "\n").encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(190)
        client.connect(socket_path)
        client.sendall(payload)
        return _read_core_response(client)


def _retry_delay(exc: Exception, backoff: int) -> int:
    if isinstance(exc, TelegramError) and exc.retry_after is not None:
        return exc.retry_after
    return max(1, min(int(backoff), 60))


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    env = _env(os.environ.get("AI_AGENT_TELEGRAM_ENV", "/etc/ai-agent/telegram.env"))
    token = env.get("TELEGRAM_BOT_TOKEN", "")
    chats = frozenset(int(item.strip()) for item in env.get("TELEGRAM_ALLOWED_CHAT_IDS", "").split(",") if item.strip())
    if not token or not chats:
        raise SystemExit("Telegram token and allowlist are required")
    client = TelegramBotClient(token, proxy=env.get("TELEGRAM_PROXY") or "http://10.110.112.1:2080")
    offset_path = env.get("TELEGRAM_OFFSET_PATH") or DEFAULT_TELEGRAM_OFFSET_PATH
    health_path = env.get("TELEGRAM_HEALTH_PATH") or DEFAULT_TELEGRAM_HEALTH_PATH
    worker = TelegramWorker(
        client,
        lambda method, params: _core_request("/var/run/ai-agent.sock", method, params),
        chats,
        offset_path=offset_path,
    )
    backoff = 1
    consecutive_errors = 0
    last_update_at: int | None = None
    write_telegram_health(health_path, {
        "status": "starting",
        "offset": worker.offset,
        "consecutive_errors": 0,
    })
    while True:
        try:
            processed = worker.run_once()
            now = int(time.time())
            if processed:
                last_update_at = now
            consecutive_errors = 0
            backoff = 1
            write_telegram_health(health_path, {
                "status": "ready",
                "offset": worker.offset,
                "last_poll_at": now,
                "last_update_at": last_update_at,
                "consecutive_errors": 0,
            })
        except Exception as exc:
            consecutive_errors += 1
            delay = _retry_delay(exc, backoff)
            safe_error = redact_text(str(exc) or type(exc).__name__)[:300]
            write_telegram_health(health_path, {
                "status": "degraded",
                "offset": worker.offset,
                "last_update_at": last_update_at,
                "consecutive_errors": consecutive_errors,
                "last_error": safe_error,
                "retry_in_seconds": delay,
            })
            LOG.warning("Telegram polling failed; retry in %ss: %s", delay, safe_error)
            time.sleep(delay)
            backoff = min(backoff * 2, 60)


if __name__ == "__main__":
    main()
