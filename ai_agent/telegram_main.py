from __future__ import annotations

import json
import os
import socket
import time

from .telegram import TelegramBotClient
from .telegram_worker import TelegramWorker


def _env(path: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in open(path, encoding="utf-8"):
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def _core_request(socket_path: str, method: str, params: dict) -> dict:
    payload = (json.dumps({"method": method, "params": params}, ensure_ascii=False) + "\n").encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(190)
        client.connect(socket_path)
        client.sendall(payload)
        data = client.recv(2 * 1024 * 1024)
    return json.loads(data.split(b"\n", 1)[0].decode())


def main() -> None:
    env = _env(os.environ.get("AI_AGENT_TELEGRAM_ENV", "/etc/ai-agent/telegram.env"))
    token = env.get("TELEGRAM_BOT_TOKEN", "")
    chats = frozenset(int(item.strip()) for item in env.get("TELEGRAM_ALLOWED_CHAT_IDS", "").split(",") if item.strip())
    if not token or not chats:
        raise SystemExit("Telegram token and allowlist are required")
    client = TelegramBotClient(token, proxy=env.get("TELEGRAM_PROXY") or "http://10.110.112.1:2080")
    worker = TelegramWorker(client, lambda method, params: _core_request("/var/run/ai-agent.sock", method, params), chats)
    while True:
        try:
            worker.run_once()
        except Exception:
            time.sleep(5)


if __name__ == "__main__":
    main()
