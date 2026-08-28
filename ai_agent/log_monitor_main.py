from __future__ import annotations

import fcntl
import json
import subprocess

import requests

from .config import DEFAULT_COMPLEX_MODEL, load_secret
from .llm_client import LLMClient
from .log_monitor import LogMonitor, collect_logread
from .telegram import TelegramBotClient
from .telegram_main import _env


def _status(command: list[str]) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=8, check=False)
        return (result.stdout or result.stderr).strip().lower()[:80]
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _process_running(fragment: str) -> bool:
    try:
        result = subprocess.run(["/bin/ps", "w"], capture_output=True, text=True, timeout=8, check=False)
        return any(fragment in line for line in result.stdout.splitlines())
    except (OSError, subprocess.SubprocessError):
        return False


def runtime_state() -> dict[str, str]:
    agent_status = _status(["/etc/init.d/ai-agent", "status"])
    return {
        "ai_agent": "ready" if agent_status == "running" else agent_status,
        "telegram": _status(["/etc/init.d/ai-agent-telegram", "status"]),
        "adguardhome": _status(["/etc/init.d/adguardhome", "status"]),
        "zapret": _status(["/etc/init.d/zapret", "status"]),
        "sing_box": "running" if _process_running("/usr/bin/sing-box run") else "not_running",
    }


def main() -> None:
    with open("/var/run/ai-agent-log-monitor.lock", "w", encoding="ascii") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        telegram_env = _env("/etc/ai-agent/telegram.env")
        chats = [int(item.strip()) for item in telegram_env.get("TELEGRAM_ALLOWED_CHAT_IDS", "").split(",") if item.strip()]
        api_key = load_secret("/etc/ai-agent/secrets.env")
        http = requests.Session()
        http.trust_env = False
        llm = LLMClient("https://ai.api.cloud.yandex.net/v1", api_key, DEFAULT_COMPLEX_MODEL, timeout=60, session=http)
        telegram = TelegramBotClient(
            telegram_env["TELEGRAM_BOT_TOKEN"], proxy=telegram_env.get("TELEGRAM_PROXY") or "http://10.110.112.1:2080"
        )
        monitor = LogMonitor(llm, telegram, chats, "/var/lib/ai-agent/log-monitor-state.json")
        print(json.dumps(monitor.run(collect_logread(), current_state=runtime_state()), ensure_ascii=False))


if __name__ == "__main__":
    main()
