from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any


DEFAULT_TELEGRAM_OFFSET_PATH = "/var/lib/ai-agent/telegram-offset.json"
DEFAULT_TELEGRAM_HEALTH_PATH = "/var/run/ai-agent-telegram-health.json"


def _atomic_json_write(path: str | Path, payload: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=target.parent,
            prefix=f".{target.name}.", delete=False,
        ) as handle:
            temporary = handle.name
            json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
        temporary = None
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


class TelegramOffsetStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def initialize(self) -> None:
        if not self.path.exists():
            _atomic_json_write(self.path, {
                "offset": None,
                "updated_at": int(time.time()),
            })

    def load_state(self) -> dict[str, Any]:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"offset": None, "pending": None}
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return {"offset": None, "pending": None}
        if not isinstance(payload, dict):
            return {"offset": None, "pending": None}
        try:
            raw_offset = payload.get("offset")
            offset = int(raw_offset) if raw_offset is not None else None
            if offset is not None and offset < 0:
                offset = None
        except (TypeError, ValueError):
            offset = None
        pending = payload.get("pending")
        if not isinstance(pending, dict):
            pending = None
        else:
            try:
                update_id = int(pending["update_id"])
                key = str(pending["key"])
                response = pending["response"]
                if update_id < 0 or not key or not isinstance(response, dict):
                    raise ValueError
                normalized = {
                    "update_id": update_id,
                    "key": key,
                    "response": response,
                }
                delivery = pending.get("delivery")
                if isinstance(delivery, dict):
                    try:
                        delivery_key = str(delivery["key"])
                        sent_chunks = int(delivery["sent_chunks"])
                        if not delivery_key or sent_chunks < 0:
                            raise ValueError
                        normalized["delivery"] = {
                            "key": delivery_key,
                            "sent_chunks": sent_chunks,
                        }
                    except (KeyError, TypeError, ValueError):
                        pass
                pending = normalized
            except (KeyError, TypeError, ValueError):
                pending = None
        if pending is not None and offset is not None and pending["update_id"] < offset:
            pending = None
        return {"offset": offset, "pending": pending}

    def load(self) -> int | None:
        return self.load_state()["offset"]

    def save_pending(
        self,
        offset: int | None,
        update_id: int,
        key: str,
        response: dict[str, Any],
        delivery: dict[str, Any] | None = None,
    ) -> None:
        pending: dict[str, Any] = {
            "update_id": int(update_id),
            "key": str(key),
            "response": response,
        }
        if isinstance(delivery, dict):
            pending["delivery"] = {
                "key": str(delivery["key"]),
                "sent_chunks": max(0, int(delivery["sent_chunks"])),
            }
        payload: dict[str, Any] = {
            "offset": offset,
            "updated_at": int(time.time()),
            "pending": pending,
        }
        _atomic_json_write(self.path, payload)

    def save(self, offset: int) -> None:
        value = int(offset)
        if value < 0:
            raise ValueError("Telegram offset must be non-negative")
        _atomic_json_write(self.path, {
            "offset": value,
            "updated_at": int(time.time()),
        })


def write_telegram_health(path: str | Path, payload: dict[str, Any]) -> None:
    allowed = {
        "status", "offset", "last_poll_at", "last_update_at",
        "consecutive_errors", "last_error", "retry_in_seconds",
    }
    _atomic_json_write(path, {key: value for key, value in payload.items() if key in allowed})


def read_telegram_health(
    path: str | Path = DEFAULT_TELEGRAM_HEALTH_PATH,
    *,
    now: float | None = None,
    stale_after: int = 90,
) -> dict[str, Any]:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"status": "unknown"}
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return {"status": "invalid"}
    if not isinstance(raw, dict):
        return {"status": "invalid"}
    result = {
        key: raw[key]
        for key in (
            "status", "offset", "last_poll_at", "last_update_at",
            "consecutive_errors", "last_error", "retry_in_seconds",
        )
        if key in raw
    }
    status = str(result.get("status") or "unknown")
    if status not in {"starting", "ready", "degraded"}:
        status = "invalid"
    try:
        last_poll = float(result.get("last_poll_at", 0))
    except (TypeError, ValueError):
        last_poll = 0
    current = time.time() if now is None else float(now)
    if status == "ready" and (last_poll <= 0 or current - last_poll > max(1, stale_after)):
        status = "stale"
    result["status"] = status
    return result
