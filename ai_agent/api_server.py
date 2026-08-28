from __future__ import annotations

import json
import logging
import os
import signal
import socket
import socketserver
import stat
import threading
from pathlib import Path
from typing import Any

from .errors import AgentError


LOG = logging.getLogger("ai-agent.api")


class AgentRequestHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        maximum = self.server.core.config.max_request_bytes  # type: ignore[attr-defined]
        raw = self.rfile.readline(maximum + 1)
        if len(raw) > maximum:
            self._write({"ok": False, "error": "request_too_large", "message": "Запрос превышает лимит"})
            return
        try:
            request = json.loads(raw.decode("utf-8"))
            if not isinstance(request, dict):
                raise ValueError("request is not an object")
            response = self.server.core.dispatch(request)  # type: ignore[attr-defined]
        except AgentError as exc:
            response = exc.to_dict()
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
            response = {"ok": False, "error": "invalid_request", "message": str(exc)[:300]}
        except Exception:
            LOG.exception("unhandled API error")
            response = {"ok": False, "error": "internal_error", "message": "Внутренняя ошибка агента"}
        self._write(response)

    def _write(self, response: dict[str, Any]) -> None:
        encoded = json.dumps(response, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
        self.wfile.write(encoded)


class ThreadingUnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, path: str, core):
        self.core = core
        super().__init__(path, AgentRequestHandler)


def serve(core) -> None:
    path = Path(core.config.socket_path)
    if path.exists() or path.is_socket():
        mode = path.lstat().st_mode
        if not stat.S_ISSOCK(mode):
            raise AgentError("unsafe_socket_path", f"{path} существует и не является сокетом")
        path.unlink()
    path.parent.mkdir(parents=True, exist_ok=True)
    previous_umask = os.umask(0o177)
    try:
        server = ThreadingUnixServer(str(path), core)
    finally:
        os.umask(previous_umask)
    os.chmod(path, 0o600)
    stopping = threading.Event()

    def stop(_signum, _frame):
        if not stopping.is_set():
            stopping.set()
            threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
        try:
            path.unlink()
        except FileNotFoundError:
            pass

