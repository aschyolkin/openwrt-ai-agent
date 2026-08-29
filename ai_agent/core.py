from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import requests

from .adapters import UBusAdapter, UCIAdapter, load_agent_config
from .command import CommandRunner
from .config import AgentConfig, ensure_private_directory, load_secret
from .context import ToolContext
from .errors import AgentError
from .llm_client import LLMClient, Orchestrator
from .model_router import ModelRouter
from .redaction import sanitize
from .registry import ToolRegistry
from .safety.actions import ActionManager
from .safety.backup import BackupStore
from .storage.metrics import MetricsStore
from .storage.sessions import SessionStore
from .telegram_state import read_telegram_health
from .tools import register_all
from .tools.backup import backup_restore


LOG = logging.getLogger("ai-agent")


class AgentCore:
    def __init__(self, config: AgentConfig | None = None):
        bootstrap_runner = CommandRunner(max_output_bytes=(config.command_output_limit if config else 65536))
        bootstrap_uci = UCIAdapter(bootstrap_runner)
        self.config = config or load_agent_config(bootstrap_uci)
        ensure_private_directory(self.config.state_dir)
        self.runner = CommandRunner(max_output_bytes=self.config.command_output_limit)
        self.uci = UCIAdapter(self.runner)
        self.ubus = UBusAdapter(self.runner)
        self.http = requests.Session()
        self.http.trust_env = False
        self.sessions = SessionStore(self.config.database_path)
        self.backups = BackupStore(self.config.backups_dir, self.uci)
        self.metrics = MetricsStore(self.config.metrics_path)
        self.context = ToolContext(self.config, self.runner, self.uci, self.ubus, self.http, self.backups, self.metrics)
        self.registry = ToolRegistry()
        register_all(self.registry)
        self.registry.register(backup_restore)
        self.actions = ActionManager(
            self.registry, self.sessions, self.backups, self.context,
            self.config.audit_path, self.config.confirm_ttl_seconds,
        )
        interrupted = self.actions.recover_interrupted()
        self.startup_warnings = [
            f"Обнаружено незавершённое действие {action_id}; оно помечено manual_review и не продолжено автоматически."
            for action_id in interrupted
        ]
        try:
            self.backups.cleanup(self.config.backup_retention_days)
        except OSError as exc:
            LOG.warning("backup cleanup failed: %s", exc)
        self.orchestrator: Orchestrator | None = None
        self.llm_error: AgentError | None = None
        try:
            api_key = load_secret(self.config.secrets_path)
            prompt = self._load_prompt()
            complex_client = LLMClient(
                self.config.api_base_url, api_key, self.config.complex_model_id,
                self.config.request_timeout_seconds, self.http,
            )
            simple_client = LLMClient(
                self.config.api_base_url, api_key, self.config.simple_model_id,
                self.config.request_timeout_seconds, self.http,
            )
            router = ModelRouter(simple_client, complex_client) if self.config.model_routing_enabled else None
            self.orchestrator = Orchestrator(
                complex_client, self.registry, self.actions, self.sessions, self.context,
                prompt, self.config.max_tool_loop_iterations, router, self.config.conversation_max_chars,
                self.config.tool_context_max_chars,
            )
        except AgentError as exc:
            self.llm_error = exc

    def _load_prompt(self) -> str:
        candidates = [
            Path(self.config.system_prompt_path),
            Path(__file__).resolve().parent / "prompts" / "system_prompt.md",
        ]
        for path in candidates:
            try:
                content = path.read_text(encoding="utf-8").strip()
            except OSError:
                continue
            if content:
                return content
        raise AgentError("missing_system_prompt", "Не найден system_prompt.md")

    def chat(self, session_id: str | None, message: str) -> dict[str, Any]:
        session_id = self.sessions.ensure_session(session_id)
        if self.orchestrator is None:
            assert self.llm_error is not None
            result = self.llm_error.to_dict()
            result["session_id"] = session_id
            return result
        result = self.orchestrator.chat(session_id, message)
        if self.startup_warnings:
            result["warnings"] = list(self.startup_warnings)
            self.startup_warnings.clear()
        return result

    def confirm(self, session_id: str, action_id: str, approve: bool) -> dict[str, Any]:
        result = self.actions.confirm(session_id, action_id, approve)
        self.sessions.append_message(
            session_id,
            {"role": "user", "content": f"[local confirmation: action={action_id}, approve={str(approve).lower()}]"},
        )
        return result

    def rollback(self, session_id: str, action_id: str, approve: bool) -> dict[str, Any]:
        result = self.actions.confirm_rollback(session_id, action_id, approve)
        self.sessions.append_message(
            session_id,
            {"role": "user", "content": f"[local rollback confirmation: action={action_id}, approve={str(approve).lower()}]"},
        )
        return result

    def reverify(self, session_id: str, action_id: str) -> dict[str, Any]:
        result = self.actions.reverify(session_id, action_id)
        self.sessions.append_message(
            session_id,
            {"role": "user", "content": f"[local re-verification: action={action_id}]"},
        )
        return result

    def history(self, session_id: str, limit: int = 100) -> dict[str, Any]:
        return {"ok": True, "session_id": session_id, "messages": self.sessions.history(session_id, limit)}

    def health(self) -> dict[str, Any]:
        active = self.sessions.active_action()
        active_summary = None
        if active is not None:
            active_summary = {
                "action_id": active["id"], "tool_name": active["tool_name"],
                "state": active["state"], "created_at": active["created_at"],
                "updated_at": active["updated_at"], "expires_at": active["expires_at"],
            }
        return {
            "ok": True,
            "status": "ready" if self.orchestrator is not None else "degraded",
            "llm": "configured" if self.orchestrator is not None else (self.llm_error.code if self.llm_error else "unavailable"),
            "model": self.config.complex_model_id,
            "models": {
                "routing": self.config.model_routing_enabled,
                "simple_read_only": self.config.simple_model_id,
                "complex": self.config.complex_model_id,
            },
            "socket": self.config.socket_path,
            "native_bindings": {"uci": self.uci.native, "ubus": self.ubus.native},
            "tools": len(list(self.registry)),
            "telegram": read_telegram_health(),
            "active_action": active_summary,
            "startup_warnings": list(self.startup_warnings),
        }

    def debug_uci(self, package: str) -> dict[str, Any]:
        if package not in {"network", "dhcp", "firewall", "netshift", "zapret", "adguardhome", "ai-agent"}:
            raise AgentError("debug_package_denied", "UCI-пакет отсутствует в debug allowlist")
        return {
            "ok": True, "package": package, "raw": self.uci.export(package),
            "warning": "Прямой debug-вывод не передаётся LLM и может содержать чувствительные данные.",
        }

    def dispatch(self, request: dict[str, Any]) -> dict[str, Any]:
        method = request.get("method")
        params = request.get("params") or {}
        if not isinstance(params, dict):
            raise AgentError("invalid_request", "params должен быть объектом")
        if method == "health":
            return self.health()
        if method == "chat":
            return self.chat(params.get("session_id"), str(params.get("message", "")))
        if method == "confirm":
            if not isinstance(params.get("approve"), bool):
                raise AgentError("invalid_request", "approve должен быть boolean")
            return self.confirm(str(params.get("session_id", "")), str(params.get("action_id", "")), params["approve"])
        if method == "rollback":
            if not isinstance(params.get("approve"), bool):
                raise AgentError("invalid_request", "approve должен быть boolean")
            return self.rollback(str(params.get("session_id", "")), str(params.get("action_id", "")), params["approve"])
        if method == "reverify":
            return self.reverify(str(params.get("session_id", "")), str(params.get("action_id", "")))
        if method == "history":
            return self.history(str(params.get("session_id", "")), int(params.get("limit", 100)))
        if method == "debug_uci":
            return self.debug_uci(str(params.get("package", "")))
        if method == "cleanup_backups":
            return {"ok": True, "removed": self.backups.cleanup(self.config.backup_retention_days)}
        raise AgentError("unknown_method", f"Неизвестный метод API: {method}")


def build_core() -> AgentCore:
    return AgentCore()
