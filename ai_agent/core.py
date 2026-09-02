from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

import requests

from .adapters import UBusAdapter, UCIAdapter, load_agent_config
from .command import CommandRunner
from .config import AgentConfig, ensure_private_directory, load_env_file, load_secret
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
from .telegram_state import DEFAULT_TELEGRAM_HEALTH_PATH, read_telegram_health
from .tools import register_all
from .tools.backup import backup_restore


LOG = logging.getLogger("ai-agent")

# A confirmed action gives the model one more turn so a request that needs
# several mutating steps ("close 2022 and open ssh on 9888") is not silently
# truncated after the first one. Each step still needs its own confirmation, so
# the chain cannot run away on its own; this cap only stops a model that keeps
# proposing the same step forever.
FOLLOW_UP_CHAIN_LIMIT = 8


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
        self._session_locks = tuple(threading.RLock() for _ in range(64))
        self._state_lock = threading.RLock()
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
        with self._session_lock(session_id):
            if self.orchestrator is None:
                assert self.llm_error is not None
                result = self.llm_error.to_dict()
                result["session_id"] = session_id
                return result
            result = self.orchestrator.chat(session_id, message)
            with self._runtime_state_lock():
                if self.startup_warnings:
                    result["warnings"] = list(self.startup_warnings)
                    self.startup_warnings.clear()
            return result

    def confirm(self, session_id: str, action_id: str, approve: bool) -> dict[str, Any]:
        with self._session_lock(session_id):
            result = self.actions.confirm(session_id, action_id, approve)
            replayed = bool(result.pop("replayed", False))
            marker = f"[local confirmation: action={action_id}, approve={str(approve).lower()}]"
            follow_up = self._continue_after_action(
                session_id, action_id, marker, approve, result, replayed=replayed,
            )
            if follow_up is not None:
                result["follow_up"] = follow_up
            return result

    def _continue_after_action(
        self,
        session_id: str,
        action_id: str,
        marker: str,
        approve: bool,
        result: dict[str, Any],
        *,
        replayed: bool = False,
    ) -> dict[str, Any] | None:
        """Let the model take one more turn after a successfully applied action.

        Returns the follow-up chat response (which may itself be another
        `awaiting_confirmation` plan) or None when the chain must stop: the user
        declined, the action did not verify, or the chain hit its cap. In every
        stop case the marker is still appended so the transcript stays complete.
        """
        applied = bool(approve and result.get("ok") and result.get("state") == "verified")
        action = self.sessions.get_action(action_id)
        if not applied or self.orchestrator is None:
            if not replayed or not self._history_contains(session_id, marker):
                self.sessions.append_message(session_id, {"role": "user", "content": marker})
            return None
        if action and action.get("follow_up_state") == "completed":
            return action.get("follow_up")

        marker_present = any(
            item.get("role") == "user" and str(item.get("content") or "").startswith(marker)
            for item in self.sessions.history(session_id, 500)
        )
        steps = self._follow_up_depth(session_id) + (0 if marker_present else 1)
        if steps > FOLLOW_UP_CHAIN_LIMIT:
            if not self._history_contains(session_id, marker):
                self.sessions.append_message(session_id, {"role": "user", "content": marker})
            LOG.warning("follow-up chain limit reached for session %s", session_id)
            follow_up = {
                "ok": True, "session_id": session_id, "status": "chain_limit",
                "message": (
                    f"Выполнено подряд {FOLLOW_UP_CHAIN_LIMIT} действий. Если что-то из запроса ещё "
                    "не сделано, напиши это отдельным сообщением."
                ),
            }
            if action:
                self.sessions.complete_follow_up(action_id, follow_up)
            return follow_up
        detail = str(result.get("message") or "").strip()
        prompt = (
            f"{marker} Действие применено и проверено"
            + (f": {detail}" if detail else "")
            + ". Если в последнем запросе пользователя остались невыполненные части — вызови следующий "
            "нужный tool сейчас. Если запрос выполнен полностью — коротко подтверди результат одним предложением."
        )
        previous_state = self.sessions.begin_follow_up(action_id) if action else ""
        prompt_present = self._history_contains(session_id, prompt)
        if previous_state == "running" and prompt_present:
            recovered = self._recover_follow_up(session_id, action_id, prompt)
            if recovered is not None:
                if action:
                    self.sessions.complete_follow_up(action_id, recovered)
                return recovered
        if not prompt_present:
            self.sessions.append_message(session_id, {"role": "user", "content": prompt})
        try:
            follow_up = self.orchestrator.chat(session_id, prompt, persist_user=False)
        except AgentError as exc:
            LOG.warning("follow-up turn failed: %s", exc)
            follow_up = None
        if action:
            self.sessions.complete_follow_up(action_id, follow_up)
        return follow_up

    def _recover_follow_up(
        self, session_id: str, previous_action_id: str, prompt: str,
    ) -> dict[str, Any] | None:
        active = self.sessions.active_action()
        if active and active["session_id"] == session_id and active["id"] != previous_action_id:
            return {
                "ok": True,
                "session_id": session_id,
                "status": "awaiting_confirmation",
                "action_id": active["id"],
                "expires_at": active["expires_at"],
                "plan": {
                    key: active["plan"].get(key)
                    for key in ("summary", "diff", "targets", "services", "verifier")
                },
            }
        messages = self.sessions.history(session_id, 500)
        positions = [
            index for index, item in enumerate(messages)
            if item.get("role") == "user" and item.get("content") == prompt
        ]
        if not positions:
            return None
        for item in reversed(messages[positions[-1] + 1:]):
            if item.get("role") == "assistant" and not item.get("tool_calls"):
                return {
                    "ok": True,
                    "session_id": session_id,
                    "status": "completed",
                    "message": item.get("content") or "",
                }
        return None

    def _follow_up_depth(self, session_id: str) -> int:
        count = 0
        for item in reversed(self.sessions.history(session_id, 500)):
            if item.get("role") != "user":
                continue
            if str(item.get("content") or "").startswith("[local confirmation:"):
                count += 1
                continue
            break
        return count

    def _history_contains(self, session_id: str, content: str) -> bool:
        return any(
            item.get("role") == "user" and item.get("content") == content
            for item in self.sessions.history(session_id, 500)
        )

    def _runtime_state_lock(self) -> threading.RLock:
        lock = getattr(self, "_state_lock", None)
        if lock is None:
            lock = threading.RLock()
            self._state_lock = lock
        return lock

    def _session_lock(self, session_id: str) -> threading.RLock:
        locks = getattr(self, "_session_locks", None)
        if locks is None:
            with self._runtime_state_lock():
                locks = getattr(self, "_session_locks", None)
                if locks is None:
                    locks = tuple(threading.RLock() for _ in range(64))
                    self._session_locks = locks
        return locks[hash(session_id) % len(locks)]

    def rollback(self, session_id: str, action_id: str, approve: bool) -> dict[str, Any]:
        with self._session_lock(session_id):
            result = self.actions.confirm_rollback(session_id, action_id, approve)
            replayed = bool(result.pop("replayed", False))
            marker = f"[local rollback confirmation: action={action_id}, approve={str(approve).lower()}]"
            if not replayed or not self._history_contains(session_id, marker):
                self.sessions.append_message(session_id, {"role": "user", "content": marker})
            return result

    def reverify(self, session_id: str, action_id: str) -> dict[str, Any]:
        with self._session_lock(session_id):
            result = self.actions.reverify(session_id, action_id)
            replayed = bool(result.pop("replayed", False))
            marker = f"[local re-verification: action={action_id}]"
            if not replayed or not self._history_contains(session_id, marker):
                self.sessions.append_message(session_id, {"role": "user", "content": marker})
            return result

    def history(self, session_id: str, limit: int = 100) -> dict[str, Any]:
        with self._session_lock(session_id):
            messages = self.sessions.history(session_id, limit)
        return {"ok": True, "session_id": session_id, "messages": messages}

    def health(self) -> dict[str, Any]:
        active = self.sessions.active_action()
        active_summary = None
        if active is not None:
            active_summary = {
                "action_id": active["id"], "tool_name": active["tool_name"],
                "state": active["state"], "created_at": active["created_at"],
                "updated_at": active["updated_at"], "expires_at": active["expires_at"],
            }
        with self._runtime_state_lock():
            startup_warnings = list(self.startup_warnings)
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
            "telegram": read_telegram_health(
                load_env_file(os.environ.get("AI_AGENT_TELEGRAM_ENV", "/etc/ai-agent/telegram.env"))
                .get("TELEGRAM_HEALTH_PATH", DEFAULT_TELEGRAM_HEALTH_PATH)
            ),
            "active_action": active_summary,
            "startup_warnings": startup_warnings,
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
