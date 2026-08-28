from __future__ import annotations

import fcntl
import json
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from ..adapters import state_hashes
from ..errors import AgentError
from ..models import MutationPlan, VerificationResult
from ..redaction import sanitize
from ..registry import ExecClass, ToolRegistry, validate_schema
from ..storage.sessions import SessionStore
from .backup import BackupStore


class ActionManager:
    def __init__(
        self,
        registry: ToolRegistry,
        sessions: SessionStore,
        backups: BackupStore,
        context: Any,
        audit_path: str,
        ttl_seconds: int = 300,
        lock_path: str = "/var/run/ai-agent.mutation.lock",
    ):
        self.registry = registry
        self.sessions = sessions
        self.backups = backups
        self.context = context
        self.audit_path = audit_path
        self.ttl_seconds = ttl_seconds
        self.lock_path = lock_path
        self._process_lock = threading.RLock()

    def recover_interrupted(self) -> list[str]:
        recovered = self.sessions.recover_interrupted()
        for action_id in recovered:
            action = self.sessions.get_action(action_id)
            if action and action.get("backup_dir"):
                try:
                    self.backups.update_state(action["backup_dir"], "manual_review", {"recovered_after_restart": True})
                except AgentError:
                    pass
            self._audit("manual_review", action_id, {"reason": "process_restart"})
        return recovered

    def plan(self, session_id: str, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        spec = self.registry.get(tool_name)
        if spec.exec_class != ExecClass.MUTATING or spec.planner is None:
            raise AgentError("not_mutating", f"Tool {tool_name} не является mutating")
        validate_schema(spec.parameters, arguments)
        mutation = spec.planner(self.context, arguments)
        action_id = f"{int(time.time())}-{uuid.uuid4().hex[:10]}"
        try:
            self.sessions.create_action(
                action_id, session_id, tool_name, arguments, mutation.to_dict(), self.ttl_seconds
            )
        except sqlite3.IntegrityError as exc:
            raise AgentError(
                "mutation_locked",
                "Другое изменяющее действие уже ожидает подтверждения или завершения",
                retryable=True,
            ) from exc
        self._audit("pending", action_id, {"session_id": session_id, "tool": tool_name, "arguments": sanitize(arguments)})
        return {
            "ok": True,
            "status": "awaiting_confirmation",
            "action_id": action_id,
            "expires_at": int(time.time()) + self.ttl_seconds,
            "plan": {
                "summary": mutation.summary,
                "diff": mutation.diff,
                "targets": mutation.targets,
                "services": mutation.services,
                "verifier": mutation.verifier,
            },
        }

    def confirm(self, session_id: str, action_id: str, approve: bool) -> dict[str, Any]:
        with self._process_lock:
            action = self._owned_action(session_id, action_id)
            if action["state"] != "pending":
                raise AgentError("invalid_action_state", f"Действие находится в состоянии {action['state']}")
            if int(action["expires_at"]) < int(time.time()):
                self.sessions.transition(action_id, "pending", "expired")
                self._audit("expired", action_id, {})
                raise AgentError("confirmation_expired", "Срок подтверждения истёк; постройте план заново")
            if not approve:
                self.sessions.transition(action_id, "pending", "cancelled")
                self._audit("cancelled", action_id, {"session_id": session_id})
                return {"ok": True, "action_id": action_id, "state": "cancelled", "message": "Действие отменено"}
            if not self.sessions.transition(action_id, "pending", "confirmed"):
                raise AgentError("action_race", "Состояние действия изменилось параллельно")
            return self._apply(action_id)

    def confirm_rollback(self, session_id: str, action_id: str, approve: bool) -> dict[str, Any]:
        with self._process_lock:
            action = self._owned_action(session_id, action_id)
            if action["state"] != "rollback_pending":
                raise AgentError("invalid_action_state", f"Откат недоступен в состоянии {action['state']}")
            if not approve:
                self.sessions.transition(action_id, "rollback_pending", "rollback_declined")
                self._audit("rollback_declined", action_id, {"session_id": session_id})
                return {"ok": True, "action_id": action_id, "state": "rollback_declined"}
            return self._rollback(action)

    def _apply(self, action_id: str) -> dict[str, Any]:
        action = self.sessions.get_action(action_id)
        assert action is not None
        spec = self.registry.get(action["tool_name"])
        plan = MutationPlan(**action["plan"])
        lock_file = self._lock_file()
        backup_dir = ""
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            for package in plan.uci_packages:
                pending = self.context.uci.changes(package)
                if pending:
                    self.sessions.transition(action_id, "confirmed", "stale", error={"uci_changes": pending[:4096]})
                    self._audit("stale", action_id, {"reason": "foreign_uci_changes", "package": package})
                    return {
                        "ok": False,
                        "action_id": action_id,
                        "state": "stale",
                        "error": "foreign_uci_changes",
                        "message": f"В UCI {package} есть чужие незакоммиченные изменения; действие отменено",
                    }
            actual = state_hashes([target for target in plan.targets if target.startswith("file:") or target.startswith("/")])
            expected = {key: value for key, value in plan.precondition_hashes.items() if key in actual}
            if actual != expected:
                self.sessions.transition(action_id, "confirmed", "stale", error={"expected": expected, "actual": actual})
                self._audit("stale", action_id, {"reason": "state_hash_changed"})
                return {
                    "ok": False, "action_id": action_id, "state": "stale",
                    "error": "state_changed", "message": "Конфигурация изменилась после построения плана; постройте план заново",
                }
            backup_dir = self.backups.create(action_id, action["tool_name"], plan)
            self.sessions.transition(action_id, "confirmed", "applying", backup_dir=backup_dir)
            self._audit("applying", action_id, {"backup_dir": Path(backup_dir).name})
            assert spec.applier is not None
            apply_result = spec.applier(self.context, plan)
            self.sessions.transition(action_id, "applying", "applied")
            self.backups.update_state(backup_dir, "applied", {"apply_result": sanitize(apply_result)})
            assert spec.verifier is not None
            verification = spec.verifier(self.context, plan)
            if verification.ok:
                self.sessions.transition(action_id, "applied", "verified")
                self.backups.update_state(backup_dir, "verified", {"verification": sanitize(verification.to_dict())})
                self._audit("verified", action_id, {"verification": sanitize(verification.to_dict())})
                return {
                    "ok": True, "action_id": action_id, "state": "verified",
                    "apply_result": apply_result, "verification": verification.to_dict(),
                    "message": verification.message or "Действие выполнено и проверено",
                }
            error = {"verification": verification.to_dict()}
            self.sessions.transition(action_id, "applied", "failed", error=error)
            self.sessions.transition(action_id, "failed", "rollback_pending", error=error)
            self.backups.update_state(backup_dir, "rollback_pending", error)
            self._audit("rollback_pending", action_id, sanitize(error))
            return {
                "ok": False, "action_id": action_id, "state": "rollback_pending",
                "error": "verification_failed", "verification": verification.to_dict(),
                "message": "Проверка после изменения не прошла; требуется отдельное подтверждение отката",
            }
        except Exception as exc:
            current = self.sessions.get_action(action_id)
            state = current["state"] if current else "unknown"
            error = {"type": type(exc).__name__, "message": str(exc)[:1000]}
            if state in {"applying", "applied", "failed"}:
                self.sessions.transition(action_id, ("applying", "applied", "failed"), "rollback_pending", error=error)
                if backup_dir:
                    self.backups.update_state(backup_dir, "rollback_pending", {"error": sanitize(error)})
                state = "rollback_pending"
            elif state == "confirmed":
                self.sessions.transition(action_id, "confirmed", "failed", error=error)
                state = "failed"
            self._audit(state, action_id, sanitize(error))
            return {"ok": False, "action_id": action_id, "state": state, "error": "apply_failed", "message": str(exc)}
        finally:
            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            finally:
                lock_file.close()

    def _rollback(self, action: dict[str, Any]) -> dict[str, Any]:
        action_id = action["id"]
        spec = self.registry.get(action["tool_name"])
        plan = MutationPlan(**action["plan"])
        backup_dir = action.get("backup_dir") or ""
        lock_file = self._lock_file()
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            self.backups.update_state(backup_dir, "rolling_back")
            if spec.rollback is not None:
                verification = spec.rollback(self.context, plan, backup_dir)
            else:
                restored = self.backups.restore(backup_dir)
                verification = VerificationResult(True, restored, "Бэкап восстановлен")
            if verification.ok:
                self.sessions.transition(action_id, "rollback_pending", "rolled_back")
                self.backups.update_state(backup_dir, "rolled_back", {"rollback_verification": verification.to_dict()})
                self._audit("rolled_back", action_id, {"verification": verification.to_dict()})
                return {
                    "ok": True, "action_id": action_id, "state": "rolled_back",
                    "verification": verification.to_dict(),
                    "message": verification.message or "Откат выполнен",
                }
            self.sessions.transition(action_id, "rollback_pending", "manual_review", error={"rollback": verification.to_dict()})
            self.backups.update_state(backup_dir, "manual_review", {"rollback_verification": verification.to_dict()})
            self._audit("manual_review", action_id, {"verification": verification.to_dict()})
            return {
                "ok": False, "action_id": action_id, "state": "manual_review",
                "verification": verification.to_dict(),
                "message": verification.message or "Результат отката требует ручной проверки",
            }
        except Exception as exc:
            self.sessions.transition(action_id, "rollback_pending", "manual_review", error={"message": str(exc)[:1000]})
            self._audit("manual_review", action_id, {"message": str(exc)[:1000]})
            return {"ok": False, "action_id": action_id, "state": "manual_review", "error": "rollback_failed", "message": str(exc)}
        finally:
            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            finally:
                lock_file.close()

    def _owned_action(self, session_id: str, action_id: str) -> dict[str, Any]:
        action = self.sessions.get_action(action_id)
        if action is None:
            raise AgentError("unknown_action", "Действие не найдено")
        if action["session_id"] != session_id:
            raise AgentError("action_session_mismatch", "Действие принадлежит другой сессии")
        return action

    def _lock_file(self):
        Path(self.lock_path).parent.mkdir(parents=True, exist_ok=True)
        return open(self.lock_path, "a+", encoding="utf-8")

    def _audit(self, event: str, action_id: str, details: dict[str, Any]) -> None:
        record = json.dumps(
            {"ts": int(time.time()), "event": event, "action_id": action_id, "details": sanitize(details)},
            ensure_ascii=False, separators=(",", ":"),
        ) + "\n"
        Path(self.audit_path).parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(self.audit_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(descriptor, record.encode("utf-8"))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
