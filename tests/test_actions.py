from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from ai_agent.adapters import state_hashes
from ai_agent.errors import AgentError
from ai_agent.models import MutationPlan, VerificationResult
from ai_agent.registry import ExecClass, ToolRegistry, tool
from ai_agent.safety.actions import ActionManager
from ai_agent.safety.backup import BackupStore
from ai_agent.storage.sessions import SessionStore


class FakeUCI:
    def changes(self, package):
        return ""

    def export(self, package):
        return ""


class ActionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.target = root / "target.conf"
        self.target.write_text("before\n", encoding="utf-8")
        self.registry = ToolRegistry()
        self.uci = FakeUCI()
        self.backups = BackupStore(str(root / "backups"), self.uci)
        self.context = SimpleNamespace(uci=self.uci, backups=self.backups, target=self.target, verifier_ok=True)
        self.sessions = SessionStore(str(root / "sessions.sqlite"))

        def apply(context, plan):
            context.target.write_text(plan.prepared["value"], encoding="utf-8")
            return {"written": True}

        def verify(context, plan):
            return VerificationResult(context.verifier_ok, {"content": context.target.read_text(encoding="utf-8")})

        @tool(
            name="test_mutation", description="test",
            parameters={"type": "object", "properties": {"value": {"type": "string"}}, "required": ["value"], "additionalProperties": False},
            exec_class=ExecClass.MUTATING, applier=apply, verifier=verify,
        )
        def planner(context, arguments):
            targets = [f"file:{context.target}"]
            return MutationPlan(
                "write fake file", f"- before\n+ {arguments['value']}", targets, state_hashes(targets),
                prepared={"value": arguments["value"]}, backup_files=[str(context.target)], verifier="fake",
            )

        self.registry.register(planner)
        self.manager = ActionManager(
            self.registry, self.sessions, self.backups, self.context,
            str(root / "audit.log"), 300, str(root / "mutation.lock"),
        )
        self.session = self.sessions.ensure_session("s1")

    def tearDown(self):
        self.temp.cleanup()

    def test_apply_and_verify(self):
        pending = self.manager.plan(self.session, "test_mutation", {"value": "after\n"})
        result = self.manager.confirm(self.session, pending["action_id"], True)
        self.assertTrue(result["ok"])
        self.assertEqual(result["state"], "verified")
        self.assertEqual(result["message"], "Действие выполнено и проверено")
        self.assertEqual(self.target.read_text(encoding="utf-8"), "after\n")

    def test_stale_hash_cancels(self):
        pending = self.manager.plan(self.session, "test_mutation", {"value": "after\n"})
        self.target.write_text("foreign\n", encoding="utf-8")
        result = self.manager.confirm(self.session, pending["action_id"], True)
        self.assertEqual(result["state"], "stale")
        self.assertEqual(self.target.read_text(encoding="utf-8"), "foreign\n")

    def test_failed_verifier_requires_confirmed_rollback(self):
        self.context.verifier_ok = False
        pending = self.manager.plan(self.session, "test_mutation", {"value": "broken\n"})
        result = self.manager.confirm(self.session, pending["action_id"], True)
        self.assertEqual(result["state"], "rollback_pending")
        self.assertEqual(self.target.read_text(encoding="utf-8"), "broken\n")
        rolled_back = self.manager.confirm_rollback(self.session, pending["action_id"], True)
        self.assertEqual(rolled_back["state"], "rolled_back")
        self.assertEqual(self.target.read_text(encoding="utf-8"), "before\n")

    def test_pending_action_globally_blocks_other_sessions_until_cancelled(self):
        pending = self.manager.plan(self.session, "test_mutation", {"value": "first\n"})
        second_session = self.sessions.ensure_session("s2")

        with self.assertRaises(AgentError) as raised:
            self.manager.plan(second_session, "test_mutation", {"value": "second\n"})
        self.assertEqual(raised.exception.code, "mutation_locked")

        cancelled = self.manager.confirm(self.session, pending["action_id"], False)
        self.assertEqual(cancelled["state"], "cancelled")
        self.assertEqual(cancelled["message"], "Действие отменено")
        replacement = self.manager.plan(second_session, "test_mutation", {"value": "second\n"})
        self.assertEqual(replacement["status"], "awaiting_confirmation")

    def test_interrupted_confirmed_action_requires_manual_review(self):
        pending = self.manager.plan(self.session, "test_mutation", {"value": "after\n"})
        action_id = pending["action_id"]
        self.assertTrue(self.sessions.transition(action_id, "pending", "confirmed"))

        recovered = self.manager.recover_interrupted()

        self.assertEqual(recovered, [action_id])
        self.assertEqual(self.sessions.get_action(action_id)["state"], "manual_review")


if __name__ == "__main__":
    unittest.main()
