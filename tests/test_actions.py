from __future__ import annotations

import tempfile
import json
import os
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

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

    def test_duplicate_confirmation_replays_without_applying_twice(self):
        pending = self.manager.plan(self.session, "test_mutation", {"value": "after\n"})
        action_id = pending["action_id"]

        first = self.manager.confirm(self.session, action_id, True)
        replay = self.manager.confirm(self.session, action_id, True)

        self.assertEqual(replay["state"], first["state"])
        self.assertTrue(replay["replayed"])
        audit = [
            json.loads(line) for line in (Path(self.temp.name) / "audit.log")
            .read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(sum(item["event"] == "applying" for item in audit), 1)

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

    def test_successful_reverify_keeps_change_and_marks_verified(self):
        self.context.verifier_ok = False
        pending = self.manager.plan(self.session, "test_mutation", {"value": "working\n"})
        action_id = pending["action_id"]
        failed = self.manager.confirm(self.session, action_id, True)
        self.assertEqual(failed["state"], "rollback_pending")
        self.context.verifier_ok = True

        result = self.manager.reverify(self.session, action_id)

        self.assertTrue(result["ok"])

        self.assertEqual(result["state"], "verified")
        self.assertEqual(self.target.read_text(encoding="utf-8"), "working\n")
        self.assertIsNone(self.sessions.active_action())
    def test_rollback_retry_does_not_return_stale_apply_result(self):
        self.context.verifier_ok = False
        pending = self.manager.plan(self.session, "test_mutation", {"value": "broken\n"})
        action_id = pending["action_id"]
        failed = self.manager.confirm(self.session, action_id, True)
        self.assertEqual(failed["state"], "rollback_pending")
        # Simulate a crash after committing the decision but before persisting
        # its response: result_json still contains the apply/verifier result.
        self.assertTrue(self.sessions.transition(
            action_id, "rollback_pending", "rollback_declined",
        ))

        replay = self.manager.confirm_rollback(self.session, action_id, False)

        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["state"], "rollback_declined")


    def test_failed_reverify_remains_rollback_pending(self):
        self.context.verifier_ok = False
        pending = self.manager.plan(self.session, "test_mutation", {"value": "broken\n"})
        action_id = pending["action_id"]
        self.manager.confirm(self.session, action_id, True)

        result = self.manager.reverify(self.session, action_id)

        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "rollback_pending")
        self.assertEqual(self.sessions.active_action()["id"], action_id)

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

    def test_rollback_pending_survives_restart_recovery(self):
        self.context.verifier_ok = False
        pending = self.manager.plan(self.session, "test_mutation", {"value": "broken\n"})
        action_id = pending["action_id"]
        result = self.manager.confirm(self.session, action_id, True)
        self.assertEqual(result["state"], "rollback_pending")

        recovered = self.manager.recover_interrupted()

        self.assertEqual(recovered, [])
        self.assertEqual(self.sessions.get_action(action_id)["state"], "rollback_pending")

    def test_cleanup_preserves_nonterminal_and_damaged_backups(self):
        now = 2_000_000_000
        old = now - 60 * 86400
        verified = self.backups.root / "old_verified"
        pending = self.backups.root / "old_rollback_pending"
        damaged = self.backups.root / "old_damaged"
        for directory in (verified, pending, damaged):
            directory.mkdir()
        self.backups.write_meta(str(verified), {
            "action_id": "verified", "state": "verified", "created_at": old,
        })
        self.backups.write_meta(str(pending), {
            "action_id": "pending", "state": "rollback_pending", "created_at": old,
        })
        (damaged / "meta.json").write_text("not json", encoding="utf-8")
        for directory in (verified, pending, damaged):
            os.utime(directory, (old, old))

        with patch("ai_agent.safety.backup.time.time", return_value=now):
            removed = self.backups.cleanup(30)

        self.assertEqual(removed, 1)
        self.assertFalse(verified.exists())
        self.assertTrue(pending.exists())
        self.assertTrue(damaged.exists())


if __name__ == "__main__":
    unittest.main()
