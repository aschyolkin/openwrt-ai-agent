from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ai_agent.core import FOLLOW_UP_CHAIN_LIMIT, AgentCore
from ai_agent.errors import AgentError
from ai_agent.storage.sessions import SessionStore


class FakeOrchestrator:
    """Records each extra turn and replies with a canned response per call."""

    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.prompts = []

    def chat(self, session_id, message, *, persist_user=True):
        self.prompts.append(message)
        if self.responses:
            return self.responses.pop(0)
        return {"ok": True, "status": "completed", "message": "готово"}


class FakeActions:
    def __init__(self, results):
        self.results = list(results)

    def confirm(self, session_id, action_id, approve):
        # Copy: core mutates the result by attaching follow_up.
        return dict(self.results.pop(0))


def build_core(temporary, actions, orchestrator):
    core = AgentCore.__new__(AgentCore)
    core.sessions = SessionStore(str(Path(temporary) / "sessions.sqlite"))
    core.actions = actions
    core.orchestrator = orchestrator
    return core


VERIFIED = {"ok": True, "state": "verified", "message": "Порт закрыт"}


class FollowUpChainTests(unittest.TestCase):
    def test_confirmed_action_gets_one_more_turn(self):
        with tempfile.TemporaryDirectory() as temporary:
            orchestrator = FakeOrchestrator([
                {"status": "awaiting_confirmation", "action_id": "a2", "message": "Открыть SSH на 9888"},
            ])
            core = build_core(temporary, FakeActions([VERIFIED]), orchestrator)
            session = core.sessions.ensure_session("chain")
            result = core.confirm(session, "a1", True)
            self.assertEqual(result["follow_up"]["action_id"], "a2")
            self.assertIn("[local confirmation: action=a1, approve=true]", orchestrator.prompts[0])
            self.assertIn("остались невыполненные части", orchestrator.prompts[0])

    def test_chain_continues_across_many_steps(self):
        with tempfile.TemporaryDirectory() as temporary:
            orchestrator = FakeOrchestrator()
            core = build_core(temporary, FakeActions([VERIFIED] * 6), orchestrator)
            session = core.sessions.ensure_session("long")
            for index in range(6):
                result = core.confirm(session, f"a{index}", True)
                self.assertIsNotNone(result["follow_up"])
            self.assertEqual(len(orchestrator.prompts), 6)
            self.assertEqual(core._follow_up_depth(session), 6)

    def test_chain_stops_at_limit(self):
        with tempfile.TemporaryDirectory() as temporary:
            orchestrator = FakeOrchestrator()
            core = build_core(temporary, FakeActions([VERIFIED] * (FOLLOW_UP_CHAIN_LIMIT + 1)), orchestrator)
            session = core.sessions.ensure_session("limit")
            for index in range(FOLLOW_UP_CHAIN_LIMIT):
                core.confirm(session, f"a{index}", True)
            capped = core.confirm(session, "overflow", True)
            self.assertEqual(capped["follow_up"]["status"], "chain_limit")
            self.assertEqual(len(orchestrator.prompts), FOLLOW_UP_CHAIN_LIMIT)

    def test_no_follow_up_when_declined_or_not_verified(self):
        with tempfile.TemporaryDirectory() as temporary:
            orchestrator = FakeOrchestrator()
            failed = {"ok": False, "state": "rollback_pending", "message": "Проверка не прошла"}
            cancelled = {"ok": True, "state": "cancelled"}
            core = build_core(temporary, FakeActions([failed, cancelled]), orchestrator)
            session = core.sessions.ensure_session("stop")
            self.assertNotIn("follow_up", core.confirm(session, "a1", True))
            self.assertNotIn("follow_up", core.confirm(session, "a2", False))
            self.assertEqual(orchestrator.prompts, [])
            roles = [item["content"] for item in core.sessions.history(session)]
            self.assertIn("[local confirmation: action=a1, approve=true]", roles)
            self.assertIn("[local confirmation: action=a2, approve=false]", roles)

    def test_failed_follow_up_turn_does_not_break_confirmation(self):
        with tempfile.TemporaryDirectory() as temporary:
            class Broken(FakeOrchestrator):
                def chat(self, session_id, message, *, persist_user=True):
                    raise AgentError("llm_unavailable", "модель недоступна")

            core = build_core(temporary, FakeActions([VERIFIED]), Broken())
            session = core.sessions.ensure_session("broken")
            result = core.confirm(session, "a1", True)
            self.assertTrue(result["ok"])
            self.assertNotIn("follow_up", result)

    def test_completed_follow_up_is_replayed_without_second_llm_call(self):
        with tempfile.TemporaryDirectory() as temporary:
            orchestrator = FakeOrchestrator([
                {"ok": True, "status": "completed", "message": "всё готово"},
            ])
            core = build_core(temporary, FakeActions([VERIFIED]), orchestrator)
            session = core.sessions.ensure_session("durable")
            core.sessions.create_action(
                "a1", session, "fake", {}, {
                    "summary": "test", "diff": "", "targets": [],
                    "precondition_hashes": {}, "prepared": {},
                }, 300,
            )
            for before, after in (
                ("pending", "confirmed"), ("confirmed", "applying"),
                ("applying", "applied"), ("applied", "verified"),
            ):
                self.assertTrue(core.sessions.transition("a1", before, after))
            core.sessions.store_action_result("a1", VERIFIED)

            first = core.confirm(session, "a1", True)
            self.assertEqual(first["follow_up"]["message"], "всё готово")
            core.actions = FakeActions([{**VERIFIED, "replayed": True}])
            core.orchestrator = FakeOrchestrator()

            replay = core.confirm(session, "a1", True)

            self.assertEqual(replay["follow_up"]["message"], "всё готово")
            self.assertEqual(core.orchestrator.prompts, [])


if __name__ == "__main__":
    unittest.main()
