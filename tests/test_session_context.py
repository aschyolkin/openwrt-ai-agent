import json
import tempfile
import unittest
from pathlib import Path

from ai_agent.storage.sessions import SessionStore


class SessionContextTests(unittest.TestCase):
    def test_llm_usage_is_persisted_per_request(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = SessionStore(str(Path(temporary) / "sessions.sqlite"))
            session = store.ensure_session("usage")
            store.record_llm_usage(session, {
                "model": "gpt-oss-20b", "model_route": "simple_read_only",
                "prompt_tokens": 5842, "completion_tokens": 413, "total_tokens": 6255,
                "cached_tokens": 1200, "tools_count": 4, "tool_calls": 1,
                "messages_chars": 12000, "tool_schema_chars": 1800,
            })
            rows = store.usage_history(session)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["total_tokens"], 6255)
            self.assertEqual(rows[0]["tools_count"], 4)

    def test_bounded_history_keeps_complete_latest_turn(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = SessionStore(str(Path(temporary) / "sessions.sqlite"))
            session = store.ensure_session("bounded")
            for index in range(8):
                store.append_message(session, {"role": "user", "content": f"old-{index}-" + "x" * 500})
                store.append_message(session, {"role": "assistant", "content": f"answer-{index}-" + "y" * 500})
            store.append_message(session, {"role": "user", "content": "latest"})
            store.append_message(session, {"role": "assistant", "tool_calls": [{"id": "c1"}], "content": ""})
            store.append_message(session, {"role": "tool", "tool_call_id": "c1", "content": "result"})
            store.append_message(session, {"role": "assistant", "content": "done"})
            result = store.history_bounded(session, max_chars=1800)
            self.assertEqual(result[0]["role"], "user")
            self.assertEqual(result[-4]["content"], "latest")
            self.assertEqual([item["role"] for item in result[-4:]], ["user", "assistant", "tool", "assistant"])
            self.assertLessEqual(len(json.dumps(result, ensure_ascii=False)), 1800)

    def test_old_history_is_replaced_with_compact_summary(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = SessionStore(str(Path(temporary) / "sessions.sqlite"))
            session = store.ensure_session("summary")
            for index in range(20):
                store.append_message(session, {"role": "user", "content": f"проверь сервис {index} " + "x" * 300})
                store.append_message(session, {"role": "assistant", "content": f"сервис {index} работает " + "y" * 300})
            result = store.history_with_summary(session, max_chars=5000)
            self.assertEqual(result[0]["role"], "system")
            self.assertIn("Краткое состояние", result[0]["content"])
            self.assertIn("Запрос пользователя", result[0]["content"])
            self.assertEqual(result[-1]["role"], "assistant")
            self.assertLessEqual(len(json.dumps(result, ensure_ascii=False, separators=(",", ":"))), 5000)


if __name__ == "__main__":
    unittest.main()
