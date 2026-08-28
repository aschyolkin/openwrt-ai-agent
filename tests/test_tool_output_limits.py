import json
import unittest

from ai_agent.llm_client import compact_tool_result


class ToolOutputLimitTests(unittest.TestCase):
    def test_large_log_keeps_only_tail_and_stays_bounded(self):
        encoded = compact_tool_result({"ok": True, "output": "\n".join(f"line-{i}" for i in range(1000))}, 4000)
        data = json.loads(encoded)
        self.assertLessEqual(len(encoded), 4000)
        self.assertTrue(data["context_truncated"])
        self.assertNotIn("line-0\n", data["output"])
        self.assertIn("line-999", data["output"])

    def test_huge_structured_result_returns_valid_bounded_json(self):
        encoded = compact_tool_result({"rows": [{"value": "x" * 1000} for _ in range(500)]}, 4096)
        data = json.loads(encoded)
        self.assertLessEqual(len(encoded), 4096)
        self.assertEqual(data["error"], "tool_output_truncated")


if __name__ == "__main__":
    unittest.main()
