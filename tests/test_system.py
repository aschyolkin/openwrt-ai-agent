from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from ai_agent.tools.system import agent_audit_log


class AgentAuditLogTests(unittest.TestCase):
    def _context_with_entries(self, tmp_dir: str, entries: list[dict]) -> SimpleNamespace:
        path = Path(tmp_dir) / "audit.log"
        with path.open("w", encoding="utf-8") as handle:
            for entry in entries:
                handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return SimpleNamespace(config=SimpleNamespace(audit_path=str(path)))

    def test_missing_file_returns_empty(self):
        context = SimpleNamespace(config=SimpleNamespace(audit_path="/nonexistent/audit.log"))
        result = agent_audit_log(context, {})
        self.assertEqual(result["entries"], [])
        self.assertEqual(result["total"], 0)
        self.assertIsNone(result["next_offset"])

    def test_returns_newest_first_and_paginates(self):
        with TemporaryDirectory() as tmp:
            entries = [
                {"ts": 100, "event": "pending", "action_id": "a1", "details": {}},
                {"ts": 300, "event": "verified", "action_id": "a2", "details": {}},
                {"ts": 200, "event": "applying", "action_id": "a1", "details": {}},
            ]
            context = self._context_with_entries(tmp, entries)
            result = agent_audit_log(context, {"limit": 2})
            self.assertEqual([entry["ts"] for entry in result["entries"]], [300, 200])
            self.assertEqual(result["total"], 3)
            self.assertEqual(result["next_offset"], 2)
            self.assertTrue(all("time" in entry for entry in result["entries"]))

            second_page = agent_audit_log(context, {"limit": 2, "offset": 2})
            self.assertEqual([entry["ts"] for entry in second_page["entries"]], [100])
            self.assertIsNone(second_page["next_offset"])

    def test_contains_filters_by_substring(self):
        with TemporaryDirectory() as tmp:
            entries = [
                {"ts": 100, "event": "pending", "action_id": "a1", "details": {"tool": "netshift_add_domain_to_section"}},
                {"ts": 200, "event": "verified", "action_id": "a2", "details": {"tool": "firewall_open_wan_port"}},
            ]
            context = self._context_with_entries(tmp, entries)
            result = agent_audit_log(context, {"contains": "firewall"})
            self.assertEqual(len(result["entries"]), 1)
            self.assertEqual(result["entries"][0]["action_id"], "a2")

    def test_skips_malformed_lines(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.log"
            path.write_text('{"ts": 100, "event": "pending", "action_id": "a1", "details": {}}\nnot json\n', encoding="utf-8")
            context = SimpleNamespace(config=SimpleNamespace(audit_path=str(path)))
            result = agent_audit_log(context, {})
            self.assertEqual(result["total"], 1)


if __name__ == "__main__":
    unittest.main()
