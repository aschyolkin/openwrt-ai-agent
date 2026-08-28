from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from ai_agent.tools.system import agent_audit_log, sys_baseline_compare


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


class SysBaselineCompareTests(unittest.TestCase):
    @staticmethod
    def _context(recent_samples):
        return SimpleNamespace(metrics=SimpleNamespace(recent_samples=lambda metric, since: recent_samples))

    @patch("ai_agent.tools.system.sample_current_metrics", return_value={"cpu_percent": 50.0})
    def test_insufficient_data(self, _sample):
        context = self._context([1.0] * 5)
        result = sys_baseline_compare(context, {"metric": "cpu_percent"})
        self.assertEqual(result["status"], "insufficient_data")
        self.assertEqual(result["sample_count"], 5)

    @patch("ai_agent.tools.system.sample_current_metrics", return_value={"cpu_percent": 90.0})
    def test_high_bad_anomalous(self, _sample):
        history = [10.0] * 20
        context = self._context(history)
        result = sys_baseline_compare(context, {"metric": "cpu_percent"})
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["anomalous"])

    @patch("ai_agent.tools.system.sample_current_metrics", return_value={"cpu_percent": 11.0})
    def test_high_bad_not_anomalous(self, _sample):
        history = [10.0] * 20
        context = self._context(history)
        result = sys_baseline_compare(context, {"metric": "cpu_percent"})
        self.assertFalse(result["anomalous"])

    @patch("ai_agent.tools.system.sample_current_metrics", return_value={"mem_available_percent": 2.0})
    def test_low_bad_anomalous(self, _sample):
        history = [50.0] * 20
        context = self._context(history)
        result = sys_baseline_compare(context, {"metric": "mem_available_percent"})
        self.assertTrue(result["anomalous"])

    @patch("ai_agent.tools.system.sample_current_metrics", return_value={"lan_client_count": 1.0})
    def test_neutral_anomalous_low(self, _sample):
        history = [5.0] * 19 + [5.0]
        context = self._context(history)
        result = sys_baseline_compare(context, {"metric": "lan_client_count"})
        self.assertTrue(result["anomalous"])

    @patch("ai_agent.tools.system.sample_current_metrics", return_value={"lan_client_count": 5.0})
    def test_neutral_not_anomalous(self, _sample):
        history = [5.0] * 20
        context = self._context(history)
        result = sys_baseline_compare(context, {"metric": "lan_client_count"})
        self.assertFalse(result["anomalous"])


if __name__ == "__main__":
    unittest.main()
