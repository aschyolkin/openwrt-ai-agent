import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock

from ai_agent.log_monitor import LogMonitor, recent_or_new_lines, suspicious_lines
from ai_agent.telegram import FakeTelegramClient


NOW = datetime(2026, 8, 28, 12, 0, 0)


class LogMonitorTests(unittest.TestCase):
    def test_recent_window_and_cursor(self):
        lines = ["Fri Aug 28 07:00:00 old", "Fri Aug 28 09:00:00 warning failed", "Fri Aug 28 11:00:00 error"]
        self.assertEqual(recent_or_new_lines(lines, {}, NOW), lines[1:])
        state = {"last_line_hash": __import__("hashlib").sha256(lines[1].encode()).hexdigest()}
        self.assertEqual(recent_or_new_lines(lines, state, NOW), lines[2:])

    def test_benign_logs_skip_llm_and_alert(self):
        with tempfile.TemporaryDirectory() as temporary:
            llm = Mock()
            telegram = FakeTelegramClient()
            monitor = LogMonitor(llm, telegram, [587849205], str(Path(temporary) / "state.json"))
            result = monitor.run(["Fri Aug 28 11:00:00 daemon.notice service started"], NOW)
            self.assertFalse(result["alerted"])
            llm.chat.assert_not_called()

    def test_warning_is_redacted_and_sent_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            llm = Mock()
            llm.chat.return_value = {"content": '{"severity":"warning","title":"Сбой DNS","summary":"Повторы","evidence":["timeout"],"recommended_actions":["проверить DNS"]}'}
            telegram = FakeTelegramClient()
            monitor = LogMonitor(llm, telegram, [587849205], str(Path(temporary) / "state.json"))
            line = "Fri Aug 28 11:00:00 daemon.err token=abc123456789 error to 8.8.8.8 example.com"
            first = monitor.run([line], NOW)
            second = monitor.run([line], NOW)
            self.assertTrue(first["alerted"])
            self.assertFalse(second["alerted"])
            sent_payload = llm.chat.call_args.args[0][1]["content"]
            self.assertNotIn("abc123456789", sent_payload)
            self.assertNotIn("8.8.8.8", sent_payload)
            self.assertEqual(len(telegram.sent), 1)

    def test_critical_fallback_alerts_when_llm_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            llm = Mock()
            llm.chat.side_effect = RuntimeError("offline")
            telegram = FakeTelegramClient()
            monitor = LogMonitor(llm, telegram, [587849205], str(Path(temporary) / "state.json"))
            result = monitor.run(["Fri Aug 28 11:00:00 kern.crit kernel panic detected"], NOW)
            self.assertTrue(result["alerted"])
            self.assertEqual(result["severity"], "critical")

    def test_recovered_service_downgrades_non_kernel_critical(self):
        with tempfile.TemporaryDirectory() as temporary:
            llm = Mock()
            llm.chat.return_value = {"content": '{"severity":"critical","title":"ai-agent failed","summary":"duplicate tool","evidence":["duplicate"],"recommended_actions":[]}'}
            telegram = FakeTelegramClient()
            monitor = LogMonitor(llm, telegram, [587849205], str(Path(temporary) / "state.json"))
            result = monitor.run(
                ["Fri Aug 28 11:00:00 daemon.err ai-agent failed duplicate tool"], NOW,
                current_state={"ai_agent": "ready", "telegram": "running"},
            )
            self.assertEqual(result["severity"], "warning")
            self.assertTrue(result["downgraded_recovered"])

    def test_suspicious_filter_removes_expected_disconnect_noise(self):
        lines = [
            "Fri Aug 28 11:00:00 authpriv.err dropbear[1]: Exit root: Disconnect received",
            "Fri Aug 28 11:01:00 daemon.err sing-box failed",
        ]
        self.assertEqual(len(suspicious_lines(lines)), 1)


if __name__ == "__main__":
    unittest.main()
