import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock

from ai_agent.log_monitor import LogMonitor, prepare_candidates, recent_or_new_lines, suspicious_lines
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

    def test_telegram_token_in_transport_trace_is_redacted_before_llm(self):
        with tempfile.TemporaryDirectory() as temporary:
            token = "1234567890:AAGabcdefghijklmnopqrstuvwxyz_123456"
            llm = Mock()
            llm.chat.return_value = {"content": '{"severity":"none","title":"","summary":"","evidence":[],"recommended_actions":[]}'}
            monitor = LogMonitor(
                llm, FakeTelegramClient(), [587849205],
                str(Path(temporary) / "state.json"),
            )
            line = (
                "Fri Aug 28 11:00:00 daemon.err ProxyError: failed URL "
                f"https://api.telegram.org/bot{token}/sendMessage"
            )
            monitor.run([line], NOW)
            sent_payload = llm.chat.call_args.args[0][1]["content"]
            self.assertNotIn(token, sent_payload)
            self.assertIn("***redacted-telegram-token***", sent_payload)

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
            "Fri Aug 28 11:00:30 cron.err crond[1]: USER root pid 2 cmd /usr/bin/ai-agent-metrics-sample",
            "Fri Aug 28 11:01:00 daemon.err sing-box failed",
        ]
        self.assertEqual(len(suspicious_lines(lines)), 1)

    def test_netshift_maintenance_transients_are_suppressed_without_llm(self):
        with tempfile.TemporaryDirectory() as temporary:
            llm = Mock()
            telegram = FakeTelegramClient()
            monitor = LogMonitor(llm, telegram, [587849205], str(Path(temporary) / "state.json"))
            lines = [
                "Fri Aug 28 11:00:00 user.notice netshift: Stopped sing-box health monitor",
                "Fri Aug 28 11:00:01 user.notice netshift: Stop sing-box",
                "Fri Aug 28 11:00:02 user.notice AdGuardHome: [error] dnsproxy: exchange failed "
                'upstream=127.0.0.42:53 err="connection refused"',
                "Fri Aug 28 11:00:04 daemon.err ai-agent-telegram: Telegram polling failed; retry in 1s",
                "Fri Aug 28 11:00:11 user.notice netshift: Started sing-box health monitor",
            ]
            result = monitor.run(lines, NOW, current_state={"sing_box": "running", "adguardhome": "running"})
            self.assertEqual(result["maintenance_suppressed"], 2)
            self.assertEqual(result["candidates"], 0)
            self.assertFalse(result["alerted"])
            llm.chat.assert_not_called()

    def test_malformed_dns_burst_never_alerts_and_skips_llm(self):
        with tempfile.TemporaryDirectory() as temporary:
            llm = Mock()
            telegram = FakeTelegramClient()
            monitor = LogMonitor(llm, telegram, [587849205], str(Path(temporary) / "state.json"))
            lines = [
                "Fri Aug 28 11:00:00 user.notice AdGuardHome: [error] dnsproxy: "
                'unpacking udp packet err="bad question name: dns: bad rdata"'
                for _ in range(620)
            ]
            result = monitor.run(lines, NOW, current_state={"adguardhome": "running"})
            self.assertEqual(result["malformed_dns"], 620)
            self.assertEqual(result["candidates"], 0)
            self.assertFalse(result["alerted"])
            self.assertEqual(telegram.sent, [])
            llm.chat.assert_not_called()
            self.assertEqual(result["malformed_dns_types"]["bad_rdata"], 620)

    def test_malformed_dns_matches_every_unpack_wording(self):
        with tempfile.TemporaryDirectory() as temporary:
            llm = Mock()
            telegram = FakeTelegramClient()
            monitor = LogMonitor(llm, telegram, [587849205], str(Path(temporary) / "state.json"))
            lines = [
                'Fri Aug 28 11:00:00 user.notice AdGuardHome[1]: [error] dnsproxy: unpacking udp packet err="dns: bad rdata"',
                'Fri Aug 28 11:00:01 user.notice AdGuardHome[1]: [error] dnsproxy: unpacking udp packet err="dns: buffer size too small"',
                'Fri Aug 28 11:00:02 user.notice AdGuardHome: [error] dnsproxy: unpacking udp packet err="bad question name: dns: bad rdata"',
                'Fri Aug 28 11:00:03 user.notice AdGuardHome: [error] dnsproxy: reading msg proto=tcp err="unexpected EOF"',
                'Fri Aug 28 11:00:04 user.notice AdGuardHome[1]: [error] dnsproxy: handling tcp; unpacking msg err="bad question name: dns: buffer size too small"',
            ]
            result = monitor.run(lines, NOW, current_state={"adguardhome": "running"})
            self.assertEqual(result["malformed_dns"], 5)
            self.assertEqual(result["candidates"], 0)
            self.assertFalse(result["alerted"])
            llm.chat.assert_not_called()

    def test_real_problem_next_to_malformed_dns_still_alerts(self):
        with tempfile.TemporaryDirectory() as temporary:
            llm = Mock()
            llm.chat.return_value = {"content": json.dumps({
                "severity": "critical", "title": "sing-box упал",
                "summary": "Процесс sing-box остановлен.",
                "evidence": ["sing-box: panic"], "recommended_actions": ["Перезапустить sing-box"],
            })}
            telegram = FakeTelegramClient()
            monitor = LogMonitor(llm, telegram, [587849205], str(Path(temporary) / "state.json"))
            lines = [
                'Fri Aug 28 11:00:00 user.notice AdGuardHome[1]: [error] dnsproxy: unpacking udp packet err="dns: bad rdata"'
                for _ in range(300)
            ] + ["Fri Aug 28 11:05:00 daemon.err sing-box[123]: panic: runtime error"]
            result = monitor.run(lines, NOW, current_state={"adguardhome": "running"})
            self.assertEqual(result["malformed_dns"], 300)
            self.assertEqual(result["candidates"], 1)
            self.assertTrue(result["alerted"])
            self.assertNotIn("DNS", telegram.sent[0]["text"])

    def test_agent_own_info_lines_are_not_analysed_but_warnings_are(self):
        lines = [
            "Fri Aug 28 11:00:00 daemon.err python3[3049]: ai-agent[3049]: INFO ai-agent.llm: "
            "llm_usage model=gpt://x route=complex prompt_tokens=8464 tool_calls=1",
            "Fri Aug 28 11:00:01 daemon.err python3[3049]: ai-agent[3049]: WARNING ai-agent.core: "
            "follow-up turn failed: llm_unavailable",
        ]
        candidates, _meta = prepare_candidates(lines, NOW)
        self.assertEqual(len(candidates), 1)
        self.assertIn("WARNING", candidates[0])

    def test_alert_formatter_enforces_small_hard_limit(self):
        alert = LogMonitor._format_alert({
            "severity": "warning",
            "title": "T" * 500,
            "summary": "S" * 1000,
            "evidence": ["E" * 500 for _ in range(8)],
            "recommended_actions": ["A" * 500 for _ in range(8)],
        })
        self.assertLessEqual(len(alert), 900)
        self.assertNotIn("E" * 161, alert)
        self.assertNotIn("A" * 161, alert)


if __name__ == "__main__":
    unittest.main()
