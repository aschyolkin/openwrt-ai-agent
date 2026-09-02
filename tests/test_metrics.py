from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from ai_agent import metrics


class MemAvailablePercentTests(unittest.TestCase):
    def test_computes_percent(self):
        content = "MemTotal:        1000000 kB\nMemFree:          200000 kB\nMemAvailable:     500000 kB\n"
        with patch("pathlib.Path.read_text", return_value=content):
            self.assertEqual(metrics.mem_available_percent(), 50.0)

    def test_missing_proc_meminfo_returns_none(self):
        with patch("pathlib.Path.read_text", side_effect=OSError("no such file")):
            self.assertIsNone(metrics.mem_available_percent())


class ConntrackCountTests(unittest.TestCase):
    @patch("ai_agent.metrics.first_executable", return_value="/usr/sbin/conntrack")
    @patch("ai_agent.metrics.subprocess.run")
    def test_falls_back_to_compact_count_command(self, run_mock, _executable):
        run_mock.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="3\n", stderr="",
        )
        with patch("pathlib.Path.read_text", side_effect=OSError("missing proc counter")):
            self.assertEqual(metrics.conntrack_count(), 3)
        self.assertEqual(run_mock.call_args.args[0], ["/usr/sbin/conntrack", "-C"])

    def test_reads_kernel_counter_without_spawning_conntrack(self):
        with patch("pathlib.Path.read_text", return_value="42\n"), \
                patch("ai_agent.metrics.subprocess.run") as run_mock:
            self.assertEqual(metrics.conntrack_count(), 42)
        run_mock.assert_not_called()

    def test_missing_binary_returns_none(self):
        from ai_agent.errors import AgentError

        with patch("pathlib.Path.read_text", side_effect=OSError("missing")), \
                patch("ai_agent.metrics.first_executable", side_effect=AgentError("x", "x")):
            self.assertIsNone(metrics.conntrack_count())

    @patch("ai_agent.metrics.first_executable", return_value="/usr/sbin/conntrack")
    @patch("ai_agent.metrics.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="conntrack", timeout=10))
    def test_timeout_returns_none(self, _run, _executable):
        with patch("pathlib.Path.read_text", side_effect=OSError("missing")):
            self.assertIsNone(metrics.conntrack_count())


class LanClientCountTests(unittest.TestCase):
    def test_counts_nonempty_lines(self):
        with patch("pathlib.Path.read_text", return_value="a b c\nd e f\n\n"):
            self.assertEqual(metrics.lan_client_count(), 2)

    def test_missing_leases_file_returns_none(self):
        with patch("pathlib.Path.read_text", side_effect=OSError("missing")):
            self.assertIsNone(metrics.lan_client_count())


class PingWanTests(unittest.TestCase):
    @patch("ai_agent.metrics.first_executable", return_value="/bin/ping")
    @patch("ai_agent.metrics.subprocess.run")
    def test_parses_latency_and_loss(self, run_mock, _executable):
        stdout = (
            "PING 1.1.1.1 (1.1.1.1): 56 data bytes\n"
            "--- 1.1.1.1 ping statistics ---\n"
            "5 packets transmitted, 5 packets received, 0% packet loss\n"
            "round-trip min/avg/max = 10.0/12.5/15.0 ms\n"
        )
        run_mock.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr="")
        latency, loss = metrics.ping_wan()
        self.assertEqual(latency, 12.5)
        self.assertEqual(loss, 0.0)

    @patch("ai_agent.metrics.first_executable", return_value="/bin/ping")
    @patch("ai_agent.metrics.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="ping", timeout=20))
    def test_timeout_returns_none_none(self, _run, _executable):
        self.assertEqual(metrics.ping_wan(), (None, None))


class SampleCurrentMetricsTests(unittest.TestCase):
    @patch("ai_agent.metrics.lan_client_count", return_value=4)
    @patch("ai_agent.metrics.ping_wan", return_value=(11.0, 0.0))
    @patch("ai_agent.metrics.conntrack_count", return_value=3000)
    @patch("ai_agent.metrics.mem_available_percent", return_value=60.0)
    @patch("ai_agent.metrics.cpu_usage_percent", return_value={"cpu": 7.5})
    def test_combines_all_metrics(self, _cpu, _mem, _conntrack, _ping, _lan):
        sample = metrics.sample_current_metrics()
        self.assertEqual(sample, {
            "cpu_percent": 7.5,
            "mem_available_percent": 60.0,
            "conntrack_count": 3000,
            "wan_latency_ms": 11.0,
            "packet_loss_percent": 0.0,
            "lan_client_count": 4,
        })


if __name__ == "__main__":
    unittest.main()
