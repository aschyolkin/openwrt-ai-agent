from __future__ import annotations

import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import mock_open, patch

import requests

from ai_agent.adapters import UBusAdapter
from ai_agent.command import CommandRunner
from ai_agent.errors import ValidationError
from ai_agent.registry import ToolRegistry
from ai_agent.tools import register_all
from ai_agent.tools.netshift_singbox import _clash_request, _netshift_config_verification
from ai_agent.tools.service_health import netshift_service_health
from ai_agent.tools.system_inspect import _page_text, _redact_uci_sections


class SystemInspectTests(unittest.TestCase):
    def test_pagination_and_filter(self):
        result = _page_text("alpha\nbeta\nBETA two\ngamma\n", "beta", 1, 1)
        self.assertEqual(result["lines"], ["BETA two"])
        self.assertEqual(result["total_lines"], 2)
        self.assertIsNone(result["next_offset"])

    def test_uci_secrets_are_redacted(self):
        result = _redact_uci_sections({
            "main": {
                ".type": "section",
                "enabled": "1",
                "password": "secret",
                "api_key": "secret",
                "uuid": "secret",
                "subscription_url": "https://secret.invalid",
                "user_domains_text": "private.invalid",
            }
        })
        self.assertEqual(result["main"]["enabled"], "1")
        for key in ("password", "api_key", "uuid", "subscription_url", "user_domains_text"):
            self.assertEqual(result["main"][key], "***redacted***")

    def test_exact_read_only_command_validation(self):
        allowed = {
            "/bin/ubus", "/usr/bin/ip", "/bin/netstat", "/bin/df",
            "/usr/bin/mount", "/sbin/lsmod", "/usr/bin/apk",
        }
        runner = CommandRunner(allowed=allowed)
        for argv in (
            ["/bin/ubus", "list"],
            ["/usr/bin/ip", "route", "show", "table", "all"],
            ["/bin/netstat", "-lntup"],
            ["/bin/df", "-h"],
            ["/usr/bin/mount"],
            ["/sbin/lsmod"],
            ["/usr/bin/apk", "info"],
            ["/usr/bin/apk", "info", "-e", "coreutils-whoami"],
            ["/usr/bin/apk", "add", "coreutils-whoami"],
            ["/usr/bin/apk", "del", "coreutils-whoami"],
        ):
            runner._validate(argv)
        with self.assertRaises(ValidationError):
            runner._validate(["/usr/bin/ip", "link", "delete", "br-lan"])
        with self.assertRaises(ValidationError):
            runner._validate(["/usr/bin/apk", "add", "coreutils-whoami;reboot"])
        with self.assertRaises(ValidationError):
            runner._validate(["/usr/bin/apk", "add", "--allow-untrusted", "evil.apk"])

    def test_new_tools_are_registered(self):
        registry = ToolRegistry()
        register_all(registry)
        names = {item["function"]["name"] for item in registry.schemas()}
        self.assertTrue({
            "sys_inspect", "sys_service_control", "sys_package_install", "sys_package_remove",
            "netshift_service_health", "agh_diagnose_domain", "agent_audit_log", "sys_baseline_compare",
        } <= names)


class AdapterRegressionTests(unittest.TestCase):
    def test_native_ubus_single_item_list_is_unwrapped(self):
        adapter = object.__new__(UBusAdapter)
        adapter.runner = None
        adapter._module = SimpleNamespace(call=lambda *_args: [{"interface": [{"interface": "lan"}]}])
        self.assertEqual(adapter.call("network.interface", "dump"), {"interface": [{"interface": "lan"}]})

    def test_clash_api_falls_back_to_lan_endpoint(self):
        calls = []

        class Response:
            content = b"{}"

            @staticmethod
            def raise_for_status():
                return None

            @staticmethod
            def json():
                return {"proxies": {}}

        class HTTP:
            @staticmethod
            def request(method, url, **kwargs):
                calls.append(url)
                if url.startswith("http://127.0.0.1"):
                    raise requests.ConnectionError("not listening")
                return Response()

        result = _clash_request(SimpleNamespace(http=HTTP()), "GET", "/proxies")
        self.assertEqual(result, {"proxies": {}})
        self.assertEqual(calls[-1], "http://10.110.112.1:9090/proxies")

    @patch("ai_agent.tools.netshift_singbox.time.sleep")
    @patch("ai_agent.tools.netshift_singbox.process_running", return_value=True)
    @patch("builtins.open", new_callable=mock_open, read_data="{}")
    def test_netshift_verifier_retries_transient_dns_readiness(self, _open, _process, sleep):
        failed = {"ok": False, "addresses": [], "returncode": 9}
        ready = {"ok": True, "addresses": ["198.18.1.10"], "returncode": 0}
        with patch(
            "ai_agent.tools.netshift_singbox.dns_query",
            side_effect=[failed, failed, ready, ready],
        ):
            result = _netshift_config_verification(
                SimpleNamespace(), "example.com", dns_attempts=2, dns_retry_delay=0,
            )
        self.assertTrue(result.ok)
        self.assertEqual(result.checks["dns_attempts"], 2)
        sleep.assert_called_once_with(0.0)


class ServiceHealthRegressionTests(unittest.TestCase):
    @staticmethod
    def _dns(_context, _domain, server, _port=53):
        suffix = "11" if server == "10.110.112.1" else "12"
        return {"ok": True, "server": server, "port": 53, "addresses": [f"198.18.1.{suffix}"], "returncode": 0}

    _FIREWALL_ACTIVE = {
        "checked": True, "table_present": True, "tproxy_rule_present": True,
        "tproxy_port": 1602, "active": True,
    }

    @patch("ai_agent.tools.service_health._firewall_interception_active", return_value=_FIREWALL_ACTIVE)
    @patch("ai_agent.tools.service_health._configured_rules", return_value=["main-telegram-community-ruleset"])
    @patch("ai_agent.tools.service_health.process_running", return_value=True)
    @patch("ai_agent.tools.service_health.dns_query", side_effect=_dns.__func__)
    @patch("ai_agent.tools.service_health._selectors", return_value={"main-out": {"now": "Sweden"}})
    @patch("ai_agent.tools.service_health._clash_request")
    def test_telegram_active_traffic_is_working(self, clash, _selectors_mock, _dns_mock, _process_mock, _rules_mock, _firewall_mock):
        clash.return_value = {
            "connections": [{
                "metadata": {"host": "api.telegram.org", "network": "tcp", "destinationPort": "443"},
                "chains": ["Sweden", "main-out"],
                "rule": "main-telegram-community-ruleset",
                "upload": 1024,
                "download": 4096,
            }]
        }

        result = netshift_service_health(None, {"service": "telegram"})

        self.assertEqual(result["status"], "working_traffic_observed")
        self.assertTrue(result["configured_via_netshift"])
        self.assertTrue(result["active_traffic_observed"])
        self.assertFalse(result["restart_recommended"])

    @patch("ai_agent.tools.service_health._firewall_interception_active", return_value=_FIREWALL_ACTIVE)
    @patch("ai_agent.tools.service_health._configured_rules", return_value=["main-telegram-community-ruleset"])
    @patch("ai_agent.tools.service_health.process_running", return_value=True)
    @patch("ai_agent.tools.service_health.dns_query", side_effect=_dns.__func__)
    @patch("ai_agent.tools.service_health._selectors", return_value={"main-out": {"now": "Sweden"}})
    @patch("ai_agent.tools.service_health._clash_request", return_value={"connections": []})
    def test_no_current_connection_is_not_an_outage(self, _clash_mock, _selectors_mock, _dns_mock, _process_mock, _rules_mock, _firewall_mock):
        result = netshift_service_health(None, {"service": "telegram"})

        self.assertEqual(result["status"], "configured_via_netshift_no_active_traffic_observed")
        self.assertTrue(result["configured_via_netshift"])
        self.assertFalse(result["active_traffic_observed"])
        self.assertFalse(result["restart_recommended"])

    @patch("ai_agent.tools.service_health._firewall_interception_active", return_value=_FIREWALL_ACTIVE)
    @patch("ai_agent.tools.service_health._configured_rules", return_value=["main-telegram-community-ruleset"])
    @patch("ai_agent.tools.service_health.process_running", return_value=True)
    @patch("ai_agent.tools.service_health.dns_query", side_effect=_dns.__func__)
    @patch("ai_agent.tools.service_health._selectors")
    def test_api_error_with_fakeip_does_not_recommend_restart(self, selectors, _dns_mock, _process_mock, _rules_mock, _firewall_mock):
        from ai_agent.errors import ServiceNotReady

        selectors.side_effect = ServiceNotReady("sing-box", "API unavailable")
        result = netshift_service_health(None, {"service": "telegram"})

        self.assertEqual(result["status"], "indeterminate_needs_more_evidence")
        self.assertFalse(result["restart_recommended"])
        self.assertTrue(all(item["fakeip_observed"] for item in result["dns"]))

    @patch("ai_agent.tools.service_health._firewall_interception_active", return_value={
        "checked": True, "table_present": False, "tproxy_rule_present": False, "tproxy_port": None, "active": False,
    })
    @patch("ai_agent.tools.service_health._configured_rules", return_value=["main-telegram-community-ruleset"])
    @patch("ai_agent.tools.service_health.process_running", return_value=True)
    @patch("ai_agent.tools.service_health.dns_query", side_effect=_dns.__func__)
    @patch("ai_agent.tools.service_health._selectors", return_value={"main-out": {"now": "Sweden"}})
    @patch("ai_agent.tools.service_health._clash_request", return_value={"connections": []})
    def test_firewall_interception_missing_with_fakeip_recommends_restart(
        self, _clash_mock, _selectors_mock, _dns_mock, _process_mock, _rules_mock, _firewall_mock,
    ):
        result = netshift_service_health(None, {"service": "telegram"})

        self.assertEqual(result["status"], "firewall_interception_missing")
        self.assertFalse(result["configured_via_netshift"])
        self.assertTrue(result["restart_recommended"])
        self.assertFalse(result["firewall"]["active"])


class PromptRegressionTests(unittest.TestCase):
    def test_packaged_prompts_stay_in_sync_and_require_capability_checks(self):
        root = Path(__file__).resolve().parents[1]
        package_prompt = (root / "ai_agent/prompts/system_prompt.md").read_text(encoding="utf-8")
        install_prompt = (root / "etc/ai-agent/system_prompt.md").read_text(encoding="utf-8")

        self.assertEqual(package_prompt, install_prompt)
        self.assertIn("проверь sys_inspect", package_prompt)
        self.assertIn("используй netshift_service_health", package_prompt)
        self.assertIn("Отсутствие активного соединения — неопределённость, а не отказ", package_prompt)

    def test_installer_schedules_backup_cleanup(self):
        root = Path(__file__).resolve().parents[1]
        installer = (root / "install.sh").read_text(encoding="utf-8")

        self.assertIn("/usr/bin/ai-agent-maintenance # ai-agent-maintenance", installer)
        self.assertNotIn("ai-agent-cli --json health >/dev/null 2>&1 # ai-agent-maintenance", installer)

    def test_cron_invoked_bin_scripts_set_pythonpath(self):
        # Скрипты, запускаемые напрямую через `python3 -m ai_agent.<module>` из
        # cron (не через ai-agent-cli и не через procd, который сам передаёт env),
        # обязаны сами экспортировать PYTHONPATH — иначе cron роняет их с
        # ModuleNotFoundError ещё до входа в код, а последствия неотличимы от
        # "cron не сработал" (см. ai-agent-log-monitor/ai-agent-metrics-sample).
        root = Path(__file__).resolve().parents[1]
        installer = (root / "install.sh").read_text(encoding="utf-8")
        cron_lines = [line for line in installer.splitlines() if line.strip().startswith(("*", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9")) and "/usr/bin/" in line]
        for line in cron_lines:
            script_name = line.split("/usr/bin/", 1)[1].split()[0]
            script_path = root / "bin" / script_name
            content = script_path.read_text(encoding="utf-8")
            if "python3 -m ai_agent." in content:
                self.assertIn(
                    "export PYTHONPATH=/usr/lib/ai-agent", content,
                    f"bin/{script_name} запускается из cron и напрямую вызывает python3 -m, но не экспортирует PYTHONPATH",
                )


if __name__ == "__main__":
    unittest.main()
