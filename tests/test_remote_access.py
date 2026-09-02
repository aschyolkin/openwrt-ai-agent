from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from ai_agent.errors import ValidationError
from ai_agent.tools import firewall as firewall_tools
from ai_agent.tools import remote_access
from ai_agent.tools.firewall import firewall_open_wan_port
from ai_agent.tools.remote_access import (
    DROPBEAR_SECTION,
    _ssh_close_verify,
    _ssh_open_apply,
    _ssh_open_verify,
    ssh_close_wan_access,
    ssh_open_wan_access,
)


class FakeUCI:
    def __init__(self, packages=None):
        self.packages = packages or {"dropbear": {}, "firewall": {}}
        self.commits = []

    def get_all(self, package):
        return {name: dict(values) for name, values in self.packages.get(package, {}).items()}

    def create_section(self, package, section, section_type):
        self.packages.setdefault(package, {})[section] = {".type": section_type}

    def set(self, package, section, option, value):
        self.packages[package][section][option] = value

    def delete_section(self, package, section):
        self.packages[package].pop(section, None)

    def commit(self, package):
        self.commits.append(package)


class SSHWanAccessTests(unittest.TestCase):
    def setUp(self):
        self.uci = FakeUCI()
        self.context = SimpleNamespace(uci=self.uci, runner=None, backups=None)
        self.listening = set()
        patches = [
            patch.object(remote_access, "port_listening", lambda port, proto: port in self.listening),
            patch.object(remote_access, "_authorized_key_files", lambda: ["/etc/dropbear/authorized_keys"]),
            patch.object(remote_access, "service_action", lambda *args, **kwargs: {"ok": True}),
            patch.object(remote_access, "service_status", lambda context, service: {"service": service, "running": True}),
            patch.object(remote_access, "_nft_rule_present", lambda context, section: section in self.nft),
            patch.object(remote_access, "_wait_listening", lambda port, **kwargs: port in self.listening),
            patch.object(remote_access, "state_hashes", lambda targets: {}),
        ]
        self.nft = set()
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def test_plan_covers_both_dropbear_and_firewall(self):
        plan = ssh_open_wan_access(self.context, {"port": 2022})
        self.assertEqual(plan.prepared["port"], 2022)
        self.assertEqual(plan.prepared["firewall_section"], "ai_agent_wan_tcp_2022")
        self.assertIn("dropbear", plan.uci_packages)
        self.assertIn("firewall", plan.uci_packages)
        self.assertIn("option Port '2022'", plan.diff)
        self.assertIn("option PasswordAuth 'off'", plan.diff)
        self.assertIn("option src 'wan'", plan.diff)

    def test_apply_then_verify_requires_listening_socket(self):
        plan = ssh_open_wan_access(self.context, {"port": 2022})
        _ssh_open_apply(self.context, plan)
        self.nft.add("ai_agent_wan_tcp_2022")
        failed = _ssh_open_verify(self.context, plan)
        self.assertFalse(failed.ok)
        self.assertFalse(failed.checks["sshd_listening_on_port"])
        self.listening.add(2022)
        passed = _ssh_open_verify(self.context, plan)
        self.assertTrue(passed.ok)
        self.assertEqual(self.uci.packages["dropbear"][DROPBEAR_SECTION]["PasswordAuth"], "off")
        self.assertEqual(self.uci.packages["firewall"]["ai_agent_wan_tcp_2022"]["target"], "ACCEPT")

    def test_rejects_management_ports_and_missing_keys(self):
        for port in (22, 80, 443, 53, 9090, 1023, 1024):
            with self.assertRaises(ValidationError):
                ssh_open_wan_access(self.context, {"port": port})
        with patch.object(remote_access, "_authorized_key_files", lambda: []):
            with self.assertRaises(ValidationError):
                ssh_open_wan_access(self.context, {"port": 2022})

    def test_rejects_busy_port_and_double_open(self):
        self.listening.add(2022)
        with self.assertRaises(ValidationError):
            ssh_open_wan_access(self.context, {"port": 2022})
        self.listening.discard(2022)
        _ssh_open_apply(self.context, ssh_open_wan_access(self.context, {"port": 2022}))
        with self.assertRaises(ValidationError):
            ssh_open_wan_access(self.context, {"port": 2023})

    def test_verify_rejects_enabled_password_auth_or_changed_firewall(self):
        plan = ssh_open_wan_access(self.context, {"port": 2022})
        _ssh_open_apply(self.context, plan)
        self.nft.add("ai_agent_wan_tcp_2022")
        self.listening.add(2022)
        self.uci.packages["dropbear"][DROPBEAR_SECTION]["PasswordAuth"] = "on"
        self.assertFalse(_ssh_open_verify(self.context, plan).ok)

        self.uci.packages["dropbear"][DROPBEAR_SECTION]["PasswordAuth"] = "off"
        self.uci.packages["firewall"]["ai_agent_wan_tcp_2022"]["src"] = "lan"
        self.assertFalse(_ssh_open_verify(self.context, plan).ok)

    def test_close_removes_both_sections(self):
        plan = ssh_open_wan_access(self.context, {"port": 2022})
        _ssh_open_apply(self.context, plan)
        self.nft.add("ai_agent_wan_tcp_2022")
        self.listening.add(2022)
        close_plan = ssh_close_wan_access(self.context, {})
        self.assertTrue(close_plan.prepared["firewall_rule_present"])
        remote_access._ssh_close_apply(self.context, close_plan)
        self.nft.discard("ai_agent_wan_tcp_2022")
        self.listening.discard(2022)
        self.assertTrue(_ssh_close_verify(self.context, close_plan).ok)
        self.assertNotIn(DROPBEAR_SECTION, self.uci.packages["dropbear"])
        self.assertNotIn("ai_agent_wan_tcp_2022", self.uci.packages["firewall"])

    def test_reuses_existing_half_open_firewall_rule(self):
        self.uci.packages["firewall"]["ai_agent_wan_tcp_2022"] = {
            ".type": "rule", "src": "wan", "proto": "tcp", "dest_port": "2022",
            "target": "ACCEPT", "family": "ipv4",
        }
        plan = ssh_open_wan_access(self.context, {"port": 2022})
        self.assertFalse(plan.prepared["create_firewall_rule"])
        self.assertIn("переиспользуется", plan.diff)
        _ssh_open_apply(self.context, plan)
        self.assertIn(DROPBEAR_SECTION, self.uci.packages["dropbear"])
        self.assertEqual(self.uci.packages["firewall"]["ai_agent_wan_tcp_2022"]["dest_port"], "2022")

    def test_rejects_when_section_name_holds_a_different_rule(self):
        self.uci.packages["firewall"]["ai_agent_wan_tcp_2022"] = {".type": "rule", "target": "DROP"}
        with self.assertRaises(ValidationError):
            ssh_open_wan_access(self.context, {"port": 2022})

    def test_close_rejects_when_nothing_was_opened(self):
        with self.assertRaises(ValidationError):
            ssh_close_wan_access(self.context, {})
    def test_close_refuses_to_delete_changed_firewall_rule(self):
        plan = ssh_open_wan_access(self.context, {"port": 2022})
        _ssh_open_apply(self.context, plan)
        self.uci.packages["firewall"]["ai_agent_wan_tcp_2022"]["dest_port"] = "9999"

        with self.assertRaises(ValidationError):
            ssh_close_wan_access(self.context, {})
        self.assertIn("ai_agent_wan_tcp_2022", self.uci.packages["firewall"])



    def test_plan_fails_before_touching_uci_when_dropbear_is_unreachable(self):
        def boom(context, service):
            raise ValidationError("Команда отсутствует в allowlist", {"executable": "/etc/init.d/dropbear"})

        with patch.object(remote_access, "service_status", boom):
            with self.assertRaises(ValidationError):
                ssh_open_wan_access(self.context, {"port": 2022})
        self.assertNotIn(DROPBEAR_SECTION, self.uci.packages["dropbear"])
        self.assertEqual(self.uci.packages["firewall"], {})


class CommandAllowlistTests(unittest.TestCase):
    def test_dropbear_init_script_is_allowed(self):
        from ai_agent.command import DEFAULT_ALLOWED_EXECUTABLES, CommandRunner

        self.assertIn("/etc/init.d/dropbear", DEFAULT_ALLOWED_EXECUTABLES)
        CommandRunner()._validate(["/etc/init.d/dropbear", "restart"])
        with self.assertRaises(ValidationError):
            CommandRunner()._validate(["/etc/init.d/dropbear", "keygen"])


class OpenWanPortListenerWarningTests(unittest.TestCase):
    def setUp(self):
        self.uci = FakeUCI({"firewall": {}})
        self.context = SimpleNamespace(uci=self.uci, runner=None)
        item = patch.object(firewall_tools, "state_hashes", lambda targets: {})
        item.start()
        self.addCleanup(item.stop)

    def test_plan_warns_when_nobody_listens(self):
        with patch.object(firewall_tools, "port_listening", lambda port, proto: False):
            plan = firewall_open_wan_port(self.context, {"port": 2022, "proto": "tcp"})
        self.assertFalse(plan.prepared["listener_present"])
        self.assertIn("никто не слушает", plan.summary)
        self.assertIn("ssh_open_wan_access", plan.summary)

    def test_plan_is_quiet_when_service_listens(self):
        with patch.object(firewall_tools, "port_listening", lambda port, proto: True):
            plan = firewall_open_wan_port(self.context, {"port": 8443, "proto": "tcp"})
        self.assertTrue(plan.prepared["listener_present"])
        self.assertNotIn("никто не слушает", plan.summary)

    def test_verify_reports_missing_listener(self):
        with patch.object(firewall_tools, "port_listening", lambda port, proto: True):
            plan = firewall_open_wan_port(self.context, {"port": 8443, "proto": "tcp"})
        self.uci.packages["firewall"]["ai_agent_wan_tcp_8443"] = {
            ".type": "rule", "src": "wan", "proto": "tcp", "dest_port": "8443",
            "target": "ACCEPT", "family": "ipv4",
        }
        with patch.object(firewall_tools, "_nft_rule_present", lambda context, section: True), \
                patch.object(firewall_tools, "port_listening", lambda port, proto: False):
            result = firewall_tools._open_verify(self.context, plan)
        self.assertTrue(result.ok)
        self.assertFalse(result.checks["listener_present"])
        self.assertIn("никто не слушает", result.message)


if __name__ == "__main__":
    unittest.main()
