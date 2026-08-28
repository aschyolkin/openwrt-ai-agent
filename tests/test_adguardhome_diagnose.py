from __future__ import annotations

import unittest
from unittest.mock import patch

from ai_agent.tools.adguardhome import agh_diagnose_domain


class AghDiagnoseDomainTests(unittest.TestCase):
    @staticmethod
    def _dns(ok: bool, addresses: list[str]):
        return {"ok": ok, "server": "x", "port": 53, "addresses": addresses, "returncode": 0 if ok else 1}

    @patch("ai_agent.tools.adguardhome._agh_filter_matches", return_value=[])
    @patch("ai_agent.tools.adguardhome.dns_query")
    @patch("ai_agent.tools.adguardhome.nft_ruleset_text", return_value="... !fw4: Intercept-DNS ...")
    @patch("ai_agent.tools.adguardhome.service_status", return_value={"service": "adguardhome", "running": False, "status": "stopped"})
    def test_agh_down_short_circuits(self, _status, _nft, dns_mock, _filters):
        dns_mock.side_effect = [self._dns(False, []), self._dns(False, [])]
        result = agh_diagnose_domain(None, {"domain": "example.com"})
        self.assertEqual(result["status"], "adguardhome_down")
        self.assertFalse(result["adguardhome_running"])

    @patch("ai_agent.tools.adguardhome._agh_filter_matches", return_value=[])
    @patch("ai_agent.tools.adguardhome.dns_query")
    @patch("ai_agent.tools.adguardhome.nft_ruleset_text", return_value="no dns intercept rule here")
    @patch("ai_agent.tools.adguardhome.service_status", return_value={"service": "adguardhome", "running": True, "status": "running"})
    def test_dns_interception_missing(self, _status, _nft, dns_mock, _filters):
        dns_mock.side_effect = [self._dns(True, ["1.2.3.4"]), self._dns(True, ["1.2.3.4"])]
        result = agh_diagnose_domain(None, {"domain": "example.com"})
        self.assertEqual(result["status"], "dns_interception_missing")
        self.assertFalse(result["dns_interception_active"])

    @patch("ai_agent.tools.adguardhome._agh_filter_matches", return_value=[{"file": "block.txt", "line": 1, "rule": "example.com"}])
    @patch("ai_agent.tools.adguardhome.dns_query")
    @patch("ai_agent.tools.adguardhome.nft_ruleset_text", return_value="... !fw4: Intercept-DNS ...")
    @patch("ai_agent.tools.adguardhome.service_status", return_value={"service": "adguardhome", "running": True, "status": "running"})
    def test_blocked_by_agh_filter(self, _status, _nft, dns_mock, _filters):
        # adguard returns 0.0.0.0 (blocked), direct singbox resolves fine
        dns_mock.side_effect = [self._dns(True, ["0.0.0.0"]), self._dns(True, ["93.184.216.34"])]
        result = agh_diagnose_domain(None, {"domain": "example.com"})
        self.assertEqual(result["status"], "blocked_by_agh_filter")
        self.assertTrue(result["blocked_by_agh"])
        self.assertTrue(result["resolves_direct"])
        self.assertEqual(len(result["filter_matches_explanatory_only"]), 1)

    @patch("ai_agent.tools.adguardhome._agh_filter_matches", return_value=[])
    @patch("ai_agent.tools.adguardhome.dns_query")
    @patch("ai_agent.tools.adguardhome.nft_ruleset_text", return_value="... !fw4: Intercept-DNS ...")
    @patch("ai_agent.tools.adguardhome.service_status", return_value={"service": "adguardhome", "running": True, "status": "running"})
    def test_domain_unresolvable_everywhere(self, _status, _nft, dns_mock, _filters):
        dns_mock.side_effect = [self._dns(False, []), self._dns(False, [])]
        result = agh_diagnose_domain(None, {"domain": "example.com"})
        self.assertEqual(result["status"], "domain_unresolvable_everywhere")
        self.assertFalse(result["resolves_direct"])

    @patch("ai_agent.tools.adguardhome._agh_filter_matches", return_value=[])
    @patch("ai_agent.tools.adguardhome.dns_query")
    @patch("ai_agent.tools.adguardhome.nft_ruleset_text", return_value="... !fw4: Intercept-DNS ...")
    @patch("ai_agent.tools.adguardhome.service_status", return_value={"service": "adguardhome", "running": True, "status": "running"})
    def test_resolves_normally(self, _status, _nft, dns_mock, _filters):
        dns_mock.side_effect = [self._dns(True, ["93.184.216.34"]), self._dns(True, ["93.184.216.34"])]
        result = agh_diagnose_domain(None, {"domain": "example.com"})
        self.assertEqual(result["status"], "resolves_normally")
        self.assertFalse(result["blocked_by_agh"])


if __name__ == "__main__":
    unittest.main()
