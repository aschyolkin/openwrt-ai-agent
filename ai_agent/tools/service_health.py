from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..errors import AgentError, ServiceNotReady
from ..registry import tool
from .common import dns_query, is_fakeip, nft_ruleset_text, process_running
from .netshift_singbox import _clash_request, _selectors


SERVICE_PROBES = {
    "telegram": {"domains": ["web.telegram.org", "api.telegram.org"], "rule_keywords": ["telegram"]},
    "discord": {"domains": ["discord.com"], "rule_keywords": ["discord"]},
    "youtube": {"domains": ["youtube.com"], "rule_keywords": ["youtube", "google"]},
    "openai": {"domains": ["chatgpt.com"], "rule_keywords": ["openai", "chatgpt"]},
    "claude": {"domains": ["claude.ai"], "rule_keywords": ["claude", "anthropic", "ai_section"]},
    "gemini": {"domains": ["gemini.google.com"], "rule_keywords": ["google_ai", "ai_section"]},
}


def _matching_config_strings(value: Any, keywords: list[str], matches: list[str]) -> None:
    if len(matches) >= 100:
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if any(keyword in str(key).casefold() for keyword in keywords):
                matches.append(str(key)[:300])
            _matching_config_strings(item, keywords, matches)
    elif isinstance(value, list):
        for item in value:
            _matching_config_strings(item, keywords, matches)
    elif isinstance(value, str) and any(keyword in value.casefold() for keyword in keywords):
        # Возвращаем только имена rule/rule-set/outbound, не весь конфиг с credentials.
        matches.append(value[:300])


def _configured_rules(keywords: list[str]) -> list[str]:
    try:
        config = json.loads(Path("/etc/sing-box/config.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    matches: list[str] = []
    route = config.get("route", {}) if isinstance(config, dict) else {}
    _matching_config_strings(route, keywords, matches)
    return list(dict.fromkeys(matches))[:100]


_NFT_TABLE_PATTERN = re.compile(r"table\s+inet\s+NetShiftTable\b")
_NFT_TPROXY_PATTERN = re.compile(r"tproxy\s+ip\s+to\s+127\.0\.0\.1:(\d+)")


def _firewall_interception_active(context) -> dict[str, Any]:
    """Check that netshift's nftables tproxy interception table+rule exist.

    Single global check (NOT per-service/per-domain): NetShiftTable's mangle
    chain redirects marked fake-IP/subnet traffic to sing-box's tproxy port
    for all configured sections/domains at once, so one ruleset read answers
    the question for every `service` value.
    """
    text = nft_ruleset_text(context)
    table_present = bool(_NFT_TABLE_PATTERN.search(text))
    tproxy_match = _NFT_TPROXY_PATTERN.search(text) if table_present else None
    return {
        "checked": bool(text),
        "table_present": table_present,
        "tproxy_rule_present": bool(tproxy_match),
        "tproxy_port": int(tproxy_match.group(1)) if tproxy_match else None,
        "active": table_present and bool(tproxy_match),
    }


@tool(
    name="netshift_service_health",
    description=(
        "Проверить маршрутизацию популярного сервиса через netshift без ложного ping fake-IP: "
        "DNS/fake-IP, процесс sing-box, Clash API, сгенерированные route/rule-set, nftables-перехват "
        "(table inet NetShiftTable + tproxy) и активные соединения. "
        "Отличает 'маршрут настроен' от 'активный трафик наблюдается' и не рекомендует restart по одному слабому сигналу."
    ),
    parameters={
        "type": "object",
        "properties": {"service": {"type": "string", "enum": list(SERVICE_PROBES)}},
        "required": ["service"],
        "additionalProperties": False,
    },
    sensitivity="medium",
    network_side_effect="diagnostic_dns_and_local_api_reads",
)
def netshift_service_health(context, arguments: dict[str, Any]) -> dict[str, Any]:
    service = arguments["service"]
    probe = SERVICE_PROBES[service]
    domains = probe["domains"]
    keywords = [keyword.casefold() for keyword in probe["rule_keywords"]]

    dns_checks = []
    for domain in domains:
        adguard = dns_query(context, domain, "10.110.112.1", 53)
        singbox_dns = dns_query(context, domain, "127.0.0.42", 53)
        addresses = adguard.get("addresses", []) + singbox_dns.get("addresses", [])
        dns_checks.append({
            "domain": domain,
            "adguard": adguard,
            "singbox_direct": singbox_dns,
            "fakeip_observed": any(is_fakeip(address) for address in addresses),
        })

    api_available = False
    selectors = []
    connections = []
    api_error = None
    try:
        selector_map = _selectors(context)
        selectors = [{"name": name, "active": data.get("now")} for name, data in sorted(selector_map.items())]
        payload = _clash_request(context, "GET", "/connections")
        for item in payload.get("connections", []):
            metadata = item.get("metadata", {}) if isinstance(item, dict) else {}
            host = str(metadata.get("host", ""))
            rule = str(item.get("rule", "")) if isinstance(item, dict) else ""
            chains = list(item.get("chains", []))[:10] if isinstance(item, dict) else []
            haystack = " ".join([host, rule, *map(str, chains)]).casefold()
            if any(domain in host.casefold() for domain in domains) or any(keyword in haystack for keyword in keywords):
                connections.append({
                    "host": host or None,
                    "network": metadata.get("network"),
                    "destination_port": metadata.get("destinationPort"),
                    "chains": chains,
                    "rule": rule[:500],
                    "upload": item.get("upload"),
                    "download": item.get("download"),
                })
        api_available = True
    except (ServiceNotReady, AgentError) as exc:
        api_error = exc.code

    process_alive = process_running("sing-box")
    configured_rules = _configured_rules(keywords)
    firewall = _firewall_interception_active(context)
    fakeip_observed = any(check["fakeip_observed"] for check in dns_checks)
    route_configured = bool(
        process_alive and api_available and fakeip_observed and configured_rules and firewall["active"]
    )
    active_traffic = bool(connections)

    if active_traffic:
        status = "working_traffic_observed"
    elif route_configured:
        status = "configured_via_netshift_no_active_traffic_observed"
    elif not process_alive:
        status = "singbox_process_down"
    elif fakeip_observed and not firewall["active"]:
        status = "firewall_interception_missing"
    else:
        status = "indeterminate_needs_more_evidence"

    restart_recommended = (
        not process_alive
        or (not api_available and not fakeip_observed)
        or (fakeip_observed and not firewall["active"])
    )
    return {
        "service": service,
        "status": status,
        "configured_via_netshift": route_configured,
        "active_traffic_observed": active_traffic,
        "restart_recommended": restart_recommended,
        "singbox_process": process_alive,
        "clash_api": {"available": api_available, "error": api_error},
        "firewall": firewall,
        "dns": dns_checks,
        "matched_route_references": configured_rules,
        "selectors": selectors,
        "matching_connections": connections,
        "interpretation": (
            "Отсутствие активного соединения не означает поломку: клиент мог не использовать сервис в момент проверки. "
            "Ping fake-IP и zapret dwc.sh не являются проверками доступности этого сервиса. "
            "nftables-перехват проверяется один раз на весь netshift (общая таблица), а не отдельно на домен."
        ),
    }
