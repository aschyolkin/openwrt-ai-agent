from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ..adapters import state_hashes
from ..errors import AgentError
from ..models import MutationPlan, VerificationResult
from ..registry import ExecClass, tool
from .common import DOMAIN_PATTERN, dns_query, nft_ruleset_text, normalize_domain, service_action, service_status


EMPTY_OBJECT = {"type": "object", "properties": {}, "additionalProperties": False}


def _agh_blocked_verdict(adguard: dict[str, Any], singbox: dict[str, Any]) -> tuple[bool, bool]:
    """Return (blocked_by_agh, resolves_direct) from two dns_query results."""
    blocked_by_agh = not adguard["addresses"] or all(
        address in {"0.0.0.0", "127.0.0.1"} for address in adguard["addresses"]
    )
    resolves_direct = bool(singbox["addresses"]) and not all(address == "0.0.0.0" for address in singbox["addresses"])
    return blocked_by_agh, resolves_direct


def _agh_filter_matches(domain: str, limit: int = 10) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    filter_root = Path("/opt/adguardhome/data/filters")
    if filter_root.is_dir():
        for file_path in sorted(filter_root.glob("*.txt")):
            try:
                with file_path.open("r", encoding="utf-8", errors="replace") as handle:
                    for number, line in enumerate(handle, 1):
                        if domain in line.lower():
                            matches.append({"file": file_path.name, "line": number, "rule": line.strip()[:300]})
                            if len(matches) >= limit:
                                break
            except OSError:
                continue
            if len(matches) >= limit:
                break
    return matches


@tool(name="agh_service_status", description="Проверить состояние AdGuardHome.", parameters=EMPTY_OBJECT)
def agh_service_status(context, arguments: dict[str, Any]) -> dict[str, Any]:
    return service_status(context, "adguardhome")


@tool(
    name="agh_config_read",
    description="Прочитать только allowlist безопасных параметров AdGuardHome; пользователи, пароли, правила и URL не возвращаются.",
    parameters=EMPTY_OBJECT,
    sensitivity="medium",
)
def agh_config_read(context, arguments: dict[str, Any]) -> dict[str, Any]:
    path = Path("/etc/adguardhome/adguardhome.yaml")
    if not path.is_file():
        path = Path("/etc/adguardhome.yaml")
    try:
        config = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise AgentError("agh_config_invalid", "Не удалось безопасно прочитать конфиг AdGuardHome") from exc
    dns = config.get("dns", {}) if isinstance(config.get("dns"), dict) else {}
    filtering = config.get("filtering", {}) if isinstance(config.get("filtering"), dict) else {}
    filters = filtering.get("filters", config.get("filters", []))
    return {
        "config_path": str(path),
        "dns": {
            "bind_hosts": dns.get("bind_hosts", []), "port": dns.get("port", 53),
            "cache_size": dns.get("cache_size"), "cache_ttl_min": dns.get("cache_ttl_min"),
            "cache_ttl_max": dns.get("cache_ttl_max"),
            "upstream_count": len(dns.get("upstream_dns", []) or []),
        },
        "filtering": {"enabled": filtering.get("filtering_enabled"), "filter_count": len(filters or [])},
        "omitted_sensitive_fields": ["users", "passwords", "user_rules", "filter_urls", "upstream_values"],
    }


@tool(
    name="agh_check_domain_blocked",
    description="Проверить блокировку домена фактическими DNS-запросами; локальные фильтры используются только как пояснение.",
    parameters={
        "type": "object", "properties": {"domain": {"type": "string", "pattern": DOMAIN_PATTERN, "maxLength": 253}},
        "required": ["domain"], "additionalProperties": False,
    },
    sensitivity="medium",
    network_side_effect="diagnostic_dns_queries",
)
def agh_check_domain_blocked(context, arguments: dict[str, Any]) -> dict[str, Any]:
    domain = normalize_domain(arguments["domain"])
    adguard = dns_query(context, domain, "10.110.112.1", 53)
    singbox = dns_query(context, domain, "127.0.0.42", 53)
    blocked_answer, direct_answer = _agh_blocked_verdict(adguard, singbox)
    matches = _agh_filter_matches(domain)
    return {
        "domain": domain, "blocked_by_actual_dns_test": blocked_answer and direct_answer,
        "adguard": adguard, "singbox_direct": singbox,
        "filter_matches_explanatory_only": matches,
        "filter_match_is_not_source_of_truth": True,
    }


@tool(
    name="agh_diagnose_domain",
    description=(
        "Диагностическая воронка для домена через AdGuardHome: сервис AGH, активность DNS-перехвата "
        "firewall (!fw4: Intercept-DNS), DNS-тест через AGH и напрямую. Различает 'AGH не отвечает', "
        "'клиенты обходят AGH (DNS-перехват не активен)', 'домен блокируется фильтром AGH' и "
        "'домен не резолвится нигде' — вместо одного плоского ответа."
    ),
    parameters={
        "type": "object", "properties": {"domain": {"type": "string", "pattern": DOMAIN_PATTERN, "maxLength": 253}},
        "required": ["domain"], "additionalProperties": False,
    },
    sensitivity="medium",
    network_side_effect="diagnostic_dns_and_local_reads",
)
def agh_diagnose_domain(context, arguments: dict[str, Any]) -> dict[str, Any]:
    domain = normalize_domain(arguments["domain"])

    agh_running = bool(service_status(context, "adguardhome")["running"])
    dns_intercept_active = "!fw4: Intercept-DNS" in nft_ruleset_text(context)

    adguard = dns_query(context, domain, "10.110.112.1", 53)
    singbox_direct = dns_query(context, domain, "127.0.0.42", 53)
    blocked_by_agh, resolves_direct = _agh_blocked_verdict(adguard, singbox_direct)
    filter_matches = _agh_filter_matches(domain)

    if not agh_running:
        status = "adguardhome_down"
    elif not dns_intercept_active:
        status = "dns_interception_missing"
    elif blocked_by_agh and resolves_direct:
        status = "blocked_by_agh_filter"
    elif blocked_by_agh and not resolves_direct:
        status = "domain_unresolvable_everywhere"
    elif not blocked_by_agh:
        status = "resolves_normally"
    else:
        status = "indeterminate_needs_more_evidence"

    return {
        "domain": domain,
        "status": status,
        "adguardhome_running": agh_running,
        "dns_interception_active": dns_intercept_active,
        "blocked_by_agh": blocked_by_agh,
        "resolves_direct": resolves_direct,
        "adguard": adguard,
        "singbox_direct": singbox_direct,
        "filter_matches_explanatory_only": filter_matches,
        "filter_match_is_not_source_of_truth": True,
        "interpretation": (
            "AGH не отвечает — это отказ сервиса, а не блокировка домена. "
            "Отсутствие DNS-перехвата (!fw4: Intercept-DNS) означает, что LAN-клиенты могут резолвить "
            "домены напрямую через свой DNS, минуя AGH — это не то же самое, что 'AGH не блокирует домен'. "
            "grep по фильтрам AGH — только пояснение, не источник истины: см. blocked_by_agh."
        ),
    }


def _agh_restart_apply(context, plan: MutationPlan) -> dict[str, Any]:
    return service_action(context, "adguardhome", "restart", 60)


def _agh_restart_verify(context, plan: MutationPlan) -> VerificationResult:
    status = service_status(context, "adguardhome")
    return VerificationResult(bool(status["running"]), {"service": status}, "AdGuardHome отвечает" if status["running"] else "AdGuardHome не запущен")


def _agh_restart_rollback(context, plan: MutationPlan, backup_dir: str) -> VerificationResult:
    service_action(context, "adguardhome", "restart", 60)
    return _agh_restart_verify(context, plan)


@tool(
    name="agh_restart",
    description="Перезапустить AdGuardHome после явного подтверждения; конфиг не меняется.",
    parameters=EMPTY_OBJECT,
    exec_class=ExecClass.MUTATING,
    network_side_effect="dns_service_restart",
    applier=_agh_restart_apply,
    verifier=_agh_restart_verify,
    rollback=_agh_restart_rollback,
)
def agh_restart(context, arguments: dict[str, Any]) -> MutationPlan:
    before = service_status(context, "adguardhome")
    return MutationPlan(
        summary="Перезапустить AdGuardHome (возможна краткая пауза DNS)",
        diff=f"runtime adguardhome: {'running' if before['running'] else 'stopped'} -> restart",
        targets=[], precondition_hashes={}, services=["adguardhome"], verifier="service_running",
        rollback_data={"was_running": before["running"]},
    )

