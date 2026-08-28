from __future__ import annotations

import difflib
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests

from ..adapters import sha256_file, state_hashes
from ..command import first_executable
from ..errors import AgentError, ServiceNotReady, ValidationError
from ..models import MutationPlan, VerificationResult
from ..registry import ExecClass, tool
from .common import (
    DOMAIN_PATTERN,
    SECTION_PATTERN,
    dns_query,
    is_fakeip,
    normalize_domain,
    process_running,
    service_action,
    service_status,
)


CLASH_API_CANDIDATES = (
    "http://127.0.0.1:9090",
    "http://10.110.112.1:9090",
)
NETSHIFT_UCI_FIELD_TYPES = {
    "user_domains_text": "option",
    "user_subnets_text": "option",
    "subscription_filter_include_keywords": "list",
    "subscription_filter_exclude_keywords": "list",
}

# Профили маршрутизации netshift объявлены как `config section 'main'` /
# `config section 'ai_section'` (см. CLAUDE.md) — `settings` не профиль, исключаем.
NETSHIFT_PROFILE_SECTION_TYPES = {"section"}


def _clash_request(context, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
    last_error: Exception | None = None
    for base_url in CLASH_API_CANDIDATES:
        try:
            response = context.http.request(method, base_url + path, json=payload, timeout=(3, 10))
            response.raise_for_status()
            return response.json() if response.content else {}
        except (requests.RequestException, ValueError) as exc:
            last_error = exc
    raise ServiceNotReady("sing-box", "Clash API sing-box пока недоступен") from last_error


def _selectors(context) -> dict[str, dict[str, Any]]:
    payload = _clash_request(context, "GET", "/proxies")
    proxies = payload.get("proxies", {}) if isinstance(payload, dict) else {}
    return {
        name: data for name, data in proxies.items()
        if isinstance(data, dict) and str(data.get("type", "")).lower() == "selector"
    }


def _reload_netshift(context) -> dict[str, Any]:
    try:
        executable = first_executable(("/usr/bin/netshift",))
        result = context.runner.run([executable, "reload"], timeout=90, max_output_bytes=32768)
        if not result.ok:
            raise AgentError("netshift_reload_failed", "netshift reload завершился ошибкой", {"stderr": result.stderr[:4096]})
        output = result.stdout[:4096]
    except AgentError as first_error:
        try:
            fallback = service_action(context, "netshift", "reload", 90)
            output = fallback.get("output", "")
        except AgentError:
            raise first_error
    return {"service": "netshift", "action": "reload", "output": output}


def _safe_list(value: Any) -> list[str]:
    if value is None:
        return []
    return [str(item) for item in value] if isinstance(value, list) else [str(value)]


@tool(
    name="netshift_config_show",
    description="Показать безопасную сводку секций netshift без URL подписки и содержимого личных доменов/подсетей.",
    parameters={"type": "object", "properties": {}, "additionalProperties": False},
    sensitivity="medium",
)
def netshift_config_show(context, arguments: dict[str, Any]) -> dict[str, Any]:
    raw = context.uci.get_all("netshift")
    sections = []
    for name, values in raw.items():
        if not isinstance(values, dict) or values.get(".type") not in NETSHIFT_PROFILE_SECTION_TYPES:
            continue
        domains = str(context.uci.get("netshift", name, "user_domains_text", "") or "").splitlines()
        subnets = str(context.uci.get("netshift", name, "user_subnets_text", "") or "").splitlines()
        sections.append({
            "name": name,
            "enabled": str(values.get("enabled", "1")) != "0",
            "user_domain_list_type": values.get("user_domain_list_type"),
            "user_subnet_list_type": values.get("user_subnet_list_type"),
            "user_domain_count": len([line for line in domains if line.strip()]),
            "user_subnet_count": len([line for line in subnets if line.strip()]),
            "include_keywords": _safe_list(values.get("subscription_filter_include_keywords")),
            "exclude_keyword_count": len(_safe_list(values.get("subscription_filter_exclude_keywords"))),
            "community_lists": sorted(
                key for key, value in values.items()
                if key.startswith("community_") and str(value) not in {"0", "disabled", ""}
            ),
        })
    return {
        "sections": sections, "native_uci": context.uci.native,
        "omitted_sensitive_fields": ["subscription_url", "user_domains_text", "user_subnets_text", "node_credentials"],
        "field_types": NETSHIFT_UCI_FIELD_TYPES,
    }


@tool(
    name="singbox_active_proxies",
    description="Показать активные Selector-группы и названия доступных нод через локальный Clash API.",
    parameters={"type": "object", "properties": {}, "additionalProperties": False},
    network_side_effect="localhost_api_read",
)
def singbox_active_proxies(context, arguments: dict[str, Any]) -> dict[str, Any]:
    selectors = _selectors(context)
    return {
        "selectors": [
            {"name": name, "active": data.get("now"), "options": list(data.get("all", []))[:100]}
            for name, data in sorted(selectors.items())
        ]
    }


@tool(
    name="singbox_connections",
    description="Показать ограниченную сводку текущих соединений и цепочек маршрутизации sing-box.",
    parameters={
        "type": "object", "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 100}},
        "additionalProperties": False,
    },
    sensitivity="medium",
    network_side_effect="localhost_api_read",
)
def singbox_connections(context, arguments: dict[str, Any]) -> dict[str, Any]:
    payload = _clash_request(context, "GET", "/connections")
    limit = arguments.get("limit", 30)
    connections = []
    for item in payload.get("connections", [])[:limit]:
        metadata = item.get("metadata", {}) if isinstance(item, dict) else {}
        connections.append({
            "host": metadata.get("host"), "destination_port": metadata.get("destinationPort"),
            "network": metadata.get("network"), "type": metadata.get("type"),
            "chains": list(item.get("chains", []))[:10] if isinstance(item, dict) else [],
        })
    return {"connections": connections, "total": len(payload.get("connections", []))}


@tool(
    name="netshift_check_domain_routing",
    description="Проверить fake-IP DNS-маршрутизацию домена и совпадение с ручными секциями netshift.",
    parameters={
        "type": "object", "properties": {"domain": {"type": "string", "pattern": DOMAIN_PATTERN, "maxLength": 253}},
        "required": ["domain"], "additionalProperties": False,
    },
    sensitivity="medium",
    network_side_effect="diagnostic_dns_query",
)
def netshift_check_domain_routing(context, arguments: dict[str, Any]) -> dict[str, Any]:
    domain = normalize_domain(arguments["domain"])
    raw = context.uci.get_all("netshift")
    matching_sections = []
    for name, values in raw.items():
        if not isinstance(values, dict) or values.get(".type") not in NETSHIFT_PROFILE_SECTION_TYPES:
            continue
        lines = str(context.uci.get("netshift", name, "user_domains_text", "") or "").splitlines()
        for line in lines:
            entry = line.strip().lower().rstrip(".")
            if entry.startswith("*."):
                matched = domain == entry[2:] or domain.endswith("." + entry[2:])
            else:
                matched = domain == entry
            if matched:
                matching_sections.append(name)
                break
    dns = dns_query(context, domain, "127.0.0.42", 53)
    return {
        "domain": domain, "singbox_dns": dns,
        "uses_fakeip": any(is_fakeip(address) for address in dns["addresses"]),
        "manual_list_matching_sections": matching_sections,
        "community_list_matching_not_introspected": True,
    }


def _switch_node_apply(context, plan: MutationPlan) -> dict[str, Any]:
    selector = plan.prepared["selector"]
    expected_before = plan.rollback_data["previous_node"]
    current = _selectors(context).get(selector, {}).get("now")
    if current != expected_before:
        raise AgentError("state_changed", "Активная нода изменилась после построения плана", {"expected": expected_before, "actual": current})
    _clash_request(context, "PUT", "/proxies/" + quote(selector, safe=""), {"name": plan.prepared["node"]})
    return {"selector": selector, "active": plan.prepared["node"]}


def _switch_node_verify(context, plan: MutationPlan) -> VerificationResult:
    selector = plan.prepared["selector"]
    active = _selectors(context).get(selector, {}).get("now")
    expected = plan.prepared["node"]
    return VerificationResult(active == expected, {"selector": selector, "expected": expected, "actual": active}, "Selector переключён" if active == expected else "Selector остался на другой ноде")


def _switch_node_rollback(context, plan: MutationPlan, backup_dir: str) -> VerificationResult:
    selector = plan.prepared["selector"]
    previous = plan.rollback_data["previous_node"]
    _clash_request(context, "PUT", "/proxies/" + quote(selector, safe=""), {"name": previous})
    active = _selectors(context).get(selector, {}).get("now")
    return VerificationResult(active == previous, {"selector": selector, "expected": previous, "actual": active}, "Предыдущая нода восстановлена")


@tool(
    name="netshift_switch_node",
    description="Временно переключить ноду Selector в sing-box после подтверждения.",
    parameters={
        "type": "object",
        "properties": {
            "selector": {"type": "string", "minLength": 1, "maxLength": 128},
            "node": {"type": "string", "minLength": 1, "maxLength": 256},
        },
        "required": ["selector", "node"], "additionalProperties": False,
    },
    exec_class=ExecClass.MUTATING,
    network_side_effect="localhost_runtime_change",
    applier=_switch_node_apply,
    verifier=_switch_node_verify,
    rollback=_switch_node_rollback,
)
def netshift_switch_node(context, arguments: dict[str, Any]) -> MutationPlan:
    selectors = _selectors(context)
    selector = arguments["selector"]
    node = arguments["node"]
    if selector not in selectors:
        raise ValidationError("Selector не найден", {"selector": selector})
    options = list(selectors[selector].get("all", []))
    if node not in options:
        raise ValidationError("Нода отсутствует в Selector", {"selector": selector, "node": node})
    previous = selectors[selector].get("now")
    if previous == node:
        raise ValidationError("Эта нода уже активна")
    return MutationPlan(
        summary=f"Переключить Selector {selector} на {node}",
        diff=f"runtime selector {selector}:\n- {previous}\n+ {node}",
        targets=[f"runtime:clash-selector:{selector}"], precondition_hashes={f"runtime:clash-selector:{selector}": str(previous)},
        prepared={"selector": selector, "node": node}, services=["sing-box"], verifier="clash_selector_matches",
        rollback_data={"previous_node": previous},
    )


def _add_domain_apply(context, plan: MutationPlan) -> dict[str, Any]:
    section = plan.prepared["section"]
    context.uci.set("netshift", section, "user_domains_text", plan.prepared["new_value"])
    context.uci.commit("netshift")
    reload_result = _reload_netshift(context)
    agh_result = service_action(context, "adguardhome", "restart", 60)
    return {"uci": f"netshift.{section}.user_domains_text", "domain": plan.prepared["domain"], "netshift": reload_result, "adguardhome": agh_result}


def _netshift_config_verification(context, domain: str | None = None) -> VerificationResult:
    checks: dict[str, Any] = {}
    try:
        with open("/etc/sing-box/config.json", "r", encoding="utf-8") as handle:
            json.load(handle)
        checks["singbox_config_json"] = True
    except (OSError, json.JSONDecodeError) as exc:
        checks["singbox_config_json"] = False
        checks["config_error"] = str(exc)[:300]
    checks["singbox_process"] = process_running("sing-box")
    if domain:
        direct_dns = dns_query(context, domain.lstrip("*."), "127.0.0.42", 53)
        lan_dns = dns_query(context, domain.lstrip("*."), "10.110.112.1", 53)
        checks["singbox_dns"] = direct_dns
        checks["lan_dns"] = lan_dns
        checks["fakeip"] = any(is_fakeip(address) for address in direct_dns["addresses"] + lan_dns["addresses"])
    ok = bool(checks.get("singbox_config_json") and checks.get("singbox_process") and (domain is None or checks.get("fakeip")))
    return VerificationResult(ok, checks, "netshift/sing-box прошёл проверку" if ok else "Проверка netshift/sing-box не пройдена")


def _add_domain_verify(context, plan: MutationPlan) -> VerificationResult:
    section = plan.prepared["section"]
    actual_lines = [line.strip().lower() for line in str(context.uci.get("netshift", section, "user_domains_text", "") or "").splitlines()]
    domain = plan.prepared["domain"]
    result = _netshift_config_verification(context, domain)
    result.checks["uci_contains_domain"] = domain in actual_lines
    result.ok = result.ok and result.checks["uci_contains_domain"]
    return result


def _add_domain_rollback(context, plan: MutationPlan, backup_dir: str) -> VerificationResult:
    context.backups.restore(backup_dir)
    _reload_netshift(context)
    service_action(context, "adguardhome", "restart", 60)
    result = _netshift_config_verification(context)
    expected_hash = plan.precondition_hashes.get("file:/etc/config/netshift")
    actual_hash = sha256_file("/etc/config/netshift")
    result.checks["uci_file_hash_restored"] = actual_hash == expected_hash
    result.ok = result.ok and result.checks["uci_file_hash_restored"]
    return result


@tool(
    name="netshift_add_domain_to_section",
    description="Добавить домен в многострочный UCI option user_domains_text с дедупликацией, бэкапом и проверкой.",
    parameters={
        "type": "object",
        "properties": {
            "section": {"type": "string", "pattern": SECTION_PATTERN, "maxLength": 64},
            "domain": {"type": "string", "pattern": r"(?:\*\.)?" + DOMAIN_PATTERN, "maxLength": 255},
        },
        "required": ["section", "domain"], "additionalProperties": False,
    },
    exec_class=ExecClass.MUTATING,
    sensitivity="medium",
    network_side_effect="config_reload_and_dns_restart",
    applier=_add_domain_apply,
    verifier=_add_domain_verify,
    rollback=_add_domain_rollback,
)
def netshift_add_domain_to_section(context, arguments: dict[str, Any]) -> MutationPlan:
    section = arguments["section"]
    domain = normalize_domain(arguments["domain"], allow_wildcard=True)
    sections = context.uci.get_all("netshift")
    if section not in sections or sections[section].get(".type") not in NETSHIFT_PROFILE_SECTION_TYPES:
        raise ValidationError("Секция netshift не найдена", {"section": section})
    if NETSHIFT_UCI_FIELD_TYPES["user_domains_text"] != "option":
        raise AgentError("field_type_mismatch", "Статическая таблица типов UCI повреждена")
    old_value = str(context.uci.get("netshift", section, "user_domains_text", "") or "")
    normalized = []
    seen = set()
    for line in old_value.splitlines():
        entry = line.strip().lower().rstrip(".")
        if entry and entry not in seen:
            normalized.append(entry)
            seen.add(entry)
    if domain in seen:
        raise ValidationError("Домен уже присутствует в секции", {"section": section, "domain": domain})
    normalized.append(domain)
    new_value = "\n".join(normalized) + "\n"
    before_lines = [line + "\n" for line in old_value.splitlines()]
    after_lines = [line + "\n" for line in new_value.splitlines()]
    diff = "".join(difflib.unified_diff(before_lines, after_lines, fromfile=f"netshift.{section}.user_domains_text", tofile=f"netshift.{section}.user_domains_text (planned)"))
    targets = ["file:/etc/config/netshift"]
    return MutationPlan(
        summary=f"Добавить {domain} в netshift.{section}.user_domains_text и перезагрузить netshift/AdGuardHome",
        diff=diff, targets=targets, precondition_hashes=state_hashes(targets),
        prepared={"section": section, "domain": domain, "new_value": new_value},
        uci_packages=["netshift"], services=["netshift", "sing-box", "adguardhome"],
        verifier="singbox_json+process+fakeip_dns+uci_contains_domain",
        rollback_data={"old_value": old_value},
    )


def _reload_apply(context, plan: MutationPlan) -> dict[str, Any]:
    result = _reload_netshift(context)
    result["adguardhome"] = service_action(context, "adguardhome", "restart", 60)
    return result


def _reload_verify(context, plan: MutationPlan) -> VerificationResult:
    return _netshift_config_verification(context)


def _reload_rollback(context, plan: MutationPlan, backup_dir: str) -> VerificationResult:
    _reload_netshift(context)
    service_action(context, "adguardhome", "restart", 60)
    return _netshift_config_verification(context)


@tool(
    name="netshift_reload",
    description="Перегенерировать sing-box config и перезапустить netshift/AdGuardHome после подтверждения.",
    parameters={"type": "object", "properties": {}, "additionalProperties": False},
    exec_class=ExecClass.MUTATING,
    network_side_effect="vpn_and_dns_restart",
    applier=_reload_apply,
    verifier=_reload_verify,
    rollback=_reload_rollback,
)
def netshift_reload(context, arguments: dict[str, Any]) -> MutationPlan:
    targets = ["file:/etc/config/netshift"]
    return MutationPlan(
        summary="Перезагрузить netshift и очистить DNS-кэш перезапуском AdGuardHome",
        diff="runtime: netshift reload\nruntime: adguardhome restart",
        targets=targets, precondition_hashes=state_hashes(targets),
        uci_packages=["netshift"],
        services=["netshift", "sing-box", "adguardhome"], verifier="singbox_json+process",
    )

