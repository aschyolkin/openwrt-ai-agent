from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from ..command import first_executable
from ..errors import AgentError, ValidationError
from ..models import MutationPlan, VerificationResult
from ..redaction import redact_text, sanitize
from ..registry import ExecClass, tool


INSPECTION_TOPICS = (
    "firewall_ruleset",
    "routes",
    "policy_rules",
    "addresses",
    "network_links",
    "neighbors",
    "listening_sockets",
    "conntrack",
    "processes",
    "services",
    "packages",
    "disk",
    "mounts",
    "kernel_modules",
    "cron",
    "ubus_objects",
    "board",
    "uci_config",
)

UCI_PACKAGES = (
    "network", "dhcp", "firewall", "system", "wireless", "dropbear",
    "uhttpd", "netshift", "zapret", "adguardhome", "sing-box", "ai-agent",
)

_SENSITIVE_UCI_OPTION = re.compile(
    r"password|passwd|secret|token|api.?key|private|credential|cookie|uuid|short.?id|"
    r"subscription|user_domains_text|user_subnets_text|wireless.*key|^key$",
    re.I,
)
_SERVICE_NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}")


def _page_text(text: str, contains: str, offset: int, limit: int) -> dict[str, Any]:
    lines = text.splitlines()
    if contains:
        needle = contains.casefold()
        lines = [line for line in lines if needle in line.casefold()]
    total = len(lines)
    page = lines[offset:offset + limit]
    next_offset = offset + len(page)
    return {
        "lines": page,
        "total_lines": total,
        "offset": offset,
        "next_offset": next_offset if next_offset < total else None,
        "page_truncated": next_offset < total,
        "filter": contains or None,
    }


def _run_page(context, candidates: tuple[str, ...], args: list[str], arguments: dict[str, Any], timeout: int = 20) -> dict[str, Any]:
    executable = first_executable(candidates)
    result = context.runner.run(
        [executable, *args],
        timeout=timeout,
        max_output_bytes=1024 * 1024,
    )
    text = redact_text(result.stdout)
    page = _page_text(
        text,
        str(arguments.get("contains", "")),
        int(arguments.get("offset", 0)),
        int(arguments.get("limit", 200)),
    )
    page.update({
        "ok": result.ok,
        "returncode": result.returncode,
        "command": [os.path.basename(executable), *args],
        "runner_truncated": result.truncated,
    })
    if result.stderr:
        page["stderr"] = redact_text(result.stderr[:4096])
    return page


def _firewall(context, arguments: dict[str, Any]) -> dict[str, Any]:
    result = _run_page(context, ("/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"), ["list", "ruleset"], arguments, 30)
    full_text = "\n".join(result["lines"])
    result["page_summary"] = {
        "tables": re.findall(r"^\s*table\s+(\S+)\s+(\S+)\s*\{", full_text, re.M)[:100],
        "chains": re.findall(r"^\s*chain\s+(\S+)\s*\{", full_text, re.M)[:200],
    }
    result["note"] = "Это фактический nftables ruleset; цепочки fw4, netshift и zapret могут сосуществовать."
    return result


def _processes(arguments: dict[str, Any]) -> dict[str, Any]:
    needle = str(arguments.get("contains", "")).casefold()
    entries = []
    for directory in Path("/proc").iterdir():
        if not directory.name.isdigit():
            continue
        try:
            name = (directory / "comm").read_text(encoding="utf-8", errors="replace").strip()
            status = (directory / "status").read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if needle and needle not in name.casefold():
            continue
        uid_match = re.search(r"^Uid:\s+(\d+)", status, re.M)
        state_match = re.search(r"^State:\s+(.+)$", status, re.M)
        rss_match = re.search(r"^VmRSS:\s+(.+)$", status, re.M)
        entries.append({
            "pid": int(directory.name),
            "name": name,
            "uid": int(uid_match.group(1)) if uid_match else None,
            "state": state_match.group(1) if state_match else None,
            "rss": rss_match.group(1) if rss_match else None,
        })
    entries.sort(key=lambda item: item["pid"])
    offset = int(arguments.get("offset", 0))
    limit = int(arguments.get("limit", 200))
    return {
        "processes": entries[offset:offset + limit],
        "total": len(entries),
        "offset": offset,
        "next_offset": offset + limit if offset + limit < len(entries) else None,
        "note": "Аргументы процессов намеренно не передаются модели: в них бывают токены и пароли.",
    }


def _services(arguments: dict[str, Any]) -> dict[str, Any]:
    needle = str(arguments.get("contains", "")).casefold()
    init_dir = Path("/etc/init.d")
    names = sorted(path.name for path in init_dir.iterdir() if path.is_file() and _SERVICE_NAME.fullmatch(path.name))
    enabled = set()
    rc_dir = Path("/etc/rc.d")
    if rc_dir.is_dir():
        for path in rc_dir.iterdir():
            match = re.fullmatch(r"S\d\d(.+)", path.name)
            if match:
                enabled.add(match.group(1))
    rows = [{"name": name, "enabled": name in enabled} for name in names if not needle or needle in name.casefold()]
    offset = int(arguments.get("offset", 0))
    limit = int(arguments.get("limit", 200))
    return {"services": rows[offset:offset + limit], "total": len(rows), "offset": offset}


def _cron(arguments: dict[str, Any]) -> dict[str, Any]:
    rows = []
    root = Path("/etc/crontabs")
    if root.is_dir():
        for path in sorted(root.iterdir()):
            if not path.is_file():
                continue
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for line in lines:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    rows.append({"user": path.name, "entry": redact_text(stripped)})
    needle = str(arguments.get("contains", "")).casefold()
    if needle:
        rows = [row for row in rows if needle in row["entry"].casefold()]
    offset = int(arguments.get("offset", 0))
    limit = int(arguments.get("limit", 200))
    return {"entries": rows[offset:offset + limit], "total": len(rows), "offset": offset}


def _redact_uci_sections(sections: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for section, options in sections.items():
        safe_options = {}
        for name, value in options.items():
            safe_options[name] = "***redacted***" if _SENSITIVE_UCI_OPTION.search(name) else sanitize(value)
        result[section] = safe_options
    return result


def _uci_config(context, arguments: dict[str, Any]) -> dict[str, Any]:
    package = str(arguments.get("package", ""))
    if package not in UCI_PACKAGES:
        raise ValidationError("Для topic=uci_config нужен разрешённый package")
    sections = _redact_uci_sections(context.uci.get_all(package))
    return {
        "package": package,
        "sections": sections,
        "redaction": "Секреты, ключи, UUID, подписки и личные domain/subnet lists скрыты.",
    }


@tool(
    name="sys_inspect",
    description=(
        "Универсальная read-only инспекция OpenWrt. Используй для nftables/firewall rules, маршрутов, "
        "policy rules, адресов, линков, ARP/neighbor, слушающих портов, установленных NAT-соединений "
        "(conntrack — реальные текущие потоки LAN-клиентов, в т.ч. напрямую мимо sing-box), процессов, "
        "сервисов, пакетов, дисков, mounts, модулей ядра, cron, ubus, board info и безопасного UCI config. "
        "Большой вывод читай страницами через offset/limit и при необходимости contains."
    ),
    parameters={
        "type": "object",
        "properties": {
            "topic": {"type": "string", "enum": list(INSPECTION_TOPICS)},
            "package": {"type": "string", "enum": list(UCI_PACKAGES)},
            "contains": {"type": "string", "maxLength": 128},
            "offset": {"type": "integer", "minimum": 0, "maximum": 20000},
            "limit": {"type": "integer", "minimum": 20, "maximum": 300},
        },
        "required": ["topic"],
        "additionalProperties": False,
    },
    sensitivity="medium",
)
def sys_inspect(context, arguments: dict[str, Any]) -> dict[str, Any]:
    topic = arguments["topic"]
    if topic == "firewall_ruleset":
        return _firewall(context, arguments)
    if topic == "routes":
        return _run_page(context, ("/usr/bin/ip", "/sbin/ip"), ["route", "show", "table", "all"], arguments)
    if topic == "policy_rules":
        return _run_page(context, ("/usr/bin/ip", "/sbin/ip"), ["rule", "show"], arguments)
    if topic == "addresses":
        return _run_page(context, ("/usr/bin/ip", "/sbin/ip"), ["address", "show"], arguments)
    if topic == "network_links":
        return _run_page(context, ("/usr/bin/ip", "/sbin/ip"), ["link", "show"], arguments)
    if topic == "neighbors":
        return _run_page(context, ("/usr/bin/ip", "/sbin/ip"), ["neighbor", "show"], arguments)
    if topic == "listening_sockets":
        return _run_page(context, ("/bin/netstat", "/usr/bin/netstat"), ["-lntup"], arguments)
    if topic == "conntrack":
        result = _run_page(context, ("/usr/sbin/conntrack", "/usr/bin/conntrack"), ["-L"], arguments, 20)
        result["note"] = (
            "Таблица NAT-соединений ядра (conntrack): показывает реально установленные потоки "
            "LAN-клиентов независимо от того, перехвачены ли они netshift tproxy (fakeip 198.18.0.0/15) "
            "или идут напрямую через WAN. Только IP:порт, без имён хостов/SNI."
        )
        return result
    if topic == "processes":
        return _processes(arguments)
    if topic == "services":
        return _services(arguments)
    if topic == "packages":
        return _run_page(context, ("/usr/bin/apk",), ["info"], arguments, 30)
    if topic == "disk":
        return _run_page(context, ("/bin/df", "/usr/bin/df"), ["-h"], arguments)
    if topic == "mounts":
        return _run_page(context, ("/usr/bin/mount", "/bin/mount"), [], arguments)
    if topic == "kernel_modules":
        return _run_page(context, ("/sbin/lsmod", "/usr/bin/lsmod"), [], arguments)
    if topic == "cron":
        return _cron(arguments)
    if topic == "ubus_objects":
        return _run_page(context, ("/bin/ubus", "/sbin/ubus", "/usr/bin/ubus"), ["list"], arguments)
    if topic == "board":
        board = context.ubus.call("system", "board", {})
        allowed = {key: board.get(key) for key in ("kernel", "hostname", "system", "model", "board_name", "rootfs_type", "release") if key in board}
        return {"board": allowed}
    if topic == "uci_config":
        return _uci_config(context, arguments)
    raise ValidationError("Неизвестный topic")


def _service_call(context, service: str, action: str):
    if not _SERVICE_NAME.fullmatch(service) or not (Path("/etc/init.d") / service).is_file():
        raise ValidationError("Сервис не найден", {"service": service})
    executable = first_executable(("/sbin/service", "/usr/sbin/service", "/usr/bin/service"))
    return context.runner.run([executable, service, action], timeout=90, max_output_bytes=32768)


def _service_state(context, service: str) -> dict[str, bool]:
    return {
        "running": _service_call(context, service, "status").returncode == 0,
        "enabled": _service_call(context, service, "enabled").returncode == 0,
    }


def _service_apply(context, plan: MutationPlan) -> dict[str, Any]:
    service = plan.prepared["service"]
    action = plan.prepared["action"]
    current = _service_state(context, service)
    if current != plan.rollback_data["previous_state"]:
        raise AgentError("state_changed", "Состояние сервиса изменилось после построения плана", {"expected": plan.rollback_data["previous_state"], "actual": current})
    result = _service_call(context, service, action)
    if not result.ok:
        raise AgentError("service_action_failed", f"service {service} {action} завершился ошибкой", {"stderr": redact_text(result.stderr[:4096])})
    return {"service": service, "action": action, "output": redact_text(result.stdout[:4096])}


def _service_verify(context, plan: MutationPlan) -> VerificationResult:
    service = plan.prepared["service"]
    action = plan.prepared["action"]
    state = _service_state(context, service)
    if action in {"start", "restart", "reload"}:
        ok = state["running"]
    elif action == "stop":
        ok = not state["running"]
    elif action == "enable":
        ok = state["enabled"]
    else:
        ok = not state["enabled"]
    return VerificationResult(ok, {"service": service, "action": action, "state": state}, "Состояние сервиса подтверждено" if ok else "Сервис не достиг ожидаемого состояния")


def _service_rollback(context, plan: MutationPlan, backup_dir: str) -> VerificationResult:
    service = plan.prepared["service"]
    previous = plan.rollback_data["previous_state"]
    current = _service_state(context, service)
    if current["enabled"] != previous["enabled"]:
        _service_call(context, service, "enable" if previous["enabled"] else "disable")
    current = _service_state(context, service)
    if current["running"] != previous["running"]:
        _service_call(context, service, "start" if previous["running"] else "stop")
    actual = _service_state(context, service)
    ok = actual == previous
    return VerificationResult(ok, {"expected": previous, "actual": actual}, "Предыдущее состояние сервиса восстановлено" if ok else "Нужна ручная проверка сервиса")


@tool(
    name="sys_service_control",
    description=(
        "Управлять любым установленным procd/init.d сервисом после локального подтверждения: "
        "start, stop, restart, reload, enable или disable. Для ai-agent self-control запрещён."
    ),
    parameters={
        "type": "object",
        "properties": {
            "service": {"type": "string", "pattern": r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}"},
            "action": {"type": "string", "enum": ["start", "stop", "restart", "reload", "enable", "disable"]},
        },
        "required": ["service", "action"],
        "additionalProperties": False,
    },
    exec_class=ExecClass.MUTATING,
    network_side_effect="service_state_change",
    applier=_service_apply,
    verifier=_service_verify,
    rollback=_service_rollback,
)
def sys_service_control(context, arguments: dict[str, Any]) -> MutationPlan:
    service = arguments["service"]
    action = arguments["action"]
    if service == "ai-agent":
        raise ValidationError("ai-agent не может безопасно управлять собственным процессом")
    if not (Path("/etc/init.d") / service).is_file():
        raise ValidationError("Сервис не найден", {"service": service})
    previous = _service_state(context, service)
    critical = service in {"network", "firewall", "dropbear", "dnsmasq", "uhttpd", "odhcpd"}
    warning = " ВНИМАНИЕ: действие может нарушить сеть или доступ по SSH." if critical and action in {"stop", "restart", "reload", "disable"} else ""
    return MutationPlan(
        summary=f"Выполнить service {service} {action}.{warning}",
        diff=f"runtime service {service}: {previous} -> action={action}",
        targets=[f"runtime:service:{service}"],
        precondition_hashes={f"runtime:service:{service}": repr(previous)},
        prepared={"service": service, "action": action},
        services=[service],
        verifier="service running/enabled state",
        rollback_data={"previous_state": previous},
    )
