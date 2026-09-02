from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..command import first_executable
from ..registry import ExecClass, tool
from .common import DOMAIN_PATTERN, EMPTY_OBJECT, dns_query, normalize_domain


@tool(
    name="net_interfaces_status",
    description="Показать безопасный структурированный статус сетевых интерфейсов OpenWrt без секретов.",
    parameters=EMPTY_OBJECT,
    sensitivity="low",
)
def net_interfaces_status(context, arguments: dict[str, Any]) -> dict[str, Any]:
    data = context.ubus.call("network.interface", "dump", {})
    raw_interfaces = data.get("interface", []) if isinstance(data, dict) else []
    interfaces = []
    for item in raw_interfaces:
        if not isinstance(item, dict):
            continue
        addresses = []
        for address in item.get("ipv4-address", []) or []:
            if isinstance(address, dict):
                addresses.append({"address": address.get("address"), "mask": address.get("mask")})
        interfaces.append({
            "interface": item.get("interface"), "up": bool(item.get("up")),
            "pending": bool(item.get("pending")), "available": bool(item.get("available", True)),
            "uptime": item.get("uptime"), "proto": item.get("proto"),
            "device": item.get("l3_device") or item.get("device"), "ipv4": addresses[:8],
        })
    return {"interfaces": interfaces, "native_ubus": context.ubus.native}


@tool(
    name="net_device_stats",
    description="Прочитать счётчики RX/TX выбранного сетевого устройства из sysfs.",
    parameters={
        "type": "object",
        "properties": {"interface": {"type": "string", "pattern": r"[a-zA-Z0-9_.:-]{1,32}"}},
        "required": ["interface"], "additionalProperties": False,
    },
)
def net_device_stats(context, arguments: dict[str, Any]) -> dict[str, Any]:
    interface = arguments["interface"]
    root = Path("/sys/class/net") / interface
    if not root.is_dir():
        return {"interface": interface, "exists": False}
    stats = {}
    for name in ("rx_bytes", "rx_packets", "rx_errors", "rx_dropped", "tx_bytes", "tx_packets", "tx_errors", "tx_dropped"):
        try:
            stats[name] = int((root / "statistics" / name).read_text(encoding="ascii").strip())
        except (OSError, ValueError):
            stats[name] = None
    try:
        operstate = (root / "operstate").read_text(encoding="ascii").strip()
    except OSError:
        operstate = "unknown"
    return {"interface": interface, "exists": True, "operstate": operstate, "statistics": stats}


@tool(
    name="net_dns_check",
    description="Сравнить фактический DNS-ответ AdGuardHome и прямой ответ sing-box для домена.",
    parameters={
        "type": "object", "properties": {"domain": {"type": "string", "pattern": DOMAIN_PATTERN, "maxLength": 253}},
        "required": ["domain"], "additionalProperties": False,
    },
    sensitivity="medium",
    network_side_effect="diagnostic_dns_queries",
)
def net_dns_check(context, arguments: dict[str, Any]) -> dict[str, Any]:
    domain = normalize_domain(arguments["domain"])
    adguard = dns_query(context, domain, "10.110.112.1", 53)
    singbox = dns_query(context, domain, "127.0.0.42", 53)
    adguard_blocked = not adguard["addresses"] or all(address in {"0.0.0.0", "127.0.0.1"} for address in adguard["addresses"])
    upstream_ok = bool(singbox["addresses"]) and not all(address == "0.0.0.0" for address in singbox["addresses"])
    return {
        "domain": domain, "adguard": adguard, "singbox_direct": singbox,
        "likely_adguard_block": adguard_blocked and upstream_ok,
    }


@tool(
    name="net_ping_traceroute",
    description="Выполнить ограниченный ping или traceroute до безопасно проверенного хоста.",
    parameters={
        "type": "object",
        "properties": {
            "host": {"type": "string", "pattern": r"[a-zA-Z0-9.:-]{1,253}"},
            "mode": {"type": "string", "enum": ["ping", "traceroute"]},
            "count": {"type": "integer", "minimum": 1, "maximum": 5},
        },
        "required": ["host", "mode"], "additionalProperties": False,
    },
    network_side_effect="diagnostic_packets",
)
def net_ping_traceroute(context, arguments: dict[str, Any]) -> dict[str, Any]:
    host = arguments["host"].strip()
    mode = arguments["mode"]
    count = arguments.get("count", 3)
    if mode == "ping":
        executable = first_executable(("/bin/ping", "/usr/bin/ping"))
        argv = [executable, "-c", str(count), "-W", "2", host]
        timeout = count * 3 + 2
    else:
        executable = first_executable(("/usr/bin/traceroute", "/bin/traceroute"))
        argv = [executable, "-m", "12", "-w", "2", host]
        timeout = 30
    result = context.runner.run(argv, timeout=timeout, max_output_bytes=32768)
    return {"host": host, "mode": mode, **result.to_dict()}

