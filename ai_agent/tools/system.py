from __future__ import annotations

import os
import shutil
import time
from pathlib import Path
from typing import Any

from ..command import first_executable
from ..redaction import redact_log_network_data
from ..registry import tool


EMPTY_OBJECT = {"type": "object", "properties": {}, "additionalProperties": False}


def _read_proc_stat_cpu_lines() -> dict[str, list[int]]:
    result: dict[str, list[int]] = {}
    with open("/proc/stat", "r", encoding="utf-8") as handle:
        for line in handle:
            if not line.startswith("cpu"):
                break
            parts = line.split()
            name = parts[0]
            if name == "cpu" and len(parts) == 1:
                continue
            result[name] = [int(field) for field in parts[1:]]
    return result


def _cpu_usage_percent(sample_seconds: float = 0.2) -> dict[str, float]:
    """Two /proc/stat samples over a short window give an instantaneous
    per-core utilization snapshot (jiffies deltas), same technique 'top' uses."""
    before = _read_proc_stat_cpu_lines()
    time.sleep(sample_seconds)
    after = _read_proc_stat_cpu_lines()
    usage: dict[str, float] = {}
    for name, after_fields in after.items():
        before_fields = before.get(name)
        if not before_fields or len(before_fields) < 4:
            continue
        total_before = sum(before_fields)
        total_after = sum(after_fields)
        idle_before = before_fields[3] + (before_fields[4] if len(before_fields) > 4 else 0)
        idle_after = after_fields[3] + (after_fields[4] if len(after_fields) > 4 else 0)
        total_delta = total_after - total_before
        idle_delta = idle_after - idle_before
        usage[name] = round(max(0.0, min(100.0, (1 - idle_delta / total_delta) * 100)), 1) if total_delta > 0 else 0.0
    return usage


def _cpu_temperatures() -> list[dict[str, Any]]:
    zones: list[dict[str, Any]] = []
    root = Path("/sys/class/thermal")
    if not root.is_dir():
        return zones
    for zone_dir in sorted(root.glob("thermal_zone*")):
        try:
            zone_type = (zone_dir / "type").read_text(encoding="utf-8").strip()
            raw_temp = (zone_dir / "temp").read_text(encoding="utf-8").strip()
            zones.append({"zone": zone_type, "celsius": round(int(raw_temp) / 1000, 1)})
        except (OSError, ValueError):
            continue
    return zones


@tool(
    name="sys_logread",
    description="Прочитать ограниченный хвост системного лога с маскированием секретов, доменов и IP.",
    parameters={
        "type": "object",
        "properties": {
            "service": {"type": "string", "enum": ["ai-agent", "netshift", "sing-box", "adguardhome", "zapret"]},
            "lines": {"type": "integer", "minimum": 1, "maximum": 200},
        },
        "additionalProperties": False,
    },
    sensitivity="high",
)
def sys_logread(context, arguments: dict[str, Any]) -> dict[str, Any]:
    executable = first_executable(("/sbin/logread", "/usr/sbin/logread", "/usr/bin/logread"))
    argv = [executable]
    if arguments.get("service"):
        argv.extend(["-e", arguments["service"]])
    result = context.runner.run(argv, timeout=10, max_output_bytes=65536)
    limit = arguments.get("lines", 100)
    lines = result.stdout.splitlines()[-limit:]
    return {
        "service_filter": arguments.get("service"), "lines": [redact_log_network_data(line) for line in lines],
        "truncated": result.truncated,
    }


@tool(
    name="sys_resource_usage",
    description="Показать загрузку CPU (общую, load average и по ядрам), температуру, память, uptime и место на overlay.",
    parameters=EMPTY_OBJECT,
)
def sys_resource_usage(context, arguments: dict[str, Any]) -> dict[str, Any]:
    meminfo = {}
    try:
        for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
            name, value = line.split(":", 1)
            if name in {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}:
                meminfo[name] = value.strip()
    except OSError:
        pass
    try:
        loadavg = Path("/proc/loadavg").read_text(encoding="ascii").split()[:3]
    except OSError:
        loadavg = []
    try:
        uptime = float(Path("/proc/uptime").read_text(encoding="ascii").split()[0])
    except (OSError, ValueError, IndexError):
        uptime = None
    overlay = shutil.disk_usage("/overlay" if Path("/overlay").exists() else "/")
    cpu_usage = _cpu_usage_percent()
    cores = sorted(
        ((name, pct) for name, pct in cpu_usage.items() if name != "cpu"),
        key=lambda item: int(item[0][3:]) if item[0][3:].isdigit() else item[0],
    )
    return {
        "load_average": loadavg, "uptime_seconds": uptime, "memory": meminfo,
        "storage": {"total": overlay.total, "used": overlay.used, "free": overlay.free},
        "cpu_percent": cpu_usage.get("cpu"),
        "cpu_percent_per_core": [{"cpu": name, "usage_percent": pct} for name, pct in cores],
        "cpu_temperatures_celsius": _cpu_temperatures(),
    }


@tool(
    name="backup_list",
    description="Показать локальные бэкапы конфигурационных действий без содержимого конфигов.",
    parameters={
        "type": "object", "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 100}},
        "additionalProperties": False,
    },
)
def backup_list(context, arguments: dict[str, Any]) -> dict[str, Any]:
    return {"backups": context.backups.list(arguments.get("limit", 30))}

