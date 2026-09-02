from __future__ import annotations

import json
import os
import shutil
import time
from pathlib import Path
from typing import Any

from ..command import first_executable
from ..metrics import cpu_temperatures, cpu_usage_percent, sample_current_metrics
from ..redaction import redact_log_network_data
from ..registry import tool
from .common import EMPTY_OBJECT

METRIC_DIRECTION = {
    "cpu_percent": "high_bad",
    "mem_available_percent": "low_bad",
    "conntrack_count": "high_bad",
    "wan_latency_ms": "high_bad",
    "packet_loss_percent": "high_bad",
    "lan_client_count": "neutral",
}
MIN_SAMPLES_FOR_BASELINE = 20


def _percentile(sorted_values: list[float], pct: float) -> float:
    index = round(pct / 100 * (len(sorted_values) - 1))
    return sorted_values[index]


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
    cpu_usage = cpu_usage_percent()
    cores = sorted(
        ((name, pct) for name, pct in cpu_usage.items() if name != "cpu"),
        key=lambda item: int(item[0][3:]) if item[0][3:].isdigit() else item[0],
    )
    return {
        "load_average": loadavg, "uptime_seconds": uptime, "memory": meminfo,
        "storage": {"total": overlay.total, "used": overlay.used, "free": overlay.free},
        "cpu_percent": cpu_usage.get("cpu"),
        "cpu_percent_per_core": [{"cpu": name, "usage_percent": pct} for name, pct in cores],
        "cpu_temperatures_celsius": cpu_temperatures(),
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


@tool(
    name="agent_audit_log",
    description=(
        "Прочитать журнал событий mutating-действий агента (что менялось, когда, статус, "
        "результат проверки). Не содержит ручных изменений по SSH — только действия агента."
    ),
    parameters={
        "type": "object",
        "properties": {
            "contains": {"type": "string", "maxLength": 128},
            "offset": {"type": "integer", "minimum": 0, "maximum": 20000},
            "limit": {"type": "integer", "minimum": 1, "maximum": 200},
        },
        "additionalProperties": False,
    },
    sensitivity="medium",
)
def agent_audit_log(context, arguments: dict[str, Any]) -> dict[str, Any]:
    path = Path(context.config.audit_path)
    entries: list[dict[str, Any]] = []
    if path.is_file():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    entries.sort(key=lambda entry: entry.get("ts", 0), reverse=True)
    for entry in entries:
        ts = entry.get("ts")
        if isinstance(ts, (int, float)):
            entry["time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    contains = str(arguments.get("contains", ""))
    if contains:
        needle = contains.casefold()
        entries = [entry for entry in entries if needle in json.dumps(entry, ensure_ascii=False).casefold()]
    offset = int(arguments.get("offset", 0))
    limit = int(arguments.get("limit", 100))
    page = entries[offset:offset + limit]
    next_offset = offset + len(page)
    return {
        "entries": page, "total": len(entries), "offset": offset,
        "next_offset": next_offset if next_offset < len(entries) else None,
        "note": "Только действия самого агента (plan/confirm/apply/verify/rollback). Ручные изменения по SSH сюда не попадают.",
    }


@tool(
    name="sys_baseline_compare",
    description=(
        "Сравнить текущее значение метрики (CPU/память/conntrack/WAN-задержка/packet loss/"
        "число клиентов LAN) с историческим baseline за последние N дней — чтобы понять, "
        "нормальное это значение или аномальное для этого роутера."
    ),
    parameters={
        "type": "object",
        "properties": {
            "metric": {"type": "string", "enum": list(METRIC_DIRECTION)},
            "days_of_history": {"type": "integer", "minimum": 1, "maximum": 30},
        },
        "required": ["metric"],
        "additionalProperties": False,
    },
)
def sys_baseline_compare(context, arguments: dict[str, Any]) -> dict[str, Any]:
    metric = arguments["metric"]
    days = int(arguments.get("days_of_history", 7))
    since = int(time.time()) - days * 86400
    history = context.metrics.recent_samples(metric, since)
    current = sample_current_metrics().get(metric)
    if len(history) < MIN_SAMPLES_FOR_BASELINE:
        return {
            "metric": metric, "status": "insufficient_data",
            "sample_count": len(history), "current": current,
            "interpretation": "Недостаточно накопленных сэмплов для baseline — не делай вывод о норме/аномалии по одному текущему значению.",
        }
    sorted_history = sorted(history)
    p5, p50, p95 = _percentile(sorted_history, 5), _percentile(sorted_history, 50), _percentile(sorted_history, 95)
    direction = METRIC_DIRECTION[metric]
    if current is None:
        anomalous = False
    elif direction == "high_bad":
        anomalous = current > p95 and current > p50 * 1.3
    elif direction == "low_bad":
        anomalous = current < p5 and current < p50 * 0.7
    else:
        anomalous = current < p5 or current > p95
    return {
        "metric": metric, "status": "ok", "current": current, "sample_count": len(history),
        "baseline": {"p5": p5, "p50": p50, "p95": p95, "min": sorted_history[0], "max": sorted_history[-1]},
        "anomalous": anomalous,
        "interpretation": "Baseline — эмпирический диапазон наблюдений, не жёсткий порог. Единичный выход за p95 — повод присмотреться, не готовый диагноз.",
    }

