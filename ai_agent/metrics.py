from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Any

from .command import first_executable
from .errors import AgentError


def read_proc_stat_cpu_lines() -> dict[str, list[int]]:
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


def cpu_usage_percent(sample_seconds: float = 0.2) -> dict[str, float]:
    """Two /proc/stat samples over a short window give an instantaneous
    per-core utilization snapshot (jiffies deltas), same technique 'top' uses."""
    before = read_proc_stat_cpu_lines()
    time.sleep(sample_seconds)
    after = read_proc_stat_cpu_lines()
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


def cpu_temperatures() -> list[dict[str, Any]]:
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


def mem_available_percent() -> float | None:
    try:
        values: dict[str, int] = {}
        for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
            name, _, rest = line.partition(":")
            if name in {"MemTotal", "MemAvailable"}:
                values[name] = int(rest.strip().split()[0])
        total = values.get("MemTotal")
        available = values.get("MemAvailable")
        if not total:
            return None
        return round(100 * available / total, 1)
    except (OSError, ValueError, IndexError):
        return None


def conntrack_count() -> int | None:
    try:
        executable = first_executable(("/usr/sbin/conntrack", "/sbin/conntrack", "/usr/bin/conntrack"))
    except AgentError:
        return None
    try:
        result = subprocess.run([executable, "-L"], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return sum(1 for line in result.stdout.splitlines() if line.strip())


def lan_client_count() -> int | None:
    try:
        lines = Path("/tmp/dhcp.leases").read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    return sum(1 for line in lines if line.strip())


def ping_wan(host: str = "1.1.1.1", count: int = 5) -> tuple[float | None, float | None]:
    try:
        executable = first_executable(("/bin/ping", "/usr/bin/ping"))
    except AgentError:
        return None, None
    try:
        result = subprocess.run(
            [executable, "-c", str(count), "-W", "3", host],
            capture_output=True, text=True, timeout=count * 3 + 5, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None, None
    output = result.stdout
    packet_loss: float | None = None
    for line in output.splitlines():
        if "packet loss" in line:
            for token in line.split(","):
                token = token.strip()
                if token.endswith("% packet loss"):
                    try:
                        packet_loss = float(token.replace("% packet loss", ""))
                    except ValueError:
                        pass
    avg_latency: float | None = None
    for line in output.splitlines():
        if line.startswith(("rtt ", "round-trip ")):
            try:
                stats = line.split("=", 1)[1].strip().split()[0]
                avg_latency = float(stats.split("/")[1])
            except (IndexError, ValueError):
                pass
    return avg_latency, packet_loss


def sample_current_metrics() -> dict[str, Any]:
    avg_latency, packet_loss = ping_wan()
    return {
        "cpu_percent": cpu_usage_percent().get("cpu"),
        "mem_available_percent": mem_available_percent(),
        "conntrack_count": conntrack_count(),
        "wan_latency_ms": avg_latency,
        "packet_loss_percent": packet_loss,
        "lan_client_count": lan_client_count(),
    }
