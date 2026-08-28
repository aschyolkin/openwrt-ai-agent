from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from typing import Any

from ..command import first_executable
from ..errors import AgentError, ServiceNotReady, ValidationError


DOMAIN_PATTERN = r"(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}"
SECTION_PATTERN = r"[a-zA-Z0-9_][a-zA-Z0-9_-]{0,63}"


def normalize_domain(value: str, allow_wildcard: bool = False) -> str:
    value = value.strip().lower().rstrip(".")
    wildcard = value.startswith("*.")
    if wildcard:
        if not allow_wildcard:
            raise ValidationError("Wildcard здесь не разрешён")
        value = value[2:]
    if not re.fullmatch(DOMAIN_PATTERN, value):
        raise ValidationError("Недопустимое доменное имя", {"domain": value})
    return ("*." if wildcard else "") + value


def service_status(context, service: str) -> dict[str, Any]:
    candidates = (f"/etc/init.d/{service}", "/sbin/service", "/usr/sbin/service", "/usr/bin/service")
    executable = first_executable(candidates)
    argv = [executable, "status"] if executable.startswith("/etc/init.d/") else [executable, service, "status"]
    result = context.runner.run(argv, timeout=15, max_output_bytes=16384)
    output = (result.stdout + "\n" + result.stderr).strip()
    return {
        "service": service,
        "running": result.returncode == 0 and not result.timed_out,
        "status": output[:4096] or ("running" if result.returncode == 0 else "stopped"),
    }


def service_action(context, service: str, action: str, timeout: int = 60) -> dict[str, Any]:
    candidates = (f"/etc/init.d/{service}", "/sbin/service", "/usr/sbin/service", "/usr/bin/service")
    executable = first_executable(candidates)
    argv = [executable, action] if executable.startswith("/etc/init.d/") else [executable, service, action]
    result = context.runner.run(argv, timeout=timeout, max_output_bytes=32768)
    if not result.ok:
        raise AgentError(
            "service_action_failed", f"{service} {action} завершился ошибкой",
            {"returncode": result.returncode, "stderr": result.stderr[:4096], "timed_out": result.timed_out},
        )
    return {"service": service, "action": action, "output": result.stdout[:4096]}


def process_running(name: str) -> bool:
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            comm = (entry / "comm").read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if comm == name:
            return True
    return False


def dns_query(context, domain: str, server: str, port: int = 53) -> dict[str, Any]:
    domain = normalize_domain(domain)
    try:
        executable = first_executable(("/usr/bin/dig", "/bin/dig"))
    except AgentError:
        return {"ok": False, "error": "dig_unavailable", "server": server, "port": port, "addresses": []}
    argv = [executable, "+time=3", "+tries=1", "+short", f"@{server}"]
    if port != 53:
        argv.extend(["-p", str(port)])
    argv.extend([domain, "A"])
    result = context.runner.run(argv, timeout=8, max_output_bytes=16384)
    addresses: list[str] = []
    for line in result.stdout.splitlines():
        candidate = line.strip().rstrip(".")
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        addresses.append(candidate)
    return {
        "ok": result.ok and bool(addresses), "server": server, "port": port,
        "addresses": addresses[:16], "returncode": result.returncode,
    }


def is_fakeip(address: str) -> bool:
    try:
        return ipaddress.ip_address(address) in ipaddress.ip_network("198.18.0.0/15")
    except ValueError:
        return False


def nft_ruleset_text(context, timeout: int = 15) -> str:
    """Full `nft list ruleset` output, or "" if nft is unavailable/fails.

    Degrades gracefully (does not raise) so callers can treat firewall-layer
    evidence as "not observed" rather than crashing the whole diagnostic tool
    when nft is missing or the command errors out — mirrors dns_query's
    handling of a missing `dig`.
    """
    try:
        executable = first_executable(("/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"))
    except AgentError:
        return ""
    result = context.runner.run([executable, "list", "ruleset"], timeout=timeout, max_output_bytes=1024 * 1024)
    return result.stdout if result.ok else ""

