from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from typing import Any

from ..command import first_executable
from ..errors import AgentError, ServiceNotReady, ValidationError


EMPTY_OBJECT = {"type": "object", "properties": {}, "additionalProperties": False}
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


def _proc_net_ports(filename: str, listening_only: bool) -> set[int]:
    """Local ports from a /proc/net/{tcp,tcp6,udp,udp6} table."""
    ports: set[int] = set()
    try:
        lines = Path("/proc/net", filename).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ports
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 4 or ":" not in fields[1]:
            continue
        if listening_only and fields[3] != "0A":  # TCP_LISTEN
            continue
        try:
            ports.add(int(fields[1].rsplit(":", 1)[1], 16))
        except ValueError:
            continue
    return ports


def port_listening(port: int, proto: str) -> bool:
    """True if a local socket is bound to `port` for any of the given protocols.

    Reads /proc directly so it works without netstat/ss and cannot be fooled by
    a shell. A WAN firewall ACCEPT rule for a port nobody listens on yields a
    refused connection, so mutating tools use this to tell the user up front.
    """
    wanted = proto.split()
    if "tcp" in wanted and (_proc_net_ports("tcp", True) | _proc_net_ports("tcp6", True)) & {port}:
        return True
    if "udp" in wanted and (_proc_net_ports("udp", False) | _proc_net_ports("udp6", False)) & {port}:
        return True
    return False


def _socket_inodes(port: int, proto: str) -> set[str]:
    inodes: set[str] = set()
    tables: list[tuple[str, bool]] = []
    if "tcp" in proto.split():
        tables.extend((("tcp", True), ("tcp6", True)))
    if "udp" in proto.split():
        tables.extend((("udp", False), ("udp6", False)))
    for filename, listening_only in tables:
        try:
            lines = Path("/proc/net", filename).read_text(
                encoding="utf-8", errors="replace",
            ).splitlines()
        except OSError:
            continue
        for line in lines[1:]:
            fields = line.split()
            if len(fields) < 10 or ":" not in fields[1]:
                continue
            try:
                local_port = int(fields[1].rsplit(":", 1)[1], 16)
            except ValueError:
                continue
            if local_port == port and (not listening_only or fields[3] == "0A"):
                inodes.add(fields[9])
    return inodes


def port_owned_by_process(port: int, proto: str, process_names: set[str]) -> bool:
    """Verify that a bound socket belongs to one of the expected processes."""
    sockets = {f"socket:[{inode}]" for inode in _socket_inodes(port, proto)}
    if not sockets:
        return False
    try:
        processes = list(Path("/proc").iterdir())
    except OSError:
        return False
    for process in processes:
        if not process.name.isdigit():
            continue
        try:
            if (process / "comm").read_text(encoding="utf-8").strip() not in process_names:
                continue
            for descriptor in (process / "fd").iterdir():
                try:
                    if os.readlink(descriptor) in sockets:
                        return True
                except OSError:
                    continue
        except OSError:
            continue
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

