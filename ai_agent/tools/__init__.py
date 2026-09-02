from __future__ import annotations

from . import (
    adguardhome, firewall, netshift_singbox, network, packages, remote_access,
    service_health, system, system_inspect, zapret,
)


def register_all(registry) -> None:
    for module in (
        network, adguardhome, netshift_singbox, service_health, zapret,
        system, system_inspect, firewall, remote_access, packages,
    ):
        for candidate in vars(module).values():
            if getattr(candidate, "__tool_spec__", None) is not None:
                registry.register(candidate)
