from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..adapters import sha256_file, state_hashes
from ..errors import AgentError, ValidationError
from ..models import MutationPlan, VerificationResult
from ..registry import ExecClass, tool
from .common import process_running, service_action, service_status


def _services_for_tool(name: str) -> list[str]:
    if name.startswith("netshift_"):
        return ["netshift", "adguardhome"]
    if name.startswith("zapret_"):
        return ["zapret"]
    if name.startswith("agh_"):
        return ["adguardhome"]
    return []


def _restart_services(context, services: list[str]) -> dict[str, Any]:
    results = {}
    for service in services:
        action = "reload" if service == "netshift" else "restart"
        results[service] = service_action(context, service, action, 90)
    return results


def _backup_restore_apply(context, plan: MutationPlan) -> dict[str, Any]:
    restored = context.backups.restore(plan.prepared["source_directory"])
    restored["services"] = _restart_services(context, plan.services)
    return restored


def _backup_restore_verify(context, plan: MutationPlan) -> VerificationResult:
    checks: dict[str, Any] = {}
    for service in plan.services:
        checks[f"service_{service}"] = service_status(context, service)["running"]
    if "netshift" in plan.services:
        checks["singbox_process"] = process_running("sing-box")
    if "zapret" in plan.services:
        checks["nfqws_process"] = process_running("nfqws")
    source_meta = context.backups.read_meta(plan.prepared["source_directory"])
    for entry in source_meta.get("uci", []):
        if entry.get("sha256") and entry["sha256"] != "missing":
            path = f"/etc/config/{entry['package']}"
            checks[f"hash_{entry['package']}"] = Path(path).is_file() and sha256_file(path) == entry["sha256"]
    ok = all(bool(value) for value in checks.values()) if checks else True
    return VerificationResult(ok, checks, "Бэкап восстановлен и сервисы проверены" if ok else "Восстановление требует ручной проверки")


def _backup_restore_rollback(context, plan: MutationPlan, backup_dir: str) -> VerificationResult:
    context.backups.restore(backup_dir)
    _restart_services(context, plan.services)
    checks = {f"service_{service}": service_status(context, service)["running"] for service in plan.services}
    ok = all(checks.values()) if checks else True
    return VerificationResult(ok, checks, "Состояние до восстановления бэкапа возвращено")


@tool(
    name="backup_restore",
    description="Восстановить выбранный action-specific бэкап после отдельного подтверждения; текущее состояние сначала тоже бэкапится.",
    parameters={
        "type": "object",
        "properties": {"backup": {"type": "string", "pattern": r"[0-9]{8}-[0-9]{6}_[a-zA-Z0-9-]{3,80}", "maxLength": 100}},
        "required": ["backup"], "additionalProperties": False,
    },
    exec_class=ExecClass.MUTATING,
    sensitivity="medium",
    network_side_effect="config_restore_and_service_restart",
    applier=_backup_restore_apply,
    verifier=_backup_restore_verify,
    rollback=_backup_restore_rollback,
)
def backup_restore(context, arguments: dict[str, Any]) -> MutationPlan:
    name = arguments["backup"]
    source = (Path(context.backups.root) / name).resolve()
    root = Path(context.backups.root).resolve()
    if source.parent != root or not source.is_dir():
        raise ValidationError("Бэкап не найден", {"backup": name})
    meta = context.backups.read_meta(str(source))
    packages = [entry["package"] for entry in meta.get("uci", [])]
    files = [entry["path"] for entry in meta.get("files", []) if entry.get("path")]
    targets = [f"file:/etc/config/{package}" for package in packages] + [f"file:{path}" for path in files]
    services = _services_for_tool(str(meta.get("tool_name", "")))
    diff_lines = [f"restore backup: {name}", f"source action: {meta.get('action_id')}"]
    diff_lines.extend(f"restore UCI package: {package}" for package in packages)
    diff_lines.extend(f"restore file: {path}" for path in files)
    diff_lines.extend(f"restart/reload service: {service}" for service in services)
    return MutationPlan(
        summary=f"Восстановить бэкап {name}", diff="\n".join(diff_lines),
        targets=targets, precondition_hashes=state_hashes(targets), prepared={"source_directory": str(source)},
        uci_packages=packages, backup_files=files, services=services,
        verifier="restored_hashes+service_processes",
    )

