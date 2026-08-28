from __future__ import annotations

import difflib
import re
from pathlib import Path
from typing import Any

from ..adapters import state_hashes
from ..command import first_executable
from ..errors import ValidationError
from ..models import MutationPlan, VerificationResult
from ..redaction import redact_text
from ..registry import ExecClass, tool


_PACKAGE_NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9+_.-]{0,127}")
_APK_WORLD = "/etc/apk/world"


def _apk() -> str:
    return first_executable(("/usr/bin/apk",))


def _installed(context, package: str) -> bool:
    result = context.runner.run([_apk(), "info", "-e", package], timeout=20, max_output_bytes=8192)
    return result.ok


def _install_apply(context, plan: MutationPlan) -> dict[str, Any]:
    package = plan.prepared["package"]
    result = context.runner.run([_apk(), "add", package], timeout=180, max_output_bytes=32768)
    return {
        "package": package,
        "returncode": result.returncode,
        "stdout": redact_text(result.stdout[-8192:]),
        "stderr": redact_text(result.stderr[-8192:]),
        "timed_out": result.timed_out,
        "truncated": result.truncated,
    }


def _install_verify(context, plan: MutationPlan) -> VerificationResult:
    package = plan.prepared["package"]
    installed = _installed(context, package)
    return VerificationResult(
        installed,
        {"package_installed": installed, "manager": "apk"},
        f"Пакет {package} установлен" if installed else f"Пакет {package} не найден среди установленных",
    )


def _install_rollback(context, plan: MutationPlan, _backup_dir: str) -> VerificationResult:
    package = plan.prepared["package"]
    result = context.runner.run([_apk(), "del", package], timeout=180, max_output_bytes=32768)
    removed = not _installed(context, package)
    return VerificationResult(
        result.ok and removed,
        {"apk_del_ok": result.ok, "package_removed": removed},
        f"Откат выполнен: пакет {package} удалён" if removed else "Откат удаления пакета требует ручной проверки",
    )


def _remove_apply(context, plan: MutationPlan) -> dict[str, Any]:
    package = plan.prepared["package"]
    result = context.runner.run([_apk(), "del", package], timeout=180, max_output_bytes=32768)
    return {
        "package": package,
        "returncode": result.returncode,
        "stdout": redact_text(result.stdout[-8192:]),
        "stderr": redact_text(result.stderr[-8192:]),
        "timed_out": result.timed_out,
        "truncated": result.truncated,
    }


def _remove_verify(context, plan: MutationPlan) -> VerificationResult:
    package = plan.prepared["package"]
    removed = not _installed(context, package)
    return VerificationResult(
        removed,
        {"package_removed": removed, "manager": "apk"},
        f"Пакет {package} удалён" if removed else f"Пакет {package} всё ещё установлен",
    )


def _remove_rollback(context, plan: MutationPlan, _backup_dir: str) -> VerificationResult:
    package = plan.prepared["package"]
    result = context.runner.run([_apk(), "add", package], timeout=180, max_output_bytes=32768)
    restored = _installed(context, package)
    return VerificationResult(
        result.ok and restored,
        {"apk_add_ok": result.ok, "package_restored": restored},
        f"Откат выполнен: пакет {package} установлен снова" if restored else "Откат установки пакета требует ручной проверки",
    )


@tool(
    name="sys_package_install",
    description=(
        "Установить один пакет из настроенных репозиториев OpenWrt через apk. Используй по явной просьбе "
        "установить пакет. Tool строит план и требует подтверждение; произвольные flags, URL и файлы запрещены."
    ),
    parameters={
        "type": "object",
        "properties": {"package": {"type": "string", "pattern": r"^[a-zA-Z0-9][a-zA-Z0-9+_.-]{0,127}$"}},
        "required": ["package"],
        "additionalProperties": False,
    },
    exec_class=ExecClass.MUTATING,
    sensitivity="high",
    network_side_effect="package_download_and_install_scripts",
    applier=_install_apply,
    verifier=_install_verify,
    rollback=_install_rollback,
)
def sys_package_install(context, arguments: dict[str, Any]) -> MutationPlan:
    package = str(arguments["package"])
    if not _PACKAGE_NAME.fullmatch(package):
        raise ValidationError("Недопустимое имя пакета")
    if _installed(context, package):
        raise ValidationError("Пакет уже установлен", {"package": package})
    before = ["installed packages\n"]
    after = ["installed packages\n", f"+ {package} (apk add)\n"]
    diff = "".join(difflib.unified_diff(before, after, fromfile="apk world (current)", tofile="apk world (planned)"))
    targets = [f"file:{_APK_WORLD}"] if Path(_APK_WORLD).is_file() else []
    return MutationPlan(
        summary=f"Установить пакет {package} через apk из настроенных репозиториев",
        diff=diff,
        targets=targets,
        precondition_hashes=state_hashes(targets),
        prepared={"package": package, "manager": "apk", "previously_installed": False},
        backup_files=[_APK_WORLD] if targets else [],
        verifier="apk info -e package",
        rollback_data={"operation": "apk del", "package": package},
    )


@tool(
    name="sys_package_remove",
    description=(
        "Удалить один установленный пакет OpenWrt через apk. Используй по явной просьбе удалить пакет; "
        "если пользователь говорит «этот пакет», возьми точное имя из истории диалога. Tool строит план "
        "и требует подтверждение; произвольные flags запрещены."
    ),
    parameters={
        "type": "object",
        "properties": {"package": {"type": "string", "pattern": r"^[a-zA-Z0-9][a-zA-Z0-9+_.-]{0,127}$"}},
        "required": ["package"],
        "additionalProperties": False,
    },
    exec_class=ExecClass.MUTATING,
    sensitivity="high",
    network_side_effect="package_removal_and_scripts",
    applier=_remove_apply,
    verifier=_remove_verify,
    rollback=_remove_rollback,
)
def sys_package_remove(context, arguments: dict[str, Any]) -> MutationPlan:
    package = str(arguments["package"])
    if not _PACKAGE_NAME.fullmatch(package):
        raise ValidationError("Недопустимое имя пакета")
    if not _installed(context, package):
        raise ValidationError("Пакет не установлен", {"package": package})
    before = ["installed packages\n", f"+ {package} (installed)\n"]
    after = ["installed packages\n"]
    diff = "".join(difflib.unified_diff(before, after, fromfile="apk world (current)", tofile="apk world (planned)"))
    targets = [f"file:{_APK_WORLD}"] if Path(_APK_WORLD).is_file() else []
    return MutationPlan(
        summary=f"Удалить установленный пакет {package} через apk",
        diff=diff,
        targets=targets,
        precondition_hashes=state_hashes(targets),
        prepared={"package": package, "manager": "apk", "previously_installed": True},
        backup_files=[_APK_WORLD] if targets else [],
        verifier="apk info -e package должен вернуть not installed",
        rollback_data={"operation": "apk add", "package": package},
    )
