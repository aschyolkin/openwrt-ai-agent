from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Callable


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    def to_dict(self, include_argv: bool = False) -> dict[str, Any]:
        result = {
            "ok": self.ok,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
            "truncated": self.truncated,
        }
        if include_argv:
            result["argv"] = self.argv
        return result


@dataclass
class MutationPlan:
    summary: str
    diff: str
    targets: list[str]
    precondition_hashes: dict[str, str]
    prepared: dict[str, Any] = field(default_factory=dict)
    uci_packages: list[str] = field(default_factory=list)
    backup_files: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    verifier: str = ""
    rollback_data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class VerificationResult:
    ok: bool
    checks: dict[str, Any]
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


Planner = Callable[[Any, dict[str, Any]], MutationPlan]
Applier = Callable[[Any, MutationPlan], dict[str, Any]]
Verifier = Callable[[Any, MutationPlan], VerificationResult]
Rollback = Callable[[Any, MutationPlan, str], VerificationResult]

