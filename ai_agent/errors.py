from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentError(Exception):
    code: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    retryable: bool = False

    def __str__(self) -> str:
        return self.message

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "ok": False,
            "error": self.code,
            "message": self.message,
        }
        if self.details:
            result["details"] = self.details
        if self.retryable:
            result["retryable"] = True
        return result


class ValidationError(AgentError):
    def __init__(self, message: str, details: dict[str, Any] | None = None):
        super().__init__("invalid_arguments", message, details or {})


class ServiceNotReady(AgentError):
    def __init__(self, service: str, message: str | None = None):
        super().__init__(
            "service_not_ready",
            message or f"Сервис {service} ещё не готов",
            {"service": service},
            retryable=True,
        )

