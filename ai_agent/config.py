from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import AgentError


DEFAULT_SIMPLE_MODEL = "gpt://b1gq9kr4q4sjlm3vradj/gpt-oss-20b/latest"
DEFAULT_COMPLEX_MODEL = "gpt://b1gq9kr4q4sjlm3vradj/deepseek-v4-flash/latest"
DEFAULT_MODEL = DEFAULT_COMPLEX_MODEL


@dataclass(frozen=True)
class AgentConfig:
    enabled: bool = True
    socket_path: str = "/var/run/ai-agent.sock"
    model_id: str = DEFAULT_MODEL
    simple_model_id: str = DEFAULT_SIMPLE_MODEL
    complex_model_id: str = DEFAULT_COMPLEX_MODEL
    model_routing_enabled: bool = True
    api_base_url: str = "https://ai.api.cloud.yandex.net/v1"
    max_tool_loop_iterations: int = 8
    confirm_ttl_seconds: int = 300
    backup_retention_days: int = 30
    log_level: str = "INFO"
    state_dir: str = "/var/lib/ai-agent"
    secrets_path: str = "/etc/ai-agent/secrets.env"
    system_prompt_path: str = "/etc/ai-agent/system_prompt.md"
    request_timeout_seconds: int = 60
    max_request_bytes: int = 1024 * 1024
    command_output_limit: int = 65536
    conversation_max_chars: int = 12000
    tool_context_max_chars: int = 16000

    @property
    def database_path(self) -> str:
        return str(Path(self.state_dir) / "sessions.sqlite")

    @property
    def metrics_path(self) -> str:
        return str(Path(self.state_dir) / "metrics.sqlite")

    @property
    def backups_dir(self) -> str:
        return str(Path(self.state_dir) / "backups")

    @property
    def audit_path(self) -> str:
        return str(Path(self.state_dir) / "audit.log")

    @classmethod
    def from_mapping(cls, values: dict[str, Any]) -> "AgentConfig":
        def integer(name: str, default: int, minimum: int, maximum: int) -> int:
            try:
                value = int(values.get(name, default))
            except (TypeError, ValueError):
                value = default
            return max(minimum, min(value, maximum))

        return cls(
            enabled=str(values.get("enable", values.get("enabled", "1"))).lower() not in {"0", "false", "no"},
            socket_path=str(values.get("socket_path", cls.socket_path)),
            model_id=str(values.get("model_id", DEFAULT_MODEL)),
            simple_model_id=str(values.get("simple_model_id", DEFAULT_SIMPLE_MODEL)),
            complex_model_id=str(values.get("complex_model_id", values.get("model_id", DEFAULT_COMPLEX_MODEL))),
            model_routing_enabled=str(values.get("model_routing_enabled", "1")).lower() not in {"0", "false", "no"},
            api_base_url=str(values.get("api_base_url", cls.api_base_url)).rstrip("/"),
            max_tool_loop_iterations=integer("max_tool_loop_iterations", 8, 1, 20),
            confirm_ttl_seconds=integer("confirm_ttl_seconds", 300, 30, 3600),
            backup_retention_days=integer("backup_retention_days", 30, 1, 365),
            log_level=str(values.get("log_level", "INFO")).upper(),
            state_dir=str(values.get("state_dir", cls.state_dir)),
            secrets_path=str(values.get("secrets_path", cls.secrets_path)),
            system_prompt_path=str(values.get("system_prompt_path", cls.system_prompt_path)),
            request_timeout_seconds=integer("request_timeout_seconds", 60, 5, 180),
            max_request_bytes=integer("max_request_bytes", 1024 * 1024, 4096, 2 * 1024 * 1024),
            command_output_limit=integer("command_output_limit", 65536, 4096, 1024 * 1024),
            conversation_max_chars=integer("conversation_max_chars", 12000, 4000, 64000),
            tool_context_max_chars=integer("tool_context_max_chars", 16000, 4000, 32768),
        )


def load_secret(path: str, key: str = "YANDEX_AI_STUDIO_API_KEY") -> str:
    secret_path = Path(path)
    try:
        mode = stat.S_IMODE(secret_path.stat().st_mode)
    except FileNotFoundError as exc:
        raise AgentError("missing_api_key", f"Не найден файл секретов {path}") from exc
    if mode & 0o077:
        raise AgentError("insecure_secret_permissions", f"Файл {path} должен иметь права 0600")
    for raw_line in secret_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        if name.strip() == key:
            value = value.strip()
            if len(value) < 16 or any(char.isspace() for char in value):
                raise AgentError("invalid_api_key", "API-ключ в secrets.env имеет недопустимый формат")
            return value
    raise AgentError("missing_api_key", f"В {path} отсутствует {key}")


def ensure_private_directory(path: str) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
