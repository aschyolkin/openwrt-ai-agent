from __future__ import annotations

import json
import os
import shlex
from pathlib import Path
from typing import Any

from .command import CommandRunner, first_executable
from .errors import AgentError


class UCIAdapter:
    """Use python3-uci when available, with a strict subprocess fallback."""

    def __init__(self, runner: CommandRunner):
        self.runner = runner
        self._uci = None
        try:
            import uci  # type: ignore
            self._uci = uci.Uci()
        except (ImportError, AttributeError, RuntimeError):
            self._uci = None

    @property
    def native(self) -> bool:
        return self._uci is not None

    def _binary(self) -> str:
        return first_executable(("/sbin/uci", "/usr/bin/uci"))

    def get(self, package: str, section: str, option: str, default: str | None = None) -> Any:
        if self._uci is not None:
            try:
                value = self._uci.get(package, section, option)
                if isinstance(value, tuple):
                    value = "\n".join(value)
                return default if value is None else value
            except Exception:
                pass
        result = self.runner.run([self._binary(), "-q", "get", f"{package}.{section}.{option}"])
        return result.stdout.rstrip("\n") if result.ok else default

    def get_all(self, package: str) -> dict[str, dict[str, Any]]:
        if self._uci is not None:
            try:
                raw = self._uci.get_all(package)
                if isinstance(raw, dict):
                    sections: dict[str, dict[str, Any]] = {}
                    for name, values in raw.items():
                        bucket = {
                            key: list(value) if isinstance(value, tuple) else value
                            for key, value in values.items()
                        }
                        bucket[".type"] = self._uci.get(package, name)
                        sections[name] = bucket
                    return sections
            except Exception:
                pass
        result = self.runner.run([self._binary(), "show", package], timeout=10)
        if not result.ok:
            raise AgentError("uci_read_failed", f"Не удалось прочитать UCI-пакет {package}")
        return parse_uci_show(package, result.stdout)

    def set(self, package: str, section: str, option: str, value: str) -> None:
        if self._uci is not None:
            try:
                native_value = tuple(value) if isinstance(value, list) else value
                self._uci.set(package, section, option, native_value)
                return
            except Exception:
                pass
        result = self.runner.run([self._binary(), "set", f"{package}.{section}.{option}={value}"])
        if not result.ok:
            raise AgentError("uci_write_failed", f"Не удалось изменить {package}.{section}.{option}", {"stderr": result.stderr})

    def create_section(self, package: str, section: str, section_type: str) -> None:
        """uci set pkg.section=type — creates a new named section of the given type."""
        if self._uci is not None:
            try:
                self._uci.set(package, section, section_type)
                return
            except Exception:
                pass
        result = self.runner.run([self._binary(), "set", f"{package}.{section}={section_type}"])
        if not result.ok:
            raise AgentError("uci_write_failed", f"Не удалось создать секцию {package}.{section}", {"stderr": result.stderr})

    def delete_section(self, package: str, section: str) -> None:
        if self._uci is not None:
            try:
                self._uci.delete(package, section)
                return
            except Exception:
                pass
        result = self.runner.run([self._binary(), "delete", f"{package}.{section}"])
        if not result.ok:
            raise AgentError("uci_delete_failed", f"Не удалось удалить секцию {package}.{section}", {"stderr": result.stderr})

    def commit(self, package: str) -> None:
        if self._uci is not None:
            try:
                self._uci.commit(package)
                return
            except Exception:
                pass
        result = self.runner.run([self._binary(), "commit", package])
        if not result.ok:
            raise AgentError("uci_commit_failed", f"Не удалось сохранить UCI-пакет {package}", {"stderr": result.stderr})

    def changes(self, package: str) -> str:
        result = self.runner.run([self._binary(), "changes", package])
        if not result.ok:
            raise AgentError("uci_changes_failed", f"Не удалось проверить изменения UCI {package}")
        return result.stdout.strip()

    def export(self, package: str) -> str:
        result = self.runner.run([self._binary(), "export", package], max_output_bytes=1024 * 1024)
        if not result.ok:
            raise AgentError("uci_export_failed", f"Не удалось экспортировать UCI {package}")
        return result.stdout

    def import_text(self, package: str, content: str) -> None:
        """Import without a shell; native binding preferred, fixed argv fallback."""
        if self._uci is not None and hasattr(self._uci, "import_config"):
            try:
                self._uci.import_config(package, content)
                self.commit(package)
                return
            except Exception:
                pass
        binary = self._binary()
        result = self.runner.run([binary, "import", package], input_text=content, max_output_bytes=65536)
        if not result.ok:
            raise AgentError("uci_import_failed", f"Не удалось импортировать UCI {package}")
        self.commit(package)


def parse_uci_show(package: str, text: str) -> dict[str, dict[str, Any]]:
    sections: dict[str, dict[str, Any]] = {}
    prefix = package + "."
    for line in text.splitlines():
        if not line.startswith(prefix) or "=" not in line:
            continue
        key, encoded = line.split("=", 1)
        parts = key[len(prefix):].split(".", 1)
        section = parts[0]
        try:
            parsed = shlex.split(encoded, posix=True)
            value = parsed[0] if parsed else ""
        except ValueError:
            value = encoded.strip("'")
        bucket = sections.setdefault(section, {})
        if len(parts) == 1:
            bucket[".type"] = value
        else:
            option = parts[1]
            if option in bucket:
                previous = bucket[option]
                bucket[option] = previous + [value] if isinstance(previous, list) else [previous, value]
            else:
                bucket[option] = value
    return sections


class UBusAdapter:
    """Use python3-ubus when available, then fall back to fixed ubus argv."""

    def __init__(self, runner: CommandRunner):
        self.runner = runner
        self._module = None
        try:
            import ubus  # type: ignore
            try:
                ubus.connect()
            except Exception:
                pass
            self._module = ubus
        except ImportError:
            self._module = None

    @property
    def native(self) -> bool:
        return self._module is not None

    def call(self, object_name: str, method: str, payload: dict[str, Any] | None = None) -> Any:
        payload = payload or {}
        if self._module is not None:
            try:
                result = self._module.call(object_name, method, payload)
                if isinstance(result, list) and len(result) == 1 and isinstance(result[0], dict):
                    return result[0]
                return result
            except Exception:
                pass
        binary = first_executable(("/bin/ubus", "/sbin/ubus", "/usr/bin/ubus"))
        result = self.runner.run([binary, "call", object_name, method, json.dumps(payload, separators=(",", ":"))])
        if not result.ok:
            raise AgentError("ubus_call_failed", f"ubus {object_name}.{method} завершился ошибкой", {"stderr": result.stderr})
        try:
            return json.loads(result.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise AgentError("ubus_invalid_response", "ubus вернул невалидный JSON") from exc


def load_agent_config(uci: UCIAdapter) -> "AgentConfig":
    from .config import AgentConfig
    try:
        sections = uci.get_all("ai-agent")
        values = next((value for value in sections.values() if value.get(".type") in {"main", "ai-agent"}), {})
    except AgentError:
        values = {}
    return AgentConfig.from_mapping(values)


def sha256_file(path: str) -> str:
    import hashlib
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def state_hashes(targets: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for target in targets:
        path = target[5:] if target.startswith("file:") else target
        result[target] = sha256_file(path) if os.path.isfile(path) else "missing"
    return result

