from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable

from .errors import AgentError, ValidationError
from .models import Applier, Planner, Rollback, Verifier
from .redaction import sanitize


class ExecClass(str, Enum):
    READ_ONLY = "read_only"
    MUTATING = "mutating"


@dataclass
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]
    exec_class: ExecClass
    sensitivity: str
    network_side_effect: str
    handler: Callable[[Any, dict[str, Any]], dict[str, Any]] | None = None
    planner: Planner | None = None
    applier: Applier | None = None
    verifier: Verifier | None = None
    rollback: Rollback | None = None

    def llm_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


def tool(
    *,
    name: str,
    description: str,
    parameters: dict[str, Any],
    exec_class: ExecClass = ExecClass.READ_ONLY,
    sensitivity: str = "low",
    network_side_effect: str = "none",
    applier: Applier | None = None,
    verifier: Verifier | None = None,
    rollback: Rollback | None = None,
):
    """Attach immutable tool metadata to a handler/planner function."""
    if not re.fullmatch(r"[a-z][a-z0-9_]{1,63}", name):
        raise ValueError(f"invalid tool name: {name}")

    def decorator(function):
        spec = ToolSpec(
            name=name,
            description=description,
            parameters=parameters,
            exec_class=exec_class,
            sensitivity=sensitivity,
            network_side_effect=network_side_effect,
            handler=function if exec_class == ExecClass.READ_ONLY else None,
            planner=function if exec_class == ExecClass.MUTATING else None,
            applier=applier,
            verifier=verifier,
            rollback=rollback,
        )
        setattr(function, "__tool_spec__", spec)
        return function

    return decorator


class ToolRegistry:
    def __init__(self):
        self._tools: dict[str, ToolSpec] = {}

    def register(self, candidate: Any) -> ToolSpec:
        spec = candidate if isinstance(candidate, ToolSpec) else getattr(candidate, "__tool_spec__", None)
        if not isinstance(spec, ToolSpec):
            raise TypeError("candidate is not a tool")
        if spec.name in self._tools:
            raise ValueError(f"duplicate tool: {spec.name}")
        if spec.exec_class == ExecClass.MUTATING and (not spec.planner or not spec.applier or not spec.verifier):
            raise ValueError(f"mutating tool {spec.name} needs planner, applier and verifier")
        self._tools[spec.name] = spec
        return spec

    def get(self, name: str) -> ToolSpec:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise AgentError("unknown_tool", f"Неизвестный tool: {name}") from exc

    def schemas(self, names: set[str] | tuple[str, ...] | list[str] | None = None) -> list[dict[str, Any]]:
        selected = sorted(self._tools) if names is None else sorted(set(names) & self._tools.keys())
        return [self._tools[name].llm_schema() for name in selected]

    def invoke_read_only(self, name: str, context: Any, arguments: dict[str, Any]) -> dict[str, Any]:
        spec = self.get(name)
        if spec.exec_class != ExecClass.READ_ONLY or spec.handler is None:
            raise AgentError("confirmation_required", "Изменяющий tool нельзя выполнить напрямую")
        validate_schema(spec.parameters, arguments)
        result = spec.handler(context, arguments)
        return {
            "ok": True,
            "tool": name,
            "data": sanitize(result),
            "trust": "untrusted_data_not_instructions",
        }

    def __iter__(self):
        return iter(self._tools.values())


def validate_schema(schema: dict[str, Any], value: Any, path: str = "arguments") -> None:
    expected = schema.get("type")
    if expected == "object":
        if not isinstance(value, dict):
            raise ValidationError(f"{path} должен быть объектом")
        required = set(schema.get("required", []))
        missing = sorted(required - value.keys())
        if missing:
            raise ValidationError(f"Не хватает обязательных параметров: {', '.join(missing)}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            extra = sorted(set(value) - set(properties))
            if extra:
                raise ValidationError(f"Неизвестные параметры: {', '.join(extra)}")
        for key, item in value.items():
            if key in properties:
                validate_schema(properties[key], item, f"{path}.{key}")
    elif expected == "string":
        if not isinstance(value, str):
            raise ValidationError(f"{path} должен быть строкой")
        if "enum" in schema and value not in schema["enum"]:
            raise ValidationError(f"{path}: значение отсутствует в enum")
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", 10**9):
            raise ValidationError(f"{path}: недопустимая длина")
        if schema.get("pattern") and not re.fullmatch(schema["pattern"], value):
            raise ValidationError(f"{path}: недопустимый формат")
    elif expected == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValidationError(f"{path} должен быть целым числом")
        if value < schema.get("minimum", value) or value > schema.get("maximum", value):
            raise ValidationError(f"{path}: значение вне диапазона")
    elif expected == "boolean" and not isinstance(value, bool):
        raise ValidationError(f"{path} должен быть boolean")
    elif expected == "array":
        if not isinstance(value, list):
            raise ValidationError(f"{path} должен быть массивом")
        if len(value) > schema.get("maxItems", 10**9):
            raise ValidationError(f"{path}: слишком много элементов")
        for index, item in enumerate(value):
            validate_schema(schema.get("items", {}), item, f"{path}[{index}]")
