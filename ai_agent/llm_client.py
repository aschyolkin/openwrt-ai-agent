from __future__ import annotations

import json
import logging
from typing import Any

import requests

from .errors import AgentError


LOG = logging.getLogger("ai-agent.llm")


def _token_count(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def compact_tool_result(value: Any, max_chars: int = 16000, max_lines: int = 200, max_items: int = 200) -> str:
    """Serialize tool data with hard, deterministic limits for the next LLM turn."""
    truncated = False

    def compact(item: Any, depth: int = 0) -> Any:
        nonlocal truncated
        if depth > 8:
            truncated = True
            return "[nested data omitted]"
        if isinstance(item, str):
            lines = item.splitlines()
            if len(lines) > max_lines:
                truncated = True
                item = "\n".join(lines[-max_lines:])
            if len(item) > max_chars // 2:
                truncated = True
                item = item[-(max_chars // 2):]
            return item
        if isinstance(item, list):
            if len(item) > max_items:
                truncated = True
                item = item[-max_items:]
            return [compact(entry, depth + 1) for entry in item]
        if isinstance(item, dict):
            return {str(key): compact(entry, depth + 1) for key, entry in item.items()}
        return item

    compacted = compact(value)
    if isinstance(compacted, dict) and truncated:
        compacted.setdefault("context_truncated", True)
    encoded = json.dumps(compacted, ensure_ascii=False, separators=(",", ":"))
    if len(encoded) <= max_chars:
        return encoded
    preview_budget = max(512, max_chars - 240)
    wrapper = {
        "ok": False,
        "error": "tool_output_truncated",
        "message": "Результат сокращён до лимита контекста; уточните фильтр/contains или запросите следующую страницу.",
        "preview_tail": encoded[-preview_budget:],
    }
    result = json.dumps(wrapper, ensure_ascii=False, separators=(",", ":"))
    while len(result) > max_chars and wrapper["preview_tail"]:
        wrapper["preview_tail"] = wrapper["preview_tail"][256:]
        result = json.dumps(wrapper, ensure_ascii=False, separators=(",", ":"))
    return result


class LLMClient:
    def __init__(self, base_url: str, api_key: str, model: str, timeout: int = 60, session: requests.Session | None = None):
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key
        self.model = model
        self.timeout = timeout
        self.session = session or requests.Session()

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> dict[str, Any]:
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.1,
            "max_tokens": 4000,
            # Reasoning models (e.g. gpt-oss) spend part of max_tokens on a hidden
            # reasoning_content before the visible answer; "low" keeps enough budget
            # for the actual reply instead of it being silently truncated to empty.
            "reasoning_effort": "low",
        }
        if tools:
            payload.update({"tools": tools, "tool_choice": "auto", "parallel_tool_calls": False})
        try:
            response = self.session.post(
                self.base_url + "/chat/completions",
                headers={"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"},
                json=payload,
                timeout=(10, self.timeout),
            )
        except requests.RequestException as exc:
            raise AgentError("llm_unavailable", "Yandex AI Studio недоступен", retryable=True) from exc
        if response.status_code >= 400:
            request_id = response.headers.get("x-request-id") or response.headers.get("request-id")
            raise AgentError(
                "llm_api_error", f"Yandex AI Studio вернул HTTP {response.status_code}",
                {"status": response.status_code, "request_id": request_id}, retryable=response.status_code >= 500,
            )
        try:
            data = response.json()
            choice = data["choices"][0]
            message = dict(choice["message"])
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise AgentError("llm_invalid_response", "Yandex AI Studio вернул неожиданный формат") from exc
        if not isinstance(message, dict):
            raise AgentError("llm_invalid_response", "В ответе LLM отсутствует message")
        if not message.get("content") and not message.get("tool_calls") and choice.get("finish_reason") == "length":
            # Reasoning models can spend the whole max_tokens budget on hidden
            # reasoning_content and return an empty visible answer; surface this
            # as a retryable error instead of a silent blank reply to the user.
            raise AgentError(
                "llm_truncated_empty_response",
                "Модель исчерпала лимит токенов на рассуждение и не оставила видимого ответа",
                retryable=True,
            )
        usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
        details = usage.get("prompt_tokens_details") if isinstance(usage.get("prompt_tokens_details"), dict) else {}
        message["_usage"] = {
            "prompt_tokens": _token_count(usage.get("prompt_tokens")),
            "completion_tokens": _token_count(usage.get("completion_tokens")),
            "total_tokens": _token_count(usage.get("total_tokens")),
            "cached_tokens": _token_count(details.get("cached_tokens", usage.get("cached_tokens"))),
        }
        message["_request_metrics"] = {
            "messages_chars": len(json.dumps(messages, ensure_ascii=False, separators=(",", ":"))),
            "tool_schema_chars": len(json.dumps(tools, ensure_ascii=False, separators=(",", ":"))),
            "tools_count": len(tools),
            "request_id": response.headers.get("x-request-id") or response.headers.get("request-id"),
        }
        return message


class Orchestrator:
    def __init__(self, client: LLMClient, registry, actions, sessions, context, system_prompt: str, max_iterations: int = 8, model_router=None, max_context_chars: int = 12000, max_tool_context_chars: int = 16000):
        self.client = client
        self.registry = registry
        self.actions = actions
        self.sessions = sessions
        self.context = context
        self.system_prompt = system_prompt
        self.max_iterations = max_iterations
        self.model_router = model_router
        self.max_context_chars = max_context_chars
        self.max_tool_context_chars = max_tool_context_chars

    def chat(self, session_id: str, user_message: str, *, persist_user: bool = True) -> dict[str, Any]:
        if not isinstance(user_message, str) or not user_message.strip():
            raise AgentError("empty_message", "Сообщение не должно быть пустым")
        if len(user_message) > 8192:
            raise AgentError("message_too_large", "Сообщение превышает 8192 символа")
        if persist_user:
            self.sessions.append_message(session_id, {"role": "user", "content": user_message.strip()})
        history = self.sessions.history_with_summary(session_id, self.max_context_chars)
        conversation = [{"role": "system", "content": self.system_prompt}] + history
        selected = self.model_router.select(user_message) if self.model_router is not None else None
        client = selected.client if selected is not None else self.client
        tool_schemas = self.registry.schemas(selected.tool_names if selected is not None else None)
        route_name = selected.route if selected is not None else "single_model"
        usage_total = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "cached_tokens": 0, "llm_calls": 0, "tool_calls": 0}
        for _iteration in range(self.max_iterations):
            assistant = client.chat(conversation, tool_schemas)
            calls = assistant.get("tool_calls") or []
            raw_usage = assistant.pop("_usage", {})
            request_metrics = assistant.pop("_request_metrics", {})
            usage_row = {
                "model": client.model, "model_route": route_name,
                "prompt_tokens": _token_count(raw_usage.get("prompt_tokens")),
                "completion_tokens": _token_count(raw_usage.get("completion_tokens")),
                "total_tokens": _token_count(raw_usage.get("total_tokens")),
                "cached_tokens": _token_count(raw_usage.get("cached_tokens")),
                "tools_count": len(tool_schemas), "tool_calls": len(calls),
                "messages_chars": _token_count(request_metrics.get("messages_chars")),
                "tool_schema_chars": _token_count(request_metrics.get("tool_schema_chars")),
                "request_id": request_metrics.get("request_id"),
            }
            self.sessions.record_llm_usage(session_id, usage_row)
            for key in ("prompt_tokens", "completion_tokens", "total_tokens", "cached_tokens"):
                usage_total[key] += usage_row[key]
            usage_total["llm_calls"] += 1
            usage_total["tool_calls"] += len(calls)
            LOG.info(
                "llm_usage model=%s route=%s prompt_tokens=%d completion_tokens=%d total_tokens=%d cached_tokens=%d session_id=%s tools_count=%d tool_calls=%d messages_chars=%d tool_schema_chars=%d",
                client.model, route_name, usage_row["prompt_tokens"], usage_row["completion_tokens"],
                usage_row["total_tokens"], usage_row["cached_tokens"], session_id,
                usage_row["tools_count"], usage_row["tool_calls"], usage_row["messages_chars"],
                usage_row["tool_schema_chars"],
            )
            stored_assistant = {
                "role": "assistant",
                "content": assistant.get("content") or "",
            }
            if assistant.get("tool_calls"):
                stored_assistant["tool_calls"] = assistant["tool_calls"]
            self.sessions.append_message(session_id, stored_assistant)
            conversation.append(stored_assistant)
            if not calls:
                result = {"ok": True, "session_id": session_id, "status": "completed", "message": assistant.get("content") or "", "usage": usage_total}
                if selected is not None:
                    result.update({"model": client.model, "model_route": selected.route})
                return result
            mutating_calls = []
            for call in calls:
                name = str(call.get("function", {}).get("name", ""))
                try:
                    if self.registry.get(name).exec_class.value == "mutating":
                        mutating_calls.append(name)
                except AgentError:
                    pass
            if mutating_calls and len(calls) > 1:
                for call in calls:
                    tool_message = {
                        "role": "tool", "tool_call_id": str(call.get("id", ""))[:128],
                        "content": json.dumps({"ok": False, "error": "parallel_mutation_denied", "message": "Mutating tool должен быть единственным tool-call в итерации"}, ensure_ascii=False),
                    }
                    self.sessions.append_message(session_id, tool_message)
                    conversation.append(tool_message)
                continue
            for call in calls:
                call_id = str(call.get("id", ""))[:128]
                function = call.get("function", {})
                name = str(function.get("name", ""))
                try:
                    arguments = json.loads(function.get("arguments") or "{}")
                    if not isinstance(arguments, dict):
                        raise ValueError("arguments is not an object")
                except (ValueError, TypeError):
                    result = {"ok": False, "error": "invalid_tool_arguments", "message": "LLM передал невалидный JSON arguments"}
                    tool_message = {"role": "tool", "tool_call_id": call_id, "content": json.dumps(result, ensure_ascii=False)}
                    self.sessions.append_message(session_id, tool_message)
                    conversation.append(tool_message)
                    continue
                try:
                    spec = self.registry.get(name)
                    if spec.exec_class.value == "mutating":
                        pending = self.actions.plan(session_id, name, arguments)
                        tool_message = {
                            "role": "tool", "tool_call_id": call_id,
                            "content": json.dumps({"ok": True, "status": "awaiting_user_confirmation", "action_id": pending["action_id"]}, ensure_ascii=False),
                        }
                        self.sessions.append_message(session_id, tool_message)
                        result = {"ok": True, "session_id": session_id, **pending, "usage": usage_total}
                        if selected is not None:
                            result.update({"model": client.model, "model_route": selected.route})
                        return result
                    result = self.registry.invoke_read_only(name, self.context, arguments)
                except AgentError as exc:
                    result = exc.to_dict()
                encoded = compact_tool_result(result, self.max_tool_context_chars)
                tool_message = {"role": "tool", "tool_call_id": call_id, "content": encoded}
                self.sessions.append_message(session_id, tool_message)
                conversation.append(tool_message)
        raise AgentError("tool_loop_limit", "Достигнут лимит итераций tool-calling")
