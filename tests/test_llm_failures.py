from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

import requests

from ai_agent.errors import AgentError
from ai_agent.llm_client import LLMClient, Orchestrator
from ai_agent.storage.sessions import SessionStore


class LLMClientFailureTests(unittest.TestCase):
    def test_success_exposes_usage_and_request_sizes_to_orchestrator(self):
        response = Mock(status_code=200)
        response.headers = {"x-request-id": "request-usage"}
        response.json.return_value = {
            "choices": [{"message": {"role": "assistant", "content": "готово"}, "finish_reason": "stop"}],
            "usage": {
                "prompt_tokens": 5842, "completion_tokens": 413, "total_tokens": 6255,
                "prompt_tokens_details": {"cached_tokens": 1200},
            },
        }
        http = Mock()
        http.post.return_value = response
        client = LLMClient("https://example.invalid/v1", "secret-api-key-value", "model", session=http)
        result = client.chat([{"role": "user", "content": "статус"}], [{"type": "function"}])
        self.assertEqual(result["_usage"]["total_tokens"], 6255)
        self.assertEqual(result["_usage"]["cached_tokens"], 1200)
        self.assertEqual(result["_request_metrics"]["tools_count"], 1)
        self.assertEqual(result["_request_metrics"]["request_id"], "request-usage")

    def test_network_failure_is_retryable_and_contains_no_secret(self):
        http = Mock()
        http.post.side_effect = requests.Timeout("upstream timeout")
        client = LLMClient("https://example.invalid/v1", "secret-api-key-value", "model", session=http)

        with self.assertRaises(AgentError) as raised:
            client.chat([], [])

        self.assertEqual(raised.exception.code, "llm_unavailable")
        self.assertTrue(raised.exception.retryable)
        self.assertNotIn("secret-api-key-value", str(raised.exception))

    def test_server_error_is_retryable_and_exposes_only_request_metadata(self):
        response = Mock(status_code=503)
        response.headers = {"x-request-id": "request-123"}
        http = Mock()
        http.post.return_value = response
        client = LLMClient("https://example.invalid/v1", "secret-api-key-value", "model", session=http)

        with self.assertRaises(AgentError) as raised:
            client.chat([], [])

        self.assertEqual(raised.exception.code, "llm_api_error")
        self.assertTrue(raised.exception.retryable)
        self.assertEqual(raised.exception.details["status"], 503)
        self.assertEqual(raised.exception.details["request_id"], "request-123")
        self.assertNotIn("secret-api-key-value", str(raised.exception))

    def test_orchestrator_failure_does_not_create_pending_action(self):
        with tempfile.TemporaryDirectory() as temporary:
            sessions = SessionStore(str(Path(temporary) / "sessions.sqlite"))
            session_id = sessions.ensure_session("llm-failure")
            client = Mock()
            client.chat.side_effect = AgentError("llm_unavailable", "upstream unavailable", retryable=True)
            actions = Mock()
            orchestrator = Orchestrator(client, Mock(), actions, sessions, None, "test prompt")

            with self.assertRaises(AgentError) as raised:
                orchestrator.chat(session_id, "проверь статус")

            self.assertEqual(raised.exception.code, "llm_unavailable")
            actions.plan.assert_not_called()
            self.assertEqual(sessions.list_actions(), [])


if __name__ == "__main__":
    unittest.main()
