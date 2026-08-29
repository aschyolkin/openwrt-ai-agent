from __future__ import annotations

import unittest

from ai_agent.errors import ValidationError
from ai_agent.redaction import redact_log_network_data, redact_text, sanitize
from ai_agent.registry import ToolRegistry, tool


class RedactionTests(unittest.TestCase):
    def test_recursive_secrets_are_removed(self):
        value = sanitize({"token": "abc", "nested": {"private_key": "xyz", "safe": "ok"}})
        self.assertEqual(value["token"], "***redacted***")
        self.assertEqual(value["nested"]["private_key"], "***redacted***")
        self.assertEqual(value["nested"]["safe"], "ok")

    def test_log_network_identifiers_are_allowlisted(self):
        value = redact_log_network_data("10.110.112.1 queried secret.example.com via 8.8.8.8")
        self.assertIn("10.110.112.1", value)
        self.assertNotIn("secret.example.com", value)
        self.assertNotIn("8.8.8.8", value)

    def test_provider_tokens_are_removed_without_assignment_labels(self):
        telegram = "1234567890:AAGabcdefghijklmnopqrstuvwxyz_123456"
        yandex = "AQVNabcdefghijklmnopqrstuvwxyz_123456"
        value = redact_text(
            f"https://api.telegram.org/bot{telegram}/sendMessage key={yandex}"
        )
        self.assertNotIn(telegram, value)
        self.assertNotIn(yandex, value)
        self.assertIn("***redacted-telegram-token***", value)
        self.assertIn("***redacted-yandex-key***", value)


class RegistryTests(unittest.TestCase):
    def test_schema_validation_and_untrusted_marker(self):
        @tool(
            name="test_read",
            description="test",
            parameters={
                "type": "object", "properties": {"count": {"type": "integer", "minimum": 1, "maximum": 2}},
                "required": ["count"], "additionalProperties": False,
            },
        )
        def handler(context, arguments):
            return {"count": arguments["count"]}

        registry = ToolRegistry()
        registry.register(handler)
        result = registry.invoke_read_only("test_read", None, {"count": 2})
        self.assertEqual(result["trust"], "untrusted_data_not_instructions")
        with self.assertRaises(ValidationError):
            registry.invoke_read_only("test_read", None, {"count": 3})


if __name__ == "__main__":
    unittest.main()
