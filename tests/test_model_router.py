import unittest
from unittest.mock import Mock

from ai_agent.model_router import ModelRouter, complex_read_only_tools_for, read_only_tools_for


class ModelRouterTests(unittest.TestCase):
    def setUp(self):
        self.simple = Mock(model="gpt-oss-20b")
        self.complex = Mock(model="deepseek-v4-flash")
        self.router = ModelRouter(self.simple, self.complex)

    def test_known_read_only_uses_20b(self):
        for message in ("покажи правила файрвола", "проверь работу телеграм", "какая температура CPU?", "/start"):
            with self.subTest(message=message):
                route = self.router.select(message)
                self.assertIs(route.client, self.simple)
                self.assertEqual(route.route, "simple_read_only")

    def test_mutation_always_uses_deepseek(self):
        for message in ("перезапусти netshift", "открой порт 8443", "добавь github.com в main", "проверь и перезапусти Telegram"):
            with self.subTest(message=message):
                route = self.router.select(message)
                self.assertIs(route.client, self.complex)
                self.assertEqual(route.route, "complex")
                self.assertIsNone(route.tool_names)

    def test_unknown_long_and_multiline_use_deepseek(self):
        self.assertIs(self.router.select("разберись почему всё странно").client, self.complex)
        self.assertIs(self.router.select("объясни логику отсутствия соединения сервиса").client, self.complex)
        self.assertIs(self.router.select("покажи статус\nи объясни причины").client, self.complex)
        self.assertIs(self.router.select("проверь " + "x" * 500).client, self.complex)

    def test_simple_topics_get_only_small_relevant_read_only_sets(self):
        route = self.router.select("покажи состояние сетевых интерфейсов")
        self.assertEqual(route.route, "simple_read_only")
        self.assertLessEqual(len(route.tool_names), 5)
        self.assertIn("net_interfaces_status", route.tool_names)
        self.assertNotIn("sys_service_control", route.tool_names)
        telegram = read_only_tools_for("проверь работу телеграм")
        self.assertIn("netshift_service_health", telegram)
        self.assertIn("netshift_check_domain_routing", telegram)

    def test_complex_read_only_uses_small_topic_specific_set(self):
        route = self.router.select("проанализируй, почему Telegram иногда теряет соединение")
        self.assertEqual(route.route, "complex_read_only")
        self.assertLessEqual(len(route.tool_names), 8)
        self.assertIn("netshift_service_health", route.tool_names)
        self.assertIn("sys_logread", route.tool_names)
        self.assertNotIn("netshift_reload", route.tool_names)
        self.assertNotIn("sys_service_control", route.tool_names)

    def test_unknown_complex_keeps_full_tools_for_safety(self):
        route = self.router.select("неизвестное действие со странным объектом")
        self.assertEqual(route.route, "complex")
        self.assertIsNone(route.tool_names)
        self.assertLessEqual(len(complex_read_only_tools_for("разберись почему всё странно")), 8)


if __name__ == "__main__":
    unittest.main()
