import unittest

from ai_agent.telegram import FakeTelegramClient
from ai_agent.telegram_worker import TelegramWorker, human_response


class TelegramWorkerTests(unittest.TestCase):
    def test_message_routes_to_core_with_dedicated_session(self):
        client = FakeTelegramClient()
        calls = []
        worker = TelegramWorker(client, lambda method, params: calls.append((method, params)) or {"message": "ok"}, frozenset({587849205}))
        result = worker.handle_update({"update_id": 1, "message": {"chat": {"id": 587849205}, "text": "статус"}})
        self.assertEqual(result, "message")
        self.assertEqual(calls[0][0], "chat")
        self.assertEqual(calls[0][1]["session_id"], "telegram:587849205")
        self.assertEqual(client.sent[0]["text"], "ok")

    def test_confirmation_callback_checks_chat_and_routes_core(self):
        client = FakeTelegramClient()
        calls = []
        worker = TelegramWorker(client, lambda method, params: calls.append((method, params)) or {"message": "done"}, frozenset({587849205}))
        result = worker.handle_update({"update_id": 2, "callback_query": {"id": "cb", "data": "confirm:a1:yes", "message": {"chat": {"id": 587849205}}}})
        self.assertEqual(result, "callback")
        self.assertEqual(calls[0], ("confirm", {"session_id": "telegram:587849205", "action_id": "a1", "approve": True}))
        self.assertEqual(client.callbacks[0]["callback_query_id"], "cb")

    def test_confirmation_plan_gets_buttons_and_output_is_escaped(self):
        client = FakeTelegramClient()
        worker = TelegramWorker(client, lambda method, params: {"status": "awaiting_confirmation", "action_id": "a1", "message": "<danger>"}, frozenset({587849205}))
        worker.handle_update({"update_id": 3, "message": {"chat": {"id": 587849205}, "text": "change"}})
        self.assertEqual(client.sent[0]["text"], "Подтвердите действие:\n&lt;danger&gt;.")
        self.assertIn("confirm:a1:yes", str(client.sent[0]["reply_markup"]))

    def test_verified_action_is_human_readable_and_hides_internal_json(self):
        response = {
            "ok": True, "action_id": "a1", "state": "verified",
            "apply_result": {"returncode": 1, "stdout": "technical output"},
            "verification": {"ok": True, "checks": {"package_installed": True}, "message": "Пакет coreutils-whoami установлен"},
        }
        self.assertEqual(human_response(response), "Готово. Пакет coreutils-whoami установлен.")
        self.assertNotIn("returncode", human_response(response))

    def test_cancel_and_failure_are_human_readable_without_json(self):
        self.assertEqual(human_response({"ok": True, "state": "cancelled"}), "Действие отменено.")
        self.assertEqual(
            human_response({"ok": False, "error": "internal"}),
            "Не удалось выполнить запрос. Подробности сохранены в журнале агента.",
        )


if __name__ == "__main__":
    unittest.main()
