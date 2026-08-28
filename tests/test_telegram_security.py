import unittest

from ai_agent.telegram_security import TelegramUpdateGuard, escape_html, split_message


class TelegramSecurityTests(unittest.TestCase):
    def test_allowlist_deduplicates_and_assigns_session(self):
        guard = TelegramUpdateGuard(frozenset({587849205}))
        update = {"update_id": 1, "message": {"chat": {"id": 587849205}, "text": "status"}}
        self.assertEqual(guard.accept(update), (True, "accepted", 587849205))
        self.assertEqual(guard.accept(update)[1], "duplicate_update")
        self.assertEqual(guard.session_id(587849205), "telegram:587849205")

    def test_rejects_unknown_chat_and_oversized_message(self):
        guard = TelegramUpdateGuard(frozenset({587849205}), max_message_length=4)
        unknown = {"update_id": 1, "message": {"chat": {"id": 99}, "text": "hi"}}
        oversized = {"update_id": 2, "message": {"chat": {"id": 587849205}, "text": "12345"}}
        self.assertEqual(guard.accept(unknown)[1], "chat_not_allowed")
        self.assertEqual(guard.accept(oversized)[1], "message_limit")

    def test_rate_limit_and_callback_chat_extraction(self):
        now = [100.0]
        guard = TelegramUpdateGuard(frozenset({587849205}), rate_limit=1, clock=lambda: now[0])
        first = {"update_id": 1, "message": {"chat": {"id": 587849205}, "text": "a"}}
        callback = {"update_id": 2, "callback_query": {"message": {"chat": {"id": 587849205}}}}
        self.assertTrue(guard.accept(first)[0])
        self.assertEqual(guard.accept(callback)[1], "rate_limited")
        now[0] += 61
        callback["update_id"] = 3
        self.assertTrue(guard.accept(callback)[0])

    def test_formatting_helpers(self):
        self.assertEqual(escape_html("<x> & \"q\""), "&lt;x&gt; &amp; \"q\"")
        self.assertEqual(split_message("abcdef", 2), ["ab", "cd", "ef"])


if __name__ == "__main__":
    unittest.main()
