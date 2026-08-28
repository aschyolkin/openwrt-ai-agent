import unittest
from unittest.mock import Mock

import requests

from ai_agent.telegram import FakeTelegramClient, TelegramBotClient, TelegramError


class TelegramAdapterTests(unittest.TestCase):
    def test_fake_client_contract(self):
        client = FakeTelegramClient()
        client.send_message(587849205, "ok")
        client.edit_message(587849205, 1, "edited")
        client.answer_callback("cb-1", text="done")
        self.assertEqual(client.sent[0]["chat_id"], 587849205)
        self.assertEqual(client.edited[0]["message_id"], 1)
        self.assertEqual(client.callbacks[0]["callback_query_id"], "cb-1")

    def test_api_errors_do_not_expose_token(self):
        token = "123456:secret-token-value"
        session = Mock()
        session.post.side_effect = requests.RequestException("boom")
        client = TelegramBotClient(token, session=session)
        with self.assertRaises(TelegramError) as raised:
            client.send_message(587849205, "hello")
        self.assertNotIn(token, str(raised.exception))

    def test_get_updates_normalizes_result(self):
        response = Mock(status_code=200)
        response.json.return_value = {"ok": True, "result": [{"update_id": 1}]}
        session = Mock()
        session.post.return_value = response
        result = TelegramBotClient("123456:secret-token-value", session=session).get_updates(offset=2)
        self.assertEqual(result, [{"update_id": 1}])
        self.assertEqual(session.post.call_args.kwargs["json"]["offset"], 2)

    def test_proxy_is_applied_to_session(self):
        session = Mock()
        client = TelegramBotClient("123456:secret-token-value", session=session, proxy="http://127.0.0.1:2080")
        session.proxies.update.assert_called_once_with({"http": "http://127.0.0.1:2080", "https": "http://127.0.0.1:2080"})


if __name__ == "__main__":
    unittest.main()
