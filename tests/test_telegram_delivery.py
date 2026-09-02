import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from ai_agent.telegram import FakeTelegramClient, TelegramBotClient, TelegramError
from ai_agent.telegram_main import _read_core_response, _retry_delay
from ai_agent.telegram_state import (
    TelegramOffsetStore,
    read_telegram_health,
    write_telegram_health,
)
from ai_agent.telegram_worker import TelegramWorker


CHAT_ID = 587849205


def message_update(update_id: int, text: str = "status") -> dict:
    return {
        "update_id": update_id,
        "message": {"chat": {"id": CHAT_ID}, "text": text},
    }


class ChunkSocket:
    def __init__(self, chunks):
        self.chunks = list(chunks)

    def recv(self, _size):
        return self.chunks.pop(0) if self.chunks else b""


class FailingSendClient(FakeTelegramClient):
    def __init__(self, error):
        super().__init__()
        self.error = error
        self.attempts = 0

    def send_message(self, chat_id, text, **kwargs):
        self.attempts += 1
        raise self.error


class FailOnAttemptClient(FakeTelegramClient):
    def __init__(self, fail_on: int):
        super().__init__()
        self.fail_on = fail_on
        self.attempts = 0

    def send_message(self, chat_id, text, **kwargs):
        self.attempts += 1
        if self.attempts == self.fail_on:
            raise TelegramError("temporary transport failure")
        return super().send_message(chat_id, text, **kwargs)


class RejectHtmlOnceClient(FakeTelegramClient):
    def __init__(self):
        super().__init__()
        self.attempts = 0

    def send_message(self, chat_id, text, **kwargs):
        self.attempts += 1
        if self.attempts == 1:
            raise TelegramError("bad HTML", status_code=400)
        return super().send_message(chat_id, text, **kwargs)


class TelegramDeliveryTests(unittest.TestCase):
    def test_core_response_is_collected_across_multiple_recv_calls(self):
        client = ChunkSocket([b'{"ok":tr', b'ue,"message":"done"}', b"\nignored"])
        self.assertEqual(_read_core_response(client), {"ok": True, "message": "done"})

    def test_core_response_limit_and_shape_are_enforced(self):
        with self.assertRaisesRegex(ValueError, "exceeds limit"):
            _read_core_response(ChunkSocket([b"123456"]), maximum=5)
        with self.assertRaisesRegex(ValueError, "not an object"):
            _read_core_response(ChunkSocket([b"[]\n"]))

    def test_offset_is_atomic_private_and_survives_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "offset.json"
            store = TelegramOffsetStore(path)
            self.assertIsNone(store.load())
            store.initialize()
            self.assertTrue(path.exists())
            self.assertEqual(store.load_state(), {"offset": None, "pending": None})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            store.save(42)
            self.assertEqual(store.load(), 42)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_worker_commits_only_after_success_and_retries_failed_update(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "offset.json")
            client = FakeTelegramClient(updates=[message_update(10), message_update(11)])
            attempts = []

            def core(method, params):
                attempts.append((method, params["message"]))
                if len(attempts) == 1:
                    raise ConnectionError("core temporarily unavailable")
                return {"message": "ok"}

            worker = TelegramWorker(client, core, frozenset({CHAT_ID}), offset_path=path)
            with self.assertRaises(ConnectionError):
                worker.run_once()
            self.assertIsNone(worker.offset)
            self.assertIsNone(TelegramOffsetStore(path).load())

            client.updates = [message_update(10), message_update(11)]
            self.assertEqual(worker.run_once(), 2)
            self.assertEqual(worker.offset, 12)
            self.assertEqual(TelegramOffsetStore(path).load(), 12)
            self.assertEqual([text for _, text in attempts], ["status", "status", "status"])

            restarted_client = FakeTelegramClient(
                updates=[message_update(11), message_update(12)]
            )
            restarted_calls = []
            restarted = TelegramWorker(
                restarted_client,
                lambda method, params: restarted_calls.append(params["message"]) or {"message": "ok"},
                frozenset({CHAT_ID}),
                offset_path=path,
            )
            self.assertEqual(restarted.offset, 12)
            self.assertEqual(restarted.run_once(), 1)
            self.assertEqual(restarted.offset, 13)
            self.assertEqual(restarted_calls, ["status"])

    def test_prepared_core_response_survives_delivery_failure_and_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "offset.json")
            first_client = FailingSendClient(TelegramError("temporary transport failure"))
            first_client.updates = [message_update(20)]
            core_calls = []
            first_worker = TelegramWorker(
                first_client,
                lambda method, params: core_calls.append((method, params)) or {
                    "message": "cached answer",
                },
                frozenset({CHAT_ID}),
                offset_path=path,
            )
            with self.assertRaises(TelegramError):
                first_worker.run_once()
            state = TelegramOffsetStore(path).load_state()
            self.assertIsNone(state["offset"])
            self.assertEqual(state["pending"]["update_id"], 20)
            self.assertEqual(len(core_calls), 1)

            restarted_client = FakeTelegramClient(updates=[message_update(20)])
            restarted_worker = TelegramWorker(
                restarted_client,
                lambda *_: self.fail("Core/LLM must not be called twice"),
                frozenset({CHAT_ID}),
                offset_path=path,
            )
            self.assertEqual(restarted_worker.run_once(), 1)
            self.assertEqual(restarted_client.sent[0]["text"], "cached answer")
            state = TelegramOffsetStore(path).load_state()
            self.assertEqual(state["offset"], 21)
            self.assertIsNone(state["pending"])

    def test_long_delivery_resumes_after_last_persisted_chunk(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "offset.json")
            first_client = FailOnAttemptClient(fail_on=2)
            first_client.updates = [message_update(30)]
            core_calls = []
            first_worker = TelegramWorker(
                first_client,
                lambda method, params: core_calls.append((method, params)) or {
                    "message": "x" * 9000,
                },
                frozenset({CHAT_ID}),
                offset_path=path,
            )
            with self.assertRaises(TelegramError):
                first_worker.run_once()
            self.assertEqual(len(first_client.sent), 1)
            state = TelegramOffsetStore(path).load_state()
            checkpoints = state["pending"]["deliveries"]
            self.assertEqual(list(checkpoints.values()), [1])

            restarted_client = FakeTelegramClient(updates=[message_update(30)])
            restarted_worker = TelegramWorker(
                restarted_client,
                lambda *_: self.fail("Core/LLM must not be called twice"),
                frozenset({CHAT_ID}),
                offset_path=path,
            )
            self.assertEqual(restarted_worker.run_once(), 1)
            self.assertEqual(len(restarted_client.sent), 2)
            delivered = first_client.sent + restarted_client.sent
            self.assertEqual(sum(len(item["text"]) for item in delivered), 9000)
            self.assertTrue(all(len(item["text"]) <= 4096 for item in delivered))
            self.assertEqual(len(core_calls), 1)
            state = TelegramOffsetStore(path).load_state()
            self.assertEqual(state["offset"], 31)

            self.assertIsNone(state["pending"])
    def test_second_callback_message_failure_does_not_duplicate_first_after_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "offset.json")
            update = {
                "update_id": 31,
                "callback_query": {
                    "id": "cb", "data": "confirm:a1:yes",
                    "message": {"chat": {"id": CHAT_ID}},
                },
            }
            response = {
                "ok": True, "state": "verified", "message": "first",
                "follow_up": {"ok": True, "status": "completed", "message": "second"},
            }
            first_client = FailOnAttemptClient(fail_on=2)
            first_client.updates = [update]
            core_calls = []
            first_worker = TelegramWorker(
                first_client,
                lambda method, params: core_calls.append((method, params)) or response,
                frozenset({CHAT_ID}), offset_path=path,
            )
            with self.assertRaises(TelegramError):
                first_worker.run_once()
            self.assertEqual([item["text"] for item in first_client.sent], ["Готово. first."])

            restarted_client = FakeTelegramClient(updates=[update])
            restarted_worker = TelegramWorker(
                restarted_client,
                lambda *_: self.fail("Core confirmation must not be repeated"),
                frozenset({CHAT_ID}), offset_path=path,
            )

            self.assertEqual(restarted_worker.run_once(), 1)
            self.assertEqual([item["text"] for item in restarted_client.sent], ["second"])
            self.assertEqual(len(core_calls), 1)

            state = TelegramOffsetStore(path).load_state()
            self.assertEqual(state["offset"], 32)
            self.assertIsNone(state["pending"])

    def test_transport_error_does_not_trigger_unsafe_plain_resend(self):
        client = FailingSendClient(TelegramError("unavailable"))
        worker = TelegramWorker(client, lambda *_: {}, frozenset({CHAT_ID}))
        with self.assertRaises(TelegramError):
            worker._send(CHAT_ID, "**hello**")
        self.assertEqual(client.attempts, 1)

    def test_definitive_html_rejection_falls_back_to_plain_text(self):
        client = RejectHtmlOnceClient()
        worker = TelegramWorker(client, lambda *_: {}, frozenset({CHAT_ID}))
        worker._send(CHAT_ID, "**hello**")
        self.assertEqual(client.attempts, 2)
        self.assertEqual(client.sent[0]["text"], "hello")
        self.assertNotIn("parse_mode", client.sent[0])

    def test_long_message_is_split_within_telegram_limit(self):
        client = FakeTelegramClient()
        worker = TelegramWorker(client, lambda *_: {}, frozenset({CHAT_ID}))
        worker._send(CHAT_ID, "x" * 9000)
        self.assertGreater(len(client.sent), 2)
        self.assertTrue(all(len(item["text"]) <= 4096 for item in client.sent))

    def test_retry_after_and_exponential_backoff_are_bounded(self):
        self.assertEqual(
            _retry_delay(TelegramError("rate limited", retry_after=17), 1),
            17,
        )
        self.assertEqual(_retry_delay(RuntimeError("temporary"), 8), 8)
        self.assertEqual(_retry_delay(RuntimeError("temporary"), 500), 60)

    def test_rate_limit_response_exposes_safe_retry_delay(self):
        response = Mock(status_code=429)
        response.json.return_value = {
            "ok": False,
            "description": "Too Many Requests",
            "parameters": {"retry_after": 23},
        }
        session = Mock()
        session.post.return_value = response
        client = TelegramBotClient(
            "1234567890:AAGabcdefghijklmnopqrstuvwxyz_123456",
            timeout=5,
            session=session,
        )
        with self.assertRaises(TelegramError) as raised:
            client.get_updates(timeout=50)
        self.assertEqual(raised.exception.status_code, 429)
        self.assertEqual(raised.exception.retry_after, 23)
        self.assertEqual(session.post.call_args.kwargs["timeout"], 60)

    def test_health_is_filtered_and_becomes_stale(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "health.json"
            write_telegram_health(path, {
                "status": "ready",
                "offset": 7,
                "last_poll_at": 100,
                "secret": "must-not-be-written",
            })
            ready = read_telegram_health(path, now=120)
            self.assertEqual(ready["status"], "ready")
            self.assertNotIn("secret", ready)
            self.assertEqual(read_telegram_health(path, now=191)["status"], "stale")

    def test_malformed_updates_are_not_silently_treated_as_empty(self):
        response = Mock(status_code=200)
        response.json.return_value = {"ok": True, "result": {"update_id": 1}}
        session = Mock()
        session.post.return_value = response
        client = TelegramBotClient(
            "1234567890:AAGabcdefghijklmnopqrstuvwxyz_123456",
            session=session,
        )
        with self.assertRaisesRegex(TelegramError, "malformed updates"):
            client.get_updates()


if __name__ == "__main__":
    unittest.main()
