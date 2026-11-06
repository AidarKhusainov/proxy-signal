"""No-network regression tests for durable Gatus DOWN-only delivery."""
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock
import urllib.error

FILE = Path(__file__).resolve().parents[1] / "gatus" / "durable-down.py"
spec = importlib.util.spec_from_file_location("gatus_durable_down", FILE)
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)


def event(state="TRIGGERED", group="observer", name="cdn-xray-public"):
    return {"state": state, "group": group, "name": name}


class DurableDownTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "alerts.db"
        self.db = relay.connect(self.path)
        self.addCleanup(self.db.close)

    def count(self, query):
        return self.db.execute(query).fetchone()[0]

    def test_utc_down_only_rearmed_on_silent_recovery(self):
        relay.accept_event(self.db, "fin1", event(), now=123)
        relay.accept_event(self.db, "fin1", event(), now=124)
        self.assertEqual(self.count("SELECT COUNT(*) FROM outbox"), 1)
        self.assertEqual(self.count("SELECT active FROM targets"), 1)
        relay.accept_event(self.db, "fin1", event("RESOLVED"), now=125)
        self.assertEqual(self.count("SELECT COUNT(*) FROM outbox"), 1)
        self.assertEqual(self.count("SELECT active FROM targets"), 0)
        relay.accept_event(self.db, "fin1", event(), now=126)
        self.assertEqual(self.count("SELECT COUNT(*) FROM outbox"), 2)

    def test_restart_keeps_incident_dedup_and_pending_send(self):
        relay.accept_event(self.db, "fin1", event(), now=123)
        self.db.close()
        self.db = relay.connect(self.path)
        relay.accept_event(self.db, "fin1", event(), now=125)
        self.assertEqual(self.count("SELECT COUNT(*) FROM outbox"), 1)
        sender = mock.Mock(side_effect=OSError("network down"))
        self.assertFalse(relay.send_one(self.db, "fin1", sender))
        self.assertEqual(self.count("SELECT COUNT(*) FROM outbox WHERE delivered_at IS NULL"), 1)
        sender = mock.Mock()
        self.assertTrue(relay.send_one(self.db, "fin1", sender))
        self.assertFalse(relay.send_one(self.db, "fin1", sender))
        sender.assert_called_once_with(
            "fin1", "observer_cdn-xray-public", 123, True
        )

    def test_rejects_unknown_or_unsafe_webhook_without_mutation(self):
        cases = [
            event(name="evil-name"), event(state="UNKNOWN"),
            event(group="other"), {"state": "TRIGGERED", "group": "observer"},
            {**event(), "token": "secret"}, "TRIGGERED", event(name=True),
            event(name="cdn-xray-public; rm /"),
            event(group="panel", name="fast-node-foreign"),
        ]
        for sample in cases:
            with self.subTest(sample=sample):
                with self.assertRaises((ValueError, TypeError)):
                    relay.accept_event(self.db, "fin1", sample)
        self.assertEqual(self.count("SELECT COUNT(*) FROM outbox"), 0)

    def test_full_queue_rejects_new_incident_without_ack(self):
        with self.db:
            self.db.executemany(
                "INSERT INTO outbox(key,created_at) VALUES (?,?)",
                (("observer_hostland-https", i) for i in range(relay.MAX_QUEUE))
            )
        with self.assertRaises(ValueError):
            relay.accept_event(self.db, "fin1", event())
        self.assertEqual(self.count("SELECT COUNT(*) FROM targets"), 0)

    def test_russian_message_and_acknowledgement_without_leaking_credentials(self):
        root = Path(self.directory.name)
        token_path, chat_path = root / "token", root / "chat"
        token_path.write_text("123456:ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")
        chat_path.write_text("-12345")
        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, n): return b'{"ok":true,"result":{"message_id":1}}'
        class Opener:
            def __init__(self): self.messages = []
            def open(self, req, timeout):
                self.messages.append(json.loads(req.data))
                self.assert_url = req.full_url
                assert timeout == 12
                return Response()
        opener = Opener()
        with mock.patch.object(relay, "TOKEN_FILE", token_path), \
             mock.patch.object(relay, "CHAT_FILE", chat_path):
            relay.send_telegram(
                "ger1", "observer_proxysignal-required-coverage",
                1794000000, False, opener=opener
            )
        self.assertEqual(len(opener.messages), 1)
        body = opener.messages[0]["text"]
        self.assertIn("DOWN", body)
        self.assertIn("Проверка:", body)
        self.assertIn("Обнаружено:", body)
        self.assertIn("восстановлен", body)
        self.assertNotIn("123456:", body)
        self.assertNotIn("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456", body)
        self.assertTrue(opener.assert_url.startswith("https://api.telegram.org/bot"))

    def test_http_success_without_telegram_ok_is_not_acknowledged(self):
        root = Path(self.directory.name)
        token_path, chat_path = root / "token", root / "chat"
        token_path.write_text("123456:ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")
        chat_path.write_text("-12345")
        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, n): return b'{"ok":false}'
        class Opener:
            def open(self, req, timeout): return Response()
        with mock.patch.object(relay, "TOKEN_FILE", token_path), \
             mock.patch.object(relay, "CHAT_FILE", chat_path):
            with self.assertRaises(ValueError):
                relay.send_telegram(
                    "fin1", "observer_cdn-xray-public", 1794000000, True,
                    opener=Opener(),
                )

    def test_reconcile_lost_trigger_and_recovery(self):
        from datetime import datetime, timezone
        now = 1794000000
        key = "observer_cdn-xray-public"
        stamp = lambda seconds: datetime.fromtimestamp(
            now + seconds, timezone.utc).isoformat().replace("+00:00", "Z")
        data = [{"key": key, "results": [
            {"timestamp": stamp(-90), "success": False},
            {"timestamp": stamp(-60), "success": False},
        ]}]
        relay.reconcile_results(self.db, "fin1", data, now)
        relay.reconcile_results(self.db, "fin1", data, now)
        self.assertEqual(self.count("SELECT COUNT(*) FROM outbox"), 1)
        data[0]["results"].append({"timestamp": stamp(-30), "success": True})
        relay.reconcile_results(self.db, "fin1", data, now)
        self.assertEqual(self.count("SELECT active FROM targets"), 0)
        data[0]["results"] = [
            {"timestamp": stamp(-30), "success": True},
            {"timestamp": stamp(-20), "success": False},
            {"timestamp": stamp(-10), "success": False},
        ]
        relay.reconcile_results(self.db, "fin1", data, now)
        self.assertEqual(self.count("SELECT COUNT(*) FROM outbox"), 2)

    def test_panel_160_keys_are_explicitly_allowlisted(self):
        relay.accept_event(self.db, "ger1",
            event(group="panel", name="fast-node-swe1"), now=123)
        relay.accept_event(self.db, "ger1",
            event(group="panel", name="audit-backupable-desired"), now=124)
        self.assertEqual(self.count("SELECT COUNT(*) FROM outbox"), 2)
        with self.assertRaises(ValueError):
            relay.accept_event(self.db, "fin1", event(group="panel", name="fast-panel"))


if __name__ == "__main__":
    unittest.main()
