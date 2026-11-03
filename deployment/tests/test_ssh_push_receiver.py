"""Offline tests for the ger1 forced-command receiver."""
import importlib.util
import pathlib
import unittest
from unittest.mock import patch

path = pathlib.Path(__file__).resolve().parents[1] / "kuma" / "ssh-push-receiver.py"
spec = importlib.util.spec_from_file_location("kuma_ssh_receiver", path)
receiver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receiver)


class TestReceiver(unittest.TestCase):
    def test_token_must_be_url_safe(self):
        for token in ("", "../hello", "token?status=down", "bad\nheader", "short"):
            with self.assertRaises(ValueError):
                receiver.send(token)

    @patch.object(receiver.urllib.request, "build_opener")
    def test_push_stays_on_localhost_and_does_not_use_proxy(self, opener):
        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        opener.return_value.open.return_value = Response()
        receiver.send("Abcdefgh123456")
        arguments = opener.return_value.open.call_args.args[0]
        self.assertEqual(
            arguments.full_url,
            "http://127.0.0.1:3001/api/push/Abcdefgh123456?status=up&msg=ProxySignal_heartbeat",
        )
        self.assertEqual(arguments.get_method(), "GET")

    @patch.object(receiver.urllib.request, "build_opener")
    def test_unacknowledged_push_fails(self, opener):
        class Response:
            status = 500

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        opener.return_value.open.return_value = Response()
        with self.assertRaises(ValueError):
            receiver.send("Abcdefgh123456")


if __name__ == "__main__":
    unittest.main()
