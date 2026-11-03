"""Offline regression checks for the isolated Gatus replacement."""
import importlib.util
from pathlib import Path
from unittest import TestCase, mock

BASE = Path(__file__).resolve().parents[1] / "gatus"


def load(filename):
    spec = importlib.util.spec_from_file_location(filename.replace("-", "_"), BASE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


render = load("render-config.py")
receiver = load("ssh-push-receiver.py")


class GatusConfigTests(TestCase):
    def test_staging_has_no_live_alerts(self):
        for role in ("ger1", "fin1"):
            result = render.render(role, "123456:ABCDEFGHIJKLMNOPQRST", "-123", "validpush123")
            self.assertNotIn("    alerts:", result)

    def test_push_is_authenticated_and_down_only(self):
        value = render.render("ger1", "123456:ABCDEFGHIJKLMNOPQRST", "-123", "validpush123", enable_alerts=True)
        self.assertIn('token: "validpush123"', value)
        self.assertIn("interval: 10m", value)
        self.assertIn("send-on-resolved: false", value)
        self.assertIn("hostland-https-secondary", value)
        self.assertLess(value.index("    alerts:"), value.index("endpoints:"))

    def test_pull_is_exact_https_down_only(self):
        value = render.render("fin1", "123456:ABCDEFGHIJKLMNOPQRST", "-123", enable_alerts=True)
        self.assertIn("interval: 5m", value)
        self.assertIn("url: https://panel.censor-amoroso.com/", value)
        self.assertIn("'[STATUS] == 200'", value)
        self.assertNotIn("external-endpoints", value)

    def test_rejects_invalid_roles_and_missing_push(self):
        with self.assertRaises(ValueError):
            render.render("other", "token", "chat")
        with self.assertRaises(ValueError):
            render.render("ger1", "token", "chat")

    def test_rejects_excessively_large_or_malformed_secrets(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secret"
            path.write_text("x" * 5000)
            with self.assertRaises(ValueError):
                render.read_secret(path, r".+")
            path.write_text("bad token")
            with self.assertRaises(ValueError):
                render.read_secret(path, r"[A-Za-z0-9_-]+")


class ReceiverTests(TestCase):
    def test_rejects_arbitrary_ssh_command(self):
        with mock.patch.dict("os.environ", {"SSH_ORIGINAL_COMMAND": "sh"}, clear=True):
            self.assertEqual(receiver.main(), 1)

    def test_invalid_token_does_not_reach_network(self):
        with self.assertRaises(ValueError):
            receiver.send("bad token")

    def test_push_targets_only_fixed_loopback_with_bearer(self):
        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *args): pass

        class Opener:
            def open(self, request, timeout):
                assert request.full_url == receiver.PUSH_URL
                assert request.get_method() == "POST"
                assert request.get_header("Authorization") == "Bearer validtoken123"
                assert timeout == 8
                return Response()

        with mock.patch.object(receiver.urllib.request, "build_opener", return_value=Opener()):
            receiver.send("validtoken123")
