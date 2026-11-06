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
        self.assertLess(value.index("    alerts:"), value.index("\nendpoints:"))

    def test_pull_is_exact_https_down_only(self):
        value = render.render("fin1", "123456:ABCDEFGHIJKLMNOPQRST", "-123", enable_alerts=True)
        self.assertIn("interval: 5m", value)
        self.assertIn("url: https://panel.censor-amoroso.com/", value)
        self.assertIn("'[STATUS] == 200'", value)
        self.assertNotIn("external-endpoints", value)

    def test_cdn_endpoints_are_independent_strict_and_down_only(self):
        for alerting in (False, True):
            value = render.render(
                "fin1", "123456:ABCDEFGHIJKLMNOPQRST", "-123",
                enable_alerts=alerting,
            )
            self.assertEqual(value.count("  - name: cdn-xray-public\n"), 1)
            self.assertEqual(value.count("  - name: cdn-subscriptions-public\n"), 1)
            self.assertEqual(value.count("  - name: hostland-https\n"), 1)
            for name, host in (
                ("cdn-xray-public", "cdn-swe1.censor-amoroso.com"),
                ("cdn-subscriptions-public", "sub.censor-amoroso.com"),
            ):
                section = value.split(f"  - name: {name}\n", 1)[1].split("\n  - name:", 1)[0]
                self.assertIn("group: observer", section)
                self.assertIn(f"url: https://{host}/generate_204", section)
                self.assertIn("method: GET", section)
                self.assertIn("interval: 5m", section)
                self.assertIn("timeout: 10s", section)
                self.assertIn("ignore-redirect: true", section)
                self.assertIn("'[STATUS] == 204'", section)
                self.assertNotIn("'[STATUS] == 200'", section)
                if alerting:
                    self.assertIn("failure-threshold: 2", section)
                    self.assertIn("success-threshold: 1", section)
                    self.assertIn("send-on-resolved: false", section)
                    self.assertIn("type: telegram", section)
                else:
                    self.assertNotIn("alerts:", section)
            self.assertEqual(value.count("failure-threshold: 2"), 3 if alerting else 0)

    def test_ger1_coverage_incident_is_separate_and_history_retained(self):
        config = render.render(
            "ger1", "123456:ABCDEFGHIJKLMNOPQRST", "-123", "validpush123",
            enable_alerts=True,
        )
        self.assertIn("maximum-number-of-results: 360", config)
        self.assertEqual(config.count("  - name: proxysignal-required-coverage\n"), 1)
        self.assertEqual(config.count("  - name: proxysignal-heartbeat\n"), 1)
        section = config.split("  - name: proxysignal-required-coverage\n", 1)[1].split(
            "\nendpoints:", 1
        )[0]
        self.assertIn("interval: 10m", section)
        self.assertIn("failure-threshold: 2", section)
        self.assertIn("success-threshold: 1", section)
        self.assertIn("send-on-resolved: false", section)
        self.assertIn("type: telegram", section)
        self.assertIn("Нет свежего подтверждения обязательных проверок", section)
        staging = render.render(
            "ger1", "123456:ABCDEFGHIJKLMNOPQRST", "-123", "validpush123",
        )
        self.assertIn("proxysignal-required-coverage", staging)
        self.assertNotIn("    alerts:", staging)
        self.assertNotIn("proxysignal-required-coverage", render.render(
            "fin1", "123456:ABCDEFGHIJKLMNOPQRST", "-123", enable_alerts=True
        ))

    def test_cdn_checks_are_fin1_only(self):
        ger1 = render.render(
            "ger1", "123456:ABCDEFGHIJKLMNOPQRST", "-123", "validpush123",
            enable_alerts=True,
        )
        self.assertNotIn("cdn-xray-public", ger1)
        self.assertNotIn("cdn-subscriptions-public", ger1)

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

    def test_coverage_command_is_scoped_and_backward_compatible(self):
        for command, urls in (
            ("heartbeat", [receiver.PUSH_URL]),
            ("heartbeat coverage=ok", [receiver.PUSH_URL, receiver.COVERAGE_OK_URL]),
            ("heartbeat coverage=fail", [receiver.PUSH_URL, receiver.COVERAGE_FAIL_URL]),
        ):
            with mock.patch.dict("os.environ", {"SSH_ORIGINAL_COMMAND": command}, clear=True), \\
                 mock.patch.object(receiver.Path, "read_text", return_value="validtoken123"), \\
                 mock.patch.object(receiver, "send") as send:
                self.assertEqual(receiver.main(), 0)
                self.assertEqual([call.args[1] if len(call.args) > 1 else receiver.PUSH_URL
                                  for call in send.call_args_list], urls)
        with mock.patch.dict("os.environ", {"SSH_ORIGINAL_COMMAND": "heartbeat coverage=ok; id"}, clear=True), \\
             mock.patch.object(receiver, "send") as send:
            self.assertEqual(receiver.main(), 1)
            send.assert_not_called()

    def test_coverage_push_rejects_unlisted_destinations(self):
        with self.assertRaises(ValueError):
            receiver.send("validtoken123", "http://127.0.0.1:3002/other")

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
