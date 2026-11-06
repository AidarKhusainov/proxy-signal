"""Issue #160: strict status transport and independent external incident endpoints."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1] / "gatus"


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / name)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


renderer = load("render-config.py")
receiver = load("ssh-push-receiver.py")


class PanelObserverContract(unittest.TestCase):
    MASTER = "validtoken123"

    def report(self, group, failed=()):
        names = receiver.PANEL_FAST if group == "fast" else receiver.PANEL_AUDIT
        return "panel-report-v1 " + group + " " + ",".join(
            name + "=" + ("0" if name in failed else "1") for name in names
        )

    def test_rendered_external_endpoints_independent_and_stale_aware(self):
        config = renderer.render(
            "ger1", "123456:ABCDEFGHIJKLMNOPQRST", "-123", self.MASTER,
            enable_alerts=True, panel_monitor=True, panel_alerts=True,
        )
        self.assertEqual(config.count("external-endpoints:"), 1)
        self.assertEqual(config.count("endpoints:"), 2)
        for group, names, interval in (
            ("fast", receiver.PANEL_FAST, "12m"),
            ("audit", receiver.PANEL_AUDIT, "4h"),
        ):
            for name in names:
                marker = f"  - name: {group}-{name}\n"
                self.assertEqual(config.count(marker), 1, marker)
                section = config.split(marker, 1)[1].split("\n  - name:", 1)[0]
                token = renderer.panel_token(self.MASTER, group, name)
                self.assertEqual(token, receiver.panel_token(self.MASTER, group, name))
                self.assertIn(f'token: "{token}"', section)
                self.assertIn(f"interval: {interval}", section)
                self.assertIn("failure-threshold: " + ("2" if group == "fast" else "1"), section)
                self.assertIn("send-on-resolved: false", section)
        self.assertNotIn(self.MASTER, config.split("  - name: fast-panel", 1)[1])
        self.assertNotIn("panel-fast", renderer.render(
            "fin1", "123456:ABCDEFGHIJKLMNOPQRST", "-123", enable_alerts=True,
        ))
        self.assertNotIn("panel-fast", renderer.render(
            "ger1", "123456:ABCDEFGHIJKLMNOPQRST", "-123", self.MASTER,
            enable_alerts=True,
        ))

    def test_new_alerts_can_stage_safely_without_silencing_existing_heartbeat(self):
        config = renderer.render(
            "ger1", "123456:ABCDEFGHIJKLMNOPQRST", "-123", self.MASTER,
            enable_alerts=True, panel_monitor=True,
        )
        self.assertIn("name: fast-panel", config)
        self.assertIn("description: ProxySignal", config)
        section = config.split("  - name: fast-panel\\n", 1)[1].split("\\n  - name:", 1)[0]
        self.assertNotIn("    alerts:", section)
        self.assertEqual(config.count("    alerts:"), 1)

    def test_complete_status_report_and_failures_not_scheduler_failures(self):
        command = self.report("fast", {"postgres", "node_fin1"})
        group, results = receiver.parse_report(command)
        self.assertEqual(group, "fast")
        self.assertFalse(results["postgres"])
        self.assertFalse(results["node_fin1"])
        self.assertTrue(results["fast_tick"])
        self.assertEqual(len(results), len(receiver.PANEL_FAST))
        self.assertEqual(set(receiver.parse_report(self.report("audit"))[1]), set(receiver.PANEL_AUDIT))

    def test_rejects_ambiguous_or_untrusted_reports(self):
        command = self.report("fast")
        for bad in (
            None, "", "heartbeat", "sh", "panel-report-v1 fast",
            command + ",other=1", command.replace("panel=1", "panel=1,panel=1"),
            command.replace("panel=1,", ""), command.replace("panel=1", "panel=yes"),
            command.replace("fast_tick=1", "fast_tick=0"),
            command.replace("fast_tick=1", "fast_tick=1;id"),
            "panel-report-v1 audit " + command.split(" ", 2)[2],
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    receiver.parse_report(bad)

    def test_existing_proxy_heartbeat_preserved(self):
        self.assertIn("proxysignal-heartbeat", receiver.PUSH_URL)
        with patch.dict(receiver.os.environ, {"SSH_ORIGINAL_COMMAND": "heartbeat"}, clear=True), \
                patch.object(receiver.Path, "read_text", return_value=self.MASTER), \
                patch.object(receiver, "send") as send:
            self.assertEqual(receiver.main(), 0)
            send.assert_called_once_with(self.MASTER)

    def test_failure_is_forwarded_but_no_untrusted_urls(self):
        with patch.dict(receiver.os.environ, {"SSH_ORIGINAL_COMMAND": self.report("fast", {"auth"})}, clear=True), \
                patch.object(receiver.Path, "read_text", return_value=self.MASTER), \
                patch.object(receiver, "send") as send:
            self.assertEqual(receiver.main(), 0)
        self.assertEqual(send.call_count, len(receiver.PANEL_FAST))
        calls = {call.kwargs["url"]: call.kwargs for call in send.call_args_list}
        self.assertIn(receiver.PANEL_URL + "fast-auth/external?success=false", calls)
        self.assertIn(receiver.PANEL_URL + "fast-fast_tick/external?success=true", calls)
        self.assertTrue(all(url.startswith(receiver.PANEL_URL) for url in calls))

    def test_invalid_report_sends_nothing(self):
        with patch.dict(receiver.os.environ, {"SSH_ORIGINAL_COMMAND": "panel-report-v1 fast panel=1"}, clear=True), \
                patch.object(receiver.Path, "read_text") as secret, \
                patch.object(receiver, "send") as send:
            self.assertEqual(receiver.main(), 1)
        secret.assert_not_called()
        send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
