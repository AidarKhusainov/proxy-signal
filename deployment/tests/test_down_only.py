"""Offline regression tests: only confirmed DOWN reaches Telegram."""
import importlib.util
import pathlib
import tempfile
import unittest
from unittest.mock import patch

path = pathlib.Path(__file__).resolve().parents[1] / "kuma" / "down-only.py"
spec = importlib.util.spec_from_file_location("kuma_down_only", path)
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)


class DownOnlyTests(unittest.TestCase):
    def body(self, status, name="Probe"):
        return {"heartbeat": {"status": status}, "monitor": {"name": name}}

    def test_alert_mode_is_explicit_and_tests_are_labeled(self):
        self.assertEqual(adapter.alert_prefix("test"), "[TEST ProxySignal]")
        self.assertEqual(adapter.alert_prefix("live"), "[ProxySignal]")
        with self.assertRaises(ValueError):
            adapter.alert_prefix("unknown")

    def test_only_new_down_notifies_and_up_rearms_without_message(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(adapter, "STATE", pathlib.Path(directory) / "state.json"), \
                patch.dict(adapter.os.environ, {"MONITOR_NAME": "Probe"}), \
                patch.object(adapter, "notify") as notify:
            adapter.process_event(self.body(1))  # initial UP
            adapter.process_event(self.body(0))  # first DOWN
            adapter.process_event(self.body(0))  # duplicate DOWN
            self.assertEqual(notify.call_count, 1)
            self.assertEqual(adapter.last_state(), "DOWN")
            adapter.process_event(self.body(1))  # silent recovery
            self.assertEqual(notify.call_count, 1)
            adapter.process_event(self.body(0))  # next real outage
            self.assertEqual(notify.call_count, 2)

    def test_notification_setup_probe_is_silent_and_does_not_touch_state(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(adapter, "STATE", pathlib.Path(directory) / "state.json"), \
                patch.dict(adapter.os.environ, {"MONITOR_NAME": "Probe"}), \
                patch.object(adapter, "notify") as notify:
            adapter.process_event({"msg": "Testing notification"})
            notify.assert_not_called()
            self.assertFalse(adapter.STATE.exists())

    def test_rejects_other_monitors_and_non_status_events(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(adapter, "STATE", pathlib.Path(directory) / "state.json"), \
                patch.dict(adapter.os.environ, {"MONITOR_NAME": "Probe"}), \
                patch.object(adapter, "notify") as notify:
            for body in (self.body(0, "Other"), self.body(True), self.body(2),
                         {"monitor": {"name": "Probe"}}):
                with self.assertRaises(ValueError):
                    adapter.process_event(body)
            notify.assert_not_called()
            self.assertFalse(adapter.STATE.exists())

    def test_failed_telegram_does_not_acknowledge_down(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(adapter, "STATE", pathlib.Path(directory) / "state.json"), \
                patch.dict(adapter.os.environ, {"MONITOR_NAME": "Probe"}), \
                patch.object(adapter, "notify", side_effect=OSError("transient")):
            with self.assertRaises(OSError):
                adapter.process_event(self.body(0))
            self.assertFalse(adapter.STATE.exists())


if __name__ == "__main__":
    unittest.main()
