"""No Docker/network required."""
import importlib.util
import pathlib
import unittest
from unittest.mock import patch
import subprocess

path = pathlib.Path(__file__).resolve().parents[1] / "watchdog.py"
spec = importlib.util.spec_from_file_location("proxy_signal_watchdog", path)
watchdog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watchdog)


class WatchdogStateTests(unittest.TestCase):
    now = 1800000000

    def healthy(self):
        return {"version": 1, "records": {
            k: {"last_status": "OK", "last_code": "egress_verified",
                "last_observed_at": self.now - 300} for k in watchdog.KEYS
        }}

    def test_fresh_eight_profiles_and_source(self):
        self.assertTrue(watchdog.validate_state(self.healthy(), self.now))

    def test_missing_profile_is_no_heartbeat(self):
        state = self.healthy()
        del state["records"]["profile/happ/p08"]
        self.assertFalse(watchdog.validate_state(state, self.now))

    def test_stale_or_future_observation_is_no_heartbeat(self):
        for delta in (watchdog.MAX_AGE_SECONDS + 1, -1):
            state = self.healthy()
            state["records"]["source/happ"]["last_observed_at"] = self.now - delta
            self.assertFalse(watchdog.validate_state(state, self.now))

    def test_stale_marker_is_no_heartbeat(self):
        state = self.healthy()
        state["records"]["profile/happ/p01"]["last_code"] = "observation_stale"
        self.assertFalse(watchdog.validate_state(state, self.now))

    def test_fresh_failed_or_unknown_is_not_a_process_outage(self):
        state = self.healthy()
        state["records"]["source/happ"]["last_status"] = "FAILED"
        state["records"]["profile/happ/p02"]["last_status"] = "UNKNOWN"
        self.assertTrue(watchdog.validate_state(state, self.now))

    def test_malformed_and_boolean_timestamps_fail_closed(self):
        state = self.healthy()
        state["records"]["source/happ"]["last_observed_at"] = True
        self.assertFalse(watchdog.validate_state(state, self.now))
        self.assertFalse(watchdog.validate_state({"version": 2, "records": {}}, self.now))


    @patch.object(watchdog.subprocess, "run")
    @patch.object(watchdog.Path, "is_file", return_value=True)
    def test_ssh_uses_pinned_host_key_and_no_remote_token(self, is_file, run):
        watchdog.ssh_ping("ger1.example.org", 52222, "kuma-push",
                          "/secure/key", "/secure/known_hosts")
        args = run.call_args.args[0]
        self.assertIn("StrictHostKeyChecking=yes", args)
        self.assertIn("ClearAllForwardings=yes", args)
        self.assertIn("UserKnownHostsFile=/secure/known_hosts", args)
        self.assertEqual(args[-2:], ["kuma-push@ger1.example.org", "heartbeat"])
        self.assertNotIn("/api/push/", " ".join(args))
        self.assertTrue(run.call_args.kwargs["check"])

    @patch.object(watchdog.subprocess, "run")
    @patch.object(watchdog.Path, "is_file", return_value=True)
    def test_ssh_error_propagates_without_fake_heartbeat(self, is_file, run):
        run.side_effect = subprocess.CalledProcessError(255, ["ssh"])
        with self.assertRaises(subprocess.CalledProcessError):
            watchdog.ssh_ping("ger1.example.org", 52222, "kuma-push",
                              "/secure/key", "/secure/known_hosts")

    @patch.object(watchdog.subprocess, "run")
    def test_ssh_rejects_invalid_target(self, run):
        with self.assertRaises(ValueError):
            watchdog.ssh_ping("-bad", 52222, "kuma-push", "/k", "/hosts")
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
