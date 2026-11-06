"""Restricted Gatus status export contains no secrets or raw failure diagnostics."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

path = Path(__file__).resolve().parents[1] / "gatus" / "export-status.py"
spec = importlib.util.spec_from_file_location("gatus_status_export", path)
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)


class ExportTests(unittest.TestCase):
    def test_allowlist_and_redaction(self):
        result = exporter.sanitized([
            {
                "key": "observer_proxysignal-required-coverage",
                "results": [{
                    "timestamp": "2026-11-06T12:00:00Z", "success": False,
                    "errors": ["private://secret?token=x"], "url": "private://secret",
                    "status": 500,
                }],
                "events": [{"timestamp": "2026-11-06T12:00:00Z", "type": "UNHEALTHY"}],
                "token": "private-token",
            },
            {"key": "observer_unrelated", "results": [
                {"timestamp": "2026-11-06T12:00:00Z", "success": True}
            ]},
        ], "ger1")
        self.assertEqual(result, [{"key": "observer_proxysignal-required-coverage",
                                   "results": [{"timestamp": "2026-11-06T12:00:00Z",
                                                "success": False}]}])
        self.assertNotIn("secret", json.dumps(result))
        self.assertNotIn("token", json.dumps(result))
        self.assertNotIn("url", json.dumps(result))

    def test_panel_160_observer_is_included_without_secret_diagnostics(self):
        self.assertEqual(len(exporter.KEYS["ger1"]), 24)
        sanitized = exporter.sanitized([
            {"key": "panel_fast-node-swe1",
             "results": [{"timestamp": "2026-11-06T12:00:00Z",
                          "success": False, "errors": ["private-token"],
                          "url": "https://private.example.org"}]},
            {"key": "panel_audit-audit-tick",
             "results": [{"timestamp": "2026-11-06T11:00:00Z",
                          "success": True}]},
        ], "ger1")
        self.assertEqual(len(sanitized), 2)
        self.assertNotIn("private-token", json.dumps(sanitized))
        self.assertNotIn("private.example.org", json.dumps(sanitized))
        with self.assertRaises(ValueError):
            exporter.sanitized([{"key": "panel_fast-node-swe1",
                                  "results": [{"timestamp": "wrong", "success": True}]}],
                               "ger1")

    def test_unsupported_role_and_unexpected_data_fail_closed(self):
        with self.assertRaises(ValueError):
            exporter.sanitized([], "unknown")
        with self.assertRaises(ValueError):
            exporter.sanitized([
                {"key": "observer_proxysignal-heartbeat", "results": []},
                {"key": "observer_proxysignal-heartbeat", "results": []},
            ], "ger1")
        with self.assertRaises(ValueError):
            exporter.sanitized([{"key": "observer_hostland-https", "results": [
                {"timestamp": "2026-11-06T12:00:00Z", "success": "false"}
            ]}], "fin1")
        with self.assertRaises(ValueError):
            exporter.sanitized([{"key": "observer_hostland-https", "results": [
                {"timestamp": "not timestamp", "success": True}
            ]}], "fin1")

    def test_export_does_not_use_proxy_or_redirect(self):
        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, size):
                assert size == exporter.MAX_BODY + 1
                return b'[{"key":"observer_hostland-https","results":[]}]'
        class Opener:
            def open(self, request, timeout):
                self_url = request.full_url
                assert self_url == exporter.ADDRESS
                assert timeout == 5
                assert request.get_method() == "GET"
                return Response()
        with mock.patch.object(exporter.urllib.request, "build_opener", return_value=Opener()):
            self.assertEqual(exporter.export("fin1"), [
                {"key": "observer_hostland-https", "results": []}
            ])

    def test_ssh_restriction_enforced(self):
        with mock.patch.object(exporter.sys, "argv", ["export-status.py", "--role", "ger1"]), \
             mock.patch.dict("os.environ", {"SSH_ORIGINAL_COMMAND": "whoami"}, clear=True):
            self.assertEqual(exporter.main(), 1)


if __name__ == "__main__":
    unittest.main()
