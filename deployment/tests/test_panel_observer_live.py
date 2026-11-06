"""Pinned real-Gatus #160 fixture. Synthetic tokens only; never contacts production."""
import http.server
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request
import uuid

IMAGE = "ghcr.io/twin/gatus@sha256:085ed63da963728965d00a3c78aa6167e3bf135218485b893201758e079e8415"
ROOT = Path(__file__).resolve().parents[1] / "gatus"
spec = importlib.util.spec_from_file_location("issue160_render", ROOT / "render-config.py")
render = importlib.util.module_from_spec(spec)
spec.loader.exec_module(render)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_until(fn, seconds=16):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            result = fn()
            if result:
                return result
        except (KeyError, IndexError, OSError, ValueError, urllib.error.URLError):
            pass
        time.sleep(0.25)
    raise AssertionError("timed out waiting for pinned isolated Gatus")


@unittest.skipUnless(os.environ.get("GATUS_LIVE_FIXTURES") == "1", "Docker fixture opt-in")
class PanelObserverGatusLive(unittest.TestCase):
    def test_generated_ger1_yaml_and_external_push_freshness(self):
        master = "isolated-fixture-master-token-123456"
        cfg = render.render(
            "ger1", "123456:ABCDEFGHIJKLMNOPQRST", "-123", master,
            enable_alerts=False, panel_monitor=True,
        )
        cfg = cfg.replace("https://panel.censor-amoroso.com/", "http://127.0.0.1:1/")
        cfg = cfg.replace("interval: 12m", "interval: 4s")
        cfg = cfg.replace("interval: 4h", "interval: 4s")
        self.assertEqual(cfg.count("interval: 4s"), len(render.PANEL_FAST) + len(render.PANEL_AUDIT))
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        name = "issue160-gatus-fixture-" + uuid.uuid4().hex[:8]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "config.yaml").write_text(cfg, encoding="utf-8")
            (root / "config.yaml").chmod(0o644)
            data = root / "data"
            data.mkdir()
            subprocess.run(["sudo", "chown", "65532:65532", str(data)], check=True, timeout=5)
            port = free_port()
            host = f"http://127.0.0.1:{port}"

            def statuses():
                with opener.open(host + "/api/v1/endpoints/statuses", timeout=2) as response:
                    self.assertEqual(response.status, 200)
                    return {entry["key"]: entry for entry in json.load(response)}

            def post(group, target, ok, token=None):
                token = token or render.panel_token(master, group, target)
                url = host + "/api/v1/endpoints/panel_" + group + "-" + target + (
                    "/external?success=true" if ok else "/external?success=false"
                )
                req = urllib.request.Request(
                    url, data=b"", method="POST", headers={"Authorization": "Bearer " + token},
                )
                with opener.open(req, timeout=3) as response:
                    return response.status

            try:
                subprocess.run([
                    "docker", "run", "-d", "--rm", "--name", name,
                    "--user=65532:65532", "--read-only",
                    "--cap-drop=ALL", "--security-opt=no-new-privileges",
                    "--pids-limit=32", "--memory=128m", "--cpus=0.25",
                    "-p", f"127.0.0.1:{port}:8080",
                    "-v", f"{root / 'config.yaml'}:/config/config.yaml:ro",
                    "-v", f"{data}:/data",
                    "-e", "GATUS_CONFIG_PATH=/config/config.yaml",
                    IMAGE,
                ], check=True, stdout=subprocess.DEVNULL, timeout=20)
                wait_until(lambda: statuses())
                self.assertEqual(post("fast", "panel", True), 200)
                self.assertEqual(post("fast", "node_fin1", False), 200)
                self.assertEqual(post("fast", "fast_tick", True), 200)
                self.assertEqual(post("audit", "firewall", True), 200)
                self.assertEqual(post("audit", "audit_tick", True), 200)
                with self.assertRaises(urllib.error.HTTPError) as denied:
                    post("fast", "panel", True, token="invalid-token-123")
                self.assertIn(denied.exception.code, (401, 403))
                self.assertTrue(wait_until(
                    lambda: any(k.endswith("fast-panel") for k in statuses())
                ))
                # The observer must never collapse a failed node into a passing Panel.
                state = statuses()
                self.assertIn("fast-panel", {s["name"] for s in state.values()})
                wait_until(lambda: not statuses()["panel_fast-node_fin1"]["results"][-1]["success"])
                # No push for panel after interval -> stale status, distinct from a failed node.
                wait_until(lambda: not statuses()["panel_fast-panel"]["results"][-1]["success"], 15)
            except Exception:
                logs = subprocess.run(["docker", "logs", "--tail", "50", name],
                                      capture_output=True, text=True, timeout=5)
                self.fail("pinned Gatus panel fixture failed: " + (logs.stdout + logs.stderr)[-1500:])
            finally:
                subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=10, check=False)
                subprocess.run(["sudo", "chown", "-R", f"{os.getuid()}:{os.getgid()}", str(data)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=10, check=False)


if __name__ == "__main__":
    unittest.main()
