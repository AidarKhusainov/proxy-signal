"""Isolated pinned-Gatus HTTP webhook integration; no production endpoints/secrets."""
import http.server
import importlib.util
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.request
import uuid

IMAGE = "ghcr.io/twin/gatus@sha256:085ed63da963728965d00a3c78aa6167e3bf135218485b893201758e079e8415"
FILE = Path(__file__).resolve().parents[1] / "gatus" / "durable-down.py"
spec = importlib.util.spec_from_file_location("durable_gatus_integration", FILE)
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def until(predicate, deadline=25):
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        try:
            if predicate():
                return
        except (OSError, ValueError, sqlite3.Error):
            pass
        time.sleep(0.2)
    raise AssertionError("isolated Gatus delivery state did not converge")


class Probe(http.server.BaseHTTPRequestHandler):
    code = 204
    def do_GET(self):
        if self.path != "/probe":
            self.send_response(404)
        else:
            self.send_response(self.code)
        self.end_headers()
    def log_message(self, *args): pass


@unittest.skipUnless(os.getenv("GATUS_LIVE_FIXTURES") == "1", "Docker-only opt-in")
class DurableGatusLive(unittest.TestCase):
    def test_confirmed_down_is_durable_deduplicated_and_rearmed_on_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            webhook = root / "webhook-key"
            webhook.write_text("X" * 48)
            state = root / "alerts.sqlite"
            with relay.connect(state) as connection:
                self.assertIsNotNone(connection)
            relay.Handler.role = "fin1"
            relay.Handler.database = state
            original_webhook_file = relay.WEBHOOK_FILE
            relay.WEBHOOK_FILE = webhook
            server = http.server.ThreadingHTTPServer(("0.0.0.0", 0), relay.Handler)
            server.daemon_threads = True
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            Probe.code = 204
            probe = http.server.ThreadingHTTPServer(("0.0.0.0", 0), Probe)
            probe.daemon_threads = True
            probe_thread = threading.Thread(target=probe.serve_forever, daemon=True)
            probe_thread.start()
            config = root / "config.yaml"
            config.write_text("""storage:
  type: sqlite
  path: /data/gatus.db
  maximum-number-of-results: 100
  maximum-number-of-events: 50
web:
  address: 0.0.0.0
  port: 8080
alerting:
  custom:
    url: http://host.docker.internal:%s/event
    method: POST
    headers:
      X-Observer-Webhook-Key: "%s"
    body: '{"state":"[ALERT_TRIGGERED_OR_RESOLVED]","group":"[ENDPOINT_GROUP]","name":"[ENDPOINT_NAME]"}'
endpoints:
  - name: cdn-xray-public
    group: observer
    url: http://host.docker.internal:%s/probe
    interval: 1s
    client:
      timeout: 700ms
      ignore-redirect: true
    conditions:
      - '[STATUS] == 204'
    alerts:
      - type: custom
        failure-threshold: 2
        success-threshold: 1
        send-on-resolved: true
        description: "TEST synthetic CDN unavailable"
""" % (server.server_port, "X" * 48, probe.server_port), encoding="utf-8")
            data = root / "data"
            data.mkdir()
            subprocess.run(["sudo", "chown", "65532:65532", str(data)], check=True)
            port = unused_port()
            name = "issue161-durable-gatus-fixture-" + uuid.uuid4().hex[:8]
            no_proxy = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            def result_count():
                with relay.connect(state) as db:
                    return db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0]
            def is_active():
                with relay.connect(state) as db:
                    row = db.execute("SELECT active FROM targets WHERE key='observer_cdn-xray-public'").fetchone()
                    return None if row is None else row[0]
            def latest():
                with no_proxy.open(f"http://127.0.0.1:{port}/api/v1/endpoints/statuses", timeout=2) as r:
                    rows = json.load(r)
                return rows[0]["results"][-1]["success"] if rows and rows[0]["results"] else None
            try:
                subprocess.run(["docker", "pull", IMAGE], check=True,
                               stdout=subprocess.DEVNULL, timeout=90)
                subprocess.run([
                    "docker", "run", "-d", "--name", name,
                    "--add-host=host.docker.internal:host-gateway",
                    "--user=65532:65532", "--read-only", "--cap-drop=ALL",
                    "--security-opt=no-new-privileges", "--pids-limit=32",
                    "--memory=128m", "--cpus=0.25",
                    "-p", f"127.0.0.1:{port}:8080",
                    "-v", f"{config}:/config/config.yaml:ro",
                    "-v", f"{data}:/data",
                    "-e", "GATUS_CONFIG_PATH=/config/config.yaml", IMAGE,
                ], check=True, stdout=subprocess.DEVNULL, timeout=20)
                until(lambda: latest() is True)
                Probe.code = 503
                until(lambda: result_count() == 1 and is_active() == 1)
                time.sleep(3)
                self.assertEqual(result_count(), 1)
                # A Gatus-only restart while DOWN must not create a repeated notice.
                subprocess.run(["docker", "restart", "-t", "2", name],
                               check=True, stdout=subprocess.DEVNULL, timeout=20)
                until(lambda: latest() is False)
                time.sleep(3)
                self.assertEqual(result_count(), 1)
                Probe.code = 204
                until(lambda: latest() is True and is_active() == 0)
                self.assertEqual(result_count(), 1, "RESOLVED must not send Telegram")
                Probe.code = 503
                until(lambda: result_count() == 2 and is_active() == 1)
                with relay.connect(state) as db:
                    self.assertFalse(relay.send_one(db, "fin1",
                        lambda *args: (_ for _ in ()).throw(OSError("TEST Telegram timeout"))))
                    self.assertEqual(db.execute(
                        "SELECT COUNT(*) FROM outbox WHERE delivered_at IS NULL"
                    ).fetchone()[0], 2)
                    delivered = []
                    self.assertTrue(relay.send_one(db, "fin1",
                        lambda *args: delivered.append(args)))
                    self.assertTrue(relay.send_one(db, "fin1",
                        lambda *args: delivered.append(args)))
                    self.assertFalse(relay.send_one(db, "fin1",
                        lambda *args: self.fail("duplicate send")))
                    self.assertEqual(len(delivered), 2)
            finally:
                subprocess.run(["docker", "rm", "-f", name], check=False,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
                subprocess.run(["sudo", "chown", "-R",
                                f"{os.getuid()}:{os.getgid()}", str(data)],
                               check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
                Probe.code = 204
                server.shutdown()
                probe.shutdown()
                thread.join(timeout=3)
                probe_thread.join(timeout=3)
                server.server_close()
                probe.server_close()
                relay.WEBHOOK_FILE = original_webhook_file


if __name__ == "__main__":
    unittest.main()
