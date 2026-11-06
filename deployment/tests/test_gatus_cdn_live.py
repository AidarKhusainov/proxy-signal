"""Isolated real-Gatus regression: exact statuses, incidents, restart, recovery.

Run explicitly with GATUS_LIVE_FIXTURES=1; no production credentials or network targets.
"""
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.request
import uuid


IMAGE = "ghcr.io/twin/gatus@sha256:085ed63da963728965d00a3c78aa6167e3bf135218485b893201758e079e8415"


class Fixture(http.server.BaseHTTPRequestHandler):
    codes = {"xray": 204, "subscriptions": 204}
    alerts = []
    lock = threading.Lock()

    def do_GET(self):
        if self.path == "/slow":
            time.sleep(3)
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/ok204")
        else:
            with self.lock:
                code = self.codes.get(self.path.lstrip("/"), 204 if self.path == "/ok204" else 200)
            self.send_response(code)
        self.end_headers()

    def do_POST(self):
        if self.path != "/alert":
            self.send_error(404)
            return
        size = min(int(self.headers.get("Content-Length", "0")), 1024)
        value = self.rfile.read(size).decode("utf-8", errors="replace")
        with self.lock:
            self.alerts.append(value)
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        pass


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for(predicate, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            result = predicate()
            if result:
                return result
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(0.25)
    raise AssertionError("timed out waiting for isolated Gatus state")


def endpoint(name, url, alert=False):
    result = f"""  - name: {name}
    group: fixture
    url: {url}
    method: GET
    interval: 1s
    client:
      timeout: 700ms
      ignore-redirect: true
    conditions:
      - '[STATUS] == 204'
"""
    if alert:
        result += """    alerts:
      - type: custom
        failure-threshold: 2
        success-threshold: 1
        send-on-resolved: false
        description: TEST only
"""
    return result


@unittest.skipUnless(os.environ.get("GATUS_LIVE_FIXTURES") == "1", "Docker integration is opt-in")
class GatusLiveFixtures(unittest.TestCase):
    def test_strict_probes_independent_incidents_and_durable_restart(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            Fixture.codes = {"xray": 204, "subscriptions": 204}
            Fixture.alerts = []
            server = http.server.ThreadingHTTPServer(("0.0.0.0", 0), Fixture)
            server.daemon_threads = True
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            https = http.server.ThreadingHTTPServer(("0.0.0.0", 0), Fixture)
            https.daemon_threads = True
            subprocess.run(
                ["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
                 "-days", "1", "-subj", "/CN=host.docker.internal",
                 "-addext", "subjectAltName=DNS:host.docker.internal",
                 "-keyout", str(root / "key.pem"), "-out", str(root / "cert.pem")],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10,
            )
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(root / "cert.pem"), str(root / "key.pem"))
            https.socket = context.wrap_socket(https.socket, server_side=True)
            ssl_thread = threading.Thread(target=https.serve_forever, daemon=True)
            ssl_thread.start()

            fixture_port = server.server_port
            host = f"host.docker.internal:{fixture_port}"
            config = """storage:
  type: sqlite
  path: /data/gatus.db
  maximum-number-of-results: 50
  maximum-number-of-events: 20
web:
  address: 0.0.0.0
  port: 8080
alerting:
  custom:
    url: http://""" + host + """/alert
    method: POST
    body: "[ALERT_TRIGGERED_OR_RESOLVED] [ENDPOINT_NAME]"
endpoints:
"""
            checks = (
                ("strict-xray", f"http://{host}/xray", True),
                ("strict-subscriptions", f"http://{host}/subscriptions", True),
                ("expected-204", f"http://{host}/ok204", False),
                ("wrong-200", f"http://{host}/ok200", False),
                ("redirect", f"http://{host}/redirect", False),
                ("timeout", f"http://{host}/slow", False),
                ("dns-failure", "http://unresolvable-gatus-test.invalid/", False),
                ("tls-failure", f"https://host.docker.internal:{https.server_port}/ok204", False),
            )
            for name, url, alerts in checks:
                config += endpoint(name, url, alerts)
            (root / "config.yaml").write_text(config, encoding="utf-8")
            data = root / "data"
            data.mkdir()
            subprocess.run(["sudo", "chown", "65532:65532", str(data)], check=True)
            config_port = port()
            name = "issue159-gatus-fixture-" + uuid.uuid4().hex[:8]
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            def statuses():
                with opener.open(f"http://127.0.0.1:{config_port}/api/v1/endpoints/statuses", timeout=2) as resp:
                    self.assertEqual(resp.status, 200)
                    return {item["name"]: item for item in json.load(resp)}
            def latest(name):
                return statuses()[name]["results"][-1]["success"]
            def count(name):
                with Fixture.lock:
                    return sum("TRIGGERED " + name in event for event in Fixture.alerts)

            try:
                subprocess.run(["docker", "pull", IMAGE], check=True, stdout=subprocess.DEVNULL, timeout=90)
                subprocess.run([
                    "docker", "run", "-d", "--name", name,
                    "--add-host=host.docker.internal:host-gateway",
                    "--user=65532:65532", "--read-only", "--cap-drop=ALL",
                    "--security-opt=no-new-privileges", "--pids-limit=32",
                    "--memory=128m", "--cpus=0.25",
                    "-p", f"127.0.0.1:{config_port}:8080",
                    "-v", f"{root / 'config.yaml'}:/config/config.yaml:ro",
                    "-v", f"{data}:/data",
                    "-e", "GATUS_CONFIG_PATH=/config/config.yaml",
                    IMAGE,
                ], check=True, stdout=subprocess.DEVNULL, timeout=20)
                wait_for(lambda: len(statuses()) == len(checks))
                wait_for(lambda: all(len(x["results"]) >= 2 for x in statuses().values()), 20)
                self.assertTrue(latest("strict-xray"))
                self.assertTrue(latest("strict-subscriptions"))
                self.assertTrue(latest("expected-204"))
                for failed in ("wrong-200", "redirect", "timeout", "dns-failure", "tls-failure"):
                    self.assertFalse(latest(failed), failed)

                with Fixture.lock:
                    Fixture.codes["xray"] = 503
                wait_for(lambda: count("strict-xray") == 1)
                self.assertEqual(count("strict-subscriptions"), 0)
                time.sleep(3)
                self.assertEqual(count("strict-xray"), 1, "repeat failure emitted duplicate")
                with Fixture.lock:
                    Fixture.codes["subscriptions"] = 200
                wait_for(lambda: count("strict-subscriptions") == 1)
                self.assertEqual(count("strict-xray"), 1)

                subprocess.run(["docker", "restart", "-t", "2", name], check=True,
                               stdout=subprocess.DEVNULL, timeout=20)
                wait_for(lambda: len(statuses()) == len(checks), 20)
                time.sleep(4)
                self.assertEqual(count("strict-xray"), 1, "restart emitted duplicate xray incident")
                self.assertEqual(count("strict-subscriptions"), 1, "restart emitted duplicate subscription incident")

                with Fixture.lock:
                    Fixture.codes.update(xray=204, subscriptions=204)
                wait_for(lambda: latest("strict-xray") and latest("strict-subscriptions"), 20)
                time.sleep(2)
                self.assertEqual(count("strict-xray"), 1, "recovery emitted an unwanted notification")
                self.assertEqual(count("strict-subscriptions"), 1, "recovery emitted an unwanted notification")
                with Fixture.lock:
                    Fixture.codes["xray"] = 503
                wait_for(lambda: count("strict-xray") == 2, 20)
                self.assertEqual(count("strict-subscriptions"), 1)
            except Exception:
                # The fixture has no secrets or production destinations.
                subprocess.run(["docker", "logs", "--tail", "80", name],
                               timeout=5, check=False)
                raise
            finally:
                subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=15, check=False)
                subprocess.run(["sudo", "chown", "-R", f"{os.getuid()}:{os.getgid()}", str(data)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)
                server.shutdown()
                https.shutdown()
                server.server_close()
                https.server_close()
                thread.join(timeout=3)
                ssl_thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
