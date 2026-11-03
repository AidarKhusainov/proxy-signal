#!/usr/bin/env python3
"""Local-only Kuma webhook adapter: send Telegram for DOWN transitions only.

Webhooks originate on the private Compose network. No host port is published.
"""
import hmac
import json
import os
import sys
import tempfile
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

STATE = Path("/data/last-state.json")
LIMIT = 8192


def is_new_down(previous, code):
    if type(code) is not int or code not in (0, 1):
        raise ValueError("unsupported status")
    return code == 0 and previous != "DOWN"


def persist(value):
    with tempfile.NamedTemporaryFile("w", encoding="ascii", dir=STATE.parent, delete=False) as stream:
        temporary = Path(stream.name)
        json.dump({"last": value}, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, STATE)


def last_state():
    try:
        contents = STATE.read_bytes()
        if len(contents) > 128:
            raise ValueError("invalid state length")
        return json.loads(contents).get("last")
    except FileNotFoundError:
        return None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def notify(label):
    token = Path("/run/secrets/telegram-token").read_text(encoding="ascii").strip()
    chat_id = Path("/run/secrets/telegram-chat-id").read_text(encoding="ascii").strip()
    if not token or not chat_id or len(token) > 256 or len(chat_id) > 64:
        raise ValueError("invalid Telegram secrets")
    data = json.dumps({
        "chat_id": chat_id,
        "text": "[TEST ProxySignal] DOWN — " + label,
        "disable_notification": False,
    }).encode("utf-8")
    request = urllib.request.Request(
        "https://api.telegram.org/bot" + token + "/sendMessage",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.build_opener(NoRedirect).open(request, timeout=10) as response:
        if response.status != 200 or not json.load(response).get("ok"):
            raise ValueError("Telegram did not acknowledge DOWN")


def process_event(body):
    if not isinstance(body, dict):
        raise ValueError("invalid payload")
    # Kuma's webhook Setup Notification test is not a monitor state transition.
    # Acknowledge it silently without changing persistence or delivering Telegram.
    if body.get("heartbeat") is None and body.get("monitor") is None and isinstance(body.get("msg"), str):
        return
    if not isinstance(body.get("heartbeat"), dict):
        raise ValueError("invalid payload")
    monitor = body.get("monitor")
    if not isinstance(monitor, dict) or monitor.get("name") != os.environ["MONITOR_NAME"]:
        raise ValueError("unexpected monitor")
    status = body["heartbeat"].get("status")
    previous = last_state()
    if is_new_down(previous, status):
        notify(os.environ["MONITOR_NAME"])
    persist("DOWN" if status == 0 else "UP")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # No request bodies, secrets or remote status in logs.

    def do_POST(self):
        try:
            if self.path != "/notify":
                self.send_error(404)
                return
            supplied = self.headers.get("X-ProxySignal-Webhook-Key", "")
            required = Path("/run/secrets/webhook-key").read_text(encoding="ascii").strip()
            if not required or not hmac.compare_digest(supplied, required):
                self.send_error(403)
                return
            size = int(self.headers.get("Content-Length", "0"))
            if size < 2 or size > LIMIT:
                self.send_error(413)
                return
            body = json.loads(self.rfile.read(size))
            process_event(body)
            self.send_response(200)
        except (OSError, ValueError, TypeError, KeyError, urllib.error.URLError,
                json.JSONDecodeError):
            self.send_response(503)
        self.send_header("Content-Length", "0")
        self.end_headers()


def main():
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()


if __name__ == "__main__":
    sys.exit(main())
