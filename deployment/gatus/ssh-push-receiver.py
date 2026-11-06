#!/usr/bin/env python3
"""Restricted SSH heartbeat: token on ger1 only; fixed loopback Gatus endpoint."""
import base64
import hashlib
import hmac
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request

TOKEN_FILE = "/etc/proxysignal-gatus-push/token"
PUSH_URL = "http://127.0.0.1:3002/api/v1/endpoints/observer_proxysignal-heartbeat/external?success=true"
PANEL_URL = "http://127.0.0.1:3002/api/v1/endpoints/panel_"
PANEL_FAST = (
    "panel", "auth", "caddy", "remnawave", "postgres", "redis",
    "subscription_page", "xray_proxy", "backupable", "node_metrics",
    "node_swe1", "node_msc1", "node_fin1", "node_nyc1", "node_ger1",
    "subscription", "fast_tick",
)
PANEL_AUDIT = ("host_state", "firewall", "backupable_desired", "audit_tick")


def parse_report(command):
    """Accept only complete, bounded reports from the existing restricted key."""
    if not isinstance(command, str) or len(command) > 1024:
        raise ValueError("invalid report")
    parts = command.split(" ")
    if len(parts) != 3 or parts[0] != "panel-report-v1":
        raise ValueError("invalid report")
    group = parts[1]
    expected = PANEL_FAST if group == "fast" else (
        PANEL_AUDIT if group == "audit" else ()
    )
    if not expected:
        raise ValueError("invalid group")
    entries = parts[2].split(",")
    if len(entries) != len(expected):
        raise ValueError("incomplete report")
    values = {}
    for entry in entries:
        if not re.fullmatch(r"[a-z0-9_]+=[01]", entry):
            raise ValueError("invalid result")
        key, status = entry.split("=")
        if key not in expected or key in values:
            raise ValueError("unexpected or repeated result")
        values[key] = status == "1"
    if set(values) != set(expected) or values[group + "_tick"] is not True:
        raise ValueError("invalid checker tick")
    return group, values


def panel_token(master, group, name):
    digest = hmac.new(
        master.encode("ascii"), f"panel-report-v1:{group}:{name}".encode("ascii"),
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")



class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def send(token, url=PUSH_URL, timeout=8):
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", token):
        raise ValueError("invalid push token")
    request = urllib.request.Request(
        url, data=b"", method="POST",
        headers={"Authorization": "Bearer " + token},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
    with opener.open(request, timeout=timeout) as response:
        if response.status != 200:
            raise ValueError("heartbeat not acknowledged")


def main():
    try:
        command = os.environ.get("SSH_ORIGINAL_COMMAND")
        if command != "heartbeat":
            group, results = parse_report(command)
        token = Path(TOKEN_FILE).read_text(encoding="ascii").strip()
        if command == "heartbeat":
            send(token)
        else:
            for name, success in results.items():
                # Derived bearer tokens stay on ger1; the client never sees them.
                url = PANEL_URL + group + "-" + name.replace("_", "-") + "/external?success=" + (
                    "true" if success else "false"
                )
                send(panel_token(token, group, name), url=url, timeout=3)
        return 0
    except (OSError, ValueError, urllib.error.URLError):
        print("Gatus Push receiver: restricted status was not delivered", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
