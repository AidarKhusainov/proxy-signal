#!/usr/bin/env python3
"""Forced SSH command on ger1; the token is never sent to or stored on Hostland."""
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

TOKEN_FILE = "/etc/proxysignal-kuma-push/token"
URL_PREFIX = "http://127.0.0.1:3001/api/push/"


def send(token):
    # Kuma-generated token, not a URL. Only loopback is reachable.
    if not re.fullmatch(r"[a-zA-Z0-9_-]{8,128}", token):
        raise ValueError("invalid push token")
    request = urllib.request.Request(
        URL_PREFIX + token + "?status=up&msg=ProxySignal_heartbeat",
        method="GET",
    )
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
        request, timeout=8
    ) as response:
        if response.status != 200:
            raise ValueError("push not acknowledged")


def main():
    try:
        token = Path(TOKEN_FILE).read_text(encoding="ascii").strip()
        send(token)
        return 0
    except (OSError, ValueError, urllib.error.URLError):
        print("ProxySignal Push receiver: heartbeat not delivered", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
