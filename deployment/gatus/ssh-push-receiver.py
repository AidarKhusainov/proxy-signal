#!/usr/bin/env python3
"""Restricted SSH heartbeat: token on ger1 only; fixed loopback Gatus endpoint."""
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request

TOKEN_FILE = "/etc/proxysignal-gatus-push/token"
PUSH_URL = "http://127.0.0.1:3002/api/v1/endpoints/observer_proxysignal-heartbeat/external?success=true"
COVERAGE_OK_URL = "http://127.0.0.1:3002/api/v1/endpoints/observer_proxysignal-required-coverage/external?success=true"
COVERAGE_FAIL_URL = "http://127.0.0.1:3002/api/v1/endpoints/observer_proxysignal-required-coverage/external?success=false"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def send(token, url=PUSH_URL):
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", token):
        raise ValueError("invalid push token")
    if url not in (PUSH_URL, COVERAGE_OK_URL, COVERAGE_FAIL_URL):
        raise ValueError("invalid push destination")
    request = urllib.request.Request(
        url, data=b"", method="POST",
        headers={"Authorization": "Bearer " + token},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
    with opener.open(request, timeout=8) as response:
        if response.status != 200:
            raise ValueError("heartbeat not acknowledged")


def main():
    try:
        command = os.environ.get("SSH_ORIGINAL_COMMAND")
        if command not in ("heartbeat", "heartbeat coverage=ok", "heartbeat coverage=fail"):
            raise ValueError("unexpected SSH command")
        token = Path(TOKEN_FILE).read_text(encoding="ascii").strip()
        send(token)
        if command == "heartbeat coverage=ok":
            send(token, COVERAGE_OK_URL)
        elif command == "heartbeat coverage=fail":
            send(token, COVERAGE_FAIL_URL)
        return 0
    except (OSError, ValueError, urllib.error.URLError):
        print("Gatus Push receiver: heartbeat not delivered", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
