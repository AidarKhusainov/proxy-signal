#!/usr/bin/env python3
"""Independent heartbeat: ping only while Docker and scheduled observations are fresh."""
import argparse
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

CONTAINER = "proxy-signal-parallel-proxy-signal-1"
KEYS = ("source/happ",) + tuple(f"profile/happ/p{i:02}" for i in range(1, 9))
MAX_AGE_SECONDS = 660  # 2 x 300-second interval plus 60-second timeout
MAX_STATE_BYTES = 512 * 1024


def validate_state(state, now):
    if not isinstance(state, dict) or state.get("version") != 1:
        return False
    records = state.get("records")
    if not isinstance(records, dict):
        return False
    for key in KEYS:
        record = records.get(key)
        if not isinstance(record, dict):
            return False
        timestamp = record.get("last_observed_at")
        if type(timestamp) is not int or not 0 <= now - timestamp <= MAX_AGE_SECONDS:
            return False
        if record.get("last_code") == "observation_stale":
            return False
    # UNKNOWN and FAILED are fresh network observations, not scheduler downtime.
    return True


def run_docker(*args):
    return subprocess.run(
        ["docker", *args], check=True, capture_output=True, timeout=12
    ).stdout


def check_container(now):
    details = json.loads(run_docker("inspect", "--format", "{{json .State}}", CONTAINER))
    if not details.get("Running") or details.get("Health", {}).get("Status") != "healthy":
        return False
    payload = run_docker("exec", "-u", "65532:65532", CONTAINER, "cat", "/data/state.json")
    if len(payload) > MAX_STATE_BYTES:
        return False
    return validate_state(json.loads(payload), now)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def ping(url):
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.fragment or any(c.isspace() for c in url)):
        raise ValueError("invalid HTTPS watchdog URL")
    opener = urllib.request.build_opener(NoRedirect)
    with opener.open(urllib.request.Request(url, method="GET"), timeout=10) as response:
        if response.status != 200:
            raise ValueError("watchdog did not acknowledge heartbeat")


def ssh_ping(host, port, user, key_file, known_hosts_file):
    """Remote forced command owns the Push token; it never resides on Hostland."""
    if not re.fullmatch(r"[a-zA-Z0-9.-]{1,253}", host) or not 1 <= port <= 65535:
        raise ValueError("invalid SSH endpoint")
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user):
        raise ValueError("invalid SSH account")
    if not Path(key_file).is_file() or not Path(known_hosts_file).is_file():
        raise ValueError("missing pinned SSH credentials")
    subprocess.run(
        [
            "ssh", "-F", "/dev/null",
            "-i", key_file, "-p", str(port),
            "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={known_hosts_file}",
            "-o", "ConnectTimeout=8", "-o", "ConnectionAttempts=1",
            "-o", "ClearAllForwardings=yes",
            "-T", "-n", f"{user}@{host}", "heartbeat",
        ],
        check=True, capture_output=True, timeout=20,
    )


def main():
    parser = argparse.ArgumentParser()
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--url-file")
    target.add_argument("--ssh-host")
    parser.add_argument("--ssh-port", type=int, default=52222)
    parser.add_argument("--ssh-user", default="kuma-push")
    parser.add_argument("--ssh-key-file")
    parser.add_argument("--ssh-known-hosts-file")
    args = parser.parse_args()
    try:
        if not check_container(int(time.time())):
            raise ValueError("unhealthy process or stale observations")
        if args.url_file:
            # Legacy SaaS mode; root-owned 0600 file; never print URL.
            url = Path(args.url_file).read_text(encoding="utf-8").strip()
            ping(url)
        else:
            if not args.ssh_key_file or not args.ssh_known_hosts_file:
                raise ValueError("missing SSH configuration")
            ssh_ping(args.ssh_host, args.ssh_port, args.ssh_user,
                     args.ssh_key_file, args.ssh_known_hosts_file)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError,
            urllib.error.URLError, json.JSONDecodeError):
        print("ProxySignal watchdog: no heartbeat (process, freshness or delivery)", file=sys.stderr)
        return 1
    print("ProxySignal watchdog: heartbeat acknowledged")
    return 0


if __name__ == "__main__":
    sys.exit(main())
