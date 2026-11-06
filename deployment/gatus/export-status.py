#!/usr/bin/env python3
"""Read-only, allowlisted Gatus snapshots for the daily observer summary.

Install behind a forced SSH command. Never returns endpoint URL, errors,
condition bodies, notification credentials, tokens or a raw Gatus config.
"""
import argparse
import json
import os
import re
import sys
import urllib.request

ADDRESS = "http://127.0.0.1:3002/api/v1/endpoints/statuses"
MAX_BODY = 512 * 1024
PANEL_FAST = (
    "panel", "auth", "caddy", "remnawave", "postgres", "redis",
    "subscription_page", "xray_proxy", "backupable", "node_metrics",
    "node_swe1", "node_msc1", "node_fin1", "node_nyc1", "node_ger1",
    "subscription", "fast_tick",
)
PANEL_AUDIT = ("host_state", "firewall", "backupable_desired", "audit_tick")
KEYS = {
    "ger1": frozenset({
        "observer_proxysignal-heartbeat",
        "observer_proxysignal-required-coverage",
        "observer_hostland-https-secondary",
    } | {"panel_fast-" + name.replace("_", "-") for name in PANEL_FAST}
      | {"panel_audit-" + name.replace("_", "-") for name in PANEL_AUDIT}),
    "fin1": frozenset({
        "observer_hostland-https",
        "observer_cdn-xray-public",
        "observer_cdn-subscriptions-public",
    }),
}


def sanitized(payload, role):
    if role not in KEYS or not isinstance(payload, list) or len(payload) > 64:
        raise ValueError("invalid observer data")
    selected = set()
    output = []
    for entry in payload:
        if not isinstance(entry, dict) or entry.get("key") not in KEYS[role]:
            continue
        key = entry["key"]
        if key in selected:
            raise ValueError("duplicate endpoint")
        selected.add(key)
        results = entry.get("results")
        if not isinstance(results, list) or len(results) > 360:
            raise ValueError("invalid result history")
        safe = []
        for result in results:
            if not isinstance(result, dict) or type(result.get("success")) is not bool:
                raise ValueError("invalid result")
            timestamp = result.get("timestamp")
            if not isinstance(timestamp, str) or not re.fullmatch(
                    r"[0-9T:.-]{19,40}Z", timestamp):
                raise ValueError("invalid timestamp")
            safe.append({"timestamp": timestamp, "success": result["success"]})
        output.append({"key": key, "results": safe})
    return output


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def export(role):
    if role not in KEYS:
        raise ValueError("invalid observer")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
    with opener.open(
        urllib.request.Request(ADDRESS, method="GET"), timeout=5
    ) as response:
        if response.status != 200:
            raise ValueError("Gatus statuses unavailable")
        body = response.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            raise ValueError("Gatus payload too large")
    return sanitized(json.loads(body), role)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=("ger1", "fin1"), required=True)
    args = parser.parse_args()
    try:
        if os.getenv("SSH_ORIGINAL_COMMAND") != "status":
            raise ValueError("not a restricted status request")
        value = export(args.role)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        print("Gatus observer status export unavailable", file=sys.stderr)
        return 1
    print(json.dumps(value, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
