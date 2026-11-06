#!/usr/bin/env python3
"""Generate private Gatus configuration from file-backed secrets (no secret env/argv)."""
import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import tempfile

MAX_SECRET = 4096
# Names are a stable, allowlisted contract shared with the Hostland reporter.
PANEL_FAST = (
    "panel", "auth", "caddy", "remnawave", "postgres", "redis",
    "subscription_page", "xray_proxy", "backupable", "node_metrics",
    "node_swe1", "node_msc1", "node_fin1", "node_nyc1", "node_ger1",
    "subscription", "fast_tick",
)
PANEL_AUDIT = ("host_state", "firewall", "backupable_desired", "audit_tick")


def panel_token(master, group, name):
    if group not in ("fast", "audit") or name not in (
        PANEL_FAST if group == "fast" else PANEL_AUDIT
    ):
        raise ValueError("unsupported panel endpoint")
    digest = hmac.new(
        master.encode("ascii"), f"panel-report-v1:{group}:{name}".encode("ascii"),
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")




def read_secret(path, pattern):
    data = path.read_bytes()
    if not data or len(data) > MAX_SECRET:
        raise ValueError("invalid secret file")
    value = data.decode("ascii").strip()
    if not re.fullmatch(pattern, value, flags=re.ASCII):
        raise ValueError("invalid secret value")
    return value


def render(role, telegram_token, chat_id, push_token=None,
           enable_alerts=False, panel_monitor=False, panel_alerts=False):
    quote = json.dumps  # JSON quoted strings are valid YAML scalars.
    header = f"""storage:
  type: sqlite
  path: /data/gatus.db
  maximum-number-of-results: 100
  maximum-number-of-events: 50
web:
  address: 0.0.0.0
  port: 8080
alerting:
  telegram:
    token: {quote(telegram_token)}
    id: {quote(chat_id)}
"""
    if role == "ger1":
        if not push_token:
            raise ValueError("missing ger1 push token")
        external = f"""external-endpoints:
  - name: proxysignal-heartbeat
    group: observer
    token: {quote(push_token)}
    heartbeat:
      interval: 10m
"""
        external_alert = """    alerts:
      - type: telegram
        failure-threshold: 1
        success-threshold: 1
        send-on-resolved: false
        description: ProxySignal не обновляет результаты проверок (ger1)
"""
        ordinary = """endpoints:
  - name: hostland-https-secondary
    group: observer
    url: https://panel.censor-amoroso.com/
    interval: 5m
    client:
      timeout: 15s
      ignore-redirect: true
    conditions:
      - '[STATUS] == 200'
"""
        external += external_alert if enable_alerts else ""
        if panel_monitor:
            for group, names, interval, threshold in (
                ("fast", PANEL_FAST, "12m", 2),
                ("audit", PANEL_AUDIT, "4h", 1),
            ):
                for name in names:
                    external += f"""  - name: {group}-{name}
    group: panel
    token: {quote(panel_token(push_token, group, name))}
    heartbeat:
      interval: {interval}
"""
                    if panel_alerts:
                        external += f"""    alerts:
      - type: telegram
        failure-threshold: {1 if name.endswith("_tick") else threshold}
        success-threshold: 1
        send-on-resolved: false
        description: {quote(f"Hostland {group}/{name}: FAILED либо нет свежего наблюдения")}
"""
        return header + external + ordinary
    if role == "fin1":
        ordinary = """endpoints:
  - name: hostland-https
    group: observer
    url: https://panel.censor-amoroso.com/
    interval: 5m
    client:
      timeout: 15s
      ignore-redirect: true
    conditions:
      - '[STATUS] == 200'
"""
        ordinary_alert = """    alerts:
      - type: telegram
        failure-threshold: 2
        success-threshold: 1
        send-on-resolved: false
        description: Hostland HTTPS недоступен (fin1)
"""
        rendered = header + ordinary + (ordinary_alert if enable_alerts else "")
        for name, url, description in (
            ("cdn-xray-public", "https://cdn-swe1.censor-amoroso.com/generate_204",
             "CDN Xray: публичный HTTPS /generate_204 недоступен (fin1)"),
            ("cdn-subscriptions-public", "https://sub.censor-amoroso.com/generate_204",
             "CDN подписок: публичный HTTPS /generate_204 недоступен (fin1)"),
        ):
            rendered += f"""  - name: {name}
    group: observer
    url: {url}
    method: GET
    interval: 5m
    client:
      timeout: 10s
      ignore-redirect: true
    conditions:
      - '[STATUS] == 204'
"""
            if enable_alerts:
                rendered += f"""    alerts:
      - type: telegram
        failure-threshold: 2
        success-threshold: 1
        send-on-resolved: false
        description: {quote(description)}
"""
        return rendered
    raise ValueError("unsupported role")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", required=True, choices=("ger1", "fin1"))
    parser.add_argument("--private-dir", required=True, type=Path)
    parser.add_argument("--push-token-file", type=Path)
    parser.add_argument("--enable-alerts", action="store_true")
    parser.add_argument("--panel-alerts", action="store_true",
                        help="Arm new panel alerts after verified parallel acceptance")
    parser.add_argument("--panel-monitor", action="store_true",
                        help="Enable issue #160 external panel status endpoints on ger1")
    args = parser.parse_args()
    directory = args.private_dir
    if directory.is_symlink() or not directory.is_dir() or directory.stat().st_mode & 0o077:
        raise ValueError("private directory permissions must be 0700")
    telegram_token = read_secret(directory / "telegram-token", r"[0-9]{5,20}:[A-Za-z0-9_-]{20,200}")
    chat_id = read_secret(directory / "telegram-chat-id", r"-?[0-9]{1,30}")
    push_token = (
        read_secret(args.push_token_file, r"[A-Za-z0-9_-]{8,128}")
        if args.role == "ger1" and args.push_token_file else None
    )
    if args.panel_monitor and args.role != "ger1":
        raise ValueError("panel monitoring receiver must be on ger1")
    if args.panel_alerts and not args.panel_monitor:
        raise ValueError("panel alerts require configured panel endpoints")
    content = render(args.role, telegram_token, chat_id, push_token,
                     args.enable_alerts, args.panel_monitor, args.panel_alerts)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=directory, delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        os.chmod(temporary, 0o440)
        if os.geteuid() == 0:
            os.chown(temporary, 0, 65532)
        os.replace(temporary, directory / "config.yaml")
    finally:
        temporary.unlink(missing_ok=True)
    print(f"Gatus {args.role}: private config rendered")


if __name__ == "__main__":
    main()
