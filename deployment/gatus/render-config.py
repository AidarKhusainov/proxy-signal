#!/usr/bin/env python3
"""Generate private Gatus configuration from file-backed secrets (no secret env/argv)."""
import argparse
import json
import os
from pathlib import Path
import re
import tempfile

MAX_SECRET = 4096


def read_secret(path, pattern):
    data = path.read_bytes()
    if not data or len(data) > MAX_SECRET:
        raise ValueError("invalid secret file")
    value = data.decode("ascii").strip()
    if not re.fullmatch(pattern, value, flags=re.ASCII):
        raise ValueError("invalid secret value")
    return value


def render(role, telegram_token, chat_id, push_token=None, enable_alerts=False):
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
        return header + external + (external_alert if enable_alerts else "") + ordinary
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
        return header + ordinary + (ordinary_alert if enable_alerts else "")
    raise ValueError("unsupported role")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", required=True, choices=("ger1", "fin1"))
    parser.add_argument("--private-dir", required=True, type=Path)
    parser.add_argument("--push-token-file", type=Path)
    parser.add_argument("--enable-alerts", action="store_true")
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
    content = render(args.role, telegram_token, chat_id, push_token, args.enable_alerts)
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
