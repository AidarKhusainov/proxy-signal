#!/usr/bin/env python3
"""Local-only Gatus incident relay: durable Russian DOWN, silent resolved, no public port."""
import hmac
from datetime import datetime, timezone
from contextlib import closing
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.request

DB = Path("/data/alerts.sqlite")
TOKEN_FILE = Path("/run/secrets/telegram-token")
CHAT_FILE = Path("/run/secrets/telegram-chat-id")
WEBHOOK_FILE = Path("/run/secrets/webhook-key")
MAX_EVENT = 2048
MAX_QUEUE = 1024
RETRY_SECONDS = 15
GATUS_STATUSES = "http://gatus:8080/api/v1/endpoints/statuses?page=1&pageSize=4"
MAX_GATUS_BODY = 256 * 1024
OBSERVERS = {
    "ger1": {
        "observer_proxysignal-heartbeat": "Нет свежего heartbeat от ProxySignal",
        "observer_proxysignal-required-coverage": "Нет подтверждения обязательного VPN-покрытия",
        "observer_hostland-https-secondary": "Резервная HTTPS-проверка Panel недоступна",
    },
    "fin1": {
        "observer_hostland-https": "Panel HTTPS недоступна",
        "observer_cdn-xray-public": "CDN Xray: HTTPS /generate_204 не отвечает 204",
        "observer_cdn-subscriptions-public": "CDN подписок: HTTPS /generate_204 не отвечает 204",
    },
}
PANEL_FAST = {
    "panel": "Panel", "auth": "Auth", "caddy": "Caddy",
    "remnawave": "Remnawave", "postgres": "PostgreSQL",
    "redis": "Redis", "subscription_page": "Subscription Page",
    "xray_proxy": "Telegram/Xray proxy", "backupable": "Backupable",
    "node_metrics": "Метрики нод", "node_swe1": "Нода swe1",
    "node_msc1": "Нода msc1", "node_fin1": "Нода fin1",
    "node_nyc1": "Нода nyc1", "node_ger1": "Нода ger1",
    "subscription": "Подписка", "fast_tick": "Быстрый наблюдатель",
}
PANEL_AUDIT = {
    "host_state": "Состояние Hostland", "firewall": "Hostland firewall",
    "backupable_desired": "Конфигурация Backupable",
    "audit_tick": "Инфраструктурный наблюдатель",
}


def labels(role):
    if role not in OBSERVERS:
        raise ValueError("unsupported role")
    result = dict(OBSERVERS[role])
    if role == "ger1":
        for name, description in PANEL_FAST.items():
            result["panel_fast-" + name.replace("_", "-")] = "Hostland: " + description
        for name, description in PANEL_AUDIT.items():
            result["panel_audit-" + name.replace("_", "-")] = "Hostland: " + description
    return result


def connect(path=DB):
    db = sqlite3.connect(path, timeout=5)
    db.execute("PRAGMA busy_timeout=5000")
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    db.execute("""CREATE TABLE IF NOT EXISTS targets (
        key TEXT PRIMARY KEY, active INTEGER NOT NULL CHECK (active IN (0,1))
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS outbox (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT NOT NULL, created_at INTEGER NOT NULL,
        delivered_at INTEGER
    )""")
    return db


def accept_event(db, role, event, now=None):
    """Gatus custom webhooks are best-effort; ACK only after committed SQLite write."""
    known = labels(role)
    if type(event) is not dict or set(event) != {"state", "group", "name"}:
        raise ValueError("unexpected webhook fields")
    if any(type(event[k]) is not str for k in event):
        raise ValueError("invalid webhook fields")
    key = event["group"] + "_" + event["name"].replace("_", "-")
    state = event["state"]
    if key not in known or state not in ("TRIGGERED", "RESOLVED"):
        raise ValueError("unexpected observer event")
    now = int(time.time()) if now is None else now
    db.execute("BEGIN IMMEDIATE")
    try:
        active = db.execute("SELECT active FROM targets WHERE key=?", (key,)).fetchone()
        was_active = bool(active[0]) if active is not None else False
        if state == "TRIGGERED" and not was_active:
            count = db.execute("SELECT COUNT(*) FROM outbox WHERE delivered_at IS NULL").fetchone()[0]
            if count >= MAX_QUEUE:
                raise ValueError("Telegram queue full")
            db.execute("INSERT INTO outbox(key, created_at) VALUES (?, ?)", (key, now))
            db.execute("INSERT INTO targets(key, active) VALUES (?, 1) "
                       "ON CONFLICT(key) DO UPDATE SET active=1", (key,))
        elif state == "RESOLVED":
            db.execute("INSERT INTO targets(key, active) VALUES (?, 0) "
                       "ON CONFLICT(key) DO UPDATE SET active=0", (key,))
        db.execute("DELETE FROM outbox WHERE delivered_at IS NOT NULL "
                   "AND delivered_at < ?", (now - 30 * 86400,))
        db.commit()
    except Exception:
        db.rollback()
        raise


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def secret(path, pattern):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 256:
        raise ValueError("invalid private credential")
    value = path.read_text(encoding="ascii").strip()
    if re.fullmatch(pattern, value, re.ASCII) is None:
        raise ValueError("invalid private credential")
    return value


def send_telegram(role, key, created_at, active, opener=None):
    token = secret(TOKEN_FILE, r"[0-9]{5,20}:[A-Za-z0-9_-]{20,200}")
    chat = secret(CHAT_FILE, r"-?[0-9]{1,30}")
    description = labels(role)[key]
    date = time.strftime("%d.%m.%Y %H:%M UTC", time.gmtime(created_at))
    suffix = "Сбой уже восстановлен." if not active else "Сбой подтверждён Gatus."
    mode = os.environ.get("GATUS_ALERT_MODE", "test")
    if mode not in ("test", "live"):
        raise ValueError("invalid alert mode")
    prefix = "[TEST Gatus]" if mode == "test" else "Gatus"
    message = (f"{prefix} · {role} · DOWN\nПроверка: {description}\n"
               f"Причина: условия проверки не выполнены.\n"
               f"Обнаружено: {date}\n{suffix}")
    payload = json.dumps({
        "chat_id": chat, "text": message, "disable_web_page_preview": True,
    }, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        "https://api.telegram.org/bot" + token + "/sendMessage",
        data=payload, method="POST",
        headers={"Content-Type": "application/json"},
    )
    client = opener if opener is not None else urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect,
    )
    with client.open(request, timeout=12) as response:
        if response.status != 200:
            raise ValueError("Telegram HTTP response not accepted")
        data = response.read(4097)
        if len(data) > 4096 or json.loads(data).get("ok") is not True:
            raise ValueError("Telegram response not acknowledged")


def send_one(db, role, sender=send_telegram):
    row = db.execute(
        "SELECT id, key, created_at FROM outbox "
        "WHERE delivered_at IS NULL ORDER BY id LIMIT 1"
    ).fetchone()
    if row is None:
        return False
    ident, key, timestamp = row
    active = db.execute("SELECT active FROM targets WHERE key=?", (key,)).fetchone()
    try:
        sender(role, key, timestamp, bool(active[0]) if active else False)
    except (OSError, ValueError, TypeError, KeyError, urllib.error.URLError,
            json.JSONDecodeError):
        return False
    # If the process dies between Bot API acceptance and this commit, retry
    # can send once again: at-least-once, never claim exactly-once.
    with db:
        db.execute("UPDATE outbox SET delivered_at=? "
                   "WHERE id=? AND delivered_at IS NULL", (int(time.time()), ident))
    return True


def evidence_threshold(key):
    if key == "observer_proxysignal-heartbeat":
        return 1
    if key in ("observer_proxysignal-required-coverage", "observer_hostland-https",
               "observer_cdn-xray-public", "observer_cdn-subscriptions-public"):
        return 2
    if key.startswith("panel_fast-"):
        return 1 if key == "panel_fast-fast-tick" else 2
    if key.startswith("panel_audit-"):
        return 1
    return 0  # Informational secondary Panel check has no alert.


def reconcile_results(db, role, statuses, now):
    """Recover dropped webhook transitions from pinned-Gatus persisted results.

    Only recent, allowlisted results count. Gatus errors/URLs are never logged
    or persisted. No HTTP success alone proves VPN connectivity.
    """
    if not isinstance(statuses, list) or len(statuses) > 64:
        raise ValueError("invalid Gatus result list")
    expected = labels(role)
    seen = set()
    for endpoint in statuses:
        if not isinstance(endpoint, dict):
            raise ValueError("invalid Gatus endpoint")
        key = endpoint.get("key")
        if key not in expected:
            continue
        if key in seen:
            raise ValueError("duplicate Gatus endpoint")
        seen.add(key)
        threshold = evidence_threshold(key)
        if not threshold:
            continue
        results = endpoint.get("results")
        if not isinstance(results, list) or not 1 <= len(results) <= 4:
            continue
        recent = []
        for result in results:
            if not isinstance(result, dict) or type(result.get("success")) is not bool:
                raise ValueError("invalid Gatus success field")
            stamp = result.get("timestamp")
            if not isinstance(stamp, str) or not stamp.endswith("Z"):
                raise ValueError("invalid Gatus timestamp")
            observed_at = datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()
            if observed_at < 0 or observed_at > now + 30:
                raise ValueError("future Gatus result")
            recent.append((observed_at, result["success"]))
        # Non-monotonic/malformed history is ambiguous, never report healthy.
        if any(a[0] > b[0] for a, b in zip(recent, recent[1:])):
            raise ValueError("out-of-order Gatus results")
        observed_at = recent[-1][0]
        max_age = 5 * 3600 if key.startswith("panel_audit-") else 1500
        if now - observed_at > max_age:
            continue
        success = recent[-1][1]
        streak = 0
        for _, value in reversed(recent):
            if value == success:
                streak += 1
            else:
                break
        current = db.execute("SELECT active FROM targets WHERE key=?", (key,)).fetchone()
        # Avoid reopening a delivered event while the Gatus alert is disarmed,
        # and avoid a high-frequency SQLite write on every 15s poll.
        if current is not None and bool(current[0]) == (not success):
            continue
        if success:
            if current is None:  # Healthy on first sight never needs a row.
                continue
            accept_event(db, role, {
                "state": "RESOLVED",
                "group": key.split("_", 1)[0],
                "name": key.split("_", 1)[1],
            }, int(now))
        elif streak >= threshold:
            accept_event(db, role, {
                "state": "TRIGGERED",
                "group": key.split("_", 1)[0],
                "name": key.split("_", 1)[1],
            }, int(now))


def reconcile(db, role, now=None, opener=None):
    now = time.time() if now is None else now
    client = opener if opener is not None else urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect,
    )
    with client.open(urllib.request.Request(GATUS_STATUSES, method="GET"), timeout=5) as response:
        if response.status != 200:
            raise ValueError("Gatus status API unavailable")
        data = response.read(MAX_GATUS_BODY + 1)
        if len(data) > MAX_GATUS_BODY:
            raise ValueError("Gatus response too large")
    reconcile_results(db, role, json.loads(data), now)


class Handler(BaseHTTPRequestHandler):
    role = None
    database = DB

    def log_message(self, format, *args):
        pass  # Avoid leaking headers, message bodies, tokens or Telegram URLs.

    def do_POST(self):
        self.connection.settimeout(5)
        try:
            if self.path != "/event":
                self.send_response(404)
                self.end_headers()
                return
            header = self.headers.get("X-Observer-Webhook-Key", "")
            if not header or not hmac.compare_digest(
                header, secret(WEBHOOK_FILE, r"[A-Za-z0-9_-]{32,128}")
            ):
                self.send_response(403)
                self.end_headers()
                return
            size = self.headers.get("Content-Length", "")
            if not re.fullmatch(r"[0-9]{1,4}", size) or not 2 <= int(size) <= MAX_EVENT:
                self.send_response(413)
                self.end_headers()
                return
            payload = json.loads(self.rfile.read(int(size)))
            with closing(connect(self.database)) as db:
                accept_event(db, self.role, payload)
            self.send_response(204)
            self.end_headers()
        except (ValueError, TypeError, OSError, json.JSONDecodeError, sqlite3.Error):
            self.send_response(503)
            self.end_headers()


def worker(role, stop, path=DB):
    while not stop.wait(RETRY_SECONDS):
        try:
            with closing(connect(path)) as db:
                if os.environ.get("GATUS_RECONCILE_ENABLED") == "true":
                    try:
                        reconcile(db, role)
                    except (OSError, ValueError, TypeError, KeyError,
                            json.JSONDecodeError, urllib.error.URLError):
                        print("Gatus relay: state reconciliation unavailable", file=sys.stderr)
                send_one(db, role)
        except (sqlite3.Error, OSError, ValueError):
            print("Gatus relay: queue delivery unavailable", file=sys.stderr)


def main():
    role = os.environ.get("GATUS_OBSERVER_ROLE", "")
    if role not in OBSERVERS:
        raise ValueError("invalid observer role")
    if os.environ.get("GATUS_ALERT_MODE") not in ("live", "test"):
        raise ValueError("missing explicit alert mode")
    if os.environ.get("GATUS_RECONCILE_ENABLED") not in ("true", "false"):
        raise ValueError("missing explicit reconciliation mode")
    secret(WEBHOOK_FILE, r"[A-Za-z0-9_-]{32,128}")
    with closing(connect()) as db:
        db.execute("SELECT 1")
    Handler.role = role
    stop = threading.Event()
    thread = threading.Thread(target=worker, args=(role, stop), daemon=True)
    thread.start()
    try:
        server = ThreadingHTTPServer(("0.0.0.0", 8080), Handler)
        server.daemon_threads = True
        server.serve_forever()
    finally:
        stop.set()
        thread.join(timeout=3)


if __name__ == "__main__":
    main()
