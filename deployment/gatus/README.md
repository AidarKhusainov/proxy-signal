# Staged Uptime Kuma → Gatus migration (ger1 Push, fin1 HTTPS Pull)

**Status: configuration prepared, NOT deployed.** Keep both existing Kuma instances and their DOWN-only Telegram adapters active until the entire acceptance gate passes. Keep ProxySignal on Hostland and all Remnawave checks unchanged. Current Kuma topology and rollback context: [deployment/README.md](../README.md) and [kuma-placement.md](../kuma-placement.md).

## Replacement scope

- ger1: Gatus external endpoint `observer_proxysignal-heartbeat` with bearer authentication and a 10-minute missed-heartbeat deadline; current Hostland watchdog still sends every five minutes, but initially **to Kuma**.
- fin1: Gatus HTTP GET of the existing Panel HTTPS URL, every five minutes, HTTP 200, two consecutive failed checks.
- Both: built-in Telegram DOWN alert (no recovery notification), SQLite, dedicated Compose project, unprivileged, read-only, no Docker socket or privileged mode. Bind only **127.0.0.1:3002**. Existing Kuma remains at 127.0.0.1:3001 during staging. No new public listener.
- This retains the present **monitor heartbeat vs Panel reachability** split. It does **not** add actual end-to-end VPN checks, which remain owned by Hostland ProxySignal.

## Safety prerequisites

1. Use the existing authorized `remnawave-infra` runner SSH mechanism with pinned host keys. Inspect both production nodes and Hostland **live**: CPU, available RAM, swap, free disk, current Docker containers and immutable IDs/start times, listening ports, networks, Panel HTTPS, Xray health, and the existing Kuma monitoring states. Abort on unexpected drift.
2. Resolve the official Gatus version and platform-correct OCI **@sha256 digest** on the runner. Pull the image on both nodes without building on a production VPN host. Inspect license/image provenance. The 128 MiB memory limit here is an initial admission limit, **not** a measured requirement; increase only after evidence and without starving RemnaNode. Verify image supports running as UID 65532 with SQLite under `/data`.
3. Create a dedicated `/opt/proxysignal-gatus-observer` directory on each node with `compose.yaml`, a private directory mode 0700 and `private/data` owned by UID 65532. Store an immutable image reference in a protected local `.env` as `GATUS_IMAGE=ghcr.io/twin/gatus@sha256:...`. Never commit secrets or paste tokens to logs.
4. Reuse the existing authorized Telegram bot/chat via **file-backed** `private/telegram-token` and `private/telegram-chat-id`. Do not pass tokens through Compose environment or CLI. For ger1, generate a new random URL-safe Gatus bearer token into a separate root-owned `/etc/proxysignal-gatus-push/token` (readable by the dedicated forced-command account; **do not reuse Kuma's token**). Generate `private/config.yaml` with `python3 render-config.py --role ger1 --private-dir private --push-token-file /etc/proxysignal-gatus-push/token` (or `--role fin1`). Run as root; private config becomes root:65532 0440. Do not log config contents.
5. Run `docker compose config --quiet` then start **only the new Gatus Compose project**. Inspect logs with secret redaction, the actual container image ID, database creation, local-only bound port and the existing production container start times. Verify HTTPS Pull from fin1 and authenticated Push locally on ger1 without changing the Kuma receiver.

## Push cutover (only after both Gatus instances pass parallel checks)

The current Hostland systemd watchdog runs `deployment/watchdog.py` and uses restricted SSH `kuma-push@ger1` with `SSH_ORIGINAL_COMMAND=heartbeat`. **Do not change Hostland's timer or watchdog.** The receiver on ger1 is what switches the destination:

1. Stage `ssh-push-receiver.py` at a **new**, root-owned, executable path `/usr/local/bin/proxysignal-gatus-push`, with the bearer token stored only on ger1. The receiver refuses all other SSH commands and only POSTs to Gatus over loopback. Keep original `/usr/local/bin/proxysignal-kuma-push` for rollback.
2. With a *separate, temporary test-only restricted SSH authorized key* (or an approved equally isolated local invocation), verify a single Gatus heartbeat arrives, including a denied arbitrary command. Do not alter production Ansible authorized_keys.
3. Back up the dedicated `kuma-push` account's authorized_keys. After positive Gatus acceptance, **pause the old Kuma Push monitor first** to avoid sending a false LIVE DOWN. Replace only the forced-command path in that dedicated key's restrictions, retaining `restrict`, pinned host key, `from=` restriction if present, and no interactive access. Do not modify the underlying key or the Hostland timer.
4. Confirm two separate scheduled 5-minute acknowledgements in Gatus, freshness of Hostland source/happ + eight profiles, and unchanged Panel/VPN listeners. If any acknowledgment fails, restore the old authorized_keys and resume Kuma Push.

## Notifications and retirement gate

- Gatus Telegram sends **DOWN only** (`send-on-resolved: false`), not UP. Confirm one labeled TEST DOWN per node and that recovery/repeated failures do not send additional messages. Run tests using separate disposable *synthetic* endpoints or a test bot/chat first: never deliberately impair live VPN, Panel or main ProxySignal. The built-in Telegram provider is different from the former private Kuma webhook adapter. Confirm actual Telegram acknowledgement.
- Verify Gatus observes actual **consecutive** 5-minute HTTPS checks, real Push records, missed Push detection, and persists SQLite state across restart; compare Telegram and observation history with the still-running Kuma.
- Measure **whole-container cgroup memory (idle and peak)** and CPU, disk, Docker/PID usage over multiple cycles; ensure both nodes have adequate available memory. Retire Kuma only if Gatus delivers equivalent coverage, thresholds and alerts, without resource regressions.
- Before retiring, back up both Kuma SQLite volumes consistently; do not delete backups or volumes. Stop/remove **only** the two isolated Kuma Compose projects and old adapters, and remove retired dedicated scripts/secrets only in an audited follow-up. No `docker compose down -v`. Do not modify RemnaNode or production networks.
- Rollback: restore original dedicated forced-command authorized_keys, resume Kuma Push, restart only isolated Kuma observers from their pinned prior image and persisted volumes, stop only Gatus, and verify the old 5-minute Push and HTTPS Pull are both UP. Preserve Gatus artifacts for diagnosis, without leaving two live Telegram alert pipelines indefinitely.

**Acceptance cannot be claimed from source changes or unit tests.** A live runner deployment and postflight with evidence is mandatory before replacing Kuma.
