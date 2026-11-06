# Staged Uptime Kuma → Gatus migration (ger1 Push, fin1 HTTPS Pull)

**Status: PRODUCTION MIGRATION COMPLETED, 2026-11-03.** Both old Kuma containers and DOWN-only adapters were stopped and removed, with Docker volumes left intact. Gatus is actively monitoring on both nodes. No public ports were introduced; RemnaNode, Hostland ProxySignal and the original Remnawave monitoring were preserved.

## Autonomous Hostland Panel and infrastructure reports (#160)

The existing **ger1** Gatus supports the production-specific collector in [remnawave-infra #160](https://github.com/AidarKhusainov/remnawave-infra/issues/160). No Panel/Backupable infrastructure contract is added to the generic ProxySignal Rust engine.

When explicitly rendered with `--role ger1 --panel-monitor --enable-alerts`, the generator adds **17 five-minute** external `panel_fast-*` results (Panel/Auth/Caddy and eight critical component-related checks, protected metrics, five pinned nodes, actual active subscription and worker tick) and **four three-hour** `panel_audit-*` results (host, firewall, Backupable desired state and audit tick). Gatus accepts complete reports sent by the existing restricted SSH `kuma-push` identity. The receiver rejects unexpected commands, missing/duplicate checks and incorrect worker ticks. Each endpoint uses a derived independent HMAC bearer token held only by ger1; the Hostland collector never receives a Gatus secret. Gatus remains bound to `127.0.0.1:3002`, without a new public API, socket or remote shell.

The `--panel-monitor` flag creates endpoints **without new Telegram alerts**. After guarded real runtime acceptance, `--panel-alerts` independently enables DOWN-only Telegram for these endpoints; other pre-existing alerts are unchanged. A fast component needs two failed reports; worker ticks and three-hour desired-state results alert on the first failed/missing observation. Each endpoint retains its own incident. A correctly delivered `FAILED` means a service is unhealthy, **not** that the worker stopped; a missed tick is separate evidence of silence. A successful HTTP 200 for Panel or CDN is not proof of internal component, authenticated subscription or VPN health.

The collector, expected Remnawave node UUIDs, protected database query, Caddy/Auth verification, infrastructure checks and systemd timer ownership belong exclusively to **remnawave-infra**. The pinned UUID baseline is never auto-reconciled. Ansible remains the manual infrastructure diagnostics interface. Backupable desired state does not establish backup freshness/restorability. Total loss of ger1 Gatus itself needs the separate cross-observer coverage owned by #161.

The old `panel-active-state.yml` schedule remains enabled through the coordinated #158 cutover. Deploy/rollback only through the scoped, source-SHA-reviewed production procedure in the infrastructure repository; retain its private original Gatus renderer/receiver/config backup. Never replace an operating monitoring configuration based solely on generated YAML or mock tests.

**Issue #160 runtime acceptance:** [remnawave-infra Actions 42200197275](https://github.com/AidarKhusainov/remnawave-infra/actions/runs/42200197275) verified the existing ger1 Gatus with 21 external Panel/audit results, two real Hostland fast cycles and one audit, actual isolated Telegram TEST acknowledgement, persistence across a Gatus-only restart, and unchanged non-monitoring containers. Measured Gatus cgroup resource usage: 0.02% CPU, 8.348 MiB / 128 MiB RAM, six PID. The original Gatus renderer/receiver/config and Hostland rollout journal remain in protected local backup. No legacy scheduled checks were disabled.

## Issue #161: reliable alerts and independent coverage (staged)

**Not deployed from this branch.** The production Gatus instances currently use
their built-in DOWN-only Telegram provider. The following is an opt-in
monitoring-only migration; it does not change Panel, Xray, VPN or legacy checks.

- ger1 gets `observer_proxysignal-required-coverage` independently of the
  existing `observer_proxysignal-heartbeat`. When the checker is alive,
  the Hostland watchdog may add `--send-coverage` after the receiver/config
  upgrade. A fresh FAILED VPN observation does not mark the scheduler dead;
  missing, stale, UNKNOWN, UNSUPPORTED or FAILED mandatory evidence is a
  separate false coverage result. The old single-word `heartbeat` remains
  backward-compatible.
- A tiny optional `durable-compose.yaml` overlay runs one unprivileged
  64 MiB / 0.1 CPU local notifier with **no published port**. Use a verified
  immutable `GATUS_NOTIFIER_IMAGE` reference and an explicitly selected
  `GATUS_OBSERVER_ROLE=ger1|fin1` and `GATUS_ALERT_MODE=live|test`.
  Create `private/alerts-data` owner UID 65532 (0700) and a new random
  32+ character root:65532 file-backed `private/webhook-key` (0440).
  Existing bot token/chat files are read-only mounts.
- Render with `--enable-alerts --durable-alerts`, keeping any existing
  ger1 panel-monitor flags from #160 intact. Gatus's supported *custom*
  provider posts only static endpoint keys and trigger/recovery events to
  `http://durable-down:8080/event` with the protected key header.
  Internally `send-on-resolved: true` rearms the notifier. Externally the
  notifier sends **only confirmed DOWN** in Russian; recovered is silent.
  The original ProxySignal independently retains Russian recovery notices.
  No raw Gatus error, subscription URL or Telegram token enters the relay DB.
- A triggered DOWN is inserted into durable SQLite before the Gatus webhook
  succeeds. Duplicate/retried triggers, including after restart, are
  suppressed until a confirmed RESOLVED event rearms the endpoint. The
  pending outbox retries every 15 seconds until the Telegram Bot API returns
  `ok:true`. A crash after Telegram ACK but before DB ACK can replay once;
  at-least-once, not exactly-once. Delivered rows older than 30 days are
  pruned while active incidents remain.
- The existing ger1 restricted SSH receiver also gains an allowlisted
  `status` command that exports only endpoint keys, result timestamps and
  success booleans. fin1 requires a distinct restricted read-only
  `gatus-status` SSH account/key on its **actual 53819 SSH port**. No
  public listener, unrestricted shell, raw response or shared token.
- The pinned Gatus heartbeat timer ticks at **10-minute intervals** for a
  10-minute missed-update deadline. A stale signal can therefore be detected
  at a later ticker tick (worst nominal phase approaches 20 minutes before
  transport/notification delay). The exact runtime upper bound and
  restart behavior require isolated fault-injection and live evidence;
  `interval: 10m` is not a ten-minute alert guarantee.

**Safe order:** inspect the actual current remote renderer and receiver,
especially concurrent #160 changes; checkpoint original files and take
consistent Gatus SQLite backups; stage the backward-compatible receiver and
notifier overlay **without** changing Gatus alerts; prove TEST Telegram
delivery, failed-send retry, forced-command rejection and data persistence;
switch the Gatus *config only* to the custom provider and restart Gatus only;
enable the coverage flag after two successful monitored records; verify
normal actual alert recovery/dedup and the live pinned-SSH heartbeat. Roll
back the notifier and renderer/config with Gatus-only restart if needed,
keeping the original Telegram alert path and existing protected SQLite.
Do not use production service failures as an alert fixture.

See [#161 integration rollout](https://github.com/AidarKhusainov/remnawave-infra/pull/189)
for read-only collectors, 04:27 UTC summary and independent Gatus-silence
observation. Extended observation is a separate later stage after deployment
and basic runtime acceptance.

## Independent public CDN canaries (#159)

The existing **fin1** Gatus generator adds two independent HTTPS checks in the `observer` group. No additional container or public listener is needed.

| Gatus endpoint key | Public URL | Result contract |
| --- | --- | --- |
| `observer_cdn-xray-public` | `https://cdn-swe1.censor-amoroso.com/generate_204` | Exact HTTP 204 |
| `observer_cdn-subscriptions-public` | `https://sub.censor-amoroso.com/generate_204` | Exact HTTP 204 |

Production acceptance on 2026-11-06: [guarded fin1 Gatus rollout and real Telegram TEST](https://github.com/AidarKhusainov/remnawave-infra/actions/runs/42187456240) verified separate success results for both endpoints at approximately 08:25 and 08:30 UTC, a Gatus-only restart, unchanged other containers and 0.02% CPU / 8.875 MiB / 7 PID. The pre-change observer config and renderer were backed up privately on fin1; no VPN service was restarted. [Pinned real-Gatus CI with full rendered-YAML parse](https://github.com/AidarKhusainov/proxy-signal/actions/runs/42187065363) covers negative status/TLS/DNS cases, incident isolation and restart recovery. The first guarded deployment attempt rejected an unquoted YAML description; the previously running observer was restored and the actual generated YAML is now tested in CI.

Each is a five-minute GET with a 10-second timeout, valid hostname/TLS required and redirects disabled. HTTP 200, 3xx, DNS/TLS failure and timeouts are failures. Independent Telegram incidents are armed only with `render-config.py --role fin1 ... --enable-alerts`, after two consecutive failed results; one successful result resolves the incident silently (`send-on-resolved: false`). Normal successes and repeat failures produce no extra notification. The existing `observer_hostland-https` and ger1 heartbeat remain independent.

Render the config using existing protected file-backed Telegram credentials. Deploy only after read-only runtime inspection, immutable-source review, saved original config/renderer, Gatus-only restart and verified fresh results; recover from the protected pre-deployment snapshot if acceptance fails. The Gatus API/SQLite must be inspected after restart: a previously stored success is not a fresh successful observation. No separate CDN monitoring stack, public port or provider mutation is required.

These public `/generate_204` checks do **not** establish VLESS/XHTTP tunnel operation, successful authenticated subscription issuance or Russian ISP reachability. The previous `public-edge-availability.yml` schedule in `remnawave-infra` remains enabled until the coordinated final cutover in #158.

Verified evidence:

- [Read-only production preflight](https://github.com/AidarKhusainov/remnawave-infra/actions/runs/41610412123)
- [Parallel Gatus installation, alerts disarmed](https://github.com/AidarKhusainov/remnawave-infra/actions/runs/41611663733)
- [Functional authenticated heartbeat and HTTPS acceptance](https://github.com/AidarKhusainov/remnawave-infra/actions/runs/41611916261)
- [Isolated TEST-only Telegram DOWN delivery on both nodes](https://github.com/AidarKhusainov/remnawave-infra/actions/runs/41612160611)
- [ger1 restricted SSH / Hostland watchdog cutover](https://github.com/AidarKhusainov/remnawave-infra/actions/runs/41612738150)
- [fin1 HTTPS alert cutover](https://github.com/AidarKhusainov/remnawave-infra/actions/runs/41612967295)
- [Fresh successful Gatus observations and systemd timer](https://github.com/AidarKhusainov/remnawave-infra/actions/runs/41613426253)
- [Final read-only post-retirement audit, both SQLite archives SHA256-verified](https://github.com/AidarKhusainov/remnawave-infra/actions/runs/41614146392)
- [Verified cleanup of abandoned duplicate backup and temporary staging archive](https://github.com/AidarKhusainov/remnawave-infra/actions/runs/41614532281)

The actual OCI Gatus image is pinned in each node's private `.env` as `ghcr.io/twin/gatus@sha256:085ed63da963728965d00a3c78aa6167e3bf135218485b893201758e079e8415`. No container image was built on VPN hosts. The 128 MiB memory limit remains a cap, not a guarantee of maximum measured RSS; final observed container cgroup usage was **7.328 MiB on ger1** and **7.008 MiB on fin1**. Multi-day leak stability is not yet established.

Operational state:

- `ger1`: the original five-minute Hostland timer and key remain; the dedicated `kuma-push` account's single restricted authorized key now forces `/usr/local/bin/proxysignal-gatus-push`. Original authorized_keys is backed up as root-only `/etc/proxysignal-gatus-push/kuma-authorized-keys.backup`. The new token exists only on ger1. The Gatus external endpoint monitors missing heartbeat; its secondary Hostland HTTPS check is informational, not an additional Telegram alert.
- `fin1`: Gatus HTTPS Pull checks the existing Panel URL on a five-minute schedule and alerts only on confirmed DOWN. Gatus Telegram alerts use the upstream message template, which is not fully Russian.
- Both: local-only Gatus port `127.0.0.1:3002`, separate SQLite data, normal production RemnaNode unchanged. Old Kuma was paused before retirement, so it must be explicitly resumed if rolled back. No `docker compose down -v` was used.
- The old Kuma Compose files, images, dedicated SSH receiver, tokens and Docker volumes were deliberately retained for rollback. Consistent stopped-state Kuma SQLite archives are held under `/var/backups/proxysignal-kuma-to-gatus-20261103-retry/` on ger1 and `/var/backups/proxysignal-kuma-to-gatus-20261103/` on fin1, root-only. The redundant first-attempt ger1 archive and temporary staging TAR were removed only after verifying the replacement backup checksum and active services.
- This does not establish end-to-end VPN availability from Russian ISP networks. Such tests remain ProxySignal's responsibility on Hostland.

**Rollback**: disable live Gatus Telegram alerts with `render-config.py` without `--enable-alerts` and restart only Gatus; on ger1 restore the backed-up single forced-command authorized_keys preserving owner/mode, start the old Kuma Compose project from its pinned image and unchanged Docker volume, then use the authenticated, SSH-tunnel-protected Kuma Socket.IO procedure to resume its Push monitor. On fin1 restore the old Kuma Compose project and resume its HTTPS monitor. Verify two fresh UP observations, pinned Hostland heartbeat, Telegram alerts, and unchanged VPN containers. Never restore a live SQLite database by copying over an open file.

The sections below are the safe migration procedure retained for upgrades or rollback context; they describe the staged sequence originally followed, not the current live state.

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
