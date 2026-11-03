# ProxySignal parallel deployment: operating in parallel on Hostland

The operator authorized the isolated permanent parallel instance on 2026-11-03.
It is running **alongside**, not replacing, the existing Remnawave monitoring.
This does not authorize merging the PR or changing Panel, Xray, firewall,
VPN subscriptions, or the existing monitoring.

## Verified evidence

- Hostland 8-profile pilot, 9 scheduler cycles/profile, persistence and outage
  recovery: https://github.com/AidarKhusainov/remnawave-infra/actions/runs/41576809949
- Real Telegram incident transitions and dedup:
  https://github.com/AidarKhusainov/remnawave-infra/actions/runs/41580063695
- Read-only Hostland resource/Panel preflight:
  https://github.com/AidarKhusainov/remnawave-infra/actions/runs/41585457455
- Five-node Kuma placement inventory:
  https://github.com/AidarKhusainov/remnawave-infra/actions/runs/41588618734
- Verified isolated Kuma installation and private monitor provisioning:
  https://github.com/AidarKhusainov/remnawave-infra/actions/runs/41597231351
- Hostland parallel ProxySignal, eight stable full profiles all egress OK:
  https://github.com/AidarKhusainov/remnawave-infra/actions/runs/41597823123
- ger1 restricted SSH Push and active 5-minute systemd timer:
  https://github.com/AidarKhusainov/remnawave-infra/actions/runs/41599478590
- Two independent repeated UP observations, synthetic TEST DOWN, dedup,
  silent recovery and postflight on both nodes:
  https://github.com/AidarKhusainov/remnawave-infra/actions/runs/41599745470
- LIVE DOWN-only Telegram labels applied to two isolated adapters:
  https://github.com/AidarKhusainov/remnawave-infra/actions/runs/41600675811
- Postflight verifies pinned SSH rejects arbitrary commands, source and
  eight profiles remain fresh, live-only alert mode and unchanged VPN nodes:
  https://github.com/AidarKhusainov/remnawave-infra/actions/runs/41601014591

Egress OK is **not** proof of original inbound, CDN transit, cascade hops,
leastPing decision or a route of a specific hostname.

## Layout

- Hostland: separate `proxy-signal-parallel` Compose project, no public port,
  UID 65532, read-only root, 0.5 CPU / 384 MiB / 64 PIDs, independent volume.
- ger1: Kuma Push observer and restricted SSH receiver. Kuma listens
  **only on 127.0.0.1:3001**, receives a Push after healthy source/profile
  *freshness* checks every **5 minutes** on Hostland.
- fin1: Kuma HTTPS Pull observer, checks the existing panel URL every
  **5 minutes**. This measures Panel availability, not ProxySignal health.
- Both: distinct local SQLite volumes and protected webhook adapters for
  **DOWN-only Telegram**. UI only through authorized SSH tunnels.
  No privileged containers, host networking, Docker socket or new public ports.

See `kuma-placement.md` for measured capacity and fail-open/closed details.

## Before any changes on Hostland/production nodes

1. Via the existing remnawave-infra GitHub runner SSH mechanism, verify
   *current* CPU/RAM/disk, containers/start timestamps, network bindings,
   sockets, TLS and panel health. Check Hostland can reach ger1's existing
   SSH port 52222. Only use pinned SSH host keys from the inventory.
2. On each node, resolve an **official, known-good Uptime Kuma v2 slim image**
   and Python runtime image to **immutable OCI @sha256 manifests**, and
   record their digests in a private .env. No image builds on VPN nodes.
3. Give each observer its own Compose working directory and local SQLite
   volume. For the DOWN-only adapter, precreate private/down-alert-state
   owned by UID 65532 and the private secret files
   (telegram-token, telegram-chat-id, webhook-key) as root:65532 0440.
   Parent private directory must not be world-accessible.
4. Keep the Kuma container bound to localhost; verify Docker did not publish
   it on any other interface. Keep original Xray/RemnaNode containers and
   listeners unchanged. Do not touch existing Ansible authorized_keys.
5. Using an *authorized SSH tunnel*, initialize each Kuma admin account.
   Configure only one monitor: ger1 Push; fin1 HTTPS Pull.
   Send Push from Hostland every **5 minutes** and configure fin1's HTTPS
   Pull interval to **5 minutes**. On ger1, allow small Push timer jitter:
   use a 360-second maximum interval with 2 retries of 60 seconds each.
   Disable built-in recurring DOWN notifications; disable direct Telegram
   notification providers and use the local DOWN-only webhook instead.
   It should be configured to POST JSON to
   http://down-only:8080/notify with the header
   X-ProxySignal-Webhook-Key from the private webhook-key file.
   Give the configured monitor the exact KUMA_MONITOR_NAME in .env.
   Verify actual webhook fields with the pinned Kuma release before relying
   on the filter. Test only clearly labeled TEST events in the approved chat.

## Restricted SSH from Hostland to ger1

1. Generate a NEW dedicated Ed25519 key in a protected deployment
   environment, install its private half at
   /etc/proxy-signal-parallel/ssh/id_ed25519 on Hostland (root 0600),
   and install only the public half on ger1. The initial authorized
   deployment generated the key on an ephemeral GitHub runner, transferred
   it over pinned SSH and cleaned runner files. Never commit or log it.
2. Create a dedicated unprivileged ger1 account `kuma-push`, leaving the
   production Ansible account untouched. Install
   `deployment/kuma/ssh-push-receiver.py` at
   /usr/local/bin/proxysignal-kuma-push, executable and root-owned.
3. Configure only the dedicated account's authorized_keys with
   `restrict,command="/usr/local/bin/proxysignal-kuma-push"` (also restrict
   source IP with `from="..."` after verifying Hostland's actual egress
   address). No interactive shell, SSH port forwarding, agent, X11 or PTY.
4. Obtain the ger1 Kuma Push token from its authenticated UI. Store it
   **only** on ger1 in /etc/proxysignal-kuma-push/token readable by the
   dedicated account. The receiver accepts SSH_ORIGINAL_COMMAND=heartbeat
   and calls 127.0.0.1:3001, never a user-supplied URL.
5. Create pinned known_hosts on Hostland using the existing verified
   remnawave-infra SSH host-key procedure, not `StrictHostKeyChecking=no`.
   The watchdog service is already parameterized for the dedicated key.
6. Execute a controlled, labeled test handshake and verify an actual UP Push
   record on ger1, without sending a Telegram message for this success.

**Keep the watchdog timer disabled until the Kuma Push monitor exists and
the SSH endpoint has passed the controlled live acceptance.**

## Schedule and failure semantics

The Hostland systemd timer activates once every **5 minutes**.
The watchdog reads Docker container health and last observation timestamps
for source/happ and the eight stable profile/happ/pXX identities. If
the scheduler is stopped/stale, it does not call SSH. A fresh VPN
`FAILED` or `UNKNOWN` still permits the heartbeat; ProxySignal handles
those VPN alerts independently.

- First silence after a legitimate send: ger1 Kuma eventually reports
  DOWN, expected after roughly 8–10 minutes with retry/jitter settings.
- Hostland Panel HTTPS becomes unavailable: fin1 Kuma reports DOWN on
  its independent 5-minute HTTP(S) schedule; this does not imply the
  ProxySignal child process failed.
- A full Hostland outage may produce **two distinct** DOWN events; that is
  intentional independent evidence, not duplicate resend.
- The local webhook adapter forwards only DOWN transitions, never UP or
  periodic healthy events, and persistently suppresses repeated DOWN
  webhooks. Its Telegram delivery is **at-least-once** around a
  send-before-state-write crash; validate it instead of claiming
  exactly-once semantics.

## Runtime artifact provenance and drift

The 2026-11-03 Hostland deployment runs a locally named
`proxy-signal:parallel-<run-id>-<attempt>` image built on a GitHub
runner. Its compressed Docker image archive was SHA256-verified before
`docker load` on Hostland. **It is not an OCI manifest digest reference**;
do not interpret the Compose `PROXYSIGNAL_IMAGE` placeholder as proof that
the running image was published to GHCR. The run-specific image tag is
immutable by deployment convention, but Docker tags are intrinsically mutable.
Before any replacement, inspect the running container's image ID and
`/opt/proxy-signal-parallel/.env`; verify a reviewed build and image digest
or SHA256-verified artifact. Never run `docker compose pull` for the
runner-local image or substitute a floating tag. The source used for the
initial deployment is the reviewed commit
`8a222032766b5c8ed6715f40c725065a34127c0f`.

Both Kuma observers instead use externally retrieved pinned OCI image
digests. Their notification adapter code has since been updated in place
with tested `LIVE` DOWN-only behavior. A new PR commit does not implicitly
upgrade any running image or remote file; reconcile explicitly with a
fresh read-only preflight before changing production.

## Test / update / rollback / remove

Run locally/offline on the GitHub runner:

    python3 -m unittest discover -s deployment/tests -p 'test_*.py' -v

On the actual nodes, observe CPU/RAM/PID/SQLite footprint and compare
preflight/postflight production container start timestamps. Test only a
**monitor-level** heartbeat pause (not a production Docker/Hostland kill),
one DOWN Telegram delivery, silent recovery and suppressed duplicate.
No production traffic impairment is allowed.

For an approved upgrade, pin a new image digest, back up each independent
Kuma/ProxySignal volume, and update **only** its own Compose project.
For rollback, restore the former digest and its matching volume if a
migration changed stored data. For removal, disable the Hostland dedicated
timer; remove only the Kuma Compose projects, dedicated SSH key/account,
forced-command script and private secrets, retaining volumes until a
separately approved backup/delete step. Check Panel, firewall, listeners,
Xray and old Remnawave monitoring are unchanged.

**Status: GO for the approved parallel monitoring deployment as observed
2026-11-03.** No retirement of older Remnawave monitoring is authorized.
The checked-in PR remains open for review. This acceptance proves the observed
cycles and mock failure transitions, not multi-day memory stability or outage
of the actual Hostland server. Track ongoing RAM/PID and missing heartbeats.
The monitor's Telegram delivery is at least once, not exactly once.
