# Two-node Uptime Kuma deployment (retired; rollback reference)

**Superseded on 2026-11-03:** Gatus now provides the two observer checks. Old Kuma containers were removed but SQLite volumes and consistent archives remain for rollback. See [Gatus migration runbook](gatus/README.md) and [final production audit](https://github.com/AidarKhusainov/remnawave-infra/actions/runs/41614146392). The text below documents the former approved state, not live deployment.

## Evidence from live node inventory

2026-11-03 read-only remnawave-infra run:
https://github.com/AidarKhusainov/remnawave-infra/actions/runs/41588618734

| Node | vCPU | Available RAM MiB | Root disk free MiB | Panel HTTPS | Telegram HTTPS |
|---|---:|---:|---:|---|---|
| ger1 | 1 | 1324 | 13303 | HTTP 200 | HTTP 200 |
| nyc1 | 1 | 357 | 8911 | HTTP 200 | HTTP 200 |
| fin1 | 1 | 1189 | 7427 | HTTP 200 | HTTP 200 |
| msc1 | 1 | 443 | 8609 | HTTP 200 | HTTP 200 |
| swe1 | 1 | 1382 | 13436 | HTTP 200 | HTTP 200 |

All five hosts have Docker; TCP 3001 was not occupied. This is a single
snapshot, not capacity or provider-independence proof. Each currently hosts
production VPN services. Avoid swe1 (critical primary/CDN) and 1-GiB
nyc1/msc1. Accepted placement: **ger1 Push observer** and
**fin1 HTTPS Pull observer**. fin1 has a deliberately pinned RemnaNode version;
do not update/restart/remount any existing container to install Kuma.

## Check semantics

- **ger1:** Uptime Kuma Push monitor, receives a heartbeat from the
  already written ProxySignal Hostland watchdog ONLY if Docker reports
  healthy and all nine source/profile records are current. Fresh FAILED or
  UNKNOWN VPN states are not a loss of monitoring and are handled by
  ProxySignal Telegram incident logic.
- **fin1:** Uptime Kuma HTTPS monitor of the existing Hostland Panel HTTPS
  URL. This tests externally observed reachability of the panel, **not**
  ProxySignal process health or actual VPN route.
- Monitors operate independently with separate SQLite volumes and separate
  labels. Only confirmed DOWN events reach Telegram; not periodic OK, repeated
  DOWN, or UP recovery events. Uptime Kuma's built-in notification provider
  cannot be relied upon for DOWN-only filtering (upstream #4744). The
  **separate, private** `down-only` webhook adapter in the Compose template
  filters `heartbeat.status == 0` and suppresses repeated DOWN events.
  The adapter was accepted against the deployed Kuma with authorized
  Telegram in a clearly labeled TEST transition, and its mode was then
  explicitly switched to LIVE. Two distinct DOWN notices on a full
  Hostland outage are acceptable.

## Push transport: restricted existing SSH, no WireGuard

On both observers, keep Uptime Kuma bound exclusively to
**127.0.0.1:3001**, with no public listener or Docker socket. The Hostland
watchdog sends heartbeat **once every five minutes** over existing SSH
from Hostland to ger1 (inventory port 52222), with StrictHostKeyChecking=yes
and the repository-pinned host key. No VPN mesh or new public port.

Provision one NEW dedicated, unprivileged account `kuma-push` on ger1.
Put a newly generated, *dedicated* Hostland public key in that account's
authorized_keys with `restrict,command="/usr/local/bin/proxysignal-kuma-push"`,
plus a verified `from="HOSTLAND_EGRESS_IP"` restriction if applicable.
Never reuse or modify the ansible user's key. The forced command is
deployment/kuma/ssh-push-receiver.py, installed as an executable at the
specified absolute path. It reads a Kuma-generated push token from a
ger1-only file at /etc/proxysignal-kuma-push/token, validates its shape,
and sends a single HTTP GET to 127.0.0.1:3001. No remote shell, PTY,
TCP forwarding, SSH agent forwarding or user-provided URL is permitted.
The Hostland private key must be root-owned mode 0600 in
/etc/proxy-signal-parallel/ssh/, and known_hosts must be built with the
approved pinned host-key verifier, not with disabled host checks.
**Do not execute deployment on any production node before separate
explicit authorization and a checked rollback path.**

Preflight must first confirm Hostland can resolve and reach ger1's actual
SSH port and the installed SSH user/keys do not conflict with existing
Ansible automation. Failure to deliver SSH heartbeat is never an OK.
The receiver cannot be initialized until the first Kuma Push monitor has
been configured securely and produced a private token on ger1. The Kuma
webhook notification must target `http://down-only:8080/notify` on the
dedicated Compose network with its `X-ProxySignal-Webhook-Key` header;
never publish the filter on a host port.

On fin1 only outbound HTTPS to the existing panel is needed; the read-only
inventory already confirmed HTTP 200. Do not provide public web access to
its UI. Admin access to either Kuma must use a separately authorized
localhost SSH tunnel or other operator-approved management path.

## Trial bounds and rollback

- Resolve official Kuma v2 OCI manifest to a verified immutable digest
  before preparing Docker pulls. Use **separate Compose project and local
  SQLite volume per node**; never attach another project's volume.
- Initial candidate limits: 0.5 CPU, 384 MiB RAM, 128 PIDs and bounded
  Docker logs per Kuma; validate actual cold-start memory before adoption.
  A limit is not proof that the service fits; abort if it OOMs or impacts
  VPN workloads. Prefer a supported official slim image if verified.
- Monitor only one Push or HTTPS target each, with conservative interval
  and retry/grace (5-minute sender interval; configure Push monitor timeout/retries to tolerate small scheduling delays, targeting approximately 8-10 minutes of silence before DOWN).
- First test local UI via SSH tunnel, expected monitor state, authorized
  isolated TEST-only Telegram, intentional *monitor-only* missed heartbeat,
  restoration, and duplicate suppression. Do not stop production nodes,
  Hostland or the Remnawave monitor to simulate failure.
- Postflight: verify CPU/RAM/PID/disk trends, new services' localhost-only
  bindings, unchanged production Docker start times, node health and
  original firewall/listeners. Do not leave a long-running trial without
  explicit operator approval.

Removal stops and removes only each dedicated Kuma Compose project and
(optionally, after backup and permission) its dedicated local volume.
Never remove or restart production remnanode/Xray/Remnawave containers.

**GO for the authorized parallel installation (2026-11-03):** both isolated
Kuma instances are running, ger1 receives authenticated restricted SSH Push,
fin1 checks Hostland HTTPS independently, and both LIVE down-only adapters
have been verified. See Actions runs
[41599745470](https://github.com/AidarKhusainov/remnawave-infra/actions/runs/41599745470)
and [41601014591](https://github.com/AidarKhusainov/remnawave-infra/actions/runs/41601014591).
This does not establish complete VPN-path correctness, a real Hostland power
failure test, or multi-day resource stability. Never disable the existing
Remnawave monitor. PR merge remains a separate operator action.
