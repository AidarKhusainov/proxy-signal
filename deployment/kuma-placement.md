# Two-node Uptime Kuma proposal (review-only)

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
nyc1/msc1. Proposed trial placement: **ger1 Push observer** and
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
  Telegram identities/labels. Send only transition-to-DOWN notifications,
  not periodic OK, repeated DOWN, or UP recovery events (verify the exact
  notification options of the deployed Kuma release; a filtering webhook
  may be needed). Two distinct DOWN messages on full Hostland outage are
  expected. Do not introduce a shared coordination service solely to suppress
  these two independent failure signals.

## Security gate: protected Push ingress is NOT yet provisioned

Kuma's default HTTP server listens on port 3001. A free port DOES NOT mean
a remotely reachable HTTPS service. For each node, keep the container
bound only to **127.0.0.1:3001**. Never publish the UI on the public
interface or attach the Docker socket. For ger1, the Push endpoint needs a
*separately reviewed* authenticated and TLS-verified transport from Hostland,
such as a pre-existing private inter-node network or a tightly scoped ingress
that exposes ONLY the secret-bearing /api/push/<token> route. Do not hijack
Remnawave's 443/Xray listener, change node firewall, or create a public
reverse proxy without separate approval and a host-specific route review.
TLS host key/name verification must remain on. Treat the push URL as a
credential and keep it in a root-owned 0600 file at Hostland.

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
  and retry/grace (about 2-minute heartbeat; 5-8-minute outage threshold).
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

**NO-GO:** The Push ingress and DOWN-only notification behavior remain to
be designed/verified. This document does not authorize deployment.
