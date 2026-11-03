# Hostland parallel deployment: manual review candidate

This Compose project is isolated from Remnawave. **Do not launch** until there is separate approval. Existing Remnawave monitoring remains active.

## Evidence already collected

- Hostland full-profile acceptance, three restarts and nine autonomous cycles per profile: https://github.com/AidarKhusainov/remnawave-infra/actions/runs/41576809949
- Live Telegram failure, no duplicate, recovery, durable queue: https://github.com/AidarKhusainov/remnawave-infra/actions/runs/41580063695
- Existing separate-outbound profile checks: https://github.com/AidarKhusainov/remnawave-infra/actions/runs/41531253099
- Observed peak: CPU 43.69%, memory 19.39 MiB, 19 PIDs. Laboratory cleanup completed.
- General HTTPS egress does not attest client inbound, CDN route, cascade hops or leastPing policy.

## Preconditions: NO-GO until satisfied

1. Perform a **new** read-only Hostland preflight using the existing remnawave-infra GitHub runner SSH mechanism with pinned host key: load, RAM, disk, Docker, containers, start times, networks, listeners and panel TLS health. Confirm the old lab container is absent. Do not alter production infrastructure.
2. Independently provision a missed-heartbeat monitor (such as Healthchecks.io) outside Hostland: **period 2 minutes, grace 8 minutes**, with independent Telegram/email notifications. Prove real missed-ping delivery with a provider-side test. Never assume the preexisting Remnawave watchdog is configured.
3. Build the image on a GitHub runner only. Publish it to a trusted registry and pin the resulting OCI **manifest digest** (sha256). Never build on Hostland or use a floating tag.
4. Privately prepare one HTTPS Happ subscription with the registered monitoring device and eight exact selectors from config.example.yaml; keep subscription URL/HWID/Telegram token and all secret header values outside Git. Use the approved Telegram chat and label ProxySignal notices as separate pilot notifications. No mutations to Panel, users, subscriptions or nodes.
5. Run offline watchdog tests and all existing Rust CI checks. Observe resources, Xray children and telemetry under the live Hostland limits before approval.

## Layout and secrets

Use /opt/proxy-signal-parallel/deployment for the Compose file and its private/config.yaml plus private/secrets/{hwid,user-agent,accept,telegram-token} (plus any other registered headers required by the subscription). The eight IDs are stable p01..p08. File permissions: private file owner root:65532, mode 0440, directories group 65532 mode 0750; prohibit world access. Never commit or print values.

The project name proxy-signal-parallel yields its own bridge network, container and persistent volume. No published ports, Docker socket, host network, or Remnawave mounts. The container runs as UID 65532 with read-only root, dropped capabilities, 0.5 CPU, 384 MiB and 64 PIDs. The service has restart policy and a small filesystem-based Docker healthcheck.

Store the separate watchdog URL at /etc/proxy-signal-parallel/watchdog-url with root ownership and mode 0600. Copy deployment/watchdog.py to /opt/proxy-signal-parallel/watchdog.py. Install the two systemd unit files into /etc/systemd/system. The host timer checks that Docker reports the separate container healthy **and** that source plus all eight profile records are fresh before sending the HTTPS ping. Actual VPN FAILED/UNKNOWN does not suppress heartbeat; those are delivered by ProxySignal. A host outage or frozen process stops heartbeats, which the independent external provider must alert on. Do not enable the timer until the external provider is configured.

## Image/start (ONLY after separate authorization)

In a private .env file set PROXYSIGNAL_IMAGE to ghcr.io/OWNER/proxy-signal@sha256:ACTUAL_MANIFEST_DIGEST (64 hex). Pull the reviewed digest once, verify no mutable tag is substituted, and run:

    docker pull "$PROXYSIGNAL_IMAGE"
    docker compose -f compose.yaml config --quiet
    docker compose -f compose.yaml up -d --no-build --no-deps

Wait for source/happ and all eight profile/happ/pXX records to be fresh, then:

    sudo systemctl daemon-reload
    sudo systemctl enable --now proxy-signal-parallel-watchdog.timer
    sudo systemctl start proxy-signal-parallel-watchdog.service

Confirm at least two provider heartbeat receipts, independent missed-ping notification, no duplicate alerts, preserved incidents, unchanged Panel containers, and no leaked Xray children. Do not simulate Hostland outages or stop production services.

## Update, rollback, removal

**Update:** Build and publish a new image on GitHub runner, run CI and Hostland preflight, securely back up only the isolated persistent volume, update the image digest, pull it and re-run up --no-build for this project. Verify fresh state, watchdog and Telegram. Never delete the volume during updates.

**Rollback:** Restore the previous image digest; restart only this Compose project. If state format changed, restore the matching private volume backup. Telegram is at-least-once, not exactly-once.

**Removal:** Disable the dedicated watchdog timer; docker compose -f compose.yaml down (never down -v by default). Revoke its external heartbeat URL, remove only the separate systemd files and private secrets with authorization. Delete the persistent volume separately only after approval and backup. Check old Remnawave monitoring is unchanged.

**Offline tests:** python3 -m unittest discover -s deployment/tests -p 'test_*.py' -v

**Status:** NO-GO until current Hostland preflight and independent external missed-ping delivery are verified. No persistent deployment is authorized by this PR.
