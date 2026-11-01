# ProxySignal

Small, self-hosted monitor for Xray JSON profiles. One container runs a Rust scheduler and starts the **official Xray-core 26.10.21** binary only while checking a profile. No privileged container, web UI, panel integration, or external database.

## What is actually verified

For each configured source, ProxySignal reads a **complete Xray JSON object**, replaces the original inbounds with one loopback HTTP diagnostic inbound, and runs the complete config in a supervised Xray process. It retains `dns`, `routing`, `outbounds`, `observatory`, `burstObservatory` and routing balancers without extracting one outbound. HTTPS CONNECT requests are executed *through Xray* to configurable IP-echo endpoints. The result is compared with a direct request from the same container to the same endpoint:

- `OK`: all HTTPS checks returned valid public exit IPs different from direct egress; if `expected_exit_ips` is set, the returned IP must also match it.
- `DEGRADED`: at least one endpoint verifies different egress, but not all do.
- `FAILED`: every endpoint was reachable directly but the proxied check failed or did not match allowed exit IPs.
- `UNKNOWN`: insufficient evidence (for example, direct baseline unavailable or the exit IP is identical). Xray startup failure is also `UNKNOWN`.
- `UNSUPPORTED`: the JSON cannot be safely adapted (inbound-dependent rules, API/listener semantics, no actual proxy outbound, invalid shape). Unsupported is never converted to success.

Separate `source/<id>` checks monitor JSON retrieval and parsing. Their `FAILED` status indicates **source unavailability, not a proven VPN outage**. Configured HTTPS sources return one complete Xray JSON document, **not** base64 URI lists, links, Clash/sing-box JSON, or vendor-specific subscription envelopes. No caching of unavailable subscriptions yet.

**Limitations:** Exit-IP difference is evidence for this single HTTPS scenario, not definitive proof of the selected Xray outbound, internal DNS server, expected route for other domains, balancer candidate, cascade chain, CDN behavior, `leastPing` policy, or automatic failover. Profiles with inbound-dependent routing or enabled inbound sniffing are rejected instead of being silently modified. The diagnostic inbound may have different sniffing context than a real client. Only operator-controlled trusted Xray profiles should be used; a child process inside the same container is not a security sandbox. A local monitor cannot verify its own host outage: use a separate watchdog.

The direct/proxied comparison calls an **operator-configured external HTTPS IP-echo endpoint**. Native direct requests resolve hostnames once, reject non-public DNS answers and pin the resolved addresses to limit DNS-rebinding/SSRF exposure; this cannot sandbox arbitrary operator-supplied Xray configurations. It does not need a paid service or proprietary backend, but an actual target is needed to measure external connectivity. If the direct path to the echo endpoint is blocked, result is `UNKNOWN`, not `OK`. Prefer at least two independent echo endpoints when available. Set `expected_exit_ips` for stronger expected-egress evidence; dynamic-exit nodes may need the list updated.

## Deploy

```sh
cp config.example.yaml config.yaml
mkdir -p profiles secrets
cp examples/example.json profiles/example.json
# Replace profiles/example.json with a real, authorized full Xray client JSON.
# Ensure the host files and directories are readable by UID 65532.
docker compose up -d --build
# Check observations (no credentials or raw config should be logged):
docker compose logs -f proxy-signal
```

The included `examples/example.json` contains **only a direct outbound** and intentionally reports `UNSUPPORTED`; it is a safe negative example, **not** a working VPN profile. Store actual Xray JSON only under `profiles/`; do not commit it. For authenticated HTTPS JSON subscriptions add a `kind: https` source with an HTTPS hostname and header-name-to-secret-file mappings. For an Authorization bearer token, the file contains the entire header value, e.g. `Bearer <token>`. Secrets are never put in command arguments or logs. Set token file permissions to `0400`/`0440` as appropriate for UID 65532. If Telegram is enabled, provide its token in a file and a chat ID; otherwise results only go to stdout.

One cycle can be run manually with `proxy-signal /etc/proxy-signal/config.yaml --once` (nonzero exit if any check is not `OK`). Defaults/limits are explicit in YAML: interval 30–86400 seconds, per-profile deadline 5–60 seconds, concurrency 1–4, at most 32 sources and 3 echo endpoints. Profile inputs are limited to 512 KiB, echo bodies to 64 bytes, response redirects disabled, and TLS certificates verified. Process output is suppressed to prevent credential leakage. Container has read-only root, no privileges, limits on processes, memory, CPU and temporary disk. The persistent `/data` directory is pre-owned by the unprivileged UID, including on first volume creation. Persist `/data` to retain incidents; never run two replicas sharing the same state file.

Incidents require **two matching consecutive** `FAILED` or `DEGRADED` outcomes per `source/<id>` or `profile/<id>`. Only an `OK` observation closes an active incident. `UNKNOWN` and `UNSUPPORTED` never close one. Telegram alerts are queued durably before sending (up to 128 pending transitions), retried next cycle on delivery failure, and sent once per transition (at-least-once delivery; duplicates are possible if the process crashes after Telegram accepts a message but before the acknowledgement is persisted). Durable history is limited to incident state and pending alerts, not per-check time series. This release does not implement retention/reporting of historical observations.

## Development and acceptance

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets
# In an environment with Docker and a test VPN profile:
docker compose build
docker compose run --rm proxy-signal /etc/proxy-signal/config.yaml --once
```

The Docker build uses the checked-in `Cargo.lock` with `--locked`, digest-pinned Rust, Debian and official Xray base images, and a pinned trust store. This fixes dependency and base-image resolution for repeatable builds; it does not promise bit-identical binaries across different host platforms or environments.

Offline tests cover full-profile retention, inbound-dependent unsupported paths, direct-egress false positives, multi-endpoint aggregation, incident confirmation and persistence. Run `sh scripts/smoke-docker.sh` on a host with Docker and outbound HTTPS to validate image construction, supervised Xray startup, full-profile execution and a **deliberately failed** synthetic VLESS connection without production credentials. It must report `FAILED`, never `OK`. A real positive VPN check with a non-production profile and a **different externally observable exit IP** is still required before production use.

## Additional coverage needed

- **DNS:** capture the resolver actually used and prove expected A/AAAA answers and DNS routing; exit-IP alone is insufficient.
- **Routing:** domain/IP cases with expected outbound selection and engine evidence (tag/counters); cover direct-vs-tunnel, rule ordering, and sniffing differences.
- **leastPing/balancers:** identify selected candidates and observations, evaluate policy and switching, not just that one candidate works.
- **Cascades:** verify each hop individually with independent evidence, not just ultimate exit IP.
- **CDN:** dedicated TLS/SNI/WS/gRPC transport checks, reachability from monitoring locations, and expected CDN edge or fallback path.
- **Failover:** controlled fault injection inside isolated test executions and evidence of automatic rerouting within a deadline; never modify production nodes or firewall.

All of these require separately defined scenarios and stronger engine/route telemetry. They are intentionally not claimed or implemented in this first PR.
