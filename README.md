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

## Optional DNS and routing scenarios (stage 3)

Set `scenarios` under a source only when you need a domain-specific check. Normal node monitoring is unchanged. Each scenario has a stable `scenario/<source-id>/<scenario-id>` result and incident state, separate from `profile/<source-id>`.

```yaml
sources:
  - id: test-profile
    kind: file
    path: /profiles/example.json
    scenarios:
      - id: direct-domain
        url: https://example.org/
        route: direct              # direct | proxy | block
        outbound_tag: direct       # exact tag from original Xray outbounds
        # Optional: use only when the full profile makes Xray resolve this domain.
        # DNS answers change; replace these illustrative values with known test data.
        # dns:
        #   server: "UDP:1.1.1.1:53"  # exact upstream label in Xray DNS logs
        #   expected_ips: [93.184.215.14]
```

A `direct` route requires a `freedom` outbound, `proxy` a proxy outbound (not `freedom`, `blackhole`, `loopback`, or `dns`), and `block` a `blackhole` outbound. Static tag/protocol compatibility is only an eligibility check; it is **not** proof of routing. Xray's own access log must show the diagnostic inbound selecting the expected outbound for that exact hostname and HTTPS port. For direct/proxy, the TLS-verified HTTPS request must succeed; for block, it must fail. A working HTTPS request without a matching access record is `UNKNOWN`, never `OK`. A confirmed wrong outbound or a failed request on the correctly selected direct/proxy route is `FAILED`.

If `dns` is specified, Xray must also produce diagnostic DNS records for the domain, exact upstream label, and expected A/AAAA answers. A mismatch is `FAILED`; missing or unparseable engine evidence is `UNKNOWN`. **The HTTP proxy does not force Xray's built-in DNS to resolve the domain.** Remote proxy resolution, system DNS, Xray cache, routing strategy and outbound DNS policy can mean no DNS evidence for this particular check. Such cases remain `UNKNOWN` and do not assert a resolver. DNS server names and answer sets are engine-reported evidence, not an independent packet capture of the DNS exchange. This check does not establish DNS-leak freedom or all upstream fallbacks.

The original `dns`, `routing`, `outbounds`, and rule ordering remain untouched. Temporary loopback inbound and private, size-limited Xray access/error logs are created for the test process only. Logs are not forwarded or printed and are deleted after child cleanup. Scenarios share the same per-profile time budget as egress checks. Balancer candidate and route probes start concurrently after Xray readiness, so a slow egress/scenario probe cannot starve them; timed-out checks remain `UNKNOWN`, not `OK`. Up to 8 scenarios per source / 64 total are allowed; scenario HTTPS host:port pairs must be unique within the source and must not overlap IP-echo endpoints to avoid misattributed log evidence. Use only operator-controlled test targets; no real secrets or production modifications are required. Neither access logs nor this stage prove a multi-hop cascade, balancing choice, physical DNS transport or CDN failover.

## Optional Xray balancer scenarios (stage 3)

Set `balancers` per source to inspect a named balancer in the complete Xray JSON. Existing profiles without these settings are unaffected. Up to 4 balancer scenarios per source, 8 across the configuration and 8 distinct candidates per source are supported. Test URLs must be HTTPS hostnames, unique across domain/balancer scenarios and separate from IP-echo endpoints.

```yaml
balancers:
  - id: latency
    url: https://example.com/
    balancer_tag: latency
    strategy: leastPing
    candidates: [node-a, node-b]   # exact matched outbound tags, not a node count
    fallback_tag: direct           # omit when profile has no fallbackTag
```

The static `balancer/<source>/<id>/config` observation checks the balancer tag, strategy, selector prefix expansion, exact candidate set, fallback and whether an observatory/burstObservatory covers the candidates. Xray still validates the full profile at startup. The `/candidates` observation performs separate TLS-verified HTTPS requests through each candidate using temporary loopback HTTP inbounds and inbound-specific routing rules in the **same supervised Xray process**. The main probe inbound retains the original routing decision path; these candidate probes do *not* prove that the balancer chose them. Confirmed partial outages are `DEGRADED`, all confirmed failures are `FAILED`, and missing/ambiguous Xray access records or exhausted time budget are `UNKNOWN`.

The `/route` observation uses the original routing to probe the configured HTTPS URL and requires an exact Xray access-log outbound tag. When attribution is possible, stdout reports `selected_candidate_index` (zero-based index into the configured `candidates` list) without printing raw outbound tags. Per-candidate observation keys similarly use `/candidate/0`, `/candidate/1`, etc. These indices are stable only while the candidate order is unchanged; reordering reassigns existing observation keys, so reset the corresponding candidate incident records before changing that order. When all candidates recover but leastPing policy remains unverified, the aggregate stays `UNKNOWN`, and the previous candidate-outage incident ends with an explicit `UNKNOWN` notice, never a misleading `OK`. A selected `fallback_tag` remains `UNKNOWN` because the access log cannot distinguish fallback from an ordinary choice. For conservative rule attribution, only a first, standalone `full:<test-host>` rule that uses the expected `balancerTag` qualifies; more complex production rule sets return `UNKNOWN/balancer_rule_not_attributable` rather than claiming proof. Even with a confirmed HTTPS request and selected candidate, `leastPing` and `leastLoad` return `UNKNOWN/balancer_policy_unverified`: the access log does not provide the observatory's measured delays or justify the choice. For `random` and `roundRobin` a confirmed candidate and request can verify **one** route selection, not long-term distribution or rotation. The aggregate `balancer/<source>/<id>` is `OK` only when config, all candidate checks and the route check are OK; a proven partial candidate outage stays `DEGRADED` even if route evidence is incomplete. No real switching or failover is asserted.

These diagnostics temporarily add candidate-only routing rules and loopback listeners, not production changes. Only trusted full Xray profiles are supported; log contents are private, bounded and deleted after Xray stops. Allow sufficient `timeout_seconds` for sequential candidate tests. The manual Docker smoke includes a synthetic direct/failed SOCKS candidate pair; it does not verify a remote VPN or leastPing's latency decision.

## Optional CDN / XHTTP scenarios (stage 3)

Configure `cdn` only for full Xray profiles whose VPN outbound uses XHTTP over TLS. This check does **not** configure CDN failover or modify any Xray route. Use a public, operator-approved HTTPS endpoint for the independent CDN probe, and a **different** HTTPS destination for a real request through Xray. Example:

```yaml
cdn:
  - id: edge
    endpoint_url: https://cdn.example.org/health
    expected_http_status: 404
    url: https://example.com/
    outbound_tag: vpn-xhttp
```

The outbound must explicitly use `streamSettings.network: xhttp`, `security: tls`, `tlsSettings.serverName: cdn.example.org` and an `xhttpSettings.path` beginning with `/`. When `xhttpSettings.host` is provided it must match the endpoint hostname; `mode` may be `auto`, `packet-up`, or `stream-up`. Insecure TLS is unsupported. The endpoint URL path and XHTTP path are **not** assumed to be the same: a CDN health URL may differ from the proxy transport URL. Static checks only validate the declared intent, not server-side configuration.

Each `cdn/<source>/<id>` has distinct `dns`, `tls`, `http`, `endpoint`, `config`, `tunnel`, `route`, and aggregate observations. The direct probe resolves public DNS and pins the results against DNS rebinding; it performs a TLS-verified HTTPS GET without redirects and checks **exact** HTTP status, including expected 4xx. Connection errors cannot always distinguish TCP refusal from TLS failure and use `cdn_tls_or_connect_failed` rather than claiming a specific certificate defect. Expired time budgets and unavailable evidence are not OK. The tunnel probe runs a real TLS-verified HTTPS request through the unchanged full Xray routing and requires an unambiguous access-log record for the expected outbound. Like cascade tests, only an exact first `full:<test-host>` routing rule permits conservative attribution.

Neither independent CDN GET nor the Xray access log proves a specific CDN edge or complete CDN transit: `/route` remains `UNKNOWN/cdn_route_unverified` without separate trusted evidence. Even when endpoint and tunnel are both OK, the aggregate remains `UNKNOWN`, **not** OK. A confirmed partial loss is `DEGRADED` if the other check is healthy; otherwise a confirmed loss is `FAILED`. A prior CDN endpoint/tunnel outage can retire with an explicit `UNKNOWN` notification once both recover, without announcing a fully verified path. Limits: 4 CDN scenarios/source, 8 total, unique tunnel destinations within the source. Tests use only public hostnames and no insecure certificate overrides. A live positive HTTPS-over-VPN acceptance test requires independently authorized test credentials; a synthetic failure cannot prove a working CDN tunnel.

## Optional Xray cascade scenarios (stage 3)

Set `cascades` under a source to check one ordered chain in the **original full JSON**. The `outbounds` list names the outbound selected by routing first, then every successive dialer; it is not a list of interchangeable nodes. Chains of 2–8 unique outbound tags are supported, with at most 4 scenarios per source / 8 total. IDs and HTTPS destination host:port pairs must not collide with other scenarios or egress endpoints.

```yaml
cascades:
  - id: two-hop
    url: https://example.com/
    outbounds: [entry, relay]  # entry's dialerProxy must point to relay
```

The `cascade/<source>/<id>/config` check validates unique outbound tags, protocol eligibility, **each link in its expected order**, a terminating final outbound, and contradictory dialer declarations. Cycles, missing hops and unexpected tails never pass. Xray `26.10.21` **removed** `proxySettings` and requires `streamSettings.sockopt.dialerProxy`. Legacy `proxySettings.tag` links are structurally inspected but explicitly `UNSUPPORTED/cascade_proxy_settings_removed` under the pinned runtime, not silently converted. The monitor never rewrites the chain.

The `/https` check makes a TLS-verified request through the unmodified routing path in the supervised Xray process. It requires the **first exact `full:<hostname>` routing rule** to select the chain's first outbound and an unambiguous Xray access record for that inbound and destination. Wrong selection or confirmed HTTPS failure is `FAILED`, missing/ambiguous evidence is `UNKNOWN`. Complex rules are conservatively `UNKNOWN` even when the HTTPS request succeeds.

The `/hops` result is **`UNKNOWN/cascade_hops_unverified`**: normal Xray access records prove the selected outbound but cannot attest each subsequent physical hop or its order. The aggregate stays `UNKNOWN` when configuration and HTTPS are both `OK` but hop proof is absent; a confirmed failed connection is `FAILED`. A previously confirmed HTTPS failure closes when HTTPS and its first outbound are verified again, but with an explicit `UNKNOWN` notification because intermediate-hop evidence remains missing. A failed hop attestation or unverified HTTPS does not qualify for that recovery. `OK` is reserved for complete proof and is not currently achievable for a general live profile without independent trusted per-hop evidence. Neither egress-IP differences nor the static dialer graph can replace that evidence. These tests do not measure hop latency, prove geographic location, simulate failures or validate CDN.

For an isolated manual integration test with two disposable Xray SOCKS relays and a real HTTPS request, build the image and run `sh scripts/smoke-cascade-docker.sh`. It creates an ephemeral Docker bridge without public ports, uses nonroot read-only resource-limited containers, inspects relay-side access logs, and removes everything afterward. Its **controlled test-side observations** verify the synthetic path but are deliberately not used as production telemetry. Do not run the script against a shared host without an approved preflight.

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

Incidents require **two matching consecutive** `FAILED` or `DEGRADED` outcomes per `source/<id>` or `profile/<id>`. An incident recovers only when its specific evidence is sufficient. A previously confirmed cascade HTTPS outage can retire on verified HTTPS recovery with an `UNKNOWN` notice while hop attestation stays unavailable. CDN endpoint/tunnel recovery follows the same rule. Unrelated or unverified `UNKNOWN`/`UNSUPPORTED` outcomes never close incidents, and a missing complete-route proof never sends an `OK` recovery. Telegram alerts are queued durably before sending (up to 128 pending transitions), retried next cycle on delivery failure, and sent once per transition (at-least-once delivery; duplicates are possible if the process crashes after Telegram accepts a message but before the acknowledgement is persisted). Durable history is limited to incident state and pending alerts, not per-check time series. This release does not implement retention/reporting of historical observations.

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

Offline tests cover full-profile retention, inbound-dependent unsupported paths, direct-egress false positives, multi-endpoint aggregation, incident confirmation and persistence. Run `sh scripts/smoke-docker.sh` on a host with Docker and outbound HTTPS. For the separate controlled two-hop test, run `sh scripts/smoke-cascade-docker.sh`. The synthetic smoke checks a **deliberately failed** VLESS egress, plus live Xray access-log evidence for a working direct route, blocked route, intentionally wrong route and missing DNS evidence. Expected scenario outcomes are `OK`, `OK`, `FAILED` and `UNKNOWN` respectively. The test deliberately uses no VPN credentials. A real positive VPN check with a non-production profile and a **different externally observable exit IP** is still required before production use.

## Additional coverage needed

- **DNS:** optional engine DNS-log upstream/A/AAAA matching is available when a profile actually triggers built-in DNS; the synthetic Docker smoke tests missing evidence, not a positive DNS upstream/answer. Independent packet-level confirmation and DNS-leak testing remain outside this block.
- **Routing:** optional HTTPS domain cases confirm the selected outbound via Xray access logs; IP-specific routing, client sniffing and full rule-order coverage remain outside this block.
- **leastPing/balancers:** optional candidate HTTPS availability and conservative route-tag evidence are implemented; observer RTTs, actual leastPing policy ranking and automatic switching remain unverified.
- **Cascades:** ordered graph and real HTTPS checks are available. Independently authenticated hop traversal remains unverified outside controlled tests.
- **CDN:** XHTTP/TLS configuration, DNS/TLS/HTTP endpoint reachability and full-Xray HTTPS tunnel checks are implemented. Confirmed CDN-edge traversal, alternative WS/gRPC transport checks and fallback switching remain unverified.
- **Failover:** controlled fault injection inside isolated test executions and evidence of automatic rerouting within a deadline; never modify production nodes or firewall.

All of these require separately defined scenarios and stronger engine/route telemetry. Remaining advanced guarantees require controlled test profiles and stronger engine telemetry.
