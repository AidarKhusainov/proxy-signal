# Architecture and engineering boundaries

Status: guiding design, subject to validation in M0.

## Deployment model

One self-hosted Rust controller, with the official Xray-core binary available as a subprocess for checks that need Xray semantics. Native probes do **not** start Xray. No web UI, public listener, privileged container, host networking, Docker socket, external DB or separate metrics stack by default.

Start as **one Cargo package/binary**. Extract modules only when responsibilities become real. No microservices, plugin framework, invented generic traits or premature DI layer.

## Logical boundaries (not a required folder tree)

| Responsibility | Owns | Must not own |
| --- | --- | --- |
| Sources/config | local/HTTPS input, size limits, credential handling, source identity | network probing or alerts |
| Profile model | validated profile metadata and capability/evidence expectations | executing network operations |
| Probes | bounded native HTTP/DNS/TLS checks and Xray-backed test scenarios | persistent incident policy |
| Xray executor | safe child process lifecycle, prepared config, readiness, timeouts, cleanup | alert delivery or product policy |
| State | durable observations, incidents, retention, stale status | protocol-specific assumptions |
| Notifications | Telegram delivery/retry and safe formatting | deciding whether VPN really works |

These are separation rules, **not** instructions to create six crates. Prefer simple function calls and concrete types. Add interfaces when a real I/O/security boundary or second implementation warrants them.

## Full-profile verification

Executing an isolated outbound is useful but cannot be labeled a full-profile check. For a full Xray JSON probe, preserve DNS, routing, balancer/observatory, outbound semantics and rule ordering. Only a documented, minimal set of changes (e.g. adding a local diagnostic inbound and adjusting local bind addresses) may be applied.

If inbound-specific matching would change meaning, or evidence cannot show the selected path, report UNSUPPORTED/UNKNOWN rather than alter routing or invent proof. Probes must declare what they prove; status codes alone are insufficient for routing claims.

### Inbound sniffing in Xray probes

An isolated loopback HTTP inbound replaces every original listener. When all original
inbounds have the same enabled sniffing object, its `destOverride`, `routeOnly`,
`metadataOnly`, `domainsExcluded` and `ipsExcluded` are copied unchanged.
The official Xray engine applies these settings, not a Rust reimplementation.
Disabled sniffing is not enabled by the probe. Conflicting or malformed sniffing
settings are unsupported. If the profile has inboundTag rules, the diagnostic
inbound keeps the tag of the first original inbound, leaving the routing rules
unchanged. This verifies only that selected inbound's diagnostic HTTP path;
other original inbounds, their authentication and their client behavior remain
unverified. Rules based on client source, user or attrs are unsupported.
Protocol-sensitive routing is executed by Xray with the copied sniffing policy,
but still does not establish equivalence to the original client.

Successful HTTPS and exit-IP checks establish behavior **through the diagnostic
HTTP inbound**, not the original Happ/SOCKS/TUN client's inbound semantics.
The selected route requires an independent Xray access-log observation for the
specific request. When it is missing or ambiguous, routing remains UNKNOWN even
if HTTPS succeeds. Checking the client's exact inbound behavior requires a separate
controlled client test; no synthetic egress result proves it.

Probes that intentionally modify routes to simulate a failed candidate are **simulation** checks, not proofs of automatic failover in an unchanged client. Live network impairment requires separate isolated execution and explicit opt-in; never modify the host firewall or production nodes.

### Independent outbound diagnostics

For an optional `scenarios[]` check, `independent_outbound: true` adds a
temporary loopback HTTP inbound with a rule selecting exactly the configured
`outbound_tag`. The original Xray outbounds, transport settings, DNS, dialer
dependencies and normal diagnostic inbound rules are retained. A successful
HTTPS probe with matching Xray access-log evidence reports
`outbound_https_verified`, **not** proof of the original profile's routing
policy or client inbound. Such checks cannot assert blocking or original
DNS-routing observations; configuration validation rejects those combinations.

For `cdn[]`, the same option checks the XHTTP outbound while another route
remains primary. Native CDN DNS/TLS/HTTP and HTTPS over the XHTTP outbound
produce separate observations and incidents. These observations do **not**
prove that the provider traversed a particular CDN edge, or that automatic
fallback selected it. CDN route/fallback evidence stays `UNKNOWN` without
independent proof. If either probe or its access evidence is missing, no
success is inferred. Diagnostic inbounds bind only to loopback, and no
production service, firewall or client profile is changed.

The option defaults to `false` to retain original-route behavior of existing
configurations.

## Data and identity

- Stable IDs for source/profile/scenario. Do not use profile display names as unique identifiers.
- To keep individual balancer candidate incidents stable when candidates change order, configure optional
  `candidate_ids` as a complete mapping of Xray outbound tags to opaque operator-defined IDs.
  Validate unique IDs and exact coverage of candidates. Legacy configurations without this
  mapping retain positional candidate keys for compatibility; configure IDs before relying
  on stable per-candidate incident history. Changes to key format do not prove recovery.
  Observation keys must never contain outbound tags.
- Observations include location, version/hash, timestamp, duration, kind, status, bounded failure code and available evidence.
- Freshness is independent from availability. UNKNOWN/UNSUPPORTED/stale must never silently become OK.
- Mandatory observation coverage has one additional source-level `coverage/<source-id>` record and incident.
  When a source loads successfully but a configured profile, independent scenario, balancer candidate,
  or CDN endpoint/tunnel is missing, stale, UNKNOWN or UNSUPPORTED, the coverage record is FAILED
  and alerts after comparable consecutive observations. A confirmed individual VPN FAILED/DEGRADED
  remains its **own** incident and counts as observed evidence, not healthy connectivity.
  Source HTTP failures retain their existing source incident instead of duplicating coverage alerts.
  Deliberately unproven leastPing selection, physical cascade/CDN hops and client-inbound semantics
  are excluded from mandatory evidence. A coverage recovery message means diagnostics resumed,
  **not** that every VPN route recovered.
- Incident correlation requires comparable consecutive results for the same scenario; different failures do not merge into a false consecutive outage.
- If source refresh fails, a cached profile can still be tested with age shown; the refresh failure is a separate incident.
- Stored configs and credentials are sensitive even when encrypted transport is used. SQLite is a later milestone, not an M0 prerequisite.

## Trust and process security

Operator-controlled sources only in early releases; imported data remains untrusted. Bound network output, payload sizes, execution time and recursion/complexity. Validate redirects and TLS; protect against SSRF, especially link-local/metadata destinations, and never forward secret headers to a new origin.

The Xray child process is not an isolation boundary against hostile code in the same container. Avoid shell invocation and use explicit argv, confined working directories, restrictive filesystem access and careful cancellation/child reaping. No raw stderr, tokens, UUIDs, device headers or subscription contents in logs.

Default probes are read-only and should not require elevated privileges. Fail unsupported operations explicitly instead of silently loosening permissions.

## Technology choices

- Rust stable; Tokio for async runtime/process supervision; Serde for strict external input; Reqwest/rustls for HTTPS.
- Later: SQLite for persistence, Telegram Bot API via HTTP.
- Prefer narrow dependencies and standard library; pin Rust dependencies in Cargo.lock and review their security implications.
- Do not promise Rust always uses less RAM than Go: Xray-core itself has a Go runtime. Measure whole deployment.
- Initial CI should be added with the first compilable Rust milestone, not as a workflow that fails while no Cargo package exists.

See docs/product.md for implementation order and acceptance requirements.
