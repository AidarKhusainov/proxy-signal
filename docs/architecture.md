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

Probes that intentionally modify routes to simulate a failed candidate are **simulation** checks, not proofs of automatic failover in an unchanged client. Live network impairment requires separate isolated execution and explicit opt-in; never modify the host firewall or production nodes.

## Data and identity

- Stable IDs for source/profile/scenario. Do not use profile display names as unique identifiers.
- Observations include location, version/hash, timestamp, duration, kind, status, bounded failure code and available evidence.
- Freshness is independent from availability. UNKNOWN/UNSUPPORTED/stale must never silently become OK.
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
