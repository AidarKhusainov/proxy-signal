# Product direction

Status: proposed initial scope (not implemented).

## Purpose

ProxySignal is an independent, open-source, self-hosted tool for operators who need to know whether their VPN or proxy **actually works**. Primary first user: an operator of several Xray-based nodes, subscriptions, cascades, custom routing and CDN fallback. The implementation must not hardcode that operator's addresses, node count, profile names or panel.

**Primary user flow:** provide configuration/subscription sources and secrets once at container startup; receive actionable Telegram alerts without constantly managing a dashboard.

## Product requirements

- Accept local Xray JSON and, subsequently, authenticated HTTPS subscription sources. Support explicit headers including HWID where supplied by the operator; never invent/register device identifiers.
- Distinguish transport reachability, real proxy connectivity and **full profile execution**. Validate profile consistency, expected routing, DNS, balancing candidates, cascades, CDN transport and failover through separately defined scenarios.
- Record observation location, engine/config version, proof available for the claim, time and freshness. Interpret failures per **profile + scenario**, not as a global sequence across unrelated checks.
- Support OK, DEGRADED, FAILED, UNKNOWN and UNSUPPORTED; stale data is never OK. An available candidate does not prove a working balancer; a working tunnel does not prove correct DNS/routing.
- Alert on confirmed state changes (including recovery), not every failed interval. Preserve state across restarts and send clear, safe messages in Telegram. A daily summary is optional.
- Use bounded network traffic, CPU, memory, storage, concurrency and process lifetimes. Production checks are read-only; simulated failures happen only inside controlled test executions.
- Provide local/CI diagnostics without requiring a web dashboard. Document a separate independent host watchdog.

## Non-goals (initial releases)

No proxy protocol reimplementation, production node/Remnawave management, automatic repair, external DB, mandatory UI, multi-tenant SaaS, generic plugin framework, remote shell, or promises about every client/ISP.

Other engines (e.g. mihomo/sing-box) can be introduced when a real user case and compatible execution path exist. The architecture must allow this without designing a plugin SDK prematurely.

## Milestones and acceptance gates

### M0 — Laboratory full-profile proof (first)

- Read and validate a local, synthetic Xray JSON without needing real subscriber secrets.
- Launch an official, pinned Xray-core build as a supervised subprocess with bounded lifetime and cleanup.
- Execute a TLS-verified HTTPS request through a **full** profile, preserving meaningful routing, DNS and outbound behavior.
- Run negative tests where an invalid route or DNS expectation does **not** produce a false OK.
- Determine which routing/DNS/balancer evidence the actual engine exposes; report unsupported coverage honestly.
- Measure whole-process/container RSS, CPU, duration and test traffic. Do not publish performance numbers before measuring them.

M0 is a feasibility experiment. It is not complete if it only extracts one outbound or returns an HTTP status without route evidence.

### M1 — Autonomous core

- Strict, versioned configuration with documented defaults and file-backed secrets.
- Native HTTP/TLS/DNS probes; explicit bounded schedules and graceful shutdown.
- Local state/history with retention, durable incident transitions, and Telegram notifications with retries.
- Offline tests for input errors, stale/missing checks, restart recovery and notification delivery semantics.

### M2 — Real-world configuration coverage

- Read authenticated subscriptions with safe refresh and last-known-good semantics.
- Separate verified test scenarios for individual nodes, full profiles, routing, cascades, DNS, balancing and public-CDN VPN traffic.
- Controlled failover experiments without mutating user traffic, and explicit evidence/limitations.
- Test production-like configurations **only with test credentials** and an opt-in non-destructive execution path.

### M3 — Safe migration and public release

- Compare results with the existing monitor over a representative period; retire old checks only when coverage is proven equivalent.
- External watchdog for the monitoring host, documented deployment/rollback and backup.
- Release process, compatibility matrix, honest security model and reproducible builds.

Each milestone should produce a coherent, tested result. Do not start M1/M2 features merely to make the repository look complete.
