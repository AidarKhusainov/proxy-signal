# AI development guidelines

These instructions apply to the entire ProxySignal repository and to human and AI contributors.

## Product contract

ProxySignal is a small, self-hosted VPN/proxy monitor: configure it once, run it as a container, and receive useful Telegram alerts. Its main value is **proving actual behavior**, not reporting that a port is open. See docs/product.md and docs/architecture.md before designing a feature.

## Primary engineering rule

**Write the smallest correct, secure, understandable, testable solution that satisfies the current requirement.** Minimal code does not mean putting everything in one file or sacrificing boundaries. Keep just enough structure to prevent coupling, duplication, and untestable code.

- YAGNI and KISS first. Do not implement speculative options, plugins, compatibility shims, feature flags, frameworks, or generic infrastructure.
- Prefer straightforward control flow and standard-library facilities over dependencies or elaborate patterns. Every new dependency needs a concrete reason.
- Keep responsibilities separate where changes have different reasons: configuration/sources, Xray execution, probes, state/incidents, notifications. Add modules as needed; do not pre-create empty layers.
- Do not introduce a trait, factory, repository abstraction, dependency-injection container, event bus, generic pipeline, or wrapper for a single use unless it protects a real test or security boundary.
- Do not confuse fewer lines with simpler code. Use explicit types for important states and errors; avoid hidden behavior, magical defaults, ambiguous booleans and giant functions.
- Follow idiomatic stable Rust. Avoid unsafe code unless indispensable, isolated, justified, and reviewed. Avoid panics on input or recoverable runtime failures.
- Optimize based on measurement, not guesses; do not trade clarity for speculative micro-optimizations.
- When modifying code, solve the requested problem; do not opportunistically refactor or reformat unrelated modules.

## Before implementation

1. Read the relevant product requirements, architecture decisions, and existing code/tests.
2. State the behavior to add and the smallest affected boundary; distinguish facts, assumptions, and unsupported claims.
3. For substantial design decisions, document a short proposal and trade-offs before committing to an API or dependency.
4. Implement a thin, working vertical slice with focused tests. Prefer one complete scenario to several half-implemented integrations.
5. Update docs when behavior or configuration changes, not for every internal refactor.

Public interfaces, configuration format, and stored data are contracts. Avoid accidental breaking changes. Do not silently change expected routing behavior to make tests pass.

## Trust, safety, and correctness

- Treat subscriptions, Xray JSON and network responses as untrusted input. Limit sizes, depth/complexity, durations, concurrency, redirects and outgoing traffic; fail closed on unsupported constructs.
- Do not execute shell strings, download executables from arbitrary subscription data, or grant host network, privileged mode, host filesystem mounts or Docker socket by default.
- Xray is an optional **child process** for checks that need its real behavior, not an embedded Rust rewrite or a permanently running requirement. Apply timeouts, resource limits where feasible, cancellation, process-group cleanup and child reaping.
- Never log, commit or transmit subscription URLs, tokens, UUIDs, HWIDs, auth headers or raw sensitive configs. Use file-backed secrets; redact error context and diagnostic artifacts.
- Do not weaken TLS validation, bypass authentication, change firewall settings, restart production nodes or modify VPN-panel objects as part of a probe.
- Native HTTP/DNS checks do not prove a VPN route. A successful outbound probe does not prove full-profile routing, DNS, balancing or failover.
- Report unsupported/unknown/stale states honestly. An absence of observations must never be shown as OK. Preserve enough evidence to explain an OK/FAILED/DEGRADED result.
- Tests that simulate a failure must not modify real infrastructure. Never claim simulation proves genuine network failover.
- A single in-container process boundary is not sufficient isolation for arbitrarily hostile configs; document the supported trust model.

## Testing and review

- Add focused tests for success, failures, timeouts, malformed input, cleanup and state transitions; include negative tests that catch false OK results.
- Keep unit tests deterministic and offline. Mark live-network/system integration tests explicitly; never run destructive tests against real infrastructure by default.
- When Rust code exists, run `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets` when applicable. Report what actually ran and any blockers.
- Keep PRs small and reviewable. Explain **what changed, why, how verified, security implications, and what remains unsupported**.
- Do not claim passing checks, measured performance, production compatibility or complete coverage without evidence. No merge, release or production deployment without explicit authorization.

## Scope guardrails

No mandatory web UI, SaaS control plane, Prometheus/Grafana stack, public control API, microservices, arbitrary executable plugin system or automatic remediation for the initial product. Do not add CI workflows that call nonexistent Cargo commands before a working Rust crate exists.

The first engineering milestone is a **laboratory proof of full Xray JSON execution** and honest route/DNS evidence; all other features follow after that is demonstrated.
