# ProxySignal

**Verify the proxy, not just the port.**

Lightweight, self-hosted VPN and proxy monitoring with real end-to-end checks and actionable alerts.

> **Status: design stage.** There is no working CLI, container image, or release yet.

## Goal

Configure a monitor once and receive Telegram notifications when VPN/proxy behavior fails, degrades, or recovers. ProxySignal aims to distinguish simple endpoint availability from actual configuration execution: subscriptions, encrypted tunnels, DNS, routing, cascades, balancing and failover.

The primary deployment is a single lightweight container. A web dashboard, database server and public management API are not required.

## Approach

- **Rust controller:** configuration, native HTTP/TLS/DNS checks, scheduling, incident state, history and Telegram notifications.
- **Official Xray-core:** invoked as a controlled child process only when a real tunnel or complete Xray profile must be executed.
- **Evidence-driven results:** report what was actually tested, from which location, and which behaviors remain UNKNOWN or UNSUPPORTED.
- **Optional adapters:** start with Xray JSON; keep Remnawave and other panels outside the core model.

The first implementation milestone is a testable laboratory prototype of executing a complete Xray JSON configuration, not a production-ready monitoring service.

## Documentation

- [Product scope and acceptance criteria](docs/product.md)
- [Architecture and security boundaries](docs/architecture.md)
- [Guidelines for AI agents and contributors](AGENTS.md)
- [Contributing](CONTRIBUTING.md)
- [Security reporting](SECURITY.md)

## Current limitations

Nothing is implemented yet. No compatibility claims, performance targets or Docker usage instructions should be treated as validated. A probe from one server cannot establish reachability from every ISP or exact behavior of an unrelated mobile client. An independent external watchdog will be needed to detect failure of the monitoring host itself.

## License

MIT — see [LICENSE](LICENSE).
