# Contributing to ProxySignal

The project is in design stage; functionality is not yet released. Please discuss substantial design changes in an issue before implementing them.

## Principles

- Follow [AGENTS.md](AGENTS.md), [product goals](docs/product.md), and [architecture boundaries](docs/architecture.md).
- Prefer the smallest behaviorally complete change. Do not add speculative integrations or generic abstractions.
- Keep pull requests focused, document user-visible changes, and add deterministic tests for both success and negative/error cases.
- Never use or commit real subscriber credentials, device identifiers, production endpoints or sensitive logs. Use synthetic fixtures.
- Never run destructive network impairment tests against somebody's production setup.

## Local development

The Rust crate and its CI are not yet available. Once introduced, the expected baseline is:

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all-targets`

Do not report these commands as passing until you have run them. Integration tests needing Xray or network access must be opt-in and clearly document their prerequisites.

## Pull requests

Use the PR template. State precisely what was verified, which requirements are still unsupported, and whether your changes alter resource usage, secrets handling or networking.

Contributions should not assume a specific VPN provider, country, domain, Remnawave instance or subscription format beyond the explicitly supported contract.
