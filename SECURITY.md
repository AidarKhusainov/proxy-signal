# Security policy

## Current status

ProxySignal is in the design stage and has **no supported release**. There is no deployed service to secure yet.

## Reporting vulnerabilities

Please report suspected security issues **privately** using GitHub's "Report a vulnerability" / private vulnerability reporting feature if it is enabled for this repository. Do not post tokens, working subscription URLs, device headers, exploits containing secrets, or private infrastructure details in public issues.

If private vulnerability reporting is not enabled, request a private contact channel in a public issue **without including sensitive details or an exploit**. Maintainers should enable private reporting before the first public release.

There is no guaranteed response time or security-support window at this stage.

## Planned security model

- Imported subscriptions and profiles are untrusted input, even when supplied by the operator.
- Explicit resource/network limits; no privileged mode, public management port or Docker socket by default.
- Strong TLS validation, careful redirect/SSRF handling and strict secret redaction.
- Child Xray execution needs timeouts and cleanup; process separation in one container is not a security sandbox.
- No production mutation or automated remediation as part of verification.

A supported-version policy and detailed threat model will be published before release. Please do not treat experimental branches as production-safe.
