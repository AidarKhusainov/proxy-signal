# Autonomous reliability acceptance

This procedure exercises existing checks across consecutive cycles, network errors and container restarts. It does not deploy the monitor or modify VPN servers, firewall rules, production containers, panel objects or client profiles.

## Preconditions

- Build the pinned Docker image on a CI runner, never on the production control-plane host.
- Inspect host CPU/load, available RAM, Docker and temporary storage, existing containers, networks, listeners and panel health before staging anything. Repeat the resource gate after the build.
- Use an explicitly authorized transport with pinned SSH host-key verification. On a shared host, serialize tests and retain the baseline container identities/start times and network inventory.
- The harness requires Linux cgroup v2, Docker, Python 3 and root access through the authorized helper. It refuses an occupied default bridge; it never creates a Docker network or publishes ports.
- Only the optional complete test-profile JSON contains credentials. Transfer it privately, preserve its complete DNS/routing/outbounds, and remove it with the other run-specific files. Unsupported profiles must remain unsupported.

## Run a bounded trial

`scripts/smoke-reliability-docker.sh` accepts a prebuilt run-specific image, a numeric run ID/attempt, a private temporary directory, and optionally one complete authorized test profile:

```sh
bash scripts/smoke-reliability-docker.sh \
  proxy-signal:hostland-lab-12345-1 \
  12345-1 \
  /tmp/proxy-signal-lab-XXXXXXXX \
  /private/test-profile.json
```

The image and all temporary containers must carry `org.proxysignal.lab.run=<run ID>-<attempt>`. The outer helper verifies image/harness/profile checksums and owns final image/file cleanup. Never substitute a production profile or working directory for the disposable fixtures.

The monitor runs with a read-only root, UID 65532, no capabilities, no additional privileges, no published ports, 0.5 CPU, 384 MiB RAM and 64 PIDs. The separate protocol-stall fixture has 0.25 CPU, 128 MiB RAM and 32 PIDs and uses a network-disabled namespace. Both use the same prebuilt image. No container has a Docker-socket or production-directory mount.

## Assertions

The ordinary periodic trial uses a synthetic full Xray profile. Its deliberately wrong route produces a confirmed failure after matching consecutive checks. The test checks three cycles, SIGTERM and restart with the same data directory, missing source data, source restoration and successful HTTPS on the expected route. The failed default proxy remains failed independently. If a compatible complete test profile is supplied, every accepted cycle must also verify its VPN egress against the direct baseline.

When the supplied subscription profiles require unsupported client semantics, an operator may provide a separate laboratory JSON using one self-contained authorized test outbound with its authentication, transport and TLS settings unchanged. Label that result as isolated VPN-outbound egress and lifecycle evidence. The original profiles remain unsupported; the fixture does not establish their routing, DNS, balancing or client compatibility.

Telegram credentials and recipient are synthetic, and the API hostname resolves to loopback inside the test container. Delivery failures must leave the durable queue unchanged; repeated failures and restart must not duplicate transitions. Restored source/route checks must queue exactly one recovery. Successful HTTP delivery, rejected API replies, durable acknowledgements, retry order and connection stalls are tested by the Rust suite against a local HTTP server. This does not claim delivery through the live Telegram Bot API.

The isolated network trial deliberately sends a SOCKS handshake to an HTTP listener owned by a temporary Xray fixture. It must reach the configured deadline, report an unavailable HTTPS source separately, and avoid false OK. SIGTERM while the monitor's Xray child is active must stop the container promptly and leave no observed child process. Invalid configuration and malformed persistent state must fail closed.

The harness samples kernel CPU/memory/PID accounting, checks the enforced limits, verifies no persistent zombie or overlapping Xray remains after a completed cycle, and checks temporary Xray files. The output contains numeric resource summaries and fixed evidence labels; raw profiles, secret values and raw Xray logs must never be printed or uploaded.

## Cleanup and postflight

Cleanup removes only containers/images bearing the exact run label and files under the verified run-specific temporary directory. An always-run outer postflight repeats cleanup if the inner harness failed, then checks for leftover labeled containers/images, the empty test bridge, unchanged network inventory, original panel-container start times/health, required listeners and TLS-verified panel HTTPS.

Compare the measurements and outcomes with the PR's actual Actions results. A successful short trial demonstrates the exercised cycles and failure modes. It does not establish multi-day leak freedom, live Telegram delivery or equivalence to every check in an older monitor.

## Parallel operational trial

Keep the old monitor active. Start a separately authorized parallel instance with its own data directory, supported profiles and a dedicated operator test recipient; never share a state file between replicas. Choose an interval that accommodates the whole cycle within `interval_seconds + timeout_seconds`. Treat `UNKNOWN`, `UNSUPPORTED`, stale timestamps and process downtime as coverage gaps. Use an independent host/process watchdog for silence.

Before replacing existing monitoring, compare representative failures and recoveries, supported routing coverage, resource trends and notification delivery over an agreed observation period. Deployment, live test messages and retirement of the old monitor are separate operator actions.

The outbox is bounded at 1,024 events. Saturation compacts older history while preserving each target's newest pending outage and final state. Telegram delivery is at least once: acceptance followed by a crash or acknowledgement-write failure can cause a duplicate after restart. Neither condition is an exactly-once guarantee.
