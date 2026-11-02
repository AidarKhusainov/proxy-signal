#!/bin/sh
# Non-destructive container / Xray process smoke check. No production credentials.
set -eu
cd "$(dirname "$0")/.."

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
cat > "$tmp/config.yaml" <<'YAML'
version: 1
interval_seconds: 300
timeout_seconds: 12
parallelism: 1
state_file: /data/state.json
endpoints:
  - id: ipify
    url: https://api.ipify.org
sources:
  - id: smoke
    kind: file
    path: /profiles/smoke.json
YAML
cat > "$tmp/profile.json" <<'JSON'
{
  "dns": {"servers": ["1.1.1.1"]},
  "routing": {"rules": [{"type": "field", "domain": ["domain:api.ipify.org"], "outboundTag": "broken"}]},
  "outbounds": [{"tag": "broken", "protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1", "port": 19999, "users": [{"id": "00000000-0000-0000-0000-000000000001", "encryption": "none"}]}]}}]
}
JSON

docker build -t proxy-signal:smoke .
set +e
output=$(docker run --rm --read-only --user 65532:65532 \
    --cap-drop ALL --security-opt no-new-privileges --pids-limit 64 --memory 384m \
    --tmpfs /tmp:rw,nosuid,noexec,size=16m,uid=65532,gid=65532,mode=0700 \
    --tmpfs /data:rw,nosuid,noexec,size=4m,uid=65532,gid=65532,mode=0700 \
    --mount "type=bind,src=$tmp/config.yaml,dst=/etc/proxy-signal/config.yaml,readonly" \
    --mount "type=bind,src=$tmp/profile.json,dst=/profiles/smoke.json,readonly" \
    proxy-signal:smoke /etc/proxy-signal/config.yaml --once 2>&1)
result=$?
set -e
printf '%s\n' "$output"
if [ "$result" -eq 0 ]; then
    echo 'FAIL: unreachable VLESS upstream unexpectedly reported healthy' >&2
    exit 1
fi
case "$output" in
    *'target=source/smoke status=OK evidence=source_loaded'*) ;;
    *) echo 'FAIL: JSON source was not loaded' >&2; exit 1 ;;
esac
case "$output" in
    *'target=profile/smoke status=FAILED evidence=all_egress_probes_failed'*)
        echo 'PASS: Xray ran the full profile, and failed VLESS traffic was not reported as OK' ;;
    *) echo 'FAIL: no confirmed proxy failure; check direct HTTPS connectivity and Xray startup' >&2; exit 1 ;;
esac

# A separate, nonproduction diagnostic profile exercises real Xray access logs.
# The egress check deliberately fails because its default VLESS server is absent.
cat > "$tmp/scenarios.yaml" <<'YAML'
version: 1
interval_seconds: 300
timeout_seconds: 20
parallelism: 1
state_file: /data/state.json
endpoints:
  - id: ipify
    url: https://api.ipify.org
sources:
  - id: routes
    kind: file
    path: /profiles/routes.json
    scenarios:
      - id: allowed
        url: https://example.com/
        route: direct
        outbound_tag: direct
      - id: blocked
        url: https://example.org/
        route: block
        outbound_tag: blocked
      - id: wrong-route
        url: https://www.example.net/
        route: direct
        outbound_tag: direct
      - id: dns-without-evidence
        url: https://www.example.com/
        route: direct
        outbound_tag: direct
        dns:
          server: "UDP:1.1.1.1:53"
          expected_ips: [93.184.215.14]
YAML
cat > "$tmp/routes.json" <<'JSON'
{
  "dns": {"servers": ["1.1.1.1"]},
  "routing": {"rules": [
    {"type": "field", "domain": ["full:example.com", "full:www.example.com"], "outboundTag": "direct"},
    {"type": "field", "domain": ["full:example.org", "full:www.example.net"], "outboundTag": "blocked"}
  ]},
  "outbounds": [
    {"tag": "broken", "protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1", "port": 19999, "users": [{"id": "00000000-0000-0000-0000-000000000001", "encryption": "none"}]}]}},
    {"tag": "direct", "protocol": "freedom"},
    {"tag": "blocked", "protocol": "blackhole"}
  ]
}
JSON

set +e
output=$(docker run --rm --read-only --user 65532:65532 \
    --cap-drop ALL --security-opt no-new-privileges --pids-limit 64 --memory 384m \
    --tmpfs /tmp:rw,nosuid,noexec,size=16m,uid=65532,gid=65532,mode=0700 \
    --tmpfs /data:rw,nosuid,noexec,size=4m,uid=65532,gid=65532,mode=0700 \
    --mount "type=bind,src=$tmp/scenarios.yaml,dst=/etc/proxy-signal/config.yaml,readonly" \
    --mount "type=bind,src=$tmp/routes.json,dst=/profiles/routes.json,readonly" \
    proxy-signal:smoke /etc/proxy-signal/config.yaml --once 2>&1)
result=$?
set -e
printf '%s\n' "$output"
if [ "$result" -eq 0 ]; then
    echo 'FAIL: deliberately broken default VLESS route reported healthy' >&2
    exit 1
fi
for evidence in \
    'target=scenario/routes/allowed status=OK evidence=routing_verified' \
    'target=scenario/routes/blocked status=OK evidence=routing_verified' \
    'target=scenario/routes/wrong-route status=FAILED evidence=unexpected_outbound' \
    'target=scenario/routes/dns-without-evidence status=UNKNOWN evidence=dns_not_observed'
do
    case "$output" in
        *"$evidence"*) ;;
        *) echo "FAIL: missing Xray scenario evidence: $evidence" >&2; exit 1 ;;
    esac
done
echo 'PASS: actual Xray routing evidence verified; missing DNS evidence stayed UNKNOWN'

# Optional stage-3 proof: Xray executes separate HTTPS probes for a healthy
# direct outbound and an intentionally unreachable SOCKS candidate. This is
# NOT a leastPing selection or failover proof. No VPN credentials are used.
cat > "$tmp/balancers.yaml" <<'YAML'
version: 1
interval_seconds: 300
timeout_seconds: 45
parallelism: 1
state_file: /data/state.json
endpoints:
  - id: ipify
    url: https://api.ipify.org
sources:
  - id: balancers
    kind: file
    path: /profiles/balancers.json
    balancers:
      - id: latency
        url: https://example.com/
        balancer_tag: pool
        strategy: leastPing
        candidates: [node-good, node-broken]
        fallback_tag: node-good
YAML
cat > "$tmp/balancers.json" <<'JSON'
{
  "routing": {
    "rules": [{"type":"field","domain":["full:example.com"],"balancerTag":"pool"}],
    "balancers": [{
      "tag":"pool",
      "selector":["node-"],
      "fallbackTag":"node-good",
      "strategy":{"type":"leastPing"}
    }]
  },
  "observatory": {
    "subjectSelector":["node-"],
    "probeUrl":"https://example.com/",
    "probeInterval":"10s",
    "enableConcurrency":true
  },
  "outbounds": [
    {"tag":"node-good","protocol":"freedom"},
    {"tag":"node-broken","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":19999}]}}
  ]
}
JSON

set +e
output=$(docker run --rm --read-only --user 65532:65532 \
    --cap-drop ALL --security-opt no-new-privileges --pids-limit 64 --memory 384m \
    --tmpfs /tmp:rw,nosuid,noexec,size=16m,uid=65532,gid=65532,mode=0700 \
    --tmpfs /data:rw,nosuid,noexec,size=4m,uid=65532,gid=65532,mode=0700 \
    --mount "type=bind,src=$tmp/balancers.yaml,dst=/etc/proxy-signal/config.yaml,readonly" \
    --mount "type=bind,src=$tmp/balancers.json,dst=/profiles/balancers.json,readonly" \
    proxy-signal:smoke /etc/proxy-signal/config.yaml --once 2>&1)
result=$?
set -e
printf '%s\n' "$output"
if [ "$result" -eq 0 ]; then
    echo 'FAIL: an unreachable balancer candidate incorrectly passed all checks' >&2
    exit 1
fi
for evidence in \
    'target=balancer/balancers/latency/config status=OK evidence=balancer_config_valid' \
    'target=balancer/balancers/latency/candidate/node-good status=OK evidence=candidate_https_verified' \
    'target=balancer/balancers/latency/candidate/node-broken status=FAILED evidence=candidate_https_failed' \
    'target=balancer/balancers/latency/candidates status=DEGRADED evidence=candidates_partially_failed' \
    'target=balancer/balancers/latency status=DEGRADED evidence=balancer_partial_candidates'
do
    case "$output" in
        *"$evidence"*) ;;
        *) echo "FAIL: missing actual Xray balancer candidate evidence: $evidence" >&2; exit 1 ;;
    esac
done
case "$output" in
    *'target=balancer/balancers/latency/route status=OK'*) 
        echo 'FAIL: leastPing selection was asserted without observatory telemetry' >&2
        exit 1 ;;
esac
echo 'PASS: real Xray detected partial candidate failure without leastPing false OK'
