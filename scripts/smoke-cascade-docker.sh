#!/bin/sh
# Opt-in live test: disposable Xray SOCKS relays, no VPN credentials or production ports.
# Requires a prebuilt ProxySignal image and outbound HTTPS from an isolated Docker bridge.
set -eu

IMAGE=${IMAGE:-proxy-signal:smoke}
tmp=$(mktemp -d)
# Optional stable name suffix lets an external runner verify scoped cleanup.
suffix=${CASCADE_RUN_ID:-$}
net="proxy-signal-cascade-$suffix"
a="ps-hop-a-$suffix"
b="ps-hop-b-$suffix"
cleanup() {
    docker rm -f "$a" "$b" >/dev/null 2>&1 || true
    docker network rm "$net" >/dev/null 2>&1 || true
    rm -rf "$tmp"
}
trap cleanup EXIT HUP INT TERM

cat > "$tmp/relay.json" <<'JSON'
{
  "log": {"access": "/dev/stdout", "loglevel": "warning"},
  "inbounds": [{"tag": "socks-in", "listen": "0.0.0.0", "port": 1080,
    "protocol": "socks", "settings": {"auth": "noauth", "udp": false}}],
  "outbounds": [{"tag": "direct", "protocol": "freedom"}]
}
JSON
cat > "$tmp/config.yaml" <<'YAML'
version: 1
interval_seconds: 300
timeout_seconds: 45
parallelism: 1
state_file: /data/state.json
endpoints:
  - id: ipify
    url: https://api.ipify.org
sources:
  - id: cascade-smoke
    kind: file
    path: /profiles/cascade.json
    cascades:
      - id: ordered
        url: https://example.com/
        outbounds: [entry, relay]
YAML
cat > "$tmp/profile.json" <<'JSON'
{
  "routing": {"rules": [{"type":"field", "domain":["full:example.com"], "outboundTag":"entry"}]},
  "outbounds": [
    {"tag":"broken", "protocol":"socks",
     "settings":{"servers":[{"address":"127.0.0.1","port":19999}]}},
    {"tag":"entry", "protocol":"socks",
     "settings":{"servers":[{"address":"hop-a","port":1080}]},
     "streamSettings":{"sockopt":{"dialerProxy":"relay"}}},
    {"tag":"relay", "protocol":"socks",
     "settings":{"servers":[{"address":"hop-b","port":1080}]}}
  ]
}
JSON

docker network create "$net" >/dev/null
for spec in "$a:hop-a" "$b:hop-b"; do
    name=${spec%%:*}
    alias=${spec#*:}
    docker run -d --rm --read-only --user 65532:65532 \
        --name "$name" --network "$net" --network-alias "$alias" \
        --cap-drop ALL --security-opt no-new-privileges \
        --cpus 0.25 --memory 128m --pids-limit 32 \
        --mount "type=bind,src=$tmp/relay.json,dst=/etc/xray.json,readonly" \
        --entrypoint /usr/local/bin/xray "$IMAGE" run -c /etc/xray.json >/dev/null
done
sleep 2
set +e
output=$(timeout 120s docker run --rm --read-only --user 65532:65532 \
    --network "$net" --cap-drop ALL --security-opt no-new-privileges \
    --cpus 0.5 --memory 384m --pids-limit 64 \
    --tmpfs /tmp:rw,nosuid,noexec,size=16m,uid=65532,gid=65532,mode=0700 \
    --tmpfs /data:rw,nosuid,noexec,size=4m,uid=65532,gid=65532,mode=0700 \
    --mount "type=bind,src=$tmp/config.yaml,dst=/etc/proxy-signal/config.yaml,readonly" \
    --mount "type=bind,src=$tmp/profile.json,dst=/profiles/cascade.json,readonly" \
    "$IMAGE" /etc/proxy-signal/config.yaml --once 2>&1)
result=$?
set -e
printf '%s\n' "$output"
if [ "$result" -eq 0 ]; then
    echo 'FAIL: cascade was incorrectly declared fully healthy' >&2
    exit 1
fi
for evidence in \
    'target=source/cascade-smoke status=OK evidence=source_loaded' \
    'target=cascade/cascade-smoke/ordered/config status=OK evidence=cascade_config_valid' \
    'target=cascade/cascade-smoke/ordered/https status=OK evidence=cascade_https_verified' \
    'target=cascade/cascade-smoke/ordered/hops status=UNKNOWN evidence=cascade_hops_unverified' \
    'target=cascade/cascade-smoke/ordered status=UNKNOWN evidence=cascade_https_healthy_hops_unverified'
do
    case "$output" in
        *"$evidence"*) ;;
        *) echo "FAIL: missing cascade observation: $evidence" >&2; exit 1 ;;
    esac
done
# Independently observed relay access events in this isolated one-request
# test corroborate both hops. These server logs are NOT available in production
# and are intentionally never turned into a runtime OK claim.
if ! docker logs "$b" 2>&1 | grep -q 'hop-a:1080'; then
    echo 'FAIL: relay B did not observe the dial to hop A' >&2
    exit 1
fi
if ! docker logs "$a" 2>&1 | grep -q 'example.com:443'; then
    echo 'FAIL: relay A did not observe HTTPS destination' >&2
    exit 1
fi
echo 'PASS: real HTTPS crossed both disposable Xray SOCKS relays; runtime hop proof stayed UNKNOWN'
