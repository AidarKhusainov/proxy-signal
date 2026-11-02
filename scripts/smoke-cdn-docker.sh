#!/bin/sh
# Manual negative CDN/XHTTP smoke. Requires a prebuilt image and public HTTPS.
# Uses no VPN credentials. A negative result is NOT positive VPN route proof.
set -eu
IMAGE=${IMAGE:-proxy-signal:smoke}
tmp=$(mktemp -d)
suffix=${CDN_RUN_ID:-$$}
net="proxy-signal-cdn-$suffix"
cleanup() {
    docker network rm "$net" >/dev/null 2>&1 || true
    rm -rf "$tmp"
}
trap cleanup EXIT HUP INT TERM

cat > "$tmp/config.yaml" <<'YAML'
version: 1
interval_seconds: 300
timeout_seconds: 40
parallelism: 1
state_file: /data/state.json
endpoints:
  - id: ipify
    url: https://api.ipify.org
sources:
  - id: cdn-smoke
    kind: file
    path: /profiles/cdn.json
    cdn:
      - id: xhttp
        endpoint_url: https://example.com/
        expected_http_status: 200
        url: https://example.org/
        outbound_tag: vpn-xhttp
YAML
cat > "$tmp/profile.json" <<'JSON'
{
  "routing": {"rules": [
    {"type": "field", "domain": ["full:example.org"], "outboundTag": "vpn-xhttp"}
  ]},
  "outbounds": [
    {"tag":"broken", "protocol":"socks",
     "settings":{"servers":[{"address":"127.0.0.1","port":19999}]}},
    {"tag":"vpn-xhttp", "protocol":"vless",
     "settings":{"vnext":[{"address":"example.com","port":443,
       "users":[{"id":"00000000-0000-4000-8000-000000000001","encryption":"none"}]}]},
     "streamSettings":{"network":"xhttp", "security":"tls",
       "tlsSettings":{"serverName":"example.com"},
       "xhttpSettings":{"host":"example.com","path":"/xhttp","mode":"auto"}}}
  ]
}
JSON

docker network create "$net" >/dev/null
set +e
output=$(timeout 120s docker run --rm --read-only --user 65532:65532 \
    --network "$net" --cap-drop ALL --security-opt no-new-privileges \
    --cpus 0.5 --memory 384m --pids-limit 64 \
    --tmpfs /tmp:rw,nosuid,noexec,size=16m,uid=65532,gid=65532,mode=0700 \
    --tmpfs /data:rw,nosuid,noexec,size=4m,uid=65532,gid=65532,mode=0700 \
    --mount "type=bind,src=$tmp/config.yaml,dst=/etc/proxy-signal/config.yaml,readonly" \
    --mount "type=bind,src=$tmp/profile.json,dst=/profiles/cdn.json,readonly" \
    "$IMAGE" /etc/proxy-signal/config.yaml --once 2>&1)
result=$?
set -e
printf '%s\n' "$output"
if [ "$result" -eq 0 ]; then
    echo 'FAIL: no authorized VPN server exists, but smoke reported fully healthy' >&2
    exit 1
fi
for evidence in \
    'target=source/cdn-smoke status=OK evidence=source_loaded' \
    'target=cdn/cdn-smoke/xhttp/dns status=OK evidence=cdn_public_dns_resolved' \
    'target=cdn/cdn-smoke/xhttp/tls status=OK evidence=cdn_tls_verified' \
    'target=cdn/cdn-smoke/xhttp/http status=OK evidence=cdn_http_expected_status' \
    'target=cdn/cdn-smoke/xhttp/endpoint status=OK evidence=cdn_endpoint_verified' \
    'target=cdn/cdn-smoke/xhttp/config status=OK evidence=cdn_xhttp_config_valid' \
    'target=cdn/cdn-smoke/xhttp/route status=UNKNOWN evidence=cdn_route_unverified'
do
    case "$output" in
        *"$evidence"*) ;;
        *) echo "FAIL: expected CDN observation missing: $evidence" >&2; exit 1 ;;
    esac
done
case "$output" in
    *'target=cdn/cdn-smoke/xhttp/tunnel status=OK '*)
        echo 'FAIL: broken synthetic VPN tunnel was incorrectly marked OK' >&2
        exit 1 ;;
esac
case "$output" in
    *'target=cdn/cdn-smoke/xhttp status=OK '*)
        echo 'FAIL: unproven CDN route was incorrectly marked OK' >&2
        exit 1 ;;
esac
echo 'PASS: real public CDN HTTPS health, synthetic broken XHTTP tunnel and unproven route remain separate'
