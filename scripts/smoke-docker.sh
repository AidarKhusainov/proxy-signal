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
