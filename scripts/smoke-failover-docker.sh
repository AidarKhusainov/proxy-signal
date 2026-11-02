#!/bin/sh
# Manual integration trial for a disposable, credential-free Xray lab profile.
# Requires IMAGE built on a GitHub runner. Never build or touch Remnawave on Hostland.
set -eu
IMAGE=${IMAGE:-proxy-signal:failover}
tmp=$(mktemp -d)
net="proxy-signal-failover-${FAILOVER_RUN_ID:-$$}"
cleanup() {
    docker network rm "$net" >/dev/null 2>&1 || true
    rm -rf "$tmp"
}
trap cleanup EXIT HUP INT TERM

cat > "$tmp/config.yaml" <<'YAML'
version: 1
interval_seconds: 300
timeout_seconds: 60
parallelism: 1
state_file: /data/state.json
endpoints:
  - id: ipify
    url: https://api.ipify.org
sources:
  - id: lab
    kind: file
    path: /profiles/lab.json
    failover:
      - id: controlled
        url: https://example.com/
        balancer_tag: pool
        primary_tag: main-lab
        alternatives: [backup-lab]
        fallback_tag: backup-lab
        control_port: 20001
        restore_primary: true
YAML

cat > "$tmp/profile.json" <<'JSON'
{
  "routing": {
    "rules": [{"type":"field","domain":["full:example.com"],"balancerTag":"pool"}],
    "balancers": [{
      "tag":"pool",
      "selector":["main-lab"],
      "fallbackTag":"backup-lab",
      "strategy":{"type":"leastPing"}
    }]
  },
  "observatory": {
    "subjectSelector":["main-lab"],
    "probeUrl":"https://example.com/",
    "probeInterval":"2s",
    "enableConcurrency":true
  },
  "outbounds": [
    {"tag":"main-lab","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":20001}]}},
    {"tag":"backup-lab","protocol":"freedom"}
  ]
}
JSON

docker network create "$net" >/dev/null
set +e
output=$(timeout 240s docker run --rm --read-only --user 65532:65532 \
    --network "$net" --cap-drop ALL --security-opt no-new-privileges \
    --cpus 0.5 --memory 384m --pids-limit 64 \
    --tmpfs /tmp:rw,nosuid,noexec,size=16m,uid=65532,gid=65532,mode=0700 \
    --tmpfs /data:rw,nosuid,noexec,size=4m,uid=65532,gid=65532,mode=0700 \
    --mount "type=bind,src=$tmp/config.yaml,dst=/etc/proxy-signal/config.yaml,readonly" \
    --mount "type=bind,src=$tmp/profile.json,dst=/profiles/lab.json,readonly" \
    "$IMAGE" /etc/proxy-signal/config.yaml --once 2>&1)
result=$?
set -e
printf '%s\n' "$output"
if [ "$result" -eq 124 ]; then
    echo 'FAIL: lab timed out' >&2
    exit 1
fi
for evidence in \
    'target=failover/lab/controlled/config status=OK evidence=failover_config_valid' \
    'target=failover/lab/controlled/primary status=OK evidence=failover_primary_https_verified' \
    'target=failover/lab/controlled/backup status=OK evidence=failover_backup_https_verified' \
    'target=failover/lab/controlled/switch status=OK evidence=failover_backup_selected_https_verified' \
    'target=failover/lab/controlled/recovery status=OK evidence=failover_primary_https_verified' \
    'target=failover/lab/controlled status=OK evidence=failover_verified'
do
    case "$output" in
        *"$evidence"*) ;;
        *) echo "FAIL: missing positive controlled failover phase: $evidence" >&2; exit 1 ;;
    esac
done
echo 'PASS: one live Xray process selected the primary, switched to the backup after isolated sidecar termination and restored'
