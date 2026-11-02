#!/usr/bin/env bash
# Bounded, opt-in runtime acceptance. Build the image elsewhere before running.
# Usage: smoke-reliability-docker.sh IMAGE RUN_KEY PRIVATE_WORK_DIR [FULL_TEST_PROFILE]
# Requires Docker, Python 3 and cgroup v2. Does not create networks, publish ports,
# use real Telegram credentials, or change services outside its labeled containers.
set -Eeuo pipefail
umask 077
exec python3 - "$@" <<'PY'
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time


LABEL = "org.proxysignal.lab.run"
LIMIT = 384 * 1024 * 1024
START = time.monotonic()
DEADLINE = START + 480


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def command(args, timeout=20, check=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        operation = args[1] if args[:1] == ["docker"] else "operation"
        raise RuntimeError(f"laboratory {operation} failed (exit {result.returncode}); sensitive output suppressed")
    return result


def docker(*args, **kwargs):
    return command(["docker", *args], **kwargs)


def write(path, value, private=False):
    path.write_text(value, encoding="utf-8")
    path.chmod(0o600 if private else 0o644)
    if private:
        os.chown(path, 65532, 65532)


def proc(pid):
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
        return fields[19], fields[0], Path(f"/proc/{pid}/comm").read_text().strip()
    except FileNotFoundError:
        return None


class Monitor:
    def __init__(self, name, data, configuration, network="bridge", once=False):
        self.name = name
        self.data = data
        self.seen = set()
        self.samples = []
        self.pid = None
        self.group = None
        self.zombie_since = None
        self.last_cpu = None
        self.cpu_total = 0
        data.mkdir(mode=0o700)
        os.chown(data, 65532, 65532)
        args = ["create", "--pull", "never", "--name", name, "--label", f"{LABEL}={run_key}",
                "--network", network, "--read-only", "--user", "65532:65532",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--cpus", "0.5", "--memory", "384m", "--memory-swap", "384m", "--pids-limit", "64",
                "--env", "GOMAXPROCS=2", "--env", "TOKIO_WORKER_THREADS=2",
                "--log-driver", "json-file", "--log-opt", "max-size=1m", "--log-opt", "max-file=1",
                "--tmpfs", "/tmp:rw,nosuid,noexec,size=16m,uid=65532,gid=65532,mode=0700",
                "--mount", f"type=bind,src={profiles},dst=/profiles,readonly",
                "--mount", f"type=bind,src={data},dst=/data"]
        if network == "bridge":
            # Both the credential and recipient are synthetic. The address map
            # also prevents any request from reaching the real Telegram API.
            args += ["--add-host", "api.telegram.org:127.0.0.1"]
        args += [image, f"/profiles/{configuration}"]
        if once:
            args += ["--once"]
        docker(*args)
        containers.append(name)

    def start(self):
        docker("start", self.name)
        info = json.loads(docker("inspect", self.name).stdout)[0]
        host = info["HostConfig"]
        require(host["Memory"] == LIMIT and host["NanoCpus"] == 500_000_000
                and host["PidsLimit"] == 64 and not host["Privileged"]
                and host["ReadonlyRootfs"] and not host["PortBindings"], "container isolation differs")
        self.pid = info["State"]["Pid"]
        self.last_cpu = None
        if self.pid:
            try:
                entries = Path(f"/proc/{self.pid}/cgroup").read_text().splitlines()
            except FileNotFoundError:
                return  # Expected for startup-error acceptance cases.
            unified = [line.split(":", 2)[2] for line in entries if line.startswith("0::")]
            require(len(unified) == 1, "cgroup v2 metrics unavailable")
            self.group = Path("/sys/fs/cgroup") / unified[0].lstrip("/")
            self.sample()

    def sample(self):
        if self.pid is None or proc(self.pid) is None or self.group is None:
            return None
        try:
            quota, period = (self.group / "cpu.max").read_text().split()
            require(quota != "max" and 2 * int(quota) == int(period)
                    and (self.group / "memory.max").read_text().strip() == str(LIMIT)
                    and (self.group / "pids.max").read_text().strip() == "64",
                    "kernel resource limits differ from container configuration")
            pids = [int(value) for value in (self.group / "cgroup.procs").read_text().split()]
            processes = [(pid, proc(pid)) for pid in pids]
            processes = [(pid, item) for pid, item in processes if item is not None]
            for pid, item in processes:
                self.seen.add((pid, item[0]))
            cpu = dict(line.split() for line in (self.group / "cpu.stat").read_text().splitlines())
            sample = {"elapsed_seconds": round(time.monotonic() - START, 3),
                      "cpu_usec": int(cpu["usage_usec"]),
                      "memory_bytes": int((self.group / "memory.current").read_text()),
                      "pids": int((self.group / "pids.current").read_text()),
                      "processes": len(processes),
                      "xray": sum(item[2] == "xray" for _, item in processes),
                      "zombies": sum(item[1] == "Z" for _, item in processes)}
        except FileNotFoundError:
            return None
        require(sample["pids"] <= 64 and sample["memory_bytes"] <= LIMIT, "container resource limit exceeded")
        require(sample["xray"] <= 1, "overlapping or unreaped Xray children")
        if self.last_cpu is not None:
            self.cpu_total += max(0, sample["cpu_usec"] - self.last_cpu)
        self.last_cpu = sample["cpu_usec"]
        if sample["zombies"]:
            self.zombie_since = self.zombie_since or time.monotonic()
            require(time.monotonic() - self.zombie_since < 2, "persistent zombie child")
        else:
            self.zombie_since = None
        self.samples.append(sample)
        return sample

    def state(self):
        path = self.data / "state.json"
        if not path.exists():
            return None
        state = json.loads(path.read_text())
        require(path.stat().st_size <= 128 * 1024, "persistent state unexpectedly large")
        return state

    def generation(self):
        info = (self.data / "state.json").stat()
        return info.st_ino, info.st_mtime_ns

    def logs(self):
        # Never print or upload this data. Only fixed, known evidence is checked.
        return docker("logs", self.name).stdout

    def wait_for(self, predicate, label, seconds=90):
        stop = min(DEADLINE, time.monotonic() + seconds)
        while time.monotonic() < stop:
            self.sample()
            if predicate():
                return
            require(self.pid is not None and proc(self.pid) is not None,
                    f"monitor exited before {label}")
            time.sleep(0.5)
        raise RuntimeError(f"deadline exceeded waiting for {label}")

    def completed(self, key, status, count=1):
        pattern = re.compile(rf"^ts=(\d+) target={re.escape(key)} status={status} evidence=", re.M)
        matches = pattern.findall(self.logs())
        if len(matches) < count:
            return False
        # Observation logs precede the atomic state commit. Wait for both.
        state = self.state()
        record = state.get("records", {}).get(key, {}) if state else {}
        return (record.get("last_status") == status
                and record.get("last_observed_at") == int(matches[-1])
                and (self.data / "state.json").stat().st_mtime >= int(matches[-1]))

    def idle(self):
        sample = self.sample()
        require(sample is not None and sample["xray"] == 0 and sample["zombies"] == 0,
                "Xray child survived a completed cycle")
        docker("exec", self.name, "/bin/sh", "-c", 'test -z "$(ls -A /tmp)"')

    def stopped(self, expected=0):
        state = json.loads(docker("inspect", self.name).stdout)[0]["State"]
        require(not state["Running"] and not state["OOMKilled"] and state["ExitCode"] == expected,
                "monitor exit or OOM status differs")
        for pid, start in self.seen:
            current = proc(pid)
            require(current is None or current[0] != start, "container process remains after stop")

    def stop(self):
        before = time.monotonic()
        docker("stop", "--time", "8", self.name, timeout=15)
        self.stopped()
        require(time.monotonic() - before < 10, "SIGTERM was not bounded")

    def metrics(self, phase):
        require(self.samples, "runtime resource samples missing")
        samples = self.samples
        # Accumulate sampled CPU deltas across cgroups recreated at restart.
        summary = {"phase": phase, "samples": len(samples),
                   "sampled_peak_memory_bytes": max(value["memory_bytes"] for value in samples),
                   "sampled_peak_pids": max(value["pids"] for value in samples),
                   "sampled_peak_processes": max(value["processes"] for value in samples),
                   "sampled_peak_xray": max(value["xray"] for value in samples),
                   "sampled_peak_zombies": max(value["zombies"] for value in samples),
                   "sampled_cpu_seconds": round(self.cpu_total / 1e6, 3)}
        print("METRICS " + json.dumps(summary, sort_keys=True), flush=True)


def notice_sequence(state, key):
    return [item["status"] for item in state["pending"] if item["key"] == key]


def fresh_record(state, key, status, active):
    record = state["records"][key]
    require(record["last_status"] == status and record["active"] == active,
            f"unexpected incident state for {key}")
    timestamp = record.get("last_observed_at")
    require(isinstance(timestamp, int) and 0 <= time.time() - timestamp <= 30,
            "fresh observation timestamp missing or invalid")


def config(source_text, telegram=False):
    value = ("version: 1\ninterval_seconds: 30\ntimeout_seconds: 5\nparallelism: 1\n"
             "state_file: /data/state.json\nendpoints:\n"
             "  - id: ipify\n    url: https://api.ipify.org\nsources:\n" + source_text)
    if telegram:
        value += ('telegram:\n  bot_token_file: /profiles/invalid-token\n  chat_id: "0"\n')
    return value


def synthetic(route):
    return json.dumps({"routing": {"rules": [{"type": "field", "domain": ["full:example.com"],
                                              "outboundTag": route}]},
                       "outbounds": [{"tag": "unreachable", "protocol": "socks", "settings": {
                           "servers": [{"address": "127.0.0.1", "port": 19998}]}},
                                     {"tag": "expected", "protocol": "freedom"},
                                     {"tag": "wrong", "protocol": "blackhole"}]})


def replace_synthetic(value):
    staging = profiles / "synthetic.next"
    write(staging, value)
    staging.replace(profiles / "synthetic.json")


def cleanup():
    for name in reversed(containers):
        inspected = docker("inspect", name, check=False)
        if inspected.returncode:
            continue
        info = json.loads(inspected.stdout)[0]
        require(info["Config"]["Labels"].get(LABEL) == run_key, "container ownership mismatch")
        docker("rm", "--force", name)
    leftovers = docker("ps", "-aq", "--filter", f"label={LABEL}={run_key}").stdout.strip()
    require(not leftovers, "labeled laboratory container remains")
    if runtime_owned and runtime.exists():
        require(runtime.is_dir() and not runtime.is_symlink(), "runtime cleanup path differs")
        shutil.rmtree(runtime)


def failure_diagnostics():
    if not containers:
        return
    name = containers[-1]
    inspected = docker("inspect", name, check=False, timeout=3)
    if inspected.returncode:
        print("DIAGNOSTIC container_state_unavailable", file=sys.stderr, flush=True)
        return
    info = json.loads(inspected.stdout)[0]
    if info["Config"]["Labels"].get(LABEL) != run_key:
        return
    state = info["State"]
    result = docker("logs", "--tail", "80", name, check=False, timeout=3)
    output = result.stdout + result.stderr
    categories = [code for code in ("startup_or_storage_error", "telegram_delivery_failed",
                  "source_task_error", "probe_task_error") if f"ProxySignal: {code}" in output]
    # Whitelist only fixed categories and numeric/Boolean process state.
    # Never emit raw logs, daemon error strings, config values, or credentials.
    print("DIAGNOSTIC " + json.dumps({"exit_code": int(state["ExitCode"]),
          "running": bool(state["Running"]), "oom_killed": bool(state["OOMKilled"]),
          "monitor_error_categories": categories}, sort_keys=True), file=sys.stderr, flush=True)


def main():
    global runtime_owned
    require(os.geteuid() == 0, "run through the authorized isolated-host helper as root")
    require(Path("/sys/fs/cgroup/cgroup.controllers").is_file(), "cgroup v2 required for numeric metrics")
    require(docker("network", "inspect", "bridge", "--format", "{{len .Containers}}").stdout.strip() == "0",
            "default bridge already has workloads")
    require(not runtime.exists(), "laboratory runtime directory already exists")
    runtime.mkdir(mode=0o700)
    runtime_owned = True
    profiles.mkdir(mode=0o755)
    # mkdir's mode is filtered by the inherited private umask. The bind-mounted
    # directory must explicitly permit the unprivileged container to traverse it.
    profiles.chmod(0o755)
    write(profiles / "invalid-token", "0:isolated-lab-invalid-token\n")
    write(profiles / "synthetic.json", synthetic("wrong"))
    source = ("  - id: synthetic\n    kind: file\n    path: /profiles/synthetic.json\n"
              "    scenarios:\n      - id: route\n        url: https://example.com/\n"
              "        route: direct\n        outbound_tag: expected\n")
    if positive_profile:
        document = json.loads(positive_profile.read_text())
        require(isinstance(document, dict), "positive profile must be one complete JSON object")
        write(profiles / "positive.json", json.dumps(document), private=True)
        source += "  - id: positive\n    kind: file\n    path: /profiles/positive.json\n"
    write(profiles / "periodic.yaml", config(source, telegram=True))
    monitor = Monitor(prefix + "periodic", runtime / "periodic-data", "periodic.yaml")
    monitor.start()
    key = "scenario/synthetic/route"
    monitor.wait_for(lambda: monitor.completed(key, "FAILED", 3), "three periodic failure cycles", 100)
    monitor.idle()
    first = monitor.state()
    fresh_record(first, key, "FAILED", "FAILED")
    require(notice_sequence(first, key) == ["FAILED"], "failure was not confirmed once")
    require(notice_sequence(first, "profile/synthetic") == ["FAILED"], "VPN failure incident missing")
    if positive_profile:
        require(monitor.completed("profile/positive", "OK", 3), "authorized laboratory VPN egress was not verified")
        fresh_record(first, "profile/positive", "OK", None)
    require("telegram_delivery_failed" in docker("logs", monitor.name).stderr,
            "failed notification delivery was not observed")
    monitor.stop()
    persisted = monitor.state()
    require(persisted == first, "SIGTERM altered committed incident state")
    generation = monitor.generation()
    monitor.start()
    monitor.wait_for(lambda: monitor.completed(key, "FAILED", 4)
                     and monitor.generation() != generation
                     and monitor.state()["records"][key]["streak"] > first["records"][key]["streak"],
                     "newly committed failure after restart", 30)
    monitor.idle()
    restarted = monitor.state()
    require(restarted["pending"] == first["pending"], "restart duplicated or lost pending notices")
    fresh_record(restarted, key, "FAILED", "FAILED")
    print("PASS: three periodic cycles, real Xray, failed-delivery outbox and SIGTERM/restart deduplication", flush=True)

    replace_synthetic("{invalid-json")
    monitor.wait_for(lambda: monitor.completed("source/synthetic", "FAILED", 2), "source corruption cycles", 80)
    monitor.idle()
    unavailable = monitor.state()
    fresh_record(unavailable, key, "UNKNOWN", "FAILED")
    fresh_record(unavailable, "profile/synthetic", "UNKNOWN", "FAILED")
    require(notice_sequence(unavailable, key) == ["FAILED"], "missing source fabricated a recovery")
    require(notice_sequence(unavailable, "source/synthetic") == ["FAILED"], "source incident not distinct")
    print("PASS: unavailable source creates a separate incident; dependent observations UNKNOWN, active failures retained", flush=True)

    replace_synthetic(synthetic("expected"))
    monitor.wait_for(lambda: monitor.completed(key, "OK", 2), "source and route recovery cycles", 80)
    monitor.idle()
    recovered = monitor.state()
    fresh_record(recovered, key, "OK", None)
    require(notice_sequence(recovered, key) == ["FAILED", "OK"], "route recovery not queued exactly once")
    require(notice_sequence(recovered, "source/synthetic") == ["FAILED", "OK"], "source recovery not queued exactly once")
    require(notice_sequence(recovered, "profile/synthetic") == ["FAILED"], "unreachable VPN falsely recovered")
    if positive_profile:
        fresh_record(recovered, "profile/positive", "OK", None)
        positive_results = re.findall(r"^ts=\d+ target=profile/positive status=([A-Z]+) evidence=", monitor.logs(), re.M)
        require(len(positive_results) >= 8 and set(positive_results) == {"OK"},
                "authorized laboratory VPN egress was not consistently verified across the acceptance cycles")
    monitor.stop()
    monitor.metrics("periodic")
    print("PASS: genuine restored source and HTTPS route recover once; no repeated-cycle notification spam", flush=True)
    print("COVERAGE " + ("authorized laboratory VPN egress verified; fixture provenance is reported by the workflow" if positive_profile else
                         "positive production-like profile unavailable; synthetic HTTPS route verified only"), flush=True)

    # A second Xray accepts an HTTP proxy connection on loopback. The monitor's
    # SOCKS handshake deliberately never forms an HTTP request, so it stalls.
    # Both containers use a network-none namespace: no host firewall changes,
    # external packets, private-production targets, or extra Docker networks.
    write(profiles / "stall.json", json.dumps({"log": {"loglevel": "none"},
          "policy": {"levels": {"0": {"handshake": 30, "connIdle": 30}}},
          "inbounds": [{"tag": "stall", "listen": "127.0.0.1", "port": 19999,
                        "protocol": "http", "settings": {"timeout": 30, "userLevel": 0}}],
          "outbounds": [{"protocol": "blackhole", "tag": "unused"}]}))
    fixture = prefix + "stall"
    docker("run", "-d", "--pull", "never", "--name", fixture, "--label", f"{LABEL}={run_key}",
           "--network", "none", "--read-only", "--user", "65532:65532", "--cap-drop", "ALL",
           "--security-opt", "no-new-privileges", "--cpus", "0.25", "--memory", "128m",
           "--memory-swap", "128m", "--pids-limit", "32", "--env", "GOMAXPROCS=2", "--log-driver", "none",
           "--mount", f"type=bind,src={profiles / 'stall.json'},dst=/stall.json,readonly",
           "--entrypoint", "/usr/local/bin/xray", image, "run", "-config", "/stall.json")
    containers.append(fixture)
    # Observe only this disposable namespace. A running container alone does
    # not establish that the protocol-stall listener has finished starting.
    ready_by = time.monotonic() + 10
    listening = False
    while time.monotonic() < ready_by:
        fixture_state = json.loads(docker("inspect", fixture).stdout)[0]["State"]
        require(fixture_state["Running"] and fixture_state["Pid"] > 0, "stall fixture exited before readiness")
        sockets = Path(f"/proc/{fixture_state['Pid']}/net/tcp").read_text().splitlines()[1:]
        if any(row.split()[1] == f"0100007F:{19999:04X}" and row.split()[3] == "0A" for row in sockets):
            listening = True
            break
        time.sleep(0.1)
    require(listening, "stall fixture listener never became ready")
    timeout_source = ("  - id: deadline\n    kind: file\n    path: /profiles/deadline.json\n"
                      "    scenarios:\n      - id: stalled\n        url: https://example.com/\n"
                      "        route: proxy\n        outbound_tag: stall\n"
                      "  - id: fetch-unavailable\n    kind: https\n"
                      "    url: https://example.com/unavailable-profile.json\n")
    write(profiles / "deadline.json", json.dumps({"outbounds": [{"tag": "stall", "protocol": "socks",
          "settings": {"servers": [{"address": "127.0.0.1", "port": 19999}]}}]}))
    write(profiles / "deadline.yaml", config(timeout_source))
    deadline = Monitor(prefix + "deadline", runtime / "deadline-data", "deadline.yaml", "container:" + fixture)
    deadline.start()
    deadline.wait_for(lambda: deadline.completed("profile/deadline", "UNKNOWN"), "bounded stalled network cycle", 40)
    deadline.idle()
    output = deadline.logs()
    durations = re.findall(r"target=profile/deadline duration_ms=(\d+)", output)
    require(durations and 4500 <= int(durations[-1]) <= 9000, "controlled handshake did not reach bounded timeout")
    require("target=source/fetch-unavailable status=FAILED evidence=source_unavailable" in output
            and "target=profile/fetch-unavailable status=UNKNOWN evidence=source_unavailable" in output,
            "failed HTTPS retrieval was falsely available")
    require(not deadline.completed("scenario/deadline/stalled", "OK"), "stalled HTTPS was falsely OK")
    deadline.stop()
    deadline.start()
    deadline.wait_for(lambda: (deadline.sample() or {}).get("xray") == 1, "active Xray before SIGTERM", 25)
    deadline.stop()
    deadline.metrics("isolated-network-timeout")
    print("PASS: actual loopback handshake timeout, failed HTTPS source, no false OK; SIGTERM during active Xray leaves no child", flush=True)

    # Storage and configuration errors must fail before any probe is possible.
    bad = Monitor(prefix + "bad-state", runtime / "bad-state-data", "deadline.yaml", "none", once=True)
    write(bad.data / "state.json", "{invalid-json", private=True)
    bad.start()
    require(docker("wait", bad.name, timeout=10).stdout.strip() == "1", "corrupt state did not fail closed")
    bad.stopped(1)
    write(profiles / "invalid.yaml", "version: invalid\n")
    invalid = Monitor(prefix + "bad-config", runtime / "bad-config-data", "invalid.yaml", "none", once=True)
    invalid.start()
    require(docker("wait", invalid.name, timeout=10).stdout.strip() == "1", "invalid configuration did not fail closed")
    invalid.stopped(1)
    print("PASS: malformed persisted state and invalid configuration fail closed", flush=True)
    print("LIMITS: sampled short-run resources; not a long soak or live Telegram delivery test. Timestamp expiry is covered by offline tests.", flush=True)


require(len(sys.argv) in (4, 5), "expected IMAGE RUN_KEY PRIVATE_WORK_DIR [FULL_TEST_PROFILE]")
image, run_key, directory = sys.argv[1:4]
require(re.fullmatch(r"[0-9]+-[0-9]+", run_key), "invalid run identity")
require(image == f"proxy-signal:hostland-lab-{run_key}", "image must use the run-specific laboratory tag")
work = Path(directory)
require(work.is_absolute() and work.is_dir() and not work.is_symlink(), "private work directory unavailable")
positive_profile = Path(sys.argv[4]) if len(sys.argv) == 5 else None
if positive_profile:
    require(positive_profile.is_file() and not positive_profile.is_symlink()
            and positive_profile.stat().st_size <= 2 * 1024 * 1024, "test profile file unavailable or oversized")
runtime = work / "runtime"
profiles = runtime / "profiles"
prefix = f"proxy-signal-reliability-{run_key}-"
containers = []
runtime_owned = False
failed = False


def interrupted(_signum, _frame):
    raise RuntimeError("laboratory interrupted")


signal.signal(signal.SIGTERM, interrupted)
signal.signal(signal.SIGINT, interrupted)
try:
    main()
except Exception as error:
    failed = True
    # Only harness-controlled messages are safe; library errors may embed paths.
    reason = str(error) if isinstance(error, RuntimeError) else type(error).__name__
    print("FAIL: " + reason, file=sys.stderr, flush=True)
    try:
        failure_diagnostics()
    except Exception:
        print("DIAGNOSTIC unavailable", file=sys.stderr, flush=True)
finally:
    try:
        cleanup()
    except Exception:
        failed = True
        print("FAIL: laboratory cleanup incomplete; run the external postflight", file=sys.stderr, flush=True)
if failed:
    sys.exit(1)
print(f"PASS: bounded reliability acceptance completed in {time.monotonic() - START:.1f}s; temporary containers and runtime files removed", flush=True)
PY
