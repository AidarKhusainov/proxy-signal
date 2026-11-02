"""Temporary CI-only RED controls; removed before final PR delivery."""
from pathlib import Path
import subprocess


def replace_body(text, signature, body):
    start = text.index("{", text.index(signature))
    depth = 1
    end = start + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[:start + 1] + "\n" + body + "\n" + text[end - 1:]


paths = [Path("src/incident.rs"), Path("src/main.rs"), Path("src/xray.rs")]
originals = {path: path.read_text() for path in paths}
try:
    incident = replace_body(originals[paths[0]], "fn expire_stale_at(", "        let _ = (now, max_age_seconds);")
    incident = incident.replace("const MAX_PENDING: usize = 2 * MAX_RECORDS;", "const MAX_PENDING: usize = 128;")
    incident = replace_body(incident, "fn queue(", '''        if self.pending.len() == MAX_PENDING {
            self.pending.remove(0);
        }
        self.pending.push(Notice { key: key.to_string(), status, when: unix_seconds() });''')
    paths[0].write_text(incident)
    main = replace_body(originals[paths[1]], "fn fresh_observation(", "    let _ = (now, max_age_seconds);\n    observation")
    main = replace_body(main, "fn stamp_cycle(", "    let _ = (results, cycle_started_at);")
    main = main.replace("    for (key, observation) in rows {", "    state.expire_stale(max_age_seconds);\n    for (key, observation) in rows {", 1)
    paths[1].write_text(main)
    xray = originals[paths[2]].replace("        if self.finished {\n            return;\n        }\n        self.kill_group();", "        self.kill_group();", 1)
    paths[2].write_text(xray)
    result = subprocess.run(["cargo", "test", "--locked", "--all-targets"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
    print(result.stdout)
    assert result.returncode == 101 and "test result: FAILED." in result.stdout, "RED control did not execute failing tests"
    expected = [
        "expired_observations_become_unknown_without_recovering_confirmed_incidents",
        "maximum_configuration_outages_and_recoveries_remain_durable_in_order",
        "delayed_results_cannot_be_published_as_fresh_success_or_recovery",
        "late_aggregates_cannot_refresh_old_cycle_evidence",
        "repeated_stop_never_signals_a_reused_process_group",
    ]
    for name in expected:
        assert any(name + " ... FAILED" in line for line in result.stdout.splitlines()), f"missing behavioral RED: {name}"
    print("PASS: freshness, queue capacity and idempotent cleanup regressions fail with the fixes disabled")
finally:
    for path, content in originals.items():
        path.write_text(content)
