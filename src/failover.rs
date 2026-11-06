use crate::{
    balancer,
    config::{BalancerScenario, BalancerStrategy, FailoverScenario},
    incident::{Observation, Status},
    probe, scenario, xray,
};
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    io::{Read, Seek, SeekFrom},
    net::TcpListener,
    path::Path,
    time::Duration,
};
use tempfile::TempDir;
use tokio::time::{sleep, timeout_at, Instant};

pub struct Checks {
    pub config: Observation,
    pub primary: Observation,
    pub backup: Observation,
    pub switch: Observation,
    pub recovery: Observation,
    pub overall: Observation,
}

fn missing(config: Observation) -> Checks {
    let u = Observation::new(Status::Unknown, "failover_not_executed");
    Checks {
        config,
        primary: u,
        backup: u,
        switch: u,
        recovery: u,
        overall: config,
    }
}

/// Failures can only be induced on a fresh, unoccupied loopback SOCKS port.
/// Production endpoints, external sockets and routing configurations are never modified.
pub fn inspect(profile: &Value, case: &FailoverScenario) -> Observation {
    if xray::prepare(profile.clone(), 20999).is_err() {
        return Observation::new(Status::Unsupported, "failover_profile_incompatible");
    }
    let Some(primary) = profile
        .get("outbounds")
        .and_then(Value::as_array)
        .and_then(|items| {
            items
                .iter()
                .find(|o| o.get("tag").and_then(Value::as_str) == Some(case.primary_tag.as_str()))
        })
    else {
        return Observation::new(Status::Unsupported, "failover_primary_missing");
    };
    let servers = primary
        .pointer("/settings/servers")
        .and_then(Value::as_array);
    let safe = primary.get("protocol").and_then(Value::as_str) == Some("socks")
        && servers.is_some_and(|s| {
            s.len() == 1
                && s[0].get("address").and_then(Value::as_str) == Some("127.0.0.1")
                && s[0].get("port").and_then(Value::as_u64) == Some(u64::from(case.control_port))
                && s[0].get("users").is_none()
        })
        && primary
            .pointer("/streamSettings/sockopt/dialerProxy")
            .is_none()
        && primary.get("proxySettings").is_none();
    if !safe {
        return Observation::new(
            Status::Unsupported,
            "failover_requires_local_controlled_socks",
        );
    }
    let Some(outbounds) = profile.get("outbounds").and_then(Value::as_array) else {
        return Observation::new(Status::Unsupported, "failover_outbounds_missing");
    };
    let mut tags = HashSet::new();
    for o in outbounds {
        let Some(tag) = o.get("tag").and_then(Value::as_str) else {
            return Observation::new(Status::Unsupported, "failover_untagged_outbound");
        };
        if !tags.insert(tag) {
            return Observation::new(Status::Unsupported, "failover_duplicate_outbound");
        }
    }
    for alternative in &case.alternatives {
        let Some(outbound) = outbounds
            .iter()
            .find(|o| o.get("tag").and_then(Value::as_str) == Some(alternative))
        else {
            return Observation::new(Status::Failed, "failover_backup_missing");
        };
        if matches!(
            outbound.get("protocol").and_then(Value::as_str),
            None | Some("blackhole" | "loopback" | "dns")
        ) || outbound.get("proxySettings").is_some()
        {
            return Observation::new(Status::Unsupported, "failover_backup_protocol_unsupported");
        }
        // A fallback that dials through the failed primary is not independent.
        let mut next = Some(alternative.as_str());
        let mut visited = HashSet::new();
        while let Some(tag) = next {
            if tag == case.primary_tag.as_str() {
                return Observation::new(Status::Failed, "failover_backup_depends_on_primary");
            }
            if !visited.insert(tag) {
                return Observation::new(Status::Unsupported, "failover_dialer_cycle");
            }
            let Some(node) = outbounds
                .iter()
                .find(|o| o.get("tag").and_then(Value::as_str) == Some(tag))
            else {
                return Observation::new(Status::Failed, "failover_dialer_missing");
            };
            if node.get("proxySettings").is_some() {
                return Observation::new(Status::Unsupported, "failover_legacy_dialer");
            }
            next = match node.pointer("/streamSettings/sockopt/dialerProxy") {
                None => None,
                Some(Value::String(s)) if !s.is_empty() => Some(s.as_str()),
                _ => return Observation::new(Status::Unsupported, "failover_invalid_dialer"),
            };
        }
    }
    let mut candidates = vec![case.primary_tag.clone()];
    candidates.extend(
        case.alternatives
            .iter()
            .filter(|tag| Some(*tag) != case.fallback_tag.as_ref())
            .cloned(),
    );
    let balancer_case = BalancerScenario {
        id: case.id.clone(),
        url: case.url.clone(),
        balancer_tag: case.balancer_tag.clone(),
        strategy: BalancerStrategy::LeastPing,
        candidates,
        candidate_ids: Default::default(),
        fallback_tag: case.fallback_tag.clone(),
    };
    let result = balancer::inspect(profile, &balancer_case);
    if result.status != Status::Ok {
        return result;
    }
    if !balancer::attributable(profile, &balancer_case) {
        return Observation::new(Status::Unsupported, "failover_route_not_attributable");
    }
    Observation::new(Status::Ok, "failover_config_valid")
}

fn backup_status(total: usize, successes: usize, failures: usize) -> Observation {
    if successes == total && total > 0 {
        Observation::new(Status::Ok, "failover_backup_https_verified")
    } else if successes > 0 && failures > 0 {
        Observation::new(Status::Degraded, "failover_backups_partially_failed")
    } else if failures == total && total > 0 {
        Observation::new(Status::Failed, "failover_all_backups_https_failed")
    } else {
        Observation::new(Status::Unknown, "failover_backups_unverified")
    }
}

pub fn overall(
    config: Observation,
    primary: Observation,
    backup: Observation,
    switch: Observation,
    recovery: Observation,
    restore: bool,
) -> Observation {
    if config.status != Status::Ok {
        return config;
    }
    if primary.status == Status::Failed {
        return Observation::new(Status::Failed, "failover_primary_failed");
    }
    if backup.status == Status::Failed {
        return Observation::new(Status::Failed, "failover_backups_failed");
    }
    if switch.status == Status::Failed {
        return Observation::new(Status::Failed, "failover_switch_failed");
    }
    if backup.status == Status::Degraded {
        return Observation::new(Status::Degraded, "failover_partial_backups");
    }
    if primary.status != Status::Ok || backup.status != Status::Ok || switch.status != Status::Ok {
        if primary.status == Status::Ok
            && backup.status == Status::Ok
            && switch.status == Status::Unknown
        {
            return Observation::new(Status::Unknown, "failover_routes_healthy_switch_unverified");
        }
        return Observation::new(Status::Unknown, "failover_incomplete_evidence");
    }
    if restore && recovery.status == Status::Failed {
        Observation::new(Status::Degraded, "failover_recovery_failed")
    } else if restore && recovery.status != Status::Ok {
        Observation::new(Status::Unknown, "failover_recovery_unverified")
    } else {
        Observation::new(Status::Ok, "failover_verified")
    }
}

fn port() -> Result<u16> {
    Ok(TcpListener::bind("127.0.0.1:0")
        .context("failover_loopback_bind")?
        .local_addr()?
        .port())
}

fn config_file(dir: &Path, name: &str, config: &Value) -> Result<std::path::PathBuf> {
    let path = dir.join(name);
    std::fs::write(&path, serde_json::to_vec(config)?).context("failover_temp_config")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(path)
}

async fn sidecar(dir: &Path, port: u16, deadline: Instant) -> Result<xray::ManagedChild> {
    let path = config_file(
        dir,
        "sidecar.json",
        &json!({
            "log": {"loglevel":"none"},
            "inbounds":[{"tag":"controlled-socks", "listen":"127.0.0.1", "port":port, "protocol":"socks", "settings":{"auth":"noauth", "udp":false}}],
            "outbounds":[{"tag":"controlled-direct", "protocol":"freedom"}]
        }),
    )?;
    let mut child = xray::spawn_xray(&path)?;
    timeout_at(deadline, xray::ready(&mut child.child, port)).await??;
    Ok(child)
}

/// Read only the access entries generated during the current request; prior
/// successful requests must never be reused as evidence of a later phase.
fn access_delta(path: &Path, cursor: &mut u64) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let size = file.metadata().ok()?.len();
    if size < *cursor || size.saturating_sub(*cursor) > 128 * 1024 {
        return None;
    }
    file.seek(SeekFrom::Start(*cursor)).ok()?;
    let mut bytes = Vec::new();
    file.take(128 * 1024 + 1).read_to_end(&mut bytes).ok()?;
    *cursor = size;
    String::from_utf8(bytes).ok()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Primary,
    Backup,
}

async fn route_phase(
    case: &FailoverScenario,
    proxy: &str,
    path: &Path,
    cursor: &mut u64,
    deadline: Instant,
    phase: Phase,
) -> Observation {
    let mut last = Observation::new(Status::Unknown, "failover_route_not_observed");
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let result = timeout_at(deadline, probe::probe_https(&case.url, proxy, remaining)).await;
        let access = access_delta(path, cursor);
        if let (Ok(http_ok), Some(access)) = (result, access) {
            match scenario::observed_outbound(&case.url, "proxy-signal-probe-in", &access) {
                Ok(tag) if phase == Phase::Primary && tag == case.primary_tag => {
                    return if http_ok {
                        Observation::new(Status::Ok, "failover_primary_https_verified")
                    } else {
                        Observation::new(Status::Failed, "failover_primary_https_failed")
                    };
                }
                Ok(tag) if phase == Phase::Backup && case.alternatives.iter().any(|s| s == tag) => {
                    return if http_ok {
                        Observation::new(Status::Ok, "failover_backup_selected_https_verified")
                    } else {
                        Observation::new(Status::Failed, "failover_selected_backup_https_failed")
                    };
                }
                Ok(tag) if phase == Phase::Backup && tag == case.primary_tag => {
                    // The observatory may still be converging. Not a switch.
                    last = Observation::new(Status::Unknown, "failover_still_selecting_primary");
                }
                Ok(_) => last = Observation::new(Status::Unknown, "failover_unexpected_route"),
                Err(_) => last = Observation::new(Status::Unknown, "failover_route_not_observed"),
            }
        } else {
            last = Observation::new(Status::Unknown, "failover_probe_timeout_or_missing_logs");
        }
        sleep(std::cmp::min(
            Duration::from_secs(2),
            deadline.saturating_duration_since(Instant::now()),
        ))
        .await;
    }
    last
}

/// Dedicated live trial. No production socket is touched: the primary must
/// point at this process's own loopback sidecar. Xray stays alive across failure.
pub async fn check(profile: Value, case: &FailoverScenario, budget: Duration) -> Checks {
    let config = inspect(&profile, case);
    if config.status != Status::Ok {
        return missing(config);
    }
    match tokio::time::timeout(budget, run(profile, case, config, budget)).await {
        Ok(Ok(checks)) => checks,
        _ => {
            let u = Observation::new(Status::Unknown, "failover_lab_runtime_unavailable");
            Checks {
                config,
                primary: u,
                backup: u,
                switch: u,
                recovery: u,
                overall: u,
            }
        }
    }
}

async fn run(
    profile: Value,
    case: &FailoverScenario,
    config: Observation,
    budget: Duration,
) -> Result<Checks> {
    let dir = TempDir::new().context("failover_tempdir")?;
    // Refuse to start if *anything* already owns the configured primary port.
    let guard =
        TcpListener::bind(("127.0.0.1", case.control_port)).context("failover_port_in_use")?;
    let probe_port = port()?;
    let mut prepared = xray::prepare(profile, probe_port)?;
    let mut candidates = Vec::new();
    let mut used_ports = HashSet::from([case.control_port, probe_port]);
    for (index, tag) in case.alternatives.iter().enumerate() {
        let candidate_port = loop {
            let available = port()?;
            if used_ports.insert(available) {
                break available;
            }
        };
        candidates.push((
            tag.clone(),
            format!("proxy-signal-failover-{index}"),
            candidate_port,
        ));
    }
    xray::install_candidate_diagnostics(&mut prepared, &candidates)?;
    let access_path = dir.path().join("access.log");
    prepared["log"] = json!({"access":access_path.to_string_lossy(), "loglevel":"info"});
    let profile_file = config_file(dir.path(), "profile.json", &prepared)?;
    drop(guard);
    let phase_budget = std::cmp::max(Duration::from_secs(1), budget / 3);
    let mut primary_child =
        sidecar(dir.path(), case.control_port, Instant::now() + phase_budget).await?;
    let mut main_child = xray::spawn_xray(&profile_file)?;
    let result = async {
        timeout_at(
            Instant::now() + phase_budget,
            xray::ready(&mut main_child.child, probe_port),
        )
        .await??;
        let proxy = format!("http://127.0.0.1:{probe_port}");
        let mut cursor = 0;
        let primary = route_phase(
            case,
            &proxy,
            &access_path,
            &mut cursor,
            Instant::now() + phase_budget,
            Phase::Primary,
        )
        .await;
        // Run all diagnostic outbound probes independently. A stalled backup
        // cannot prevent another backup from producing useful evidence.
        let candidate_deadline = Instant::now() + phase_budget;
        let mut tasks = tokio::task::JoinSet::new();
        for (index, (_, _, candidate_port)) in candidates.iter().enumerate() {
            let url = case.url.clone();
            let candidate_proxy = format!("http://127.0.0.1:{candidate_port}");
            tasks.spawn(async move {
                (
                    index,
                    timeout_at(
                        candidate_deadline,
                        probe::probe_https(&url, &candidate_proxy, phase_budget),
                    )
                    .await
                    .ok(),
                )
            });
        }
        let mut responses = vec![None; candidates.len()];
        while let Some(Ok((index, result))) = tasks.join_next().await {
            responses[index] = result;
        }
        let access = access_delta(&access_path, &mut cursor);
        let mut successes = 0;
        let mut failures = 0;
        for ((tag, inbound, _), response) in candidates.iter().zip(responses) {
            match (response, access.as_deref()) {
                (Some(ok), Some(log))
                    if scenario::observed_outbound(&case.url, inbound, log) == Ok(tag.as_str()) =>
                {
                    if ok {
                        successes += 1;
                    } else {
                        failures += 1;
                    }
                }
                _ => {}
            }
        }
        let backup = backup_status(candidates.len(), successes, failures);
        let mut switch = Observation::new(Status::Unknown, "failover_switch_not_executed");
        let mut recovery = Observation::new(Status::Unknown, "failover_recovery_not_requested");
        // A verified alternative permits the switch trial even when other
        // backups failed or lack evidence. Keep its result independent.
        if primary.status == Status::Ok && successes > 0 {
            primary_child.stop().await;
            // Ensure the injected failure is real before checking route selection.
            if tokio::net::TcpStream::connect(("127.0.0.1", case.control_port))
                .await
                .is_err()
            {
                switch = route_phase(
                    case,
                    &proxy,
                    &access_path,
                    &mut cursor,
                    Instant::now() + phase_budget,
                    Phase::Backup,
                )
                .await;
                if case.restore_primary {
                    primary_child =
                        sidecar(dir.path(), case.control_port, Instant::now() + phase_budget)
                            .await?;
                    recovery = route_phase(
                        case,
                        &proxy,
                        &access_path,
                        &mut cursor,
                        Instant::now() + phase_budget,
                        Phase::Primary,
                    )
                    .await;
                }
            } else {
                switch = Observation::new(Status::Unknown, "failover_fault_not_isolated");
            }
        }
        let overall = overall(
            config,
            primary,
            backup,
            switch,
            recovery,
            case.restore_primary,
        );
        Ok(Checks {
            config,
            primary,
            backup,
            switch,
            recovery,
            overall,
        })
    }
    .await;
    main_child.stop().await;
    primary_child.stop().await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn case() -> FailoverScenario {
        FailoverScenario {
            id: "switch".into(),
            url: "https://example.com/".into(),
            balancer_tag: "pool".into(),
            primary_tag: "primary".into(),
            alternatives: vec!["backup".into()],
            fallback_tag: Some("backup".into()),
            control_port: 34567,
            restore_primary: true,
        }
    }
    fn profile() -> Value {
        json!({
            "outbounds":[
                {"tag":"primary","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":34567}]}},
                {"tag":"backup","protocol":"freedom"}
            ],
            "routing":{"balancers":[{"tag":"pool","selector":["primary"],"fallbackTag":"backup","strategy":{"type":"leastPing"}}],
              "rules":[{"type":"field","domain":["full:example.com"],"balancerTag":"pool"}]},
            "observatory":{"subjectSelector":["primary"],"probeUrl":"https://example.com/","probeInterval":"2s"}
        })
    }
    #[test]
    fn rejects_nonlocal_or_dependent_outages() {
        assert_eq!(inspect(&profile(), &case()).status, Status::Ok);
        let mut p = profile();
        p["outbounds"][0]["settings"]["servers"][0]["address"] = json!("example.org");
        assert_eq!(inspect(&p, &case()).status, Status::Unsupported);
        p = profile();
        p["outbounds"][1]["streamSettings"] = json!({"sockopt":{"dialerProxy":"primary"}});
        assert_eq!(
            inspect(&p, &case()).code,
            "failover_backup_depends_on_primary"
        );
        p = profile();
        p["routing"]["rules"][0]["domain"] = json!(["domain:example.com"]);
        assert_eq!(inspect(&p, &case()).status, Status::Unsupported);
        p = profile();
        p["routing"]["balancers"][0]["fallbackTag"] = json!("wrong");
        assert_eq!(inspect(&p, &case()).status, Status::Failed);
    }
    #[test]
    fn no_false_ok_on_missing_evidence_or_recovery() {
        let ok = Observation::new(Status::Ok, "ok");
        let u = Observation::new(Status::Unknown, "unknown");
        let bad = Observation::new(Status::Failed, "failed");
        assert_eq!(overall(ok, ok, ok, u, ok, true).status, Status::Unknown);
        assert_eq!(overall(ok, ok, ok, bad, ok, true).status, Status::Failed);
        assert_eq!(overall(ok, ok, ok, ok, bad, true).status, Status::Degraded);
        assert_eq!(overall(ok, ok, ok, ok, u, true).status, Status::Unknown);
        assert_eq!(overall(ok, ok, ok, ok, ok, true).status, Status::Ok);
    }

    #[test]
    fn multiple_backup_status_requires_complete_success_evidence() {
        for (total, successes, failures, expected) in [
            (1, 1, 0, Status::Ok),
            (2, 2, 0, Status::Ok),
            (2, 1, 1, Status::Degraded),
            (3, 1, 1, Status::Degraded),
            (2, 1, 0, Status::Unknown),
            (2, 0, 1, Status::Unknown),
            (2, 0, 2, Status::Failed),
            (2, 0, 0, Status::Unknown),
            (0, 0, 0, Status::Unknown),
        ] {
            assert_eq!(
                backup_status(total, successes, failures).status,
                expected,
                "total={total}, successes={successes}, failures={failures}"
            );
        }
    }

    #[test]
    fn verified_switch_does_not_hide_partial_backup_outage() {
        let ok = Observation::new(Status::Ok, "ok");
        let partial = Observation::new(Status::Degraded, "partial_backups");
        let unknown = Observation::new(Status::Unknown, "unobserved");
        for (recovery, restore) in [(ok, true), (unknown, false)] {
            let result = overall(ok, ok, partial, ok, recovery, restore);
            assert_eq!(result.status, Status::Degraded);
            assert_eq!(result.code, "failover_partial_backups");
        }
    }

    #[test]
    fn partial_backup_outage_remains_known_when_switch_is_unverified() {
        let ok = Observation::new(Status::Ok, "ok");
        let partial = Observation::new(Status::Degraded, "partial_backups");
        let unknown = Observation::new(Status::Unknown, "unobserved");
        let result = overall(ok, ok, partial, unknown, unknown, true);
        assert_eq!(result.status, Status::Degraded);
        assert_eq!(result.code, "failover_partial_backups");
    }

    #[test]
    fn confirmed_failures_take_precedence_over_partial_backup_outage() {
        let ok = Observation::new(Status::Ok, "ok");
        let partial = Observation::new(Status::Degraded, "partial_backups");
        let failed = Observation::new(Status::Failed, "confirmed_failure");
        let unknown = Observation::new(Status::Unknown, "unobserved");
        for (primary, backup, switch, code) in [
            (failed, partial, ok, "failover_primary_failed"),
            (ok, failed, unknown, "failover_backups_failed"),
            (ok, partial, failed, "failover_switch_failed"),
            (ok, unknown, failed, "failover_switch_failed"),
        ] {
            let result = overall(ok, primary, backup, switch, unknown, false);
            assert_eq!(result.status, Status::Failed);
            assert_eq!(result.code, code);
        }
    }

    #[test]
    fn verified_switch_does_not_prove_unobserved_backups_healthy() {
        let ok = Observation::new(Status::Ok, "ok");
        let unknown = Observation::new(Status::Unknown, "unobserved");
        let result = overall(ok, ok, unknown, ok, ok, true);
        assert_eq!(result.status, Status::Unknown);
        assert_eq!(result.code, "failover_incomplete_evidence");
    }

    #[tokio::test]
    async fn occupied_control_port_cannot_be_modified() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let occupied = listener.local_addr().unwrap().port();
        let mut c = case();
        c.control_port = occupied;
        let mut p = profile();
        p["outbounds"][0]["settings"]["servers"][0]["port"] = json!(occupied);
        let result = check(p, &c, Duration::from_millis(10)).await;
        assert_eq!(result.config.status, Status::Ok);
        assert_eq!(result.overall.status, Status::Unknown);
        assert!(listener.local_addr().is_ok());
    }

    #[tokio::test]
    async fn expired_phase_does_not_reuse_stale_route_evidence() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("access");
        std::fs::write(
            &path,
            "2026/01/01 from 127.0.0.1:123 accepted //example.com:443 [proxy-signal-probe-in ==> backup]",
        ).unwrap();
        let mut cursor = 0;
        let result = route_phase(
            &case(),
            "http://127.0.0.1:9",
            &path,
            &mut cursor,
            Instant::now(),
            Phase::Backup,
        )
        .await;
        assert_eq!(result.status, Status::Unknown);
    }

    #[test]
    fn phase_evidence_is_not_reused() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("log");
        std::fs::write(&path, "first").unwrap();
        let mut offset = 0;
        assert_eq!(access_delta(&path, &mut offset).as_deref(), Some("first"));
        assert_eq!(access_delta(&path, &mut offset).as_deref(), Some(""));
        std::fs::write(&path, "second").unwrap();
        assert_eq!(access_delta(&path, &mut offset).as_deref(), Some("d"));
    }
}
