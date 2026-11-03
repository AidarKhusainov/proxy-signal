mod balancer;
mod cascade;
mod cdn;
mod config;
mod failover;
mod incident;
mod probe;
mod scenario;
mod source;
mod telegram;
mod xray;

use crate::{
    config::{Config, Source},
    incident::{Observation, State, Status},
    probe::TargetResult,
};
use anyhow::{Context, Result};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::{task::JoinSet, time::MissedTickBehavior};

type ResultRow = (String, Observation);

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        // Errors can contain secrets (especially HTTP URLs); never print their chains.
        eprintln!(
            "ProxySignal: startup_or_storage_error (see configuration and filesystem permissions)"
        );
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() < 2 || args.len() > 3 || (args.len() == 3 && args[2] != "--once") {
        anyhow::bail!("usage: proxy-signal /etc/proxy-signal/config.yaml [--once]");
    }
    let config = config::load(&args[1])?;
    let sender = config
        .telegram
        .as_ref()
        .map(telegram::Sender::new)
        .transpose()?;
    let mut state = State::load(&config.state_file).context("state_load")?;
    // Keep confirmed incidents, but do not present an old checkpoint as a
    // current observation while the first network checks are still running.
    let max_age_seconds = config.interval_seconds + config.timeout_seconds;
    state.expire_stale(max_age_seconds);
    state.persist(&config.state_file)?;
    let mut timer = tokio::time::interval(Duration::from_secs(config.interval_seconds));
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = shutdown() => break,
            _ = timer.tick() => {
                state.expire_stale(max_age_seconds);
                state.persist(&config.state_file)?;
                // Keep shutdown responsive even if a profile check stalls.
                let rows = tokio::select! {
                    _ = shutdown() => break,
                    rows = cycle(&config) => rows,
                };
                let healthy = record_cycle(&mut state, &rows, sender.is_some(), max_age_seconds);
                // Persist transitions *before* any delivery; failed sends stay pending.
                state.persist(&config.state_file)?;
                if let Some(sender) = &sender {
                    tokio::select! {
                        _ = shutdown() => break,
                        delivered = sender.deliver_pending(&mut state, &config.state_file) => delivered?,
                    }
                }
                if args.len() == 3 {
                    if !healthy {
                        anyhow::bail!("one_shot_unhealthy");
                    }
                    break;
                }
            }
        }
    }
    Ok(())
}

fn record_cycle(
    state: &mut State,
    rows: &[ResultRow],
    notifications: bool,
    max_age_seconds: u64,
) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let mut healthy = true;
    for (key, observation) in rows {
        let observation = fresh_observation(*observation, now, max_age_seconds);
        healthy &= observation.status == Status::Ok;
        println!(
            "ts={} target={key} status={} evidence={}",
            observation.observed_at,
            observation.status.as_str(),
            observation.code
        );
        state.observe(key, observation, notifications);
    }
    // Refresh comparable records first: expiring a previous cycle here before
    // its new result would erase a valid failure streak during a slow cycle.
    state.expire_stale(max_age_seconds);
    healthy
}

fn fresh_observation(observation: Observation, now: u64, max_age_seconds: u64) -> Observation {
    if now
        .checked_sub(observation.observed_at)
        .is_some_and(|age| age <= max_age_seconds)
    {
        observation
    } else {
        let mut stale = Observation::new(Status::Unknown, "observation_stale");
        stale.observed_at = observation.observed_at;
        stale
    }
}

async fn shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut terminate) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = terminate.recv() => {},
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

async fn cycle(config: &Config) -> Vec<ResultRow> {
    let cycle_started_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let timeout = Duration::from_secs(config.timeout_seconds);
    // Direct observations come from the same container and endpoint as tunnel observations.
    let mut endpoints = Vec::new();
    for endpoint in &config.endpoints {
        let direct = tokio::time::timeout(timeout, probe::get_exit_ip(endpoint, None, timeout))
            .await
            .ok()
            .and_then(Result::ok);
        endpoints.push((endpoint.clone(), direct));
    }
    let mut results = Vec::new();
    let mut profiles = Vec::new();
    // Bound subscription refreshes as well as Xray processes. One slow source
    // must not block every unrelated source in the same cycle.
    for batch in config.sources.chunks(config.parallelism) {
        let mut loads = JoinSet::new();
        for entry in batch {
            let entry = entry.clone();
            loads.spawn(async move {
                let loaded = tokio::time::timeout(timeout, source::load(&entry, timeout)).await;
                (entry, loaded)
            });
        }
        let mut completed = std::collections::HashSet::new();
        while let Some(result) = loads.join_next().await {
            match result {
                Ok((entry, Ok(Ok(document)))) => {
                    completed.insert(entry.id().to_string());
                    // Loading the subscription is not proof that all expected
                    // profiles are present and no extra entries appeared.
                    let actual_entries = document.as_array().map_or(1, Vec::len);
                    match source::select(&entry, document) {
                        Ok(selected) => {
                            let complete =
                                source::selection_complete(&selected, actual_entries);
                            results.push((
                                format!("source/{}", entry.id()),
                                if complete {
                                    Observation::new(Status::Ok, "source_loaded")
                                } else {
                                    Observation::new(Status::Failed, "source_profile_contract_failed")
                                },
                            ));
                            for selected in selected {
                                if let Some(document) = selected.document {
                                    profiles.push((selected.source, document));
                                } else {
                                    unavailable_profile(
                                        &mut results,
                                        &selected.source,
                                        selected.unavailable_code,
                                    );
                                }
                            }
                        }
                        Err(_) => {
                            results.push((
                                format!("source/{}", entry.id()),
                                Observation::new(Status::Failed, "source_invalid"),
                            ));
                            for profile in entry.expanded() {
                                unavailable_profile(&mut results, &profile, "source_invalid");
                            }
                        }
                    }
                }
                Ok((entry, _)) => {
                    completed.insert(entry.id().to_string());
                    // Failed subscription refresh is not evidence of a VPN failure.
                    results.push((
                        format!("source/{}", entry.id()),
                        Observation::new(Status::Failed, "source_unavailable"),
                    ));
                    for profile in entry.expanded() {
                        unavailable_profile(&mut results, &profile, "source_unavailable");
                    }
                }
                Err(_) => eprintln!("ProxySignal: source_task_error"),
            }
        }
        for entry in batch {
            if !completed.contains(entry.id()) {
                results.push((
                    format!("source/{}", entry.id()),
                    Observation::new(Status::Unknown, "source_task_error"),
                ));
                for profile in entry.expanded() {
                    unavailable_profile(&mut results, &profile, "source_task_error");
                }
            }
        }
    }

    for batch in profiles.chunks(config.parallelism) {
        let mut tasks = JoinSet::new();
        for (entry, document) in batch {
            let entry: Source = entry.clone();
            let document = document.clone();
            let targets = endpoints.clone();
            tasks.spawn(async move {
                let start = Instant::now();
                // Native CDN reachability starts independently of Xray startup.
                let native_cdn_task = tokio::spawn({
                    let cases = entry.cdn().to_vec();
                    async move {
                        let mut jobs = JoinSet::new();
                        let mut results: Vec<Option<cdn::EndpointChecks>> =
                            (0..cases.len()).map(|_| None).collect();
                        for (index, case) in cases.into_iter().enumerate() {
                            jobs.spawn(async move { (index, cdn::endpoint(&case, timeout).await) });
                        }
                        while let Some(Ok((index, result))) = jobs.join_next().await {
                            results[index] = Some(result);
                        }
                        results
                    }
                });
                let scenario_rows = |status: Status, code: &'static str| {
                    entry
                        .scenarios()
                        .iter()
                        .map(|case| {
                            (
                                format!("scenario/{}/{}", entry.id(), case.id),
                                if status == Status::Unknown {
                                    scenario::static_check(&document, case)
                                        .unwrap_or(Observation::new(status, code))
                                } else {
                                    Observation::new(status, code)
                                },
                            )
                        })
                        .collect::<Vec<_>>()
                };
                let unavailable_balancers = |status: Status, code: &'static str| {
                    entry
                        .balancers()
                        .iter()
                        .flat_map(|case| {
                            let key = format!("balancer/{}/{}", entry.id(), case.id);
                            let config = if status == Status::Unsupported {
                                Observation::new(status, code)
                            } else {
                                balancer::inspect(&document, case)
                            };
                            let missing = Observation::new(status, code);
                            let overall = if config.status == Status::Ok {
                                missing
                            } else {
                                config
                            };
                            let mut rows = vec![
                                (format!("{key}/config"), config),
                                (format!("{key}/candidates"), missing),
                                (format!("{key}/route"), missing),
                                (key.clone(), overall),
                            ];
                            rows.extend(
                                case.candidates
                                    .iter()
                                    .enumerate()
                                    .map(|(index, _)| (candidate_key(&key, index), missing)),
                            );
                            rows
                        })
                        .collect::<Vec<_>>()
                };
                let unavailable_cascades = |status: Status, code: &'static str| {
                    entry
                        .cascades()
                        .iter()
                        .flat_map(|case| {
                            let key = format!("cascade/{}/{}", entry.id(), case.id);
                            let config = if status == Status::Unsupported {
                                Observation::new(status, code)
                            } else {
                                cascade::inspect(&document, case)
                            };
                            let unavailable = Observation::new(status, code);
                            let overall = if config.status == Status::Ok {
                                unavailable
                            } else {
                                config
                            };
                            vec![
                                (format!("{key}/config"), config),
                                (format!("{key}/https"), unavailable),
                                (format!("{key}/hops"), unavailable),
                                (key, overall),
                            ]
                        })
                        .collect::<Vec<_>>()
                };
                let unavailable_cdn = |status: Status, code: &'static str| {
                    entry
                        .cdn()
                        .iter()
                        .map(|case| {
                            let config = if status == Status::Unsupported {
                                Observation::new(status, code)
                            } else {
                                cdn::inspect(&document, case)
                            };
                            xray::CdnChecks {
                                config,
                                tunnel: Observation::new(status, code),
                                route: Observation::new(status, code),
                            }
                        })
                        .collect::<Vec<_>>()
                };
                let (observation, checks, balance_checks, cascade_checks, cdn_xray_checks) = if xray::prepare(document.clone(), 9876)
                    .is_err()
                {
                    (
                        Observation::new(Status::Unsupported, "profile_incompatible"),
                        scenario_rows(Status::Unsupported, "profile_incompatible"),
                        unavailable_balancers(Status::Unsupported, "profile_incompatible"),
                        unavailable_cascades(Status::Unsupported, "profile_incompatible"),
                        unavailable_cdn(Status::Unsupported, "profile_incompatible"),
                    )
                } else if targets.iter().all(|(_, ip)| ip.is_none())
                    && entry.scenarios().is_empty()
                    && entry.balancers().is_empty()
                    && entry.cascades().is_empty()
                    && entry.cdn().is_empty()
                {
                    (
                        Observation::new(Status::Unknown, "no_direct_baseline"),
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                    )
                } else {
                    match xray::check(
                        document.clone(),
                        &targets,
                        entry.expected_exit_ips(),
                        entry.scenarios(),
                        entry.balancers(),
                        entry.cascades(),
                        entry.cdn(),
                        timeout,
                    )
                    .await
                    {
                        Ok(steps) => {
                            for ((endpoint, _), step) in targets.iter().zip(&steps.egress) {
                                println!(
                                    "target=profile/{} endpoint={} proof={step:?}",
                                    entry.id(),
                                    endpoint.id
                                );
                            }
                            let checks = entry
                                .scenarios()
                                .iter()
                                .zip(steps.scenarios)
                                .map(|(case, result)| {
                                    (format!("scenario/{}/{}", entry.id(), case.id), result)
                                })
                                .collect();
                            let balance_checks = entry
                                .balancers()
                                .iter()
                                .zip(steps.balancers)
                                .flat_map(|(case, evidence)| {
                                    let key = format!("balancer/{}/{}", entry.id(), case.id);
                                    if let Some(index) = evidence.selected_candidate_index {
                                        println!(
                                            "target={key} selected_candidate_index={index} proof=xray_access"
                                        );
                                    }
                                    let mut rows = vec![
                                        (format!("{key}/config"), evidence.config),
                                        (format!("{key}/candidates"), evidence.candidates),
                                        (format!("{key}/route"), evidence.route),
                                        (key.clone(), evidence.overall),
                                    ];
                                    rows.extend(
                                        case.candidates
                                            .iter()
                                            .zip(evidence.candidate_details)
                                            .enumerate()
                                            .map(|(index, (_, observation))| {
                                                (candidate_key(&key, index), observation)
                                            }),
                                    );
                                    rows
                                })
                                .collect();
                            let cascade_checks = entry
                                .cascades()
                                .iter()
                                .zip(steps.cascades)
                                .flat_map(|(case, evidence)| {
                                    let key = format!("cascade/{}/{}", entry.id(), case.id);
                                    vec![
                                        (format!("{key}/config"), evidence.config),
                                        (format!("{key}/https"), evidence.https),
                                        (format!("{key}/hops"), evidence.hops),
                                        (key, evidence.overall),
                                    ]
                                })
                                .collect();
                            let observation = if targets.iter().all(|(_, ip)| ip.is_none()) {
                                Observation::new(Status::Unknown, "no_direct_baseline")
                            } else {
                                classify(&steps.egress)
                            };
                            (observation, checks, balance_checks, cascade_checks, steps.cdn)
                        }
                        Err(_) => (
                            Observation::new(Status::Unknown, "xray_runtime_error"),
                            scenario_rows(Status::Unknown, "xray_runtime_error"),
                            unavailable_balancers(Status::Unknown, "xray_runtime_error"),
                            unavailable_cascades(Status::Unknown, "xray_runtime_error"),
                            unavailable_cdn(Status::Unknown, "xray_runtime_error"),
                        ),
                    }
                };
                let mut native_cdn = native_cdn_task.await.unwrap_or_default();
                let cdn_checks = entry
                    .cdn()
                    .iter()
                    .zip(cdn_xray_checks)
                    .enumerate()
                    .flat_map(|(index, (case, xray))| {
                        let native = native_cdn
                            .get_mut(index)
                            .and_then(Option::take)
                            .unwrap_or_else(cdn::unavailable_endpoint);
                        let key = format!("cdn/{}/{}", entry.id(), case.id);
                        let overall = cdn::overall(xray.config, native.overall, xray.tunnel, xray.route);
                        vec![
                            (format!("{key}/dns"), native.dns),
                            (format!("{key}/tls"), native.tls),
                            (format!("{key}/http"), native.http),
                            (format!("{key}/endpoint"), native.overall),
                            (format!("{key}/config"), xray.config),
                            (format!("{key}/tunnel"), xray.tunnel),
                            (format!("{key}/route"), xray.route),
                            (key, overall),
                        ]
                    })
                    .collect::<Vec<_>>();
                let client_evidence = (entry.id().contains('/') || xray::has_enabled_sniffing(&document)).then(|| {
                    (
                        format!("profile/{}/client", entry.id()),
                        Observation::new(Status::Unknown, "client_inbound_unverified"),
                    )
                });
                (
                    format!("profile/{}", entry.id()),
                    observation,
                    start.elapsed(),
                    checks,
                    balance_checks,
                    cascade_checks,
                    cdn_checks,
                    {
                        let mut checks = Vec::new();
                        for case in entry.failover() {
                            let evidence = failover::check(document.clone(), case, timeout).await;
                            let key = format!("failover/{}/{}", entry.id(), case.id);
                            checks.extend([
                                (format!("{key}/config"), evidence.config),
                                (format!("{key}/primary"), evidence.primary),
                                (format!("{key}/backup"), evidence.backup),
                                (format!("{key}/switch"), evidence.switch),
                            ]);
                            if case.restore_primary {
                                checks.push((format!("{key}/recovery"), evidence.recovery));
                            }
                            checks.push((key, evidence.overall));
                        }
                        checks
                    },
                    client_evidence,
                )
            });
        }
        let mut completed = std::collections::HashSet::new();
        while let Some(result) = tasks.join_next().await {
            if let Ok((
                key,
                observation,
                elapsed,
                scenarios,
                balancers,
                cascades,
                cdn,
                failover,
                client_evidence,
            )) = result
            {
                println!("target={key} duration_ms={}", elapsed.as_millis());
                completed.insert(key.clone());
                if key.matches('/').count() == 2 {
                    // Exit IP is not proof of the chosen route. The optional
                    // scenario/balancer checks provide any narrower route evidence.
                    results.push((
                        format!("{key}/route"),
                        Observation::new(Status::Unknown, "profile_route_unverified"),
                    ));
                }
                results.push((key, observation));
                results.extend(scenarios);
                results.extend(balancers);
                results.extend(cascades);
                results.extend(cdn);
                results.extend(failover);
                if let Some(client_evidence) = client_evidence {
                    results.push(client_evidence);
                }
            } else {
                eprintln!("ProxySignal: probe_task_error");
            }
        }
        for (entry, _) in batch {
            let key = format!("profile/{}", entry.id());
            if !completed.contains(&key) {
                unavailable_profile(&mut results, entry, "probe_task_error");
            }
        }
    }
    stamp_cycle(&mut results, cycle_started_at);
    results
}

fn stamp_cycle(results: &mut [ResultRow], cycle_started_at: u64) {
    // Aggregates and the direct baseline share this cycle. A late aggregate
    // must not make the earlier evidence supporting it appear fresh again.
    for (_, observation) in results {
        observation.observed_at = observation.observed_at.min(cycle_started_at);
    }
}

fn candidate_key(balancer_key: &str, index: usize) -> String {
    format!("{balancer_key}/candidate/{index}")
}

fn unavailable_profile(results: &mut Vec<ResultRow>, entry: &Source, code: &'static str) {
    results.push((
        format!("profile/{}", entry.id()),
        Observation::new(Status::Unknown, code),
    ));
    unavailable_checks(results, entry, code);
    if entry.id().contains('/') {
        results.push((
            format!("profile/{}/route", entry.id()),
            Observation::new(Status::Unknown, code),
        ));
        results.push((
            format!("profile/{}/client", entry.id()),
            Observation::new(Status::Unknown, "client_inbound_unverified"),
        ));
    }
}

fn unavailable_checks(results: &mut Vec<ResultRow>, entry: &Source, code: &'static str) {
    for case in entry.scenarios() {
        results.push((
            format!("scenario/{}/{}", entry.id(), case.id),
            Observation::new(Status::Unknown, code),
        ));
    }
    for case in entry.cascades() {
        let key = format!("cascade/{}/{}", entry.id(), case.id);
        for component in ["config", "https", "hops"] {
            results.push((
                format!("{key}/{component}"),
                Observation::new(Status::Unknown, code),
            ));
        }
        results.push((key, Observation::new(Status::Unknown, code)));
    }
    for case in entry.cdn() {
        let key = format!("cdn/{}/{}", entry.id(), case.id);
        for component in [
            "dns", "tls", "http", "endpoint", "config", "tunnel", "route",
        ] {
            results.push((
                format!("{key}/{component}"),
                Observation::new(Status::Unknown, code),
            ));
        }
        results.push((key, Observation::new(Status::Unknown, code)));
    }
    for case in entry.failover() {
        let key = format!("failover/{}/{}", entry.id(), case.id);
        for component in ["config", "primary", "backup", "switch"] {
            results.push((
                format!("{key}/{component}"),
                Observation::new(Status::Unknown, code),
            ));
        }
        if case.restore_primary {
            results.push((
                format!("{key}/recovery"),
                Observation::new(Status::Unknown, code),
            ));
        }
        results.push((key, Observation::new(Status::Unknown, code)));
    }
    for case in entry.balancers() {
        let key = format!("balancer/{}/{}", entry.id(), case.id);
        for component in ["config", "candidates", "route"] {
            results.push((
                format!("{key}/{component}"),
                Observation::new(Status::Unknown, code),
            ));
        }
        for (index, _) in case.candidates.iter().enumerate() {
            results.push((
                candidate_key(&key, index),
                Observation::new(Status::Unknown, code),
            ));
        }
        results.push((key, Observation::new(Status::Unknown, code)));
    }
}

fn classify(steps: &[TargetResult]) -> Observation {
    let passed = steps.iter().filter(|s| **s == TargetResult::Passed).count();
    let failed = steps.iter().filter(|s| **s == TargetResult::Failed).count();
    if passed == steps.len() && passed > 0 {
        Observation::new(Status::Ok, "egress_verified")
    } else if passed > 0 {
        Observation::new(Status::Degraded, "partial_egress")
    } else if failed == steps.len() && failed > 0 {
        Observation::new(Status::Failed, "all_egress_probes_failed")
    } else {
        Observation::new(Status::Unknown, "egress_unverified")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_profiles_have_independent_stable_incidents_across_restart_and_missing_update() {
        let source: Source = serde_yaml::from_str("kind: https\nid: subscription\nurl: https://example.org/sub\nprofiles:\n  - { id: first, remarks: A }\n  - { id: second, remarks: B }\n").unwrap();
        let doc_a = serde_json::json!({"remarks":"A","outbounds":[{"protocol":"vless"}]});
        let doc_b = serde_json::json!({"remarks":"B","outbounds":[{"protocol":"vless"}]});
        let selection =
            source::select(&source, serde_json::json!([doc_a.clone(), doc_b.clone()])).unwrap();
        let a = format!("profile/{}", selection[0].source.id());
        let b = format!("profile/{}", selection[1].source.id());
        let mut state = State::default();
        for _ in 0..2 {
            state.observe(
                &a,
                Observation::new(Status::Failed, "all_egress_probes_failed"),
                true,
            );
            state.observe(&b, Observation::new(Status::Ok, "egress_verified"), true);
        }
        assert_eq!(state.pending.len(), 1);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        state.persist(&path).unwrap();
        let mut state = State::load(&path).unwrap();
        let reordered = source::select(&source, serde_json::json!([doc_b, doc_a])).unwrap();
        assert_eq!(a, format!("profile/{}", reordered[0].source.id()));
        assert_eq!(b, format!("profile/{}", reordered[1].source.id()));
        let missing = source::select(
            &source,
            serde_json::json!([{"remarks":"B","outbounds":[{"protocol":"vless"}]}]),
        )
        .unwrap();
        let mut rows = Vec::new();
        unavailable_profile(&mut rows, &missing[0].source, missing[0].unavailable_code);
        assert_eq!(rows[0].0, a);
        assert_eq!(rows[0].1.status, Status::Unknown);
        state.observe(&a, rows[0].1, true);
        assert_eq!(state.pending.len(), 1);
        assert_eq!(state.pending[0].key, a);
        assert_eq!(state.pending[0].status, Status::Failed);
        state.observe(&b, Observation::new(Status::Ok, "egress_verified"), true);
        state.observe(&a, Observation::new(Status::Ok, "egress_verified"), true);
        assert_eq!(state.pending.len(), 2);
        assert_eq!(state.pending[1].key, a);
        assert_eq!(state.pending[1].status, Status::Ok);
    }

    #[test]
    fn delayed_results_cannot_be_published_as_fresh_success_or_recovery() {
        let mut observation = Observation::new(Status::Ok, "egress_verified");
        observation.observed_at = 100;
        assert_eq!(fresh_observation(observation, 135, 35).status, Status::Ok);
        for now in [136, 99] {
            let stale = fresh_observation(observation, now, 35);
            assert_eq!(stale.status, Status::Unknown);
            assert_eq!(stale.code, "observation_stale");
            assert_eq!(stale.observed_at, 100);
        }
        observation.status = Status::Failed;
        assert_eq!(
            fresh_observation(observation, 136, 35).status,
            Status::Unknown
        );
    }

    #[test]
    fn late_aggregates_cannot_refresh_old_cycle_evidence() {
        let mut primary = Observation::new(Status::Ok, "primary_verified");
        primary.observed_at = 100;
        let mut aggregate = Observation::new(Status::Ok, "failover_verified");
        aggregate.observed_at = 170;
        let mut rows = vec![
            ("primary".to_string(), primary),
            ("overall".to_string(), aggregate),
        ];
        stamp_cycle(&mut rows, 105);
        assert_eq!(rows[0].1.observed_at, 100);
        assert_eq!(rows[1].1.observed_at, 105);
        for (_, observation) in rows {
            assert_eq!(
                fresh_observation(observation, 196, 90).status,
                Status::Unknown
            );
        }
    }

    #[test]
    fn fresh_slow_cycles_still_confirm_consecutive_failures() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut state = State::default();
        let mut first = Observation::new(Status::Failed, "all_egress_probes_failed");
        // The first cycle began 30 seconds before the second; both take 10s.
        first.observed_at = now - 40;
        state.observe("profile/lab", first, true);
        let mut second = first;
        second.observed_at = now - 10;
        assert!(!record_cycle(
            &mut state,
            &[("profile/lab".to_string(), second)],
            true,
            35
        ));
        assert_eq!(state.pending.len(), 1);
        assert_eq!(state.pending[0].status, Status::Failed);
    }
    #[test]
    fn candidate_observation_keys_never_embed_sensitive_outbound_tags() {
        let key = candidate_key("balancer/source/latency", 1);
        assert_eq!(key, "balancer/source/latency/candidate/1");
        assert!(!key.contains("private-operator-node"));
    }

    #[test]
    fn partial_checks_are_not_ok() {
        assert_eq!(
            classify(&[TargetResult::Passed, TargetResult::Failed]).status,
            Status::Degraded
        );
        assert_eq!(
            classify(&[TargetResult::Passed, TargetResult::Unknown]).status,
            Status::Degraded
        );
        assert_eq!(classify(&[TargetResult::Unknown]).status, Status::Unknown);
        assert_eq!(
            classify(&[TargetResult::Failed, TargetResult::Unknown]).status,
            Status::Unknown
        );
        assert_eq!(classify(&[TargetResult::Failed]).status, Status::Failed);
        assert_eq!(classify(&[TargetResult::Passed]).status, Status::Ok);
    }
}
