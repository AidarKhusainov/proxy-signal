mod balancer;
mod config;
mod incident;
mod probe;
mod scenario;
mod source;
mod telegram;
mod xray;

use crate::{
    balancer,
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
    let mut timer = tokio::time::interval(Duration::from_secs(config.interval_seconds));
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = shutdown() => break,
            _ = timer.tick() => {
                // Keep shutdown responsive even if a profile check stalls.
                let rows = tokio::select! {
                    _ = shutdown() => break,
                    rows = cycle(&config) => rows,
                };
                for (key, observation) in &rows {
                    let time = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
                    println!("ts={time} target={key} status={} evidence={}", observation.status.as_str(), observation.code);
                    state.observe(key, *observation, sender.is_some());
                }
                // Persist transitions *before* any delivery; failed sends stay pending.
                state.persist(&config.state_file)?;
                if let Some(sender) = &sender {
                    for _ in 0..4 { // Bounded notification retries, no per-cycle spam.
                        let Some(notice) = state.pending.first().cloned() else { break; };
                        if sender.send(&notice).await.is_err() {
                            eprintln!("ProxySignal: telegram_delivery_failed");
                            break;
                        }
                        state.pending.remove(0);
                        state.persist(&config.state_file)?;
                    }
                }
                if args.len() == 3 {
                    if rows.iter().any(|(_, o)| o.status != Status::Ok) {
                        anyhow::bail!("one_shot_unhealthy");
                    }
                    break;
                }
            }
        }
    }
    Ok(())
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
                    results.push((
                        format!("source/{}", entry.id()),
                        Observation::new(Status::Ok, "source_loaded"),
                    ));
                    profiles.push((entry, document));
                }
                Ok((entry, _)) => {
                    completed.insert(entry.id().to_string());
                    // A source incident is distinct from a VPN failure.
                    results.push((
                        format!("source/{}", entry.id()),
                        Observation::new(Status::Failed, "source_unavailable"),
                    ));
                    results.push((
                        format!("profile/{}", entry.id()),
                        Observation::new(Status::Unknown, "source_unavailable"),
                    ));
                    unavailable_checks(&mut results, &entry, "source_unavailable");
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
                results.push((
                    format!("profile/{}", entry.id()),
                    Observation::new(Status::Unknown, "source_task_error"),
                ));
                unavailable_checks(&mut results, entry, "source_task_error");
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
                                    .map(|tag| (format!("{key}/candidate/{tag}"), missing)),
                            );
                            rows
                        })
                        .collect::<Vec<_>>()
                };
                let (observation, checks, balance_checks) = if xray::prepare(document.clone(), 9876)
                    .is_err()
                {
                    (
                        Observation::new(Status::Unsupported, "profile_incompatible"),
                        scenario_rows(Status::Unsupported, "profile_incompatible"),
                        unavailable_balancers(Status::Unsupported, "profile_incompatible"),
                    )
                } else if targets.iter().all(|(_, ip)| ip.is_none())
                    && entry.scenarios().is_empty()
                    && entry.balancers().is_empty()
                {
                    (
                        Observation::new(Status::Unknown, "no_direct_baseline"),
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
                                    let mut rows = vec![
                                        (format!("{key}/config"), evidence.config),
                                        (format!("{key}/candidates"), evidence.candidates),
                                        (format!("{key}/route"), evidence.route),
                                        (key.clone(), evidence.overall),
                                    ];
                                    rows.extend(
                                        case.candidates.iter().zip(evidence.candidate_details).map(
                                            |(tag, observation)| {
                                                (format!("{key}/candidate/{tag}"), observation)
                                            },
                                        ),
                                    );
                                    rows
                                })
                                .collect();
                            let observation = if targets.iter().all(|(_, ip)| ip.is_none()) {
                                Observation::new(Status::Unknown, "no_direct_baseline")
                            } else {
                                classify(&steps.egress)
                            };
                            (observation, checks, balance_checks)
                        }
                        Err(_) => (
                            Observation::new(Status::Unknown, "xray_runtime_error"),
                            scenario_rows(Status::Unknown, "xray_runtime_error"),
                            unavailable_balancers(Status::Unknown, "xray_runtime_error"),
                        ),
                    }
                };
                (
                    format!("profile/{}", entry.id()),
                    observation,
                    start.elapsed(),
                    checks,
                    balance_checks,
                )
            });
        }
        let mut completed = std::collections::HashSet::new();
        while let Some(result) = tasks.join_next().await {
            if let Ok((key, observation, elapsed, scenarios, balancers)) = result {
                println!("target={key} duration_ms={}", elapsed.as_millis());
                completed.insert(key.clone());
                results.push((key, observation));
                results.extend(scenarios);
                results.extend(balancers);
            } else {
                eprintln!("ProxySignal: probe_task_error");
            }
        }
        for (entry, _) in batch {
            let key = format!("profile/{}", entry.id());
            if !completed.contains(&key) {
                results.push((key, Observation::new(Status::Unknown, "probe_task_error")));
                unavailable_checks(&mut results, entry, "probe_task_error");
            }
        }
    }
    results
}

fn unavailable_checks(results: &mut Vec<ResultRow>, entry: &Source, code: &'static str) {
    for case in entry.scenarios() {
        results.push((
            format!("scenario/{}/{}", entry.id(), case.id),
            Observation::new(Status::Unknown, code),
        ));
    }
    for case in entry.balancers() {
        let key = format!("balancer/{}/{}", entry.id(), case.id);
        for component in ["config", "candidates", "route"] {
            results.push((
                format!("{key}/{component}"),
                Observation::new(Status::Unknown, code),
            ));
        }
        for tag in &case.candidates {
            results.push((
                format!("{key}/candidate/{tag}"),
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
