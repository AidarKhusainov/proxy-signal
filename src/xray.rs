use crate::{
    balancer, cascade, cdn,
    config::{BalancerScenario, CascadeScenario, CdnScenario, Endpoint, Scenario},
    incident::{Observation, Status},
    probe::{self, TargetResult},
    scenario,
};
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    future::Future,
    io::Read,
    net::{IpAddr, SocketAddr, TcpListener},
    path::Path,
    process::Stdio,
    time::Duration,
};
use tempfile::TempDir;
use tokio::{
    net::TcpStream,
    process::{Child, Command},
    task::JoinSet,
    time::{sleep, timeout_at, Instant},
};

/// Replaces only local inbounds and logs. Never reconstructs or selects a single outbound.
/// Inbound-dependent routing cannot be reproduced safely and is rejected.
pub fn prepare(mut config: Value, port: u16) -> Result<Value> {
    let object = config.as_object_mut().context("not_a_full_profile")?;
    if object.contains_key("api")
        || object.contains_key("metrics")
        || object.contains_key("reverse")
    {
        bail!("unsafe_or_unsupported_listener");
    }
    if let Some(inbounds) = object.get("inbounds") {
        let inbounds = inbounds.as_array().context("invalid_inbounds")?;
        if inbounds.iter().any(|inbound| {
            !inbound.is_object()
                || inbound.get("sniffing").and_then(|s| s.get("enabled"))
                    == Some(&Value::Bool(true))
        }) {
            bail!("inbound_sniffing_cannot_be_preserved");
        }
    }
    if let Some(routing) = object.get("routing") {
        let routing = routing.as_object().context("invalid_routing")?;
        if let Some(rules) = routing.get("rules") {
            let rules = rules.as_array().context("invalid_routing_rules")?;
            for rule in rules {
                if !rule.is_object() {
                    bail!("invalid_routing_rule");
                }
                if ["inboundTag", "source", "user", "protocol", "attrs"]
                    .iter()
                    .any(|k| rule.get(k).is_some())
                {
                    bail!("inbound_dependent_routing");
                }
            }
        }
    }
    let outbounds = object
        .get("outbounds")
        .and_then(Value::as_array)
        .context("missing_outbounds")?;
    if outbounds.is_empty() || !outbounds.iter().all(Value::is_object) {
        bail!("invalid_outbounds");
    }
    if !outbounds.iter().any(|o| {
        o.get("protocol")
            .and_then(Value::as_str)
            .is_some_and(|p| p != "freedom" && p != "blackhole")
    }) {
        bail!("no_proxy_outbound");
    }
    // Old inbounds cannot be started: they might expose authentication endpoints or bind host ports.
    object.insert(
        "inbounds".into(),
        json!([{
            "tag": "proxy-signal-probe-in",
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "http",
            "settings": { "timeout": 10 }
        }]),
    );
    object.insert("log".into(), json!({"loglevel": "none"}));
    Ok(config)
}

/// One supervised Xray process runs both ordinary egress probes and optional
/// DNS/routing cases without replacing the original DNS, routing or outbounds.
pub struct CheckResults {
    pub egress: Vec<TargetResult>,
    pub scenarios: Vec<Observation>,
    pub balancers: Vec<BalancerChecks>,
    pub cascades: Vec<CascadeChecks>,
    pub cdn: Vec<CdnChecks>,
}

pub struct BalancerChecks {
    pub config: Observation,
    pub candidates: Observation,
    pub candidate_details: Vec<Observation>,
    pub route: Observation,
    pub selected_candidate_index: Option<usize>,
    pub overall: Observation,
}

pub struct CascadeChecks {
    pub config: Observation,
    pub https: Observation,
    pub hops: Observation,
    pub overall: Observation,
}

pub struct CdnChecks {
    pub config: Observation,
    pub tunnel: Observation,
    pub route: Observation,
}

struct BalancerAttempt {
    route_http: Option<bool>,
    candidate_http: Vec<Option<bool>>,
}

// Explicit small scenario lists keep the full-profile executor simple.
// Avoid a new options layer for this single call site.
#[allow(clippy::too_many_arguments)]
pub async fn check(
    config: Value,
    endpoints: &[(Endpoint, Option<IpAddr>)],
    allowed: &[IpAddr],
    scenarios: &[Scenario],
    balancers: &[BalancerScenario],
    cascades: &[CascadeScenario],
    cdn_cases: &[CdnScenario],
    budget: Duration,
) -> Result<CheckResults> {
    let socket = TcpListener::bind("127.0.0.1:0").context("loopback_bind")?;
    let port = socket.local_addr()?.port();
    drop(socket);
    let original = config.clone();
    let mut config = prepare(config, port)?;
    let inspected: Vec<_> = balancers
        .iter()
        .map(|case| balancer::inspect(&original, case))
        .collect();
    let inspected_cascades: Vec<_> = cascades
        .iter()
        .map(|case| cascade::inspect(&original, case))
        .collect();
    let inspected_cdn: Vec<_> = cdn_cases
        .iter()
        .map(|case| cdn::inspect(&original, case))
        .collect();
    // Each unique candidate is tested through a temporary inbound with a
    // dedicated routing rule. Original probe-in traffic never matches these
    // rules, so the balancer's normal route remains intact.
    let mut diagnostics: Vec<(String, String, u16)> = Vec::new();
    let mut used_ports = HashSet::from([port]);
    for (case, status) in balancers.iter().zip(&inspected) {
        if status.status != Status::Ok {
            continue;
        }
        for tag in &case.candidates {
            if diagnostics.iter().any(|(existing, _, _)| existing == tag) {
                continue;
            }
            let candidate_port = loop {
                let socket = TcpListener::bind("127.0.0.1:0").context("candidate_loopback_bind")?;
                let candidate_port = socket.local_addr()?.port();
                if used_ports.insert(candidate_port) {
                    break candidate_port;
                }
            };
            let inbound = format!("proxy-signal-candidate-{}", diagnostics.len());
            diagnostics.push((tag.clone(), inbound, candidate_port));
        }
    }
    if !diagnostics.is_empty() {
        install_candidate_diagnostics(&mut config, &diagnostics)?;
    }

    let dir = TempDir::new().context("temporary_directory")?;
    let access_path = dir.path().join("access.log");
    let error_path = dir.path().join("error.log");
    if !scenarios.is_empty()
        || !balancers.is_empty()
        || !cascades.is_empty()
        || !cdn_cases.is_empty()
    {
        // The engine writes diagnostic records to private temporary files.
        // Never emit raw logs (they can contain domains and profile data).
        config["log"] = json!({
            "access": access_path.to_string_lossy(),
            "error": error_path.to_string_lossy(),
            "loglevel": "info",
            "dnsLog": true
        });
    }
    let path = dir.path().join("config.json");
    std::fs::write(&path, serde_json::to_vec(&config)?).context("temporary_config")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    let mut cmd = Command::new("xray");
    cmd.arg("run")
        .arg("-c")
        .arg(&path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.as_std_mut().process_group(0);
    }
    let mut child = ManagedChild::new(cmd.spawn().context("xray_spawn")?);
    let deadline = Instant::now() + budget;
    let result = async {
        timeout_at(deadline, ready(&mut child.child, port))
            .await
            .context("xray_start_timeout")??;
        let proxy = format!("http://127.0.0.1:{port}");
        // Start each balancer candidate and its route independently. Sequential
        // egress/domain checks must not exhaust the budget before they start.
        // Configuration bounds this to at most 4 routes + 32 candidates/profile.
        let mut balancing: Vec<BalancerAttempt> = balancers
            .iter()
            .map(|case| BalancerAttempt {
                route_http: None,
                candidate_http: vec![None; case.candidates.len()],
            })
            .collect();
        let mut balancer_tasks = JoinSet::new();
        for (case_index, (case, static_result)) in balancers.iter().zip(&inspected).enumerate() {
            if static_result.status != Status::Ok {
                continue;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                continue;
            }
            let url = case.url.clone();
            let route_proxy = proxy.clone();
            spawn_balancer_probe(
                &mut balancer_tasks,
                case_index,
                None,
                deadline,
                async move { probe::probe_https(&url, &route_proxy, remaining).await },
            );
            for (candidate_index, tag) in case.candidates.iter().enumerate() {
                let Some((_, _, candidate_port)) = diagnostics.iter().find(|(t, _, _)| t == tag)
                else {
                    continue;
                };
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    continue;
                }
                let url = case.url.clone();
                let candidate_proxy = format!("http://127.0.0.1:{candidate_port}");
                spawn_balancer_probe(
                    &mut balancer_tasks,
                    case_index,
                    Some(candidate_index),
                    deadline,
                    async move { probe::probe_https(&url, &candidate_proxy, remaining).await },
                );
            }
        }
        // Start independent cascade HTTPS checks before sequential egress/scenario
        // probes. Missing budget or a cancelled request must remain UNKNOWN.
        let mut cascade_tasks = JoinSet::new();
        let mut cascade_http = vec![None; cascades.len()];
        for (index, (case, static_result)) in cascades.iter().zip(&inspected_cascades).enumerate() {
            if static_result.status != Status::Ok {
                continue;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                continue;
            }
            let url = case.url.clone();
            let route_proxy = proxy.clone();
            cascade_tasks.spawn(async move {
                (
                    index,
                    timeout_at(deadline, probe::probe_https(&url, &route_proxy, remaining))
                        .await
                        .ok(),
                )
            });
        }
        // CDN tunnel requests run through the original outbound routing, not a
        // synthetic replacement of its XHTTP transport.
        let mut cdn_tasks = JoinSet::new();
        let mut cdn_http = vec![None; cdn_cases.len()];
        for (index, (case, config)) in cdn_cases.iter().zip(&inspected_cdn).enumerate() {
            if config.status != Status::Ok {
                continue;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                continue;
            }
            let url = case.url.clone();
            let route_proxy = proxy.clone();
            cdn_tasks.spawn(async move {
                (
                    index,
                    timeout_at(deadline, probe::probe_https(&url, &route_proxy, remaining))
                        .await
                        .ok(),
                )
            });
        }
        // Egress keeps its original status semantics; it does not block
        // execution of already-started balancer probes.
        let mut egress = Vec::with_capacity(endpoints.len());
        for (endpoint, direct) in endpoints {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() || direct.is_none() {
                egress.push(TargetResult::Unknown);
                continue;
            }
            let response = timeout_at(
                deadline,
                probe::get_exit_ip(endpoint, Some(&proxy), remaining),
            )
            .await;
            let observation = match response {
                Ok(value) => probe::compare(value, *direct, allowed),
                Err(_) => TargetResult::Failed,
            };
            egress.push(observation);
        }
        let mut attempts: Vec<std::result::Result<bool, Observation>> =
            Vec::with_capacity(scenarios.len());
        for case in scenarios {
            if let Some(unsupported) = scenario::static_check(&original, case) {
                attempts.push(Err(unsupported));
                continue;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                attempts.push(Err(Observation::new(Status::Unknown, "scenario_timeout")));
                continue;
            }
            let response =
                timeout_at(deadline, probe::probe_https(&case.url, &proxy, remaining)).await;
            attempts.push(Ok(response.unwrap_or(false)));
        }

        // All probes have the same hard deadline. A blocked candidate cannot
        // prevent siblings from completing and returning their own evidence.
        while let Some(joined) = balancer_tasks.join_next().await {
            let Ok((case_index, candidate_index, result)) = joined else {
                continue;
            };
            if let Some(index) = candidate_index {
                balancing[case_index].candidate_http[index] = result;
            } else {
                balancing[case_index].route_http = result;
            }
        }
        while let Some(joined) = cascade_tasks.join_next().await {
            if let Ok((index, result)) = joined {
                cascade_http[index] = result;
            }
        }
        while let Some(joined) = cdn_tasks.join_next().await {
            if let Ok((index, result)) = joined {
                cdn_http[index] = result;
            }
        }
        Ok((egress, attempts, balancing, cascade_http, cdn_http))
    }
    .await;
    child.stop().await;
    // Read only after process termination; cap both logs and fail closed on
    // oversized, invalid or inaccessible diagnostic data.
    let logs = if scenarios.is_empty()
        && balancers.is_empty()
        && cascades.is_empty()
        && cdn_cases.is_empty()
    {
        None
    } else {
        Some((read_log(&access_path), read_log(&error_path)))
    };
    result.map(|(egress, attempts, balancing, cascade_http, cdn_http)| {
        let scenarios = attempts
            .into_iter()
            .zip(scenarios)
            .map(|(attempt, case)| match attempt {
                Err(observation) => observation,
                Ok(http_ok) => match &logs {
                    Some((Some(access), error)) if case.dns.is_none() || error.is_some() => {
                        scenario::evaluate(case, http_ok, access, error.as_deref().unwrap_or(""))
                    }
                    _ => Observation::new(Status::Unknown, "diagnostic_logs_unavailable"),
                },
            })
            .collect();
        let balancers = balancers
            .iter()
            .zip(inspected)
            .zip(balancing)
            .map(|((case, config), attempt)| {
                if config.status != Status::Ok {
                    return BalancerChecks {
                        config,
                        candidates: Observation::new(
                            Status::Unsupported,
                            "balancer_config_invalid",
                        ),
                        candidate_details: case
                            .candidates
                            .iter()
                            .map(|_| {
                                Observation::new(Status::Unsupported, "balancer_config_invalid")
                            })
                            .collect(),
                        route: Observation::new(Status::Unsupported, "balancer_config_invalid"),
                        selected_candidate_index: None,
                        overall: config,
                    };
                }
                let candidates = case
                    .candidates
                    .iter()
                    .zip(attempt.candidate_http.iter())
                    .map(|(tag, http_ok)| {
                        let inbound = diagnostics.iter().find(|(existing, _, _)| existing == tag);
                        match inbound {
                            Some((_, name, _)) => balancer::candidate(
                                *http_ok,
                                logs.as_ref().and_then(|(access, _)| access.as_deref()),
                                &case.url,
                                name,
                                tag,
                            ),
                            None => Observation::new(Status::Unknown, "candidate_not_instrumented"),
                        }
                    })
                    .collect::<Vec<_>>();
                let candidate_details = candidates;
                let candidates = balancer::candidate_status(&candidate_details);
                let route = balancer::route(
                    case,
                    balancer::attributable(&original, case),
                    attempt.route_http,
                    logs.as_ref().and_then(|(access, _)| access.as_deref()),
                );
                // Report only an index into the configured candidate list:
                // outbound tags themselves may contain operator-sensitive labels.
                let selected_candidate_index = if balancer::attributable(&original, case) {
                    logs.as_ref()
                        .and_then(|(access, _)| access.as_deref())
                        .and_then(|access| {
                            scenario::observed_outbound(&case.url, "proxy-signal-probe-in", access)
                                .ok()
                        })
                        .and_then(|tag| {
                            case.candidates
                                .iter()
                                .position(|candidate| candidate == tag)
                        })
                } else {
                    None
                };
                let overall = balancer::overall(config, candidates, route);
                BalancerChecks {
                    config,
                    candidates,
                    candidate_details,
                    route,
                    selected_candidate_index,
                    overall,
                }
            })
            .collect();
        let cascades = cascades
            .iter()
            .zip(inspected_cascades)
            .zip(cascade_http)
            .map(|((case, config), http_ok)| {
                if config.status != Status::Ok {
                    let unavailable =
                        Observation::new(Status::Unsupported, "cascade_config_invalid");
                    return CascadeChecks {
                        config,
                        https: unavailable,
                        hops: unavailable,
                        overall: config,
                    };
                }
                let https = cascade::https(
                    &original,
                    case,
                    http_ok,
                    logs.as_ref().and_then(|(access, _)| access.as_deref()),
                );
                let hops = cascade::hops();
                let overall = cascade::overall(config, https, hops);
                CascadeChecks {
                    config,
                    https,
                    hops,
                    overall,
                }
            })
            .collect();
        let cdn = cdn_cases
            .iter()
            .zip(inspected_cdn)
            .zip(cdn_http)
            .map(|((case, config), http_ok)| {
                if config.status != Status::Ok {
                    return CdnChecks {
                        config,
                        tunnel: Observation::new(Status::Unsupported, "cdn_config_invalid"),
                        route: cdn::route(),
                    };
                }
                CdnChecks {
                    config,
                    tunnel: cdn::tunnel(
                        &original,
                        case,
                        http_ok,
                        logs.as_ref().and_then(|(access, _)| access.as_deref()),
                    ),
                    route: cdn::route(),
                }
            })
            .collect();
        CheckResults {
            egress,
            scenarios,
            balancers,
            cascades,
            cdn,
        }
    })
}

// Preserve UNKNOWN when an individual request runs out of time, rather than
// converting a timeout into a confirmed HTTPS failure.
fn spawn_balancer_probe<F>(
    tasks: &mut JoinSet<(usize, Option<usize>, Option<bool>)>,
    case_index: usize,
    candidate_index: Option<usize>,
    deadline: Instant,
    probe: F,
) where
    F: Future<Output = bool> + Send + 'static,
{
    tasks.spawn(async move {
        (
            case_index,
            candidate_index,
            timeout_at(deadline, probe).await.ok(),
        )
    });
}

/// Test-only inbounds force each candidate without changing routing decisions
/// for the ordinary diagnostic inbound. Never applied to a stored/source profile.
fn install_candidate_diagnostics(
    config: &mut Value,
    candidates: &[(String, String, u16)],
) -> Result<()> {
    let inbounds = config["inbounds"]
        .as_array_mut()
        .context("diagnostic_inbounds")?;
    for (_, inbound, port) in candidates {
        inbounds.push(json!({
            "tag": inbound,
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "http",
            "settings": { "timeout": 10 }
        }));
    }
    let routing = config
        .get_mut("routing")
        .and_then(Value::as_object_mut)
        .context("diagnostic_routing")?;
    let rules = routing
        .entry("rules")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .context("diagnostic_rules")?;
    // Only the candidate inbounds match these rules; the main inbound
    // follows the original ordered routing rules.
    for (tag, inbound, _) in candidates.iter().rev() {
        rules.insert(
            0,
            json!({
                "type": "field",
                "inboundTag": [inbound],
                "outboundTag": tag
            }),
        );
    }
    Ok(())
}

/// Never load unbounded untrusted Xray output into the monitor.
fn read_log(path: &Path) -> Option<String> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(128 * 1024 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > 128 * 1024 {
        return None;
    }
    String::from_utf8(bytes).ok()
}

async fn ready(child: &mut Child, port: u16) -> Result<()> {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    for _ in 0..50 {
        if child.try_wait()?.is_some() {
            bail!("xray_exited");
        }
        if TcpStream::connect(address).await.is_ok() {
            return Ok(());
        }
        sleep(Duration::from_millis(100)).await;
    }
    bail!("xray_not_ready")
}

/// Cancellation-safe ownership: dropping a pending probe kills the entire
/// Xray process group, not just its immediate child. Tokio reaps the child.
struct ManagedChild {
    child: Child,
    finished: bool,
}

impl ManagedChild {
    fn new(child: Child) -> Self {
        Self {
            child,
            finished: false,
        }
    }

    fn kill_group(&mut self) {
        #[cfg(unix)]
        if let Some(pid) = self.child.id() {
            use nix::{
                sys::signal::{killpg, Signal},
                unistd::Pid,
            };
            let _ = killpg(Pid::from_raw(pid as i32), Signal::SIGKILL);
        }
        let _ = self.child.start_kill();
    }

    async fn stop(&mut self) {
        self.kill_group();
        self.finished = matches!(
            tokio::time::timeout(Duration::from_secs(2), self.child.wait()).await,
            Ok(Ok(_))
        );
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        if !self.finished {
            self.kill_group();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn stops_child_after_timeout() {
        let mut command = Command::new("sleep");
        command.arg("30").kill_on_drop(true);
        use std::os::unix::process::CommandExt;
        command.as_std_mut().process_group(0);
        let mut managed = ManagedChild::new(command.spawn().unwrap());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), managed.child.wait())
                .await
                .is_err()
        );
        managed.stop().await;
        assert!(managed.finished);
    }

    #[tokio::test]
    async fn slow_candidate_does_not_starve_another_candidate() {
        let deadline = Instant::now() + Duration::from_millis(500);
        let mut tasks = JoinSet::new();
        spawn_balancer_probe(&mut tasks, 0, Some(0), deadline, async {
            sleep(Duration::from_secs(2)).await;
            true
        });
        spawn_balancer_probe(&mut tasks, 0, Some(1), deadline, async { true });
        let fast = tokio::time::timeout(Duration::from_millis(300), tasks.join_next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(fast, (0, Some(1), Some(true)));
        let stalled = tasks.join_next().await.unwrap().unwrap();
        assert_eq!(stalled, (0, Some(0), None));
    }

    #[test]
    fn preserves_full_profile_semantics() {
        let original = json!({
            "dns": {"servers": ["1.1.1.1"]},
            "routing": {"balancers": [{"tag": "b", "selector": ["node"]}], "rules": [{"type": "field", "domain": ["domain:example.com"], "balancerTag": "b"}]},
            "outbounds": [{"protocol": "vless", "tag": "node-a"}, {"protocol": "freedom", "tag": "direct"}],
            "observatory": {"subjectSelector": ["node"]},
            "inbounds": [{"listen": "0.0.0.0", "port": 1234, "protocol": "socks"}]
        });
        let updated = prepare(original.clone(), 12345).unwrap();
        for key in ["dns", "routing", "outbounds", "observatory"] {
            assert_eq!(updated[key], original[key]);
        }
        assert_eq!(updated["inbounds"][0]["listen"], "127.0.0.1");
        assert_ne!(updated["inbounds"], original["inbounds"]);
    }

    #[test]
    fn rejects_inbound_dependent_routes_and_direct_only() {
        let config = json!({"outbounds": [{"protocol": "vless"}], "routing": {"rules": [{"inboundTag": ["user-a"]}]}});
        assert!(prepare(config, 10001).is_err());
        assert!(prepare(json!({"outbounds": [{"protocol": "freedom"}]}), 10001).is_err());
        assert!(prepare(json!({"outbounds": [{"protocol": "vless"}], "inbounds": [{"sniffing": {"enabled": true}}]}), 10001).is_err());
    }
}
