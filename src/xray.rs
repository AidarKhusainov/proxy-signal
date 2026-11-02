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
/// The test HTTP inbound can reproduce common TCP sniffing settings, but does not
/// prove the behavior of a different client inbound protocol.
pub fn prepare(mut config: Value, port: u16) -> Result<Value> {
    let object = config.as_object_mut().context("not_a_full_profile")?;
    if object.contains_key("api")
        || object.contains_key("metrics")
        || object.contains_key("reverse")
    {
        bail!("unsafe_or_unsupported_listener");
    }
    // One loopback inbound cannot faithfully represent several different
    // inbound sniffing policies. Refuse that ambiguity instead of picking one.
    let sniffing = diagnostic_sniffing(object.get("inbounds"))?;
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
    let mut inbound = json!({
        "tag": "proxy-signal-probe-in",
        "listen": "127.0.0.1",
        "port": port,
        "protocol": "http",
        "settings": { "timeout": 10 }
    });
    if let Some(sniffing) = sniffing {
        inbound["sniffing"] = sniffing;
    }
    object.insert("inbounds".into(), Value::Array(vec![inbound]));
    object.insert("log".into(), json!({"loglevel": "none"}));
    Ok(config)
}

/// Client inbound semantics are not validated by a diagnostic HTTP proxy.
pub(crate) fn has_enabled_sniffing(config: &Value) -> bool {
    config
        .get("inbounds")
        .and_then(Value::as_array)
        .is_some_and(|inbounds| {
            inbounds.iter().any(|inbound| {
                inbound.pointer("/sniffing/enabled") == Some(&Value::Bool(true))
            })
        })
}

/// Preserve the exact sniffing object, including exclusions. Xray itself
/// interprets domain/IP rules; we do not approximate those rules in Rust.
fn diagnostic_sniffing(inbounds: Option<&Value>) -> Result<Option<Value>> {
    let Some(inbounds) = inbounds else {
        return Ok(None);
    };
    let inbounds = inbounds.as_array().context("invalid_inbounds")?;
    let mut common: Option<Option<Value>> = None;
    for inbound in inbounds {
        let inbound = inbound.as_object().context("invalid_inbound")?;
        let sniffing = match inbound.get("sniffing") {
            None | Some(Value::Null) => None,
            Some(value) => {
                let settings = value.as_object().context("invalid_sniffing")?;
                let enabled = match settings.get("enabled") {
                    None | Some(Value::Bool(false)) => false,
                    Some(Value::Bool(true)) => true,
                    _ => bail!("invalid_sniffing"),
                };
                if enabled {
                    if settings.keys().any(|key| {
                        !matches!(
                            key.as_str(),
                            "enabled" | "destOverride" | "routeOnly" | "metadataOnly"
                                | "domainsExcluded" | "ipsExcluded"
                        )
                    }) {
                        bail!("unsupported_sniffing_field");
                    }
                    for key in ["routeOnly", "metadataOnly"] {
                        if settings.get(key).is_some_and(|value| !value.is_boolean()) {
                            bail!("invalid_sniffing");
                        }
                    }
                    for key in ["destOverride", "domainsExcluded", "ipsExcluded"] {
                        if settings.get(key).is_some_and(|value| {
                            value.as_array().is_none_or(|items| !items.iter().all(Value::is_string))
                        }) {
                            bail!("invalid_sniffing");
                        }
                    }
                    Some(value.clone())
                } else {
                    None
                }
            }
        };
        match &common {
            Some(previous) if previous != &sniffing => bail!("ambiguous_inbound_sniffing"),
            None => common = Some(sniffing),
            _ => {}
        }
    }
    Ok(common.flatten())
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
    let mut child = spawn_xray(&path)?;
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
pub(crate) fn install_candidate_diagnostics(
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

pub(crate) async fn ready(child: &mut Child, port: u16) -> Result<()> {
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

pub(crate) fn spawn_xray(path: &Path) -> Result<ManagedChild> {
    let mut cmd = Command::new("xray");
    cmd.arg("run")
        .arg("-c")
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.as_std_mut().process_group(0);
    }
    Ok(ManagedChild::new(cmd.spawn().context("xray_spawn")?))
}

/// Cancellation-safe ownership: dropping a pending probe kills the entire
/// Xray process group, not just its immediate child. Tokio reaps the child.
pub(crate) struct ManagedChild {
    pub(crate) child: Child,
    #[cfg(unix)]
    process_group: Option<nix::unistd::Pid>,
    finished: bool,
}

impl ManagedChild {
    fn new(child: Child) -> Self {
        Self {
            // Child::id disappears after wait/try_wait reaps the leader, but
            // its process group may still contain descendants that we own.
            #[cfg(unix)]
            process_group: child.id().map(|pid| nix::unistd::Pid::from_raw(pid as i32)),
            child,
            finished: false,
        }
    }

    fn kill_group(&mut self) {
        #[cfg(unix)]
        if let Some(group) = self.process_group {
            use nix::sys::signal::{killpg, Signal};
            let _ = killpg(group, Signal::SIGKILL);
        }
        let _ = self.child.start_kill();
    }

    pub(crate) async fn stop(&mut self) {
        if self.finished {
            return;
        }
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

    #[cfg(target_os = "linux")]
    fn process_is_running(pid: u32) -> bool {
        std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|stat| {
                stat.rsplit_once(") ")
                    .map(|(_, tail)| tail.starts_with('Z'))
            })
            .is_some_and(|zombie| !zombie)
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn stops_descendants_after_the_group_leader_has_exited() {
        use std::os::unix::process::CommandExt;

        let dir = tempfile::tempdir().unwrap();
        let child_pid_file = dir.path().join("child.pid");
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("sleep 30 & echo $! > \"$1\"")
            .arg("test-descendant")
            .arg(&child_pid_file)
            .kill_on_drop(true);
        command.as_std_mut().process_group(0);
        let mut managed = ManagedChild::new(command.spawn().unwrap());
        tokio::time::timeout(Duration::from_secs(2), managed.child.wait())
            .await
            .unwrap()
            .unwrap();
        let descendant: u32 = std::fs::read_to_string(child_pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(process_is_running(descendant));
        managed.stop().await;
        let stopped = tokio::time::timeout(Duration::from_secs(2), async {
            while process_is_running(descendant) {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        // Keep the failing regression itself from leaking its fixture process.
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(descendant as i32),
            nix::sys::signal::Signal::SIGKILL,
        );
        assert!(stopped.is_ok(), "supervised descendant outlived its leader");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn repeated_cancelled_children_are_killed_and_reaped() {
        use std::os::unix::process::CommandExt;

        for _ in 0..5 {
            let mut command = Command::new("sleep");
            command.arg("30").kill_on_drop(true);
            command.as_std_mut().process_group(0);
            let managed = ManagedChild::new(command.spawn().unwrap());
            let pid = managed.child.id().unwrap();
            drop(managed);
            tokio::time::timeout(Duration::from_secs(2), async {
                while std::path::Path::new(&format!("/proc/{pid}")).exists() {
                    sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("cancelled child was not reaped");
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn repeated_stop_never_signals_a_reused_process_group() {
        use std::os::unix::process::CommandExt;

        let mut command = Command::new("sleep");
        command.arg("30").kill_on_drop(true);
        command.as_std_mut().process_group(0);
        let mut first = ManagedChild::new(command.spawn().unwrap());
        first.stop().await;
        let mut unrelated = ManagedChild::new(command.spawn().unwrap());
        // Simulate the kernel reusing a reaped leader's old group identifier.
        first.process_group = unrelated.process_group;
        first.stop().await;
        sleep(Duration::from_millis(20)).await;
        let still_running = unrelated.child.try_wait().unwrap().is_none();
        unrelated.stop().await;
        assert!(
            still_running,
            "a completed supervisor signalled another group"
        );
    }

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
    fn preserves_sniffing_and_routes_without_exposing_original_inbounds() {
        let original = json!({
            "inbounds": [{
                "tag": "client",
                "listen": "0.0.0.0",
                "port": 1080,
                "protocol": "socks",
                "sniffing": {
                    "enabled": true,
                    "destOverride": ["http", "tls", "quic", "fakedns"],
                    "routeOnly": true,
                    "metadataOnly": false,
                    "domainsExcluded": ["full:excluded.example.org"],
                    "ipsExcluded": ["192.0.2.0/24"]
                }
            }],
            "dns": {"servers": ["1.1.1.1"]},
            "routing": {"rules": [
                {"type": "field", "domain": ["full:sniffed.example.org"], "outboundTag": "vpn"},
                {"type": "field", "ip": ["0.0.0.0/0"], "outboundTag": "direct"}
            ]},
            "outbounds": [
                {"tag": "vpn", "protocol": "vless"},
                {"tag": "direct", "protocol": "freedom"}
            ],
            "observatory": {"subjectSelector": ["vpn"]}
        });
        assert!(has_enabled_sniffing(&original));
        let prepared = prepare(original.clone(), 19123).unwrap();
        for key in ["dns", "routing", "outbounds", "observatory"] {
            assert_eq!(prepared[key], original[key]);
        }
        assert_eq!(
            prepared["inbounds"][0]["sniffing"],
            original["inbounds"][0]["sniffing"]
        );
        assert_eq!(prepared["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(prepared["inbounds"][0]["port"], 19123);
        assert_eq!(prepared["inbounds"][0]["protocol"], "http");
        assert_eq!(prepared["inbounds"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn rejects_conflicting_sniffing_instead_of_silently_changing_routes() {
        let mut original = json!({
            "outbounds": [{"tag": "vpn", "protocol": "vless"}],
            "inbounds": [
                {"protocol": "socks", "sniffing": {
                    "enabled": true, "destOverride": ["tls"], "routeOnly": true
                }},
                {"protocol": "http", "sniffing": {
                    "enabled": true, "destOverride": ["tls"], "routeOnly": false
                }}
            ]
        });
        assert!(prepare(original.clone(), 19123).is_err());
        original["inbounds"][1]["sniffing"]["routeOnly"] = json!(true);
        assert!(prepare(original, 19123).is_ok());
    }

    #[test]
    fn unsupported_or_malformed_sniffing_fails_closed() {
        let make = |sniffing: Value| json!({
            "outbounds": [{"protocol": "vless"}],
            "inbounds": [{"protocol": "socks", "sniffing": sniffing}]
        });
        assert!(prepare(make(json!({"enabled": "yes"})), 19123).is_err());
        assert!(prepare(make(json!({"enabled": true, "destOverride": "tls"})), 19123).is_err());
        assert!(prepare(make(json!({"enabled": true, "metadataOnly": "false"})), 19123).is_err());
        assert!(prepare(make(json!({"enabled": true, "unknownFlag": true})), 19123).is_err());
        assert!(prepare(make(json!({"enabled": true, "metadataOnly": true, "routeOnly": true})), 19123).is_ok());
    }

    #[test]
    fn https_without_route_evidence_cannot_verify_sniffing_routing() {
        use crate::config::ExpectedRoute;
        let profile = json!({
            "outbounds": [{"tag":"vpn", "protocol":"vless"}],
            "inbounds": [{"protocol":"socks", "sniffing": {
                "enabled":true, "destOverride":["tls"], "domainsExcluded":["excluded.example.org"]
            }}],
            "routing": {"rules":[{"type":"field", "domain":["full:example.org"], "outboundTag":"vpn"}]}
        });
        let prepared = prepare(profile, 19123).unwrap();
        assert_eq!(prepared["inbounds"][0]["sniffing"]["enabled"], true);
        let case = Scenario {
            id: "sniff".into(),
            url: "https://example.org/".into(),
            route: ExpectedRoute::Proxy,
            outbound_tag: "vpn".into(),
            dns: None,
        };
        assert_eq!(scenario::evaluate(&case, true, "", "").status, Status::Unknown);
    }

    #[test]
    fn rejects_inbound_dependent_routes_and_direct_only() {
        let config = json!({"outbounds": [{"protocol": "vless"}], "routing": {"rules": [{"inboundTag": ["user-a"]}]}});
        assert!(prepare(config, 10001).is_err());
        assert!(prepare(json!({"outbounds": [{"protocol": "freedom"}]}), 10001).is_err());
        assert!(prepare(json!({"outbounds": [{"protocol": "vless"}], "inbounds": [{"sniffing": {"enabled": true}}]}), 10001).is_ok());
    }
}
