use crate::{
    config::{Endpoint, Scenario},
    incident::{Observation, Status},
    probe::{self, TargetResult},
    scenario,
};
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::{
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
}

pub async fn check(
    config: Value,
    endpoints: &[(Endpoint, Option<IpAddr>)],
    allowed: &[IpAddr],
    scenarios: &[Scenario],
    budget: Duration,
) -> Result<CheckResults> {
    let socket = TcpListener::bind("127.0.0.1:0").context("loopback_bind")?;
    let port = socket.local_addr()?.port();
    drop(socket);
    let original = config.clone();
    let mut config = prepare(config, port)?;

    let dir = TempDir::new().context("temporary_directory")?;
    let access_path = dir.path().join("access.log");
    let error_path = dir.path().join("error.log");
    if !scenarios.is_empty() {
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
            let response = timeout_at(
                deadline,
                probe::probe_https(&case.url, &proxy, remaining),
            )
            .await;
            attempts.push(Ok(response.unwrap_or(false)));
        }

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
        Ok((egress, attempts))
    }
    .await;
    child.stop().await;
    // Read only after process termination; cap both logs and fail closed on
    // oversized, invalid or inaccessible diagnostic data.
    let logs = if scenarios.is_empty() {
        None
    } else {
        Some((read_log(&access_path), read_log(&error_path)))
    };
    result.map(|(egress, attempts)| {
        let scenarios = attempts
            .into_iter()
            .zip(scenarios)
            .map(|(attempt, case)| match attempt {
                Err(observation) => observation,
                Ok(http_ok) => match &logs {
                    Some((Some(access), Some(error))) => {
                        scenario::evaluate(case, http_ok, access, error)
                    }
                    _ => Observation::new(Status::Unknown, "diagnostic_logs_unavailable"),
                },
            })
            .collect();
        CheckResults { egress, scenarios }
    })
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
