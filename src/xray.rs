use crate::{config::Endpoint, probe::{self, TargetResult}};
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::{net::{IpAddr, SocketAddr, TcpListener}, process::Stdio, time::Duration};
use tempfile::TempDir;
use tokio::{net::TcpStream, process::{Child, Command}, time::{sleep, timeout_at, Instant}};

/// Replaces only local inbounds and logs. Never reconstructs or selects a single outbound.
/// Inbound-dependent routing cannot be reproduced safely and is rejected.
pub fn prepare(mut config: Value, port: u16) -> Result<Value> {
    let object = config.as_object_mut().context("not_a_full_profile")?;
    if object.contains_key("api") || object.contains_key("metrics") || object.contains_key("reverse") {
        bail!("unsafe_or_unsupported_listener");
    }
    if let Some(inbounds) = object.get("inbounds") {
        let inbounds = inbounds.as_array().context("invalid_inbounds")?;
        if inbounds.iter().any(|inbound| {
            !inbound.is_object() || inbound.get("sniffing")
                .and_then(|s| s.get("enabled")) == Some(&Value::Bool(true))
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
            if ["inboundTag", "source", "user", "protocol", "attrs"].iter().any(|k| rule.get(k).is_some()) {
                    bail!("inbound_dependent_routing");
                }
            }
        }
    }
    let outbounds = object.get("outbounds").and_then(Value::as_array).context("missing_outbounds")?;
    if outbounds.is_empty() || !outbounds.iter().all(Value::is_object) {
        bail!("invalid_outbounds");
    }
    if !outbounds.iter().any(|o| o.get("protocol").and_then(Value::as_str).is_some_and(|p| p != "freedom" && p != "blackhole")) {
        bail!("no_proxy_outbound");
    }
    // Old inbounds cannot be started: they might expose authentication endpoints or bind host ports.
    object.insert("inbounds".into(), json!([{
        "tag": "proxy-signal-probe-in",
        "listen": "127.0.0.1",
        "port": port,
        "protocol": "http",
        "settings": { "timeout": 10 }
    }]));
    object.insert("log".into(), json!({"loglevel": "none"}));
    Ok(config)
}

/// Runs one bounded child per profile. The official Xray binary is supplied by the container.
pub async fn check(
    config: Value,
    endpoints: &[(Endpoint, Option<IpAddr>)],
    allowed: &[IpAddr],
    budget: Duration,
) -> Result<Vec<TargetResult>> {
    let socket = TcpListener::bind("127.0.0.1:0").context("loopback_bind")?;
    let port = socket.local_addr()?.port();
    drop(socket);
    let config = prepare(config, port)?;

    let dir = TempDir::new().context("temporary_directory")?;
    let path = dir.path().join("config.json");
    std::fs::write(&path, serde_json::to_vec(&config)?).context("temporary_config")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    let mut cmd = Command::new("xray");
    cmd.arg("run").arg("-c").arg(&path)
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
        .kill_on_drop(true);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.as_std_mut().process_group(0);
    }
    let mut child = ManagedChild::new(cmd.spawn().context("xray_spawn")?);
    let deadline = Instant::now() + budget;
    let result = async {
        timeout_at(deadline, ready(&mut child.child, port)).await.context("xray_start_timeout")??;
        let proxy = format!("http://127.0.0.1:{port}");
        let mut results = Vec::with_capacity(endpoints.len());
        for (endpoint, direct) in endpoints {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                results.push(TargetResult::Unknown);
                continue;
            }
            let response = timeout_at(deadline, probe::get_exit_ip(endpoint, Some(&proxy), remaining)).await;
            let observation = match response {
                Ok(value) => probe::compare(value, *direct, allowed),
                Err(_) => TargetResult::Failed,
            };
            results.push(observation);
        }
        Ok(results)
    }.await;
    child.stop().await;
    // The temporary configuration remains on disk until the child has been reaped.
    result
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
    fn new(child: Child) -> Self { Self { child, finished: false } }

    fn kill_group(&mut self) {
        #[cfg(unix)]
        if let Some(pid) = self.child.id() {
            use nix::{sys::signal::{killpg, Signal}, unistd::Pid};
            let _ = killpg(Pid::from_raw(pid as i32), Signal::SIGKILL);
        }
        let _ = self.child.start_kill();
    }

    async fn stop(&mut self) {
        self.kill_group();
        self.finished = tokio::time::timeout(Duration::from_secs(2), self.child.wait()).await.is_ok();
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        if !self.finished { self.kill_group(); }
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
        assert!(tokio::time::timeout(Duration::from_millis(20), managed.child.wait()).await.is_err());
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
