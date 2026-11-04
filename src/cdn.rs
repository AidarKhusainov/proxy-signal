use crate::{
    config::{self, CdnScenario},
    incident::{Observation, Status},
    scenario,
};
use serde_json::Value;
use std::time::Duration;
use tokio::time::Instant;

pub struct EndpointChecks {
    pub dns: Observation,
    pub tls: Observation,
    pub http: Observation,
    pub overall: Observation,
}

pub fn unavailable_endpoint() -> EndpointChecks {
    let missing = Observation::new(Status::Unknown, "cdn_endpoint_task_error");
    EndpointChecks {
        dns: missing,
        tls: missing,
        http: missing,
        overall: missing,
    }
}

fn unavailable(status: Status, code: &'static str) -> Observation {
    Observation::new(status, code)
}

/// Native CDN reachability is independent from Xray. Resolve and pin public
/// addresses, enforce normal certificate verification, and never follow redirects.
pub async fn endpoint(case: &CdnScenario, budget: Duration) -> EndpointChecks {
    let unknown = unavailable(Status::Unknown, "cdn_endpoint_not_tested");
    let deadline = Instant::now() + budget;
    let (host, addresses) = match config::public_resolution(&case.endpoint_url, budget).await {
        Ok(resolved) => resolved,
        Err(_) => {
            return EndpointChecks {
                dns: unavailable(Status::Failed, "cdn_dns_failed"),
                tls: unknown,
                http: unknown,
                overall: unavailable(Status::Failed, "cdn_endpoint_dns_failed"),
            };
        }
    };
    let dns = unavailable(Status::Ok, "cdn_public_dns_resolved");
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return EndpointChecks {
            dns,
            tls: unknown,
            http: unknown,
            overall: unavailable(Status::Unknown, "cdn_endpoint_timeout"),
        };
    }
    let client = match reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(remaining)
        .resolve_to_addrs(&host, &addresses)
        .build()
    {
        Ok(client) => client,
        Err(_) => {
            return EndpointChecks {
                dns,
                tls: unknown,
                http: unknown,
                overall: unavailable(Status::Unknown, "cdn_client_unavailable"),
            };
        }
    };
    match tokio::time::timeout(remaining, client.get(&case.endpoint_url).send()).await {
        Ok(Ok(response)) => {
            // A valid HTTPS response means TLS peer verification completed.
            let http = http_status(response.status().as_u16(), case.expected_http_status);
            EndpointChecks {
                dns,
                tls: unavailable(Status::Ok, "cdn_tls_verified"),
                http,
                overall: if http.status == Status::Ok {
                    unavailable(Status::Ok, "cdn_endpoint_verified")
                } else {
                    unavailable(Status::Failed, "cdn_http_unexpected_status")
                },
            }
        }
        Ok(Err(error)) => request_failed(dns, error.is_connect()),
        Err(_) => EndpointChecks {
            dns,
            tls: unknown,
            http: unknown,
            overall: unavailable(Status::Unknown, "cdn_endpoint_timeout"),
        },
    }
}

fn request_failed(dns: Observation, connection_error: bool) -> EndpointChecks {
    // reqwest reports both TCP refusal and invalid TLS certificates as
    // connection failures. Do not pretend this identifies the precise cause.
    EndpointChecks {
        dns,
        tls: if connection_error {
            unavailable(Status::Failed, "cdn_tls_or_connect_failed")
        } else {
            unavailable(Status::Unknown, "cdn_tls_unverified")
        },
        http: unavailable(Status::Unknown, "cdn_http_unobserved"),
        overall: unavailable(Status::Failed, "cdn_endpoint_unreachable"),
    }
}

fn http_status(actual: u16, expected: u16) -> Observation {
    if actual == expected {
        unavailable(Status::Ok, "cdn_http_expected_status")
    } else {
        unavailable(Status::Failed, "cdn_http_unexpected_status")
    }
}

/// Inspect transport intent only, never conflate static XHTTP settings with a
/// completed VPN connection or proof of transit through a particular CDN edge.
pub fn inspect(profile: &Value, case: &CdnScenario) -> Observation {
    let Some(outbounds) = profile.get("outbounds").and_then(Value::as_array) else {
        return unavailable(Status::Unsupported, "cdn_outbounds_missing");
    };
    let selected: Vec<_> = outbounds
        .iter()
        .filter(|o| o.get("tag").and_then(Value::as_str) == Some(case.outbound_tag.as_str()))
        .collect();
    if selected.len() != 1 {
        return unavailable(Status::Unsupported, "cdn_outbound_not_unique");
    }
    let outbound = selected[0];
    if matches!(
        outbound.get("protocol").and_then(Value::as_str),
        None | Some("freedom" | "blackhole" | "loopback" | "dns")
    ) {
        return unavailable(Status::Unsupported, "cdn_not_vpn_outbound");
    }
    let Some(stream) = outbound.get("streamSettings") else {
        return unavailable(Status::Unsupported, "cdn_stream_missing");
    };
    if stream.get("network").and_then(Value::as_str) != Some("xhttp") {
        return unavailable(Status::Unsupported, "cdn_not_xhttp");
    }
    if stream.get("security").and_then(Value::as_str) != Some("tls") {
        return unavailable(Status::Unsupported, "cdn_tls_required");
    }
    let Some(tls) = stream.get("tlsSettings") else {
        return unavailable(Status::Unsupported, "cdn_tls_settings_missing");
    };
    if tls.get("allowInsecure").and_then(Value::as_bool) == Some(true) {
        return unavailable(Status::Unsupported, "cdn_insecure_tls");
    }
    let Ok(url) = reqwest::Url::parse(&case.endpoint_url) else {
        return unavailable(Status::Unsupported, "cdn_invalid_endpoint");
    };
    let Some(host) = url.host_str() else {
        return unavailable(Status::Unsupported, "cdn_invalid_endpoint");
    };
    // Explicit SNI ties this outbound to the tested CDN hostname. Inferred
    // SNI from an IP or dynamic server address is not reliable evidence.
    if tls.get("serverName").and_then(Value::as_str) != Some(host) {
        return unavailable(Status::Unsupported, "cdn_sni_mismatch_or_missing");
    }
    let Some(xhttp) = stream.get("xhttpSettings") else {
        return unavailable(Status::Unsupported, "cdn_xhttp_settings_missing");
    };
    let Some(path) = xhttp.get("path").and_then(Value::as_str) else {
        return unavailable(Status::Unsupported, "cdn_xhttp_path_missing");
    };
    if !path.starts_with('/') || path.contains('?') || path.contains('#') {
        return unavailable(Status::Unsupported, "cdn_xhttp_path_invalid");
    }
    if let Some(value) = xhttp.get("host") {
        if value
            .as_str()
            .is_none_or(|value| !value.is_empty() && value != host)
        {
            return unavailable(Status::Unsupported, "cdn_xhttp_host_mismatch");
        }
    }
    if !matches!(
        xhttp.get("mode").and_then(Value::as_str),
        None | Some("auto" | "packet-up" | "stream-up")
    ) {
        return unavailable(Status::Unsupported, "cdn_xhttp_mode_unsupported");
    }
    unavailable(Status::Ok, "cdn_xhttp_config_valid")
}

fn attributable(profile: &Value, case: &CdnScenario) -> bool {
    if profile.pointer("/routing/script").is_some() {
        return false;
    }
    let Ok(url) = reqwest::Url::parse(&case.url) else {
        return false;
    };
    let Some(host) = url.host_str() else {
        return false;
    };
    let Some(rule) = profile.pointer("/routing/rules/0") else {
        return false;
    };
    rule.get("type").and_then(Value::as_str) == Some("field")
        && rule.get("outboundTag").and_then(Value::as_str) == Some(case.outbound_tag.as_str())
        && rule.as_object().is_some_and(|obj| {
            obj.keys()
                .all(|key| matches!(key.as_str(), "type" | "domain" | "outboundTag" | "ruleTag"))
        })
        && rule
            .get("domain")
            .and_then(Value::as_array)
            .is_some_and(|domains| {
                domains.len() == 1
                    && domains[0]
                        .as_str()
                        .is_some_and(|domain| domain == format!("full:{host}"))
            })
}

/// Real HTTPS over the unchanged full-profile diagnostic inbound. Xray access
/// evidence must identify the configured outbound; a raw HTTPS 200 is not proof.
#[cfg(test)]
pub fn tunnel(
    profile: &Value,
    case: &CdnScenario,
    http_ok: Option<bool>,
    access: Option<&str>,
) -> Observation {
    tunnel_for_inbound(profile, case, http_ok, access, "proxy-signal-probe-in")
}

pub fn tunnel_for_inbound(
    profile: &Value,
    case: &CdnScenario,
    http_ok: Option<bool>,
    access: Option<&str>,
    inbound_tag: &str,
) -> Observation {
    if !attributable(profile, case) {
        return unavailable(Status::Unknown, "cdn_tunnel_route_not_attributable");
    }
    let (Some(http_ok), Some(access)) = (http_ok, access) else {
        return unavailable(Status::Unknown, "cdn_tunnel_unobserved");
    };
    match scenario::observed_outbound(&case.url, inbound_tag, access) {
        Ok(tag) if tag != case.outbound_tag => {
            unavailable(Status::Failed, "cdn_unexpected_outbound")
        }
        Ok(_) if !http_ok => unavailable(Status::Failed, "cdn_tunnel_https_failed"),
        Ok(_) => unavailable(Status::Ok, "cdn_tunnel_https_verified"),
        Err(_) => unavailable(Status::Unknown, "cdn_tunnel_route_unobserved"),
    }
}

/// Access records attest the outbound, not the CDN edge actually traversed.
pub fn route() -> Observation {
    unavailable(Status::Unknown, "cdn_route_unverified")
}

pub fn overall(
    config: Observation,
    endpoint: Observation,
    tunnel: Observation,
    route: Observation,
) -> Observation {
    if config.status != Status::Ok {
        return config;
    }
    if endpoint.status == Status::Failed && tunnel.status == Status::Failed {
        return unavailable(Status::Failed, "cdn_endpoint_and_tunnel_failed");
    }
    if endpoint.status == Status::Failed {
        return unavailable(
            if tunnel.status == Status::Ok {
                Status::Degraded
            } else {
                Status::Failed
            },
            "cdn_endpoint_failed",
        );
    }
    if tunnel.status == Status::Failed {
        return unavailable(
            if endpoint.status == Status::Ok {
                Status::Degraded
            } else {
                Status::Failed
            },
            "cdn_tunnel_failed",
        );
    }
    if endpoint.status == Status::Ok && tunnel.status == Status::Ok {
        return if route.status == Status::Ok {
            unavailable(Status::Ok, "cdn_path_verified")
        } else if route.status == Status::Failed {
            unavailable(Status::Failed, "cdn_route_failed")
        } else {
            unavailable(
                Status::Unknown,
                "cdn_endpoint_tunnel_healthy_route_unverified",
            )
        };
    }
    unavailable(Status::Unknown, "cdn_incomplete_evidence")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn case() -> CdnScenario {
        CdnScenario {
            id: "edge".into(),
            endpoint_url: "https://cdn.example.org/health".into(),
            expected_http_status: 404,
            url: "https://example.com/".into(),
            outbound_tag: "vpn".into(),
        }
    }
    fn profile() -> Value {
        json!({
            "routing": {"rules": [{"type":"field", "domain":["full:example.com"], "outboundTag":"vpn"}]},
            "outbounds": [{"tag":"vpn", "protocol":"vless", "streamSettings": {
                "network":"xhttp", "security":"tls",
                "tlsSettings":{"serverName":"cdn.example.org"},
                "xhttpSettings":{"host":"cdn.example.org", "path":"/xhttp", "mode":"auto"}
            }}]
        })
    }

    #[test]
    fn validates_xhttp_tls_sni_host_and_path() {
        let mut value = profile();
        assert_eq!(inspect(&value, &case()).status, Status::Ok);
        value["outbounds"][0]["streamSettings"]["tlsSettings"]["allowInsecure"] = json!(true);
        assert_eq!(inspect(&value, &case()).status, Status::Unsupported);
        value["outbounds"][0]["streamSettings"]["tlsSettings"]["allowInsecure"] = json!(false);
        value["outbounds"][0]["streamSettings"]["tlsSettings"]["serverName"] =
            json!("wrong.example.org");
        assert_eq!(inspect(&value, &case()).code, "cdn_sni_mismatch_or_missing");
        value["outbounds"][0]["streamSettings"]["tlsSettings"]["serverName"] =
            json!("cdn.example.org");
        value["outbounds"][0]["streamSettings"]["xhttpSettings"]["path"] = json!("invalid");
        assert_eq!(inspect(&value, &case()).code, "cdn_xhttp_path_invalid");
        value["outbounds"][0]["streamSettings"]["xhttpSettings"]["path"] = json!("/xhttp");
        value["outbounds"][0]["streamSettings"]["network"] = json!("ws");
        assert_eq!(inspect(&value, &case()).code, "cdn_not_xhttp");
        value["outbounds"][0]["streamSettings"]["network"] = json!("xhttp");
        value["outbounds"][0]["protocol"] = json!("freedom");
        assert_eq!(inspect(&value, &case()).code, "cdn_not_vpn_outbound");
    }

    #[test]
    fn tunnel_requires_real_https_and_exact_access_evidence() {
        let value = profile();
        let access = "2026/01/01 from 127.0.0.1:1 accepted //example.com:443 [proxy-signal-probe-in ==> vpn]";
        assert_eq!(
            tunnel(&value, &case(), Some(true), Some(access)).status,
            Status::Ok
        );
        assert_eq!(
            tunnel(&value, &case(), Some(false), Some(access)).status,
            Status::Failed
        );
        assert_eq!(
            tunnel(&value, &case(), Some(true), None).status,
            Status::Unknown
        );
        assert_eq!(
            tunnel(
                &value,
                &case(),
                Some(true),
                Some(&access.replace("==> vpn", "==> direct"))
            )
            .status,
            Status::Failed
        );
        let mut ambiguous = value;
        ambiguous["routing"]["rules"][0]["domain"] = json!(["domain:example.com"]);
        assert_eq!(
            tunnel(&ambiguous, &case(), Some(true), Some(access)).status,
            Status::Unknown
        );
    }

    #[test]
    fn independent_cdn_outbound_has_separate_https_proof_without_route_claim() {
        let mut case = case();
        case.independent_outbound = true;
        let mut profile = profile();
        // Original route intentionally points elsewhere; a fallback needs
        // independent checking even while the primary is healthy.
        profile["routing"]["rules"][0]["outboundTag"] = json!("primary");
        let access = "2026/01/01 from 127.0.0.1:1 accepted //example.com:443 [proxy-signal-candidate-0 ==> vpn]";
        let checked = tunnel_for_inbound(
            &profile,
            &case,
            Some(true),
            Some(access),
            "proxy-signal-candidate-0",
        );
        assert_eq!(checked.status, Status::Ok);
        assert_eq!(checked.code, "cdn_outbound_https_verified");
        assert_eq!(route().status, Status::Unknown);
        assert_eq!(
            tunnel_for_inbound(
                &profile,
                &case,
                Some(true),
                Some(&access.replace("==> vpn", "==> primary")),
                "proxy-signal-candidate-0"
            )
            .status,
            Status::Failed
        );
        assert_eq!(
            tunnel_for_inbound(
                &profile,
                &case,
                Some(true),
                None,
                "proxy-signal-candidate-0"
            )
            .status,
            Status::Unknown
        );
    }

    #[test]
    fn endpoint_tls_http_and_route_are_independent() {
        let ok = unavailable(Status::Ok, "verified");
        let fail = unavailable(Status::Failed, "failed");
        let unknown = unavailable(Status::Unknown, "missing");
        assert_eq!(http_status(404, 404).status, Status::Ok);
        assert_eq!(http_status(495, 404).status, Status::Failed);
        assert_eq!(route().status, Status::Unknown);
        let transport_failure = request_failed(ok, true);
        assert_eq!(transport_failure.tls.status, Status::Failed);
        assert_eq!(transport_failure.http.status, Status::Unknown);
        assert_eq!(transport_failure.overall.status, Status::Failed);
        assert_eq!(request_failed(ok, false).tls.status, Status::Unknown);
        assert_eq!(overall(ok, ok, ok, unknown).status, Status::Unknown);
        assert_eq!(overall(ok, fail, ok, unknown).status, Status::Degraded);
        assert_eq!(overall(ok, ok, fail, unknown).status, Status::Degraded);
        assert_eq!(overall(ok, fail, fail, unknown).status, Status::Failed);
        assert_eq!(overall(ok, unknown, ok, unknown).status, Status::Unknown);
        assert_ne!(overall(ok, ok, ok, unknown).status, Status::Ok);
        assert_eq!(overall(ok, ok, ok, fail).status, Status::Failed);
        assert_eq!(overall(ok, ok, ok, ok).status, Status::Ok);
    }
}
