use crate::{
    config::{ExpectedRoute, Scenario},
    incident::{Observation, Status},
};
use serde_json::Value;
use std::{collections::HashSet, net::IpAddr};

/// Static compatibility is not runtime evidence. The tag must name a real outbound
/// with the expected protocol class; selection is verified separately from Xray logs.
pub fn static_check(profile: &Value, case: &Scenario) -> Option<Observation> {
    let Some(outbounds) = profile.get("outbounds").and_then(Value::as_array) else {
        return Some(Observation::new(Status::Unsupported, "scenario_missing_outbounds"));
    };
    let selected: Vec<_> = outbounds
        .iter()
        .filter(|o| o.get("tag").and_then(Value::as_str) == Some(case.outbound_tag.as_str()))
        .collect();
    if selected.len() != 1 {
        return Some(Observation::new(Status::Unsupported, "scenario_outbound_not_unique"));
    }
    let Some(protocol) = selected[0].get("protocol").and_then(Value::as_str) else {
        return Some(Observation::new(Status::Unsupported, "scenario_missing_protocol"));
    };
    let compatible = match case.route {
        ExpectedRoute::Direct => protocol == "freedom",
        ExpectedRoute::Block => protocol == "blackhole",
        ExpectedRoute::Proxy => protocol != "freedom" && protocol != "blackhole",
    };
    if compatible {
        None
    } else {
        Some(Observation::new(Status::Unsupported, "scenario_protocol_mismatch"))
    }
}

/// Requires an access event for the exact diagnostic inbound and requested
/// destination. HTTPS success by itself is never routing evidence.
pub fn evaluate(case: &Scenario, http_ok: bool, access: &str, error: &str) -> Observation {
    let Ok(url) = reqwest::Url::parse(&case.url) else {
        return Observation::new(Status::Unsupported, "scenario_invalid_url");
    };
    let Some(host) = url.host_str() else {
        return Observation::new(Status::Unsupported, "scenario_invalid_url");
    };
    let needle = format!(
        "accepted tcp:{}:{} [proxy-signal-probe-in -> ",
        host,
        url.port_or_known_default().unwrap_or(443)
    );
    let mut observed: Option<&str> = None;
    for line in access.lines() {
        let Some((_, remainder)) = line.split_once(&needle) else {
            continue;
        };
        let Some((tag, _)) = remainder.split_once(']') else {
            continue;
        };
        if tag.is_empty() || observed.is_some_and(|prior| prior != tag) {
            return Observation::new(Status::Unknown, "ambiguous_route_evidence");
        }
        observed = Some(tag);
    }
    let Some(actual) = observed else {
        return Observation::new(Status::Unknown, "route_not_observed");
    };
    if actual != case.outbound_tag {
        return Observation::new(Status::Failed, "unexpected_outbound");
    }
    if case.route == ExpectedRoute::Block {
        if http_ok {
            return Observation::new(Status::Failed, "block_bypassed");
        }
    } else if !http_ok {
        return Observation::new(Status::Failed, "routed_https_failed");
    }
    if let Some(dns) = &case.dns {
        let mut observed_families = HashSet::new();
        let expected: HashSet<IpAddr> = dns.expected_ips.iter().copied().collect();
        for line in error.lines() {
            let Some((_, entry)) = line.split_once("app/dns: ") else {
                continue;
            };
            let Some((server, response)) = entry.split_once(" got answer: ") else {
                continue;
            };
            let Some(answer) = response.strip_prefix(host) else {
                continue;
            };
            let answer = answer.strip_prefix('.').unwrap_or(answer);
            let family = if answer.starts_with(" TypeA -> [") {
                4
            } else if answer.starts_with(" TypeAAAA -> [") {
                6
            } else {
                continue;
            };
            let expected_family: HashSet<_> = expected
                .iter()
                .copied()
                .filter(|ip| (family == 4) == ip.is_ipv4())
                .collect();
            if expected_family.is_empty() {
                continue;
            }
            observed_families.insert(family);
            if server != dns.server {
                return Observation::new(Status::Failed, "dns_server_mismatch");
            }
            let Some((_, list)) = answer.split_once(" -> [") else {
                return Observation::new(Status::Unknown, "dns_log_unparseable");
            };
            let Some((list, _)) = list.split_once(']') else {
                return Observation::new(Status::Unknown, "dns_log_unparseable");
            };
            let parsed: Result<HashSet<IpAddr>, _> =
                list.split_whitespace().map(str::parse).collect();
            let Ok(actual_ips) = parsed else {
                return Observation::new(Status::Unknown, "dns_log_unparseable");
            };
            if actual_ips != expected_family {
                return Observation::new(Status::Failed, "dns_answer_mismatch");
            }
        }
        if expected.iter().any(|ip| !observed_families.contains(&if ip.is_ipv4() { 4 } else { 6 })) {
            return Observation::new(Status::Unknown, "dns_not_observed");
        }
        Observation::new(Status::Ok, "routing_dns_verified")
    } else {
        Observation::new(Status::Ok, "routing_verified")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DnsExpectation;
    use serde_json::json;

    fn case(route: ExpectedRoute, dns: bool) -> Scenario {
        Scenario {
            id: "test".into(),
            url: "https://example.org/".into(),
            route,
            outbound_tag: match route {
                ExpectedRoute::Direct => "direct",
                ExpectedRoute::Proxy => "vpn",
                ExpectedRoute::Block => "blocked",
            }.into(),
            dns: dns.then(|| DnsExpectation {
                server: "UDP:1.1.1.1:53".into(),
                expected_ips: vec!["93.184.215.14".parse().unwrap()],
            }),
        }
    }

    const DIRECT_LOG: &str =
        "2026/01/01 00:00:00 127.0.0.1:2345 accepted tcp:example.org:443 [proxy-signal-probe-in -> direct]";
    const DNS_LOG: &str =
        "2026/01/01 00:00:00 [Info] app/dns: UDP:1.1.1.1:53 got answer: example.org. TypeA -> [93.184.215.14] 5ms";

    #[test]
    fn routing_proof_requires_exact_access_tag() {
        let direct = case(ExpectedRoute::Direct, false);
        assert!(static_check(&json!({"outbounds": [{"tag":"direct","protocol":"freedom"}]}), &direct).is_none());
        assert_eq!(evaluate(&direct, true, DIRECT_LOG, "").status, Status::Ok);
        assert_eq!(evaluate(&direct, true, "", "").status, Status::Unknown);
        assert_eq!(evaluate(&direct, true, &DIRECT_LOG.replace("-> direct", "-> vpn"), "").status, Status::Failed);
        assert_eq!(evaluate(&direct, false, DIRECT_LOG, "").status, Status::Failed);
    }

    #[test]
    fn blocked_route_requires_blackhole_and_no_https() {
        let block = case(ExpectedRoute::Block, false);
        assert_eq!(evaluate(&block, false, &DIRECT_LOG.replace("-> direct", "-> blocked"), "").status, Status::Ok);
        assert_eq!(evaluate(&block, true, &DIRECT_LOG.replace("-> direct", "-> blocked"), "").status, Status::Failed);
        assert_eq!(static_check(&json!({"outbounds": [{"tag":"blocked","protocol":"freedom"}]}), &block).unwrap().status, Status::Unsupported);
    }

    #[test]
    fn dns_requires_engine_answer_and_expected_server() {
        let direct = case(ExpectedRoute::Direct, true);
        assert_eq!(evaluate(&direct, true, DIRECT_LOG, DNS_LOG).status, Status::Ok);
        assert_eq!(evaluate(&direct, true, DIRECT_LOG, "").status, Status::Unknown);
        assert_eq!(evaluate(&direct, true, DIRECT_LOG, &DNS_LOG.replace("1.1.1.1", "8.8.8.8")).status, Status::Failed);
        assert_eq!(evaluate(&direct, true, DIRECT_LOG, &DNS_LOG.replace("93.184.215.14", "93.184.215.15")).status, Status::Failed);
        assert_eq!(evaluate(&direct, true, DIRECT_LOG, &DNS_LOG.replace("93.184.215.14", "")).status, Status::Failed);
    }

    #[test]
    fn missing_or_duplicate_outbound_is_not_accepted() {
        let proxy = case(ExpectedRoute::Proxy, false);
        assert!(static_check(&json!({"outbounds": [{"tag":"vpn","protocol":"vless"}]}), &proxy).is_none());
        assert_eq!(static_check(&json!({"outbounds": [{"tag":"vpn","protocol":"freedom"}]}), &proxy).unwrap().status, Status::Unsupported);
        assert_eq!(static_check(&json!({"outbounds": [{"tag":"vpn","protocol":"vless"},{"tag":"vpn","protocol":"vless"}]}), &proxy).unwrap().status, Status::Unsupported);
    }
}
