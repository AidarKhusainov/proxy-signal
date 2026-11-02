use crate::{
    config::{BalancerScenario, BalancerStrategy},
    incident::{Observation, Status},
    scenario,
};
use serde_json::Value;
use std::collections::HashSet;

/// Static validation does not establish that Xray has observed a healthy node.
pub fn inspect(profile: &Value, case: &BalancerScenario) -> Observation {
    let Some(balancers) = profile.pointer("/routing/balancers").and_then(Value::as_array) else {
        return Observation::new(Status::Unsupported, "balancers_missing");
    };
    let matches: Vec<_> = balancers
        .iter()
        .filter(|b| b.get("tag").and_then(Value::as_str) == Some(case.balancer_tag.as_str()))
        .collect();
    if matches.len() != 1 {
        return Observation::new(Status::Failed, "balancer_tag_not_unique");
    }
    let balancer = matches[0];
    let actual_strategy = balancer
        .pointer("/strategy/type")
        .and_then(Value::as_str)
        .unwrap_or("random");
    if actual_strategy != case.strategy.as_str() {
        return Observation::new(Status::Failed, "balancer_strategy_mismatch");
    }
    if balancer.get("fallbackTag").and_then(Value::as_str) != case.fallback_tag.as_deref() {
        return Observation::new(Status::Failed, "balancer_fallback_mismatch");
    }
    let Some(prefixes) = selectors(balancer.get("selector")) else {
        return Observation::new(Status::Unsupported, "balancer_invalid_selector");
    };
    let Some(outbounds) = profile.get("outbounds").and_then(Value::as_array) else {
        return Observation::new(Status::Unsupported, "balancer_outbounds_missing");
    };
    let mut all_tags = HashSet::new();
    for outbound in outbounds {
        let Some(tag) = outbound.get("tag").and_then(Value::as_str) else {
            return Observation::new(Status::Unsupported, "balancer_untagged_outbound");
        };
        if !all_tags.insert(tag) {
            return Observation::new(Status::Unsupported, "balancer_duplicate_outbound");
        }
    }
    let actual: HashSet<_> = all_tags
        .iter()
        .copied()
        .filter(|tag| prefixes.iter().any(|prefix| tag.starts_with(prefix)))
        .collect();
    let expected: HashSet<_> = case.candidates.iter().map(String::as_str).collect();
    if actual != expected {
        return Observation::new(Status::Failed, "balancer_candidates_mismatch");
    }
    if case.fallback_tag.as_ref().is_some_and(|tag| !all_tags.contains(tag.as_str())) {
        return Observation::new(Status::Failed, "balancer_fallback_missing");
    }

    let monitored = match case.strategy {
        BalancerStrategy::LeastPing | BalancerStrategy::LeastLoad => {
            let standard = profile.get("observatory");
            let burst = profile.get("burstObservatory");
            match (standard, burst) {
                (Some(_), Some(_)) => {
                    return Observation::new(Status::Unsupported, "multiple_observatories");
                }
                (None, None) => {
                    return Observation::new(Status::Failed, "balancer_observatory_missing");
                }
                (Some(value), None) | (None, Some(value)) => value,
            }
        }
        _ => {
            return Observation::new(Status::Ok, "balancer_config_valid");
        }
    };
    let Some(observed) = selectors(monitored.get("subjectSelector")) else {
        return Observation::new(Status::Unsupported, "observatory_invalid_selector");
    };
    if !expected
        .iter()
        .all(|tag| observed.iter().any(|prefix| tag.starts_with(prefix)))
    {
        return Observation::new(Status::Failed, "observatory_candidates_missing");
    }
    if let Some(url) = monitored
        .get("probeUrl")
        .or_else(|| monitored.pointer("/pingConfig/destination"))
    {
        if !valid_probe_url(url) {
            return Observation::new(Status::Unsupported, "observatory_invalid_probe_url");
        }
    }
    if profile.get("burstObservatory").is_some()
        && monitored.get("pingConfig").is_some_and(|ping| !ping.is_object())
    {
        return Observation::new(Status::Unsupported, "observatory_invalid_ping_config");
    }
    Observation::new(Status::Ok, "balancer_config_valid")
}

fn selectors(value: Option<&Value>) -> Option<Vec<&str>> {
    let entries = value?.as_array()?;
    if entries.is_empty() {
        return None;
    }
    let parsed: Option<Vec<&str>> = entries
        .iter()
        .map(|v| v.as_str().filter(|s| !s.is_empty()))
        .collect();
    parsed
}

fn valid_probe_url(value: &Value) -> bool {
    let Some(url) = value.as_str() else {
        return false;
    };
    reqwest::Url::parse(url).is_ok_and(|v| {
        matches!(v.scheme(), "http" | "https") && v.host_str().is_some()
    })
}

/// Only an unambiguous, first, exact-domain rule permits attributing a route
/// to the named balancer. Arbitrary geosite/IP/script routing is not guessed.
pub fn attributable(profile: &Value, case: &BalancerScenario) -> bool {
    if profile.pointer("/routing/script").and_then(Value::as_str).is_some_and(|v| !v.is_empty()) {
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
    let Some(object) = rule.as_object() else {
        return false;
    };
    object.get("type").and_then(Value::as_str) == Some("field")
        && object.get("balancerTag").and_then(Value::as_str) == Some(&case.balancer_tag)
        && object.keys().all(|key| matches!(key.as_str(), "type" | "domain" | "balancerTag" | "ruleTag"))
        && rule.get("domain").and_then(Value::as_array).is_some_and(|v| {
            v.len() == 1 && v[0].as_str().is_some_and(|domain| domain == format!("full:{host}"))
        })
}

/// The candidate-specific test is intentionally routed by a diagnostic inbound,
/// not the balancer. It proves only this outbound's HTTPS availability.
pub fn candidate(http_ok: Option<bool>, access: Option<&str>, url: &str, inbound: &str, tag: &str) -> Observation {
    let (Some(http_ok), Some(access)) = (http_ok, access) else {
        return Observation::new(Status::Unknown, "candidate_unobserved");
    };
    match scenario::observed_outbound(url, inbound, access) {
        Ok(actual) if actual != tag => Observation::new(Status::Failed, "candidate_wrong_outbound"),
        Ok(_) if !http_ok => Observation::new(Status::Failed, "candidate_https_failed"),
        Ok(_) => Observation::new(Status::Ok, "candidate_https_verified"),
        Err(_) => Observation::new(Status::Unknown, "candidate_route_unobserved"),
    }
}

pub fn candidate_status(results: &[Observation]) -> Observation {
    let ok = results.iter().filter(|o| o.status == Status::Ok).count();
    let failed = results.iter().filter(|o| o.status == Status::Failed).count();
    if ok == results.len() && ok > 0 {
        Observation::new(Status::Ok, "candidates_https_verified")
    } else if ok > 0 && failed > 0 {
        Observation::new(Status::Degraded, "candidates_partially_failed")
    } else if failed == results.len() && failed > 0 {
        Observation::new(Status::Failed, "candidates_all_failed")
    } else {
        Observation::new(Status::Unknown, "candidates_incomplete")
    }
}

/// Xray access logs identify an outbound, not the measured RTTs or policy
/// decision of leastPing / leastLoad. Therefore their route stays UNKNOWN.
pub fn route(case: &BalancerScenario, attributable: bool, http_ok: Option<bool>, access: Option<&str>) -> Observation {
    if !attributable {
        return Observation::new(Status::Unknown, "balancer_rule_not_attributable");
    }
    let (Some(http_ok), Some(access)) = (http_ok, access) else {
        return Observation::new(Status::Unknown, "balancer_route_unobserved");
    };
    let actual = match scenario::observed_outbound(&case.url, "proxy-signal-probe-in", access) {
        Ok(tag) => tag,
        Err(_) => return Observation::new(Status::Unknown, "balancer_route_unobserved"),
    };
    if !case.candidates.iter().any(|c| c == actual) {
        return Observation::new(Status::Failed, "balancer_unexpected_outbound");
    }
    if !http_ok {
        return Observation::new(Status::Failed, "balancer_https_failed");
    }
    match case.strategy {
        BalancerStrategy::LeastPing | BalancerStrategy::LeastLoad => {
            Observation::new(Status::Unknown, "balancer_policy_unverified")
        }
        _ => Observation::new(Status::Ok, "balancer_route_verified"),
    }
}

pub fn overall(config: Observation, candidates: Observation, route: Observation) -> Observation {
    if config.status != Status::Ok {
        return config;
    }
    if candidates.status == Status::Failed || route.status == Status::Failed {
        Observation::new(Status::Failed, "balancer_failed")
    } else if candidates.status == Status::Degraded {
        Observation::new(Status::Degraded, "balancer_partial_candidates")
    } else if candidates.status == Status::Ok && route.status == Status::Ok {
        Observation::new(Status::Ok, "balancer_verified")
    } else {
        Observation::new(Status::Unknown, "balancer_incomplete_evidence")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn case() -> BalancerScenario {
        BalancerScenario {
            id: "pool".into(),
            url: "https://example.com/".into(),
            balancer_tag: "pool".into(),
            strategy: BalancerStrategy::LeastPing,
            candidates: vec!["node-a".into(), "node-b".into()],
            fallback_tag: None,
        }
    }

    fn profile() -> Value {
        json!({
            "routing": {
                "balancers": [{"tag":"pool", "selector":["node-"], "strategy":{"type":"leastPing"}}],
                "rules": [{"type":"field", "domain":["full:example.com"], "balancerTag":"pool"}]
            },
            "outbounds": [
                {"tag":"node-a", "protocol":"freedom"},
                {"tag":"node-b", "protocol":"socks"}
            ],
            "observatory": {"subjectSelector":["node-"], "probeUrl":"https://example.com/", "probeInterval":"10s"}
        })
    }

    #[test]
    fn validates_candidates_strategy_and_observatory() {
        let c = case();
        let p = profile();
        assert_eq!(inspect(&p, &c).status, Status::Ok);
        assert!(attributable(&p, &c));
        let mut invalid = p.clone();
        invalid["routing"]["balancers"][0]["selector"] = json!(["node-a"]);
        assert_eq!(inspect(&invalid, &c).status, Status::Failed);
        invalid = p.clone();
        invalid["observatory"]["subjectSelector"] = json!(["node-a"]);
        assert_eq!(inspect(&invalid, &c).status, Status::Failed);
        invalid = p.clone();
        invalid["routing"]["balancers"][0]["strategy"]["type"] = json!("leastLoad");
        assert_eq!(inspect(&invalid, &c).status, Status::Failed);
        invalid = p.clone();
        invalid.as_object_mut().unwrap().remove("observatory");
        assert_eq!(inspect(&invalid, &c).status, Status::Failed);
        invalid = p.clone();
        invalid["routing"]["rules"].as_array_mut().unwrap().insert(
            0, json!({"type":"field","domain":["domain:example.com"],"outboundTag":"node-a"})
        );
        assert!(!attributable(&invalid, &c));
    }

    #[test]
    fn missing_policy_proof_and_partial_failures_cannot_be_ok() {
        let c = case();
        let log = "2026/01/01 from 127.0.0.1:1234 accepted //example.com:443 [proxy-signal-probe-in ==> node-a]";
        assert_eq!(route(&c, true, Some(true), Some(log)).status, Status::Unknown);
        assert_eq!(route(&c, true, Some(true), None).status, Status::Unknown);
        assert_eq!(route(&c, true, Some(true), Some(&log.replace("node-a", "direct"))).status, Status::Failed);
        let good = Observation::new(Status::Ok, "good");
        let bad = Observation::new(Status::Failed, "bad");
        let unknown = Observation::new(Status::Unknown, "unknown");
        assert_eq!(candidate_status(&[good, bad]).status, Status::Degraded);
        assert_eq!(candidate_status(&[bad, unknown]).status, Status::Unknown);
        assert_eq!(overall(good, good, unknown).status, Status::Unknown);
        assert_eq!(overall(good, candidate_status(&[good, bad]), unknown).status, Status::Degraded);
        assert_eq!(overall(good, bad, unknown).status, Status::Failed);
    }

    #[test]
    fn forced_candidate_requires_exact_inbound_and_https() {
        let access = "2026/01/01 from 127.0.0.1:1234 accepted //example.com:443 [proxy-signal-candidate-0 ==> node-a]";
        assert_eq!(candidate(Some(true), Some(access), "https://example.com/", "proxy-signal-candidate-0", "node-a").status, Status::Ok);
        assert_eq!(candidate(Some(false), Some(access), "https://example.com/", "proxy-signal-candidate-0", "node-a").status, Status::Failed);
        assert_eq!(candidate(Some(true), Some(access), "https://example.com/", "proxy-signal-candidate-1", "node-a").status, Status::Unknown);
        assert_eq!(candidate(None, Some(access), "https://example.com/", "proxy-signal-candidate-0", "node-a").status, Status::Unknown);
    }
}
