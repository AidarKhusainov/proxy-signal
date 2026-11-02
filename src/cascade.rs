use crate::{
    config::CascadeScenario,
    incident::{Observation, Status},
    scenario,
};
use serde_json::Value;
use std::collections::HashSet;

/// Validate the ordered dialer graph, not just the presence of outbound tags.
/// Xray 26.10.21 removed proxySettings; do not silently rewrite a profile.
pub fn inspect(profile: &Value, case: &CascadeScenario) -> Observation {
    let Some(outbounds) = profile.get("outbounds").and_then(Value::as_array) else {
        return Observation::new(Status::Unsupported, "cascade_outbounds_missing");
    };
    let mut tags = HashSet::new();
    for outbound in outbounds {
        let Some(tag) = outbound.get("tag").and_then(Value::as_str) else {
            return Observation::new(Status::Unsupported, "cascade_untagged_outbound");
        };
        if !tags.insert(tag) {
            return Observation::new(Status::Unsupported, "cascade_duplicate_outbound");
        }
    }
    let mut legacy = false;
    for (index, tag) in case.outbounds.iter().enumerate() {
        let Some(outbound) = outbounds
            .iter()
            .find(|outbound| outbound.get("tag").and_then(Value::as_str) == Some(tag))
        else {
            return Observation::new(Status::Failed, "cascade_outbound_missing");
        };
        if matches!(
            outbound.get("protocol").and_then(Value::as_str),
            None | Some("blackhole" | "loopback" | "dns")
        ) {
            return Observation::new(Status::Unsupported, "cascade_protocol_unsupported");
        }
        let proxy = outbound.get("proxySettings");
        let dialer = outbound.pointer("/streamSettings/sockopt/dialerProxy");
        if proxy.is_some() && dialer.is_some() {
            return Observation::new(Status::Unsupported, "cascade_conflicting_dialers");
        }
        let link = if let Some(proxy) = proxy {
            if !proxy.is_object()
                || !proxy.get("tag").is_some_and(Value::is_string)
                || proxy
                    .get("transportLayer")
                    .is_some_and(|value| !value.is_boolean())
            {
                return Observation::new(Status::Unsupported, "cascade_invalid_proxy_settings");
            }
            legacy = true;
            proxy.get("tag").and_then(Value::as_str)
        } else if let Some(dialer) = dialer {
            if !dialer.is_string() {
                return Observation::new(Status::Unsupported, "cascade_invalid_dialer");
            }
            dialer.as_str()
        } else {
            None
        };
        if link == Some("") {
            return Observation::new(Status::Unsupported, "cascade_empty_dialer");
        }
        let expected = case.outbounds.get(index + 1).map(String::as_str);
        if link != expected {
            return Observation::new(Status::Failed, "cascade_order_mismatch");
        }
    }
    if legacy {
        Observation::new(Status::Unsupported, "cascade_proxy_settings_removed")
    } else {
        Observation::new(Status::Ok, "cascade_config_valid")
    }
}

/// Only an exact first routing rule can attribute the HTTPS request to the
/// first outbound. The access log does not reveal subsequent dialerProxy hops.
fn attributable(profile: &Value, case: &CascadeScenario) -> bool {
    if profile
        .pointer("/routing/script")
        .and_then(Value::as_str)
        .is_some_and(|v| !v.is_empty())
    {
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
        && rule.get("outboundTag").and_then(Value::as_str)
            == case.outbounds.first().map(String::as_str)
        && rule.as_object().is_some_and(|object| {
            object
                .keys()
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

/// HTTPS and the first selected outbound are separate evidence from hop traversal.
pub fn https(
    profile: &Value,
    case: &CascadeScenario,
    http_ok: Option<bool>,
    access: Option<&str>,
) -> Observation {
    if !attributable(profile, case) {
        return Observation::new(Status::Unknown, "cascade_route_not_attributable");
    }
    let (Some(http_ok), Some(access)) = (http_ok, access) else {
        return Observation::new(Status::Unknown, "cascade_https_unobserved");
    };
    match scenario::observed_outbound(&case.url, "proxy-signal-probe-in", access) {
        Ok(tag) if Some(tag) != case.outbounds.first().map(String::as_str) => {
            Observation::new(Status::Failed, "cascade_unexpected_outbound")
        }
        Ok(_) if !http_ok => Observation::new(Status::Failed, "cascade_https_failed"),
        Ok(_) => Observation::new(Status::Ok, "cascade_https_verified"),
        Err(_) => Observation::new(Status::Unknown, "cascade_route_unobserved"),
    }
}

/// Without trusted per-hop attestations, neither static links nor HTTPS prove
/// traversal. Xray's normal access log only records the selected first outbound.
pub fn hops() -> Observation {
    Observation::new(Status::Unknown, "cascade_hops_unverified")
}

pub fn overall(config: Observation, https: Observation, hops: Observation) -> Observation {
    if config.status != Status::Ok {
        return config;
    }
    if https.status == Status::Failed || hops.status == Status::Failed {
        Observation::new(Status::Failed, "cascade_connection_failed")
    } else if https.status == Status::Ok && hops.status == Status::Ok {
        Observation::new(Status::Ok, "cascade_verified")
    } else if https.status == Status::Degraded || hops.status == Status::Degraded {
        Observation::new(Status::Degraded, "cascade_partial_hops")
    } else {
        Observation::new(Status::Unknown, "cascade_incomplete_evidence")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn case() -> CascadeScenario {
        CascadeScenario {
            id: "two-hop".into(),
            url: "https://example.com/".into(),
            outbounds: vec!["entry".into(), "relay".into()],
        }
    }

    fn profile() -> Value {
        json!({
            "routing": {"rules": [{
                "type": "field",
                "domain": ["full:example.com"],
                "outboundTag": "entry"
            }]},
            "outbounds": [
                {"tag": "entry", "protocol": "socks",
                 "streamSettings": {"sockopt": {"dialerProxy": "relay"}}},
                {"tag": "relay", "protocol": "socks"}
            ]
        })
    }

    #[test]
    fn validates_order_and_rejects_missing_or_extra_links() {
        let case = case();
        let mut json = profile();
        assert_eq!(inspect(&json, &case).status, Status::Ok);
        json["outbounds"][0]["streamSettings"]["sockopt"]["dialerProxy"] = json!("missing");
        assert_eq!(inspect(&json, &case).code, "cascade_order_mismatch");
        json["outbounds"][0]["streamSettings"]["sockopt"]["dialerProxy"] = json!("relay");
        json["outbounds"][1]["streamSettings"] = json!({"sockopt": {"dialerProxy": "entry"}});
        assert_eq!(inspect(&json, &case).code, "cascade_order_mismatch");
        json["outbounds"][1]
            .as_object_mut()
            .unwrap()
            .remove("streamSettings");
        json["outbounds"][1]["tag"] = json!("wrong");
        assert_eq!(inspect(&json, &case).code, "cascade_outbound_missing");
    }

    #[test]
    fn legacy_proxy_settings_are_explicitly_unsupported() {
        let mut json = profile();
        json["outbounds"][0]
            .as_object_mut()
            .unwrap()
            .remove("streamSettings");
        json["outbounds"][0]["proxySettings"] = json!({"tag":"relay","transportLayer":true});
        assert_eq!(
            inspect(&json, &case()).code,
            "cascade_proxy_settings_removed"
        );
        json["outbounds"][0]["streamSettings"] = json!({"sockopt":{"dialerProxy":"relay"}});
        assert_eq!(inspect(&json, &case()).code, "cascade_conflicting_dialers");
    }

    #[test]
    fn no_https_or_first_outbound_log_proves_intermediate_hops() {
        let case = case();
        let json = profile();
        let log = "2026/01/01 from 127.0.0.1:1234 accepted //example.com:443 [proxy-signal-probe-in ==> entry]";
        assert_eq!(
            https(&json, &case, Some(true), Some(log)).status,
            Status::Ok
        );
        assert_eq!(hops().status, Status::Unknown);
        assert_eq!(
            overall(
                inspect(&json, &case),
                https(&json, &case, Some(true), Some(log)),
                hops()
            )
            .status,
            Status::Unknown
        );
        assert_eq!(
            https(&json, &case, Some(true), None).status,
            Status::Unknown
        );
        assert_eq!(
            https(&json, &case, Some(false), Some(log)).status,
            Status::Failed
        );
        assert_eq!(
            overall(
                inspect(&json, &case),
                https(&json, &case, Some(false), Some(log)),
                hops()
            )
            .status,
            Status::Failed
        );
        assert_eq!(
            https(
                &json,
                &case,
                Some(true),
                Some(&log.replace("==> entry", "==> relay"))
            )
            .status,
            Status::Failed
        );
        assert_eq!(https(&json, &case, None, Some(log)).status, Status::Unknown);
    }

    #[test]
    fn ambiguous_routing_cannot_be_reported_healthy() {
        let mut json = profile();
        json["routing"]["rules"][0]["domain"] = json!(["domain:example.com"]);
        assert_eq!(
            https(&json, &case(), Some(true), Some("")).status,
            Status::Unknown
        );
    }
}
