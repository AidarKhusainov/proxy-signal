use anyhow::{bail, Context, Result};
use reqwest::Url;
use serde::Deserialize;
use std::{
    collections::HashSet,
    io::Read,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u8,
    pub interval_seconds: u64,
    pub timeout_seconds: u64,
    pub parallelism: usize,
    pub state_file: PathBuf,
    pub endpoints: Vec<Endpoint>,
    pub sources: Vec<Source>,
    pub telegram: Option<Telegram>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub id: String,
    pub url: String,
    pub route: ExpectedRoute,
    pub outbound_tag: String,
    #[serde(default)]
    pub dns: Option<DnsExpectation>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BalancerScenario {
    pub id: String,
    pub url: String,
    pub balancer_tag: String,
    pub strategy: BalancerStrategy,
    pub candidates: Vec<String>,
    #[serde(default)]
    pub fallback_tag: Option<String>,
}

/// Order is the selected outbound first, followed by every proxy dialer until
/// the final outbound. Each adjacent pair must be linked in the Xray JSON.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CascadeScenario {
    pub id: String,
    pub url: String,
    pub outbounds: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BalancerStrategy {
    LeastPing,
    LeastLoad,
    Random,
    RoundRobin,
}

impl BalancerStrategy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LeastPing => "leastPing",
            Self::LeastLoad => "leastLoad",
            Self::Random => "random",
            Self::RoundRobin => "roundRobin",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedRoute {
    Direct,
    Proxy,
    Block,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsExpectation {
    /// Literal Xray upstream identifier from its DNS diagnostic log.
    pub server: String,
    pub expected_ips: Vec<IpAddr>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub id: String,
    pub url: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Source {
    File {
        id: String,
        path: PathBuf,
        #[serde(default)]
        expected_exit_ips: Vec<IpAddr>,
        #[serde(default)]
        scenarios: Vec<Scenario>,
        #[serde(default)]
        balancers: Vec<BalancerScenario>,
        #[serde(default)]
        cascades: Vec<CascadeScenario>,
    },
    Https {
        id: String,
        url: String,
        #[serde(default)]
        headers: std::collections::BTreeMap<String, PathBuf>,
        #[serde(default)]
        expected_exit_ips: Vec<IpAddr>,
        #[serde(default)]
        scenarios: Vec<Scenario>,
        #[serde(default)]
        balancers: Vec<BalancerScenario>,
        #[serde(default)]
        cascades: Vec<CascadeScenario>,
    },
}

impl Source {
    pub fn id(&self) -> &str {
        match self {
            Self::File { id, .. } | Self::Https { id, .. } => id,
        }
    }
    pub fn scenarios(&self) -> &[Scenario] {
        match self {
            Self::File { scenarios, .. } | Self::Https { scenarios, .. } => scenarios,
        }
    }
    pub fn balancers(&self) -> &[BalancerScenario] {
        match self {
            Self::File { balancers, .. } | Self::Https { balancers, .. } => balancers,
        }
    }
    pub fn cascades(&self) -> &[CascadeScenario] {
        match self {
            Self::File { cascades, .. } | Self::Https { cascades, .. } => cascades,
        }
    }
    pub fn expected_exit_ips(&self) -> &[IpAddr] {
        match self {
            Self::File {
                expected_exit_ips, ..
            }
            | Self::Https {
                expected_exit_ips, ..
            } => expected_exit_ips,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Telegram {
    pub bot_token_file: PathBuf,
    pub chat_id: String,
}

pub fn load(path: &str) -> Result<Config> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .context("read config")?
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .context("read config")?;
    if bytes.len() > 64 * 1024 {
        bail!("config too large");
    }
    let config: Config = serde_yaml::from_slice(&bytes).context("parse config")?;
    config.validate()?;
    Ok(config)
}

impl Config {
    fn validate(&self) -> Result<()> {
        if self.version != 1
            || !(30..=86_400).contains(&self.interval_seconds)
            || !(5..=60).contains(&self.timeout_seconds)
            || !(1..=4).contains(&self.parallelism)
            || !(1..=3).contains(&self.endpoints.len())
            || !(1..=32).contains(&self.sources.len())
        {
            bail!("unsupported version or out-of-range limits");
        }
        let mut ids = HashSet::new();
        for endpoint in &self.endpoints {
            if !valid_id(&endpoint.id) || !ids.insert(endpoint.id.as_str()) {
                bail!("invalid or duplicated endpoint id");
            }
            validate_https(&endpoint.url)?;
        }
        ids.clear();
        let mut total_scenarios = 0;
        let mut total_balancers = 0;
        let mut total_cascades = 0;
        for source in &self.sources {
            if !valid_id(source.id()) || !ids.insert(source.id()) {
                bail!("invalid or duplicated source id");
            }
            if let Source::Https { url, headers, .. } = source {
                validate_https(url)?;
                if headers.len() > 8 {
                    bail!("too many authorization headers");
                }
                for name in headers.keys() {
                    reqwest::header::HeaderName::from_bytes(name.as_bytes())
                        .context("invalid header name")?;
                }
            }
            total_scenarios += source.scenarios().len();
            if source.scenarios().len() > 8 || total_scenarios > 64 {
                bail!("too many scenarios");
            }
            total_balancers += source.balancers().len();
            if source.balancers().len() > 4 || total_balancers > 8 {
                bail!("too many balancer scenarios");
            }
            let mut scenario_ids = HashSet::new();
            let mut destinations = HashSet::new();
            for case in source.scenarios() {
                if !valid_id(&case.id) || !scenario_ids.insert(case.id.as_str()) {
                    bail!("invalid or duplicate scenario id");
                }
                let url = validate_https(&case.url)?;
                let destination = (
                    url.host_str().unwrap_or("").to_owned(),
                    url.port_or_known_default(),
                );
                if !destinations.insert(destination.clone()) {
                    bail!("duplicate scenario destination");
                }
                if self.endpoints.iter().any(|e| {
                    let Ok(endpoint_url) = validate_https(&e.url) else {
                        return false;
                    };
                    (
                        endpoint_url.host_str().unwrap_or("").to_owned(),
                        endpoint_url.port_or_known_default(),
                    ) == destination
                }) {
                    bail!("scenario destination overlaps egress endpoint");
                }
                if !valid_tag(&case.outbound_tag) {
                    bail!("invalid scenario outbound tag");
                }
                if let Some(dns) = &case.dns {
                    if dns.server.is_empty()
                        || dns.server.len() > 120
                        || !dns.server.bytes().all(|b| b.is_ascii_graphic())
                        || dns.expected_ips.is_empty()
                        || dns.expected_ips.len() > 16
                    {
                        bail!("invalid DNS expectation");
                    }
                }
            }
            let mut distinct_candidates = HashSet::new();
            for case in source.balancers() {
                if !valid_id(&case.id) || !scenario_ids.insert(case.id.as_str()) {
                    bail!("invalid or duplicate balancer scenario id");
                }
                let url = validate_https(&case.url)?;
                let destination = (
                    url.host_str().unwrap_or("").to_owned(),
                    url.port_or_known_default(),
                );
                if !destinations.insert(destination.clone()) {
                    bail!("duplicate scenario destination");
                }
                if self.endpoints.iter().any(|e| {
                    let Ok(endpoint_url) = validate_https(&e.url) else {
                        return false;
                    };
                    (
                        endpoint_url.host_str().unwrap_or("").to_owned(),
                        endpoint_url.port_or_known_default(),
                    ) == destination
                }) {
                    bail!("balancer destination overlaps egress endpoint");
                }
                if !valid_tag(&case.balancer_tag)
                    || case.candidates.is_empty()
                    || case.candidates.len() > 8
                    || case.candidates.iter().any(|tag| !valid_tag(tag))
                    || case
                        .fallback_tag
                        .as_ref()
                        .is_some_and(|tag| !valid_tag(tag))
                    || case.fallback_tag.as_ref() == Some(&case.balancer_tag)
                {
                    bail!("invalid balancer expectation");
                }
                let mut unique = HashSet::new();
                for tag in &case.candidates {
                    if !unique.insert(tag) {
                        bail!("duplicate balancer candidate");
                    }
                    distinct_candidates.insert(tag.as_str());
                }
            }
            total_cascades += source.cascades().len();
            if source.cascades().len() > 4 || total_cascades > 8 {
                bail!("too many cascade scenarios");
            }
            for case in source.cascades() {
                if !valid_id(&case.id) || !scenario_ids.insert(case.id.as_str()) {
                    bail!("invalid or duplicate cascade scenario id");
                }
                let url = validate_https(&case.url)?;
                let destination = (
                    url.host_str().unwrap_or("").to_owned(),
                    url.port_or_known_default(),
                );
                if !destinations.insert(destination.clone()) {
                    bail!("duplicate scenario destination");
                }
                if self.endpoints.iter().any(|e| {
                    let Ok(endpoint_url) = validate_https(&e.url) else {
                        return false;
                    };
                    (
                        endpoint_url.host_str().unwrap_or("").to_owned(),
                        endpoint_url.port_or_known_default(),
                    ) == destination
                }) {
                    bail!("cascade destination overlaps egress endpoint");
                }
                if case.outbounds.len() < 2
                    || case.outbounds.len() > 8
                    || case.outbounds.iter().any(|tag| !valid_tag(tag))
                    || case.outbounds.iter().collect::<HashSet<_>>().len() != case.outbounds.len()
                {
                    bail!("invalid cascade expectation");
                }
            }
            if distinct_candidates.len() > 8 {
                bail!("too many distinct balancer candidates");
            }
            if source.expected_exit_ips().len() > 16
                || source
                    .expected_exit_ips()
                    .iter()
                    .any(|ip| !is_public_ip(*ip))
            {
                bail!("too many expected exit IPs");
            }
        }
        if self.state_file.as_os_str().is_empty() {
            bail!("state_file is required");
        }
        if let Some(tg) = &self.telegram {
            if tg.chat_id.is_empty()
                || tg.chat_id.len() > 80
                || !tg.chat_id.bytes().all(|b| b.is_ascii_digit() || b == b'-')
            {
                bail!("invalid Telegram chat ID");
            }
        }
        Ok(())
    }
}

pub fn validate_https(s: &str) -> Result<Url> {
    let url = Url::parse(s).context("invalid HTTPS URL")?;
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        bail!("only HTTPS URLs without embedded credentials are supported");
    }
    // Only operator-configured hostnames, never loopback/metadata IP literals.
    let host = url.host_str().context("missing hostname")?;
    if host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.starts_with('[')
        || host.parse::<IpAddr>().is_ok()
    {
        bail!("URL must use a public DNS hostname");
    }
    Ok(url)
}

/// Resolve and pin direct connections so DNS rebinding cannot point native
/// HTTP requests (including requests with auth headers) at internal services.
pub async fn public_resolution(url: &str, budget: Duration) -> Result<(String, Vec<SocketAddr>)> {
    let parsed = validate_https(url)?;
    let host = parsed.host_str().context("missing hostname")?.to_owned();
    let port = parsed.port_or_known_default().context("missing port")?;
    let addresses: Vec<_> =
        tokio::time::timeout(budget, tokio::net::lookup_host((host.as_str(), port)))
            .await
            .context("dns_timeout")??
            .collect();
    if addresses.is_empty() || addresses.iter().any(|addr| !is_public_ip(addr.ip())) {
        bail!("non_public_http_destination");
    }
    Ok((host, addresses))
}

pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_broadcast()
                || ip.is_unspecified()
                || ip.is_documentation()
                || a == 0
                || a >= 224
                || a == 100 && (64..=127).contains(&b)
                || a == 192 && b == 0 && c == 0
                || a == 192 && b == 88 && c == 99
                || a == 198 && (b == 18 || b == 19))
        }
        IpAddr::V6(ip) => {
            // Conservative global-unicast check; reject documentation ranges.
            (ip.segments()[0] & 0xe000) == 0x2000
                && !(ip.segments()[0] == 0x2001 && ip.segments()[1] == 0x0db8)
        }
    }
}

fn valid_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 96
        && tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./:".contains(&b))
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_private_or_non_https_targets() {
        assert!(validate_https("http://example.com/").is_err());
        assert!(validate_https("https://127.0.0.1/").is_err());
        assert!(validate_https("https://169.254.169.254/").is_err());
        assert!(validate_https("https://user:secret@example.com/").is_err());
        assert!(validate_https("https://example.com/ip").is_ok());
        for ip in ["198.18.0.1", "192.0.0.4", "2001:db8::1", "fc00::1"] {
            assert!(!is_public_ip(ip.parse().unwrap()));
        }
        for ip in ["1.1.1.1", "2606:4700:4700::1111"] {
            assert!(is_public_ip(ip.parse().unwrap()));
        }
    }

    #[test]
    fn scenario_configuration_is_optional_and_strict() {
        let yaml = "kind: file\nid: node\npath: /tmp/profile.json\n";
        let old: Source = serde_yaml::from_str(yaml).unwrap();
        assert!(old.scenarios().is_empty());
        assert!(old.balancers().is_empty());
        assert!(old.cascades().is_empty());
        let example = "kind: file\nid: node\npath: /tmp/profile.json\nscenarios:\n  - id: dns-direct\n    url: https://example.org/\n    route: direct\n    outbound_tag: direct\n    dns:\n      server: UDP:1.1.1.1:53\n      expected_ips: [93.184.215.14]\n";
        let new: Source = serde_yaml::from_str(example).unwrap();
        assert_eq!(new.scenarios().len(), 1);
        assert!(serde_yaml::from_str::<Source>(
            &example.replace("route: direct", "route: invented")
        )
        .is_err());
    }

    #[test]
    fn optional_balancer_scenarios_parse_strictly() {
        let sample = "kind: file\nid: node\npath: /tmp/profile.json\nbalancers:\n  - id: preferred\n    url: https://example.com/\n    balancer_tag: pool\n    strategy: leastPing\n    candidates: [node-a, node-b]\n";
        let source: Source = serde_yaml::from_str(sample).unwrap();
        assert_eq!(source.balancers().len(), 1);
        assert!(serde_yaml::from_str::<Source>(&sample.replace("leastPing", "fastest")).is_err());
        assert!(serde_yaml::from_str::<Source>(&sample.replace("node-b", "node-a")).is_ok());
    }

    #[test]
    fn cascade_config_is_optional_and_rejects_unknown_fields() {
        let yaml = "kind: file\nid: node\npath: /tmp/profile.json\ncascades:\n  - id: two-hops\n    url: https://example.com/\n    outbounds: [entry, relay]\n";
        let source: Source = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(source.cascades().len(), 1);
        assert!(
            serde_yaml::from_str::<Source>(&yaml.replace("    outbounds:", "    hops:")).is_err()
        );
    }

    #[test]
    fn rejects_unknown_yaml_options() {
        let yaml = "version: 1\ninterval_seconds: 300\ntimeout_seconds: 15\nparallelism: 1\nstate_file: /tmp/state\nendpoints: []\nsources: []\nsecret: plaintext\n";
        assert!(serde_yaml::from_str::<Config>(yaml).is_err());
    }
}
