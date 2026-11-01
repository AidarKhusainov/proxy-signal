use crate::{config::{self, Endpoint}, source::read_limited};
use anyhow::{bail, Context, Result};
use reqwest::{Client, Proxy};
use std::{net::IpAddr, time::Duration};

pub async fn get_exit_ip(
    endpoint: &Endpoint,
    proxy: Option<&str>,
    timeout: Duration,
) -> Result<IpAddr> {
    let mut builder = Client::builder()
        .no_proxy() // Never honor HTTP_PROXY from the container environment.
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout);
    if let Some(proxy_url) = proxy {
        builder = builder.proxy(Proxy::all(proxy_url).context("proxy_invalid")?);
    } else {
        let (host, addrs) = config::public_resolution(&endpoint.url, timeout).await?;
        builder = builder.resolve_to_addrs(&host, &addrs);
    }
    let response = builder.build()?.get(&endpoint.url).send().await.context("probe_http")?;
    if response.status() != reqwest::StatusCode::OK {
        bail!("probe_http_status");
    }
    let body = read_limited(response, 64).await?;
    let text = std::str::from_utf8(&body).context("probe_body")?;
    let ip: IpAddr = text.trim().parse().context("probe_not_ip")?;
    if !config::is_public_ip(ip) { bail!("non_public_egress"); }
    Ok(ip)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetResult {
    Passed,
    Failed,
    Unknown,
}

pub fn compare(proxy: Result<IpAddr>, direct: Option<IpAddr>, allowed: &[IpAddr]) -> TargetResult {
    let Some(direct) = direct else { return TargetResult::Unknown; };
    let Ok(exit) = proxy else { return TargetResult::Failed; };
    if exit == direct || exit.is_ipv4() != direct.is_ipv4() {
        return TargetResult::Unknown; // No verified tunnel path.
    }
    if !allowed.is_empty() && !allowed.contains(&exit) {
        return TargetResult::Failed;
    }
    TargetResult::Passed
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn never_claims_direct_exit_as_vpn() {
        let ip = "192.0.2.1".parse().unwrap();
        assert_eq!(compare(Ok(ip), Some(ip), &[]), TargetResult::Unknown);
        assert_eq!(compare(Ok(ip), None, &[]), TargetResult::Unknown);
        assert_eq!(compare(Ok(ip), Some("192.0.2.2".parse().unwrap()), &[]), TargetResult::Passed);
        assert_eq!(compare(Ok(ip), Some("192.0.2.2".parse().unwrap()), &["192.0.2.3".parse().unwrap()]), TargetResult::Failed);
    }
}
