use crate::config::{self, Source};
use anyhow::{bail, Context, Result};
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    Client,
};
use serde_json::Value;
use std::{fs::File, io::Read, time::Duration};

const MAX_PROFILE: usize = 512 * 1024;

pub async fn load(source: &Source, timeout: Duration) -> Result<Value> {
    let bytes = match source {
        Source::File { path, .. } => {
            let mut buf = Vec::new();
            File::open(path)
                .context("source_read")?
                .take((MAX_PROFILE + 1) as u64)
                .read_to_end(&mut buf)
                .context("source_read")?;
            buf
        }
        Source::Https { url, headers, .. } => {
            let mut request_headers = HeaderMap::new();
            for (name, path) in headers {
                let mut secret = Vec::new();
                File::open(path)
                    .context("secret_read")?
                    .take(2049)
                    .read_to_end(&mut secret)
                    .context("secret_read")?;
                let secret = std::str::from_utf8(&secret).context("secret_invalid")?;
                let value = secret.trim_end_matches(|c| c == '\r' || c == '\n');
                if value.is_empty()
                    || value.len() > 2048
                    || value.bytes().any(|b| b == b'\r' || b == b'\n')
                {
                    bail!("secret_invalid");
                }
                request_headers.insert(
                    HeaderName::from_bytes(name.as_bytes()).context("header_invalid")?,
                    HeaderValue::from_str(value).context("header_invalid")?,
                );
            }
            let (host, addrs) = config::public_resolution(url, timeout).await?;
            let client = Client::builder()
                .resolve_to_addrs(&host, &addrs)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(timeout)
                .build()?;
            let response = client
                .get(url)
                .headers(request_headers)
                .send()
                .await
                .context("source_http")?;
            if !response.status().is_success() {
                bail!("source_http_status");
            }
            read_limited(response, MAX_PROFILE).await?
        }
    };
    if bytes.len() > MAX_PROFILE {
        bail!("source_oversize");
    }
    serde_json::from_slice(&bytes).context("source_json")
}

pub async fn read_limited(mut response: reqwest::Response, max: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.context("response_read")? {
        if bytes.len() + chunk.len() > max {
            bail!("response_oversize");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[tokio::test]
    async fn rejects_oversize_and_malformed_local_profiles() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profile.json");
        let source = Source::File {
            id: "test".to_string(),
            path: path.clone(),
            expected_exit_ips: Vec::<IpAddr>::new(),
        };
        std::fs::write(&path, vec![b' '; MAX_PROFILE + 1]).unwrap();
        assert!(load(&source, Duration::from_secs(5)).await.is_err());
        std::fs::write(&path, b"{not-json").unwrap();
        assert!(load(&source, Duration::from_secs(5)).await.is_err());
        std::fs::write(&path, br#"{"outbounds":[{"protocol":"vless"}]}"#).unwrap();
        assert!(load(&source, Duration::from_secs(5)).await.is_ok());
    }
}
