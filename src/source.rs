use crate::config::{self, Source};
use anyhow::{bail, Context, Result};
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    Client,
};
use serde_json::Value;
use std::{collections::BTreeMap, fs::File, io::Read, path::PathBuf, time::Duration};

const MAX_PROFILE: usize = 512 * 1024;
const MAX_SUBSCRIPTION: usize = 2 * 1024 * 1024;
const MAX_ARRAY_ITEMS: usize = 32;

pub struct SelectedProfile {
    pub source: Source,
    pub document: Option<Value>,
    pub unavailable_code: &'static str,
}

/// Matching never depends on array index. Missing, malformed and ambiguous
/// entries cannot inherit a previous successful check for another profile.
pub fn select(source: &Source, document: Value) -> Result<Vec<SelectedProfile>> {
    let entries = source.expanded();
    if source.profiles().is_empty() {
        if !document.is_object() {
            bail!("source_object_required");
        }
        return Ok(vec![SelectedProfile {
            source: entries.into_iter().next().expect("single source"),
            document: Some(document),
            unavailable_code: "profile_unavailable",
        }]);
    }
    let array = document.as_array().context("source_array_required")?;
    if array.len() > MAX_ARRAY_ITEMS {
        bail!("source_array_too_large");
    }
    Ok(source
        .profiles()
        .iter()
        .zip(entries)
        .map(|(spec, entry)| {
            let mut matching = array.iter().filter(|item| {
                item.get("remarks").and_then(Value::as_str) == Some(spec.remarks.as_str())
            });
            let first = matching.next();
            let duplicate = matching.next().is_some();
            let valid = first.is_some_and(|value| {
                value.is_object()
                    && value
                        .get("outbounds")
                        .and_then(Value::as_array)
                        .is_some_and(|outbounds| !outbounds.is_empty())
            });
            SelectedProfile {
                source: entry,
                document: if valid && !duplicate {
                    first.cloned()
                } else {
                    None
                },
                unavailable_code: if duplicate {
                    "profile_duplicate"
                } else if first.is_none() {
                    "profile_missing"
                } else {
                    "profile_invalid"
                },
            }
        })
        .collect())
}

pub async fn load(source: &Source, timeout: Duration) -> Result<Value> {
    let max_bytes = if source.profiles().is_empty() {
        MAX_PROFILE
    } else {
        MAX_SUBSCRIPTION
    };
    let bytes = match source {
        Source::File { path, .. } => {
            let mut buf = Vec::new();
            File::open(path)
                .context("source_read")?
                .take((max_bytes + 1) as u64)
                .read_to_end(&mut buf)
                .context("source_read")?;
            buf
        }
        Source::Https { url, headers, .. } => {
            let request_headers = read_headers(headers)?;
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
            read_limited(response, max_bytes).await?
        }
    };
    if bytes.len() > max_bytes {
        bail!("source_oversize");
    }
    serde_json::from_slice(&bytes).context("source_json")
}

fn read_headers(headers: &BTreeMap<String, PathBuf>) -> Result<HeaderMap> {
    let mut request_headers = HeaderMap::new();
    for (name, path) in headers {
        let mut secret = Vec::new();
        File::open(path)
            .context("secret_read")?
            .take(2049)
            .read_to_end(&mut secret)
            .context("secret_read")?;
        let secret = std::str::from_utf8(&secret).context("secret_invalid")?;
        let value = secret.trim_end_matches(['\r', '\n']);
        if value.is_empty() || value.len() > 2048 || value.bytes().any(|b| b == b'\r' || b == b'\n')
        {
            bail!("secret_invalid");
        }
        request_headers.insert(
            HeaderName::from_bytes(name.as_bytes()).context("header_invalid")?,
            HeaderValue::from_str(value).context("header_invalid")?,
        );
    }

    Ok(request_headers)
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

    #[test]
    fn loads_authorization_and_hwid_headers_from_files_without_mutating_them() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        std::fs::write(&path, "test-device-value\n").unwrap();
        let headers = BTreeMap::from([
            ("X-HWID".to_string(), path.clone()),
            ("User-Agent".to_string(), path.clone()),
            ("Accept".to_string(), path.clone()),
        ]);
        let values = read_headers(&headers).unwrap();
        assert_eq!(values.get("X-HWID").unwrap(), "test-device-value");
        assert_eq!(values.get("User-Agent").unwrap(), "test-device-value");
        assert_eq!(values.get("Accept").unwrap(), "test-device-value");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "test-device-value\n"
        );
        std::fs::write(&path, "bad\nvalue").unwrap();
        assert!(read_headers(&headers).is_err());
    }

    #[test]
    fn select_full_documents_by_explicit_remarks_in_any_order() {
        let source: Source = serde_yaml::from_str("kind: https\nid: happ\nurl: https://example.org/sub\nprofiles:\n  - { id: sweden, remarks: Sweden }\n  - { id: germany, remarks: Germany }\n").unwrap();
        let original = serde_json::json!({"remarks":"Sweden","inbounds":[{"sniffing":{"enabled":true}}],"dns":{"servers":["1.1.1.1"]},"routing":{"rules":[]},"outbounds":[{"protocol":"vless"}],"observatory":{"subjectSelector":["a"]}});
        let other = serde_json::json!({"remarks":"Germany","outbounds":[{"protocol":"vless"}]});
        for array in [
            vec![original.clone(), other.clone()],
            vec![other.clone(), original.clone()],
        ] {
            let entries = select(&source, Value::Array(array)).unwrap();
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[0].source.id(), "happ/sweden");
            assert_eq!(entries[1].source.id(), "happ/germany");
            assert_eq!(entries[0].document, Some(original.clone()));
            assert_eq!(entries[1].document, Some(other.clone()));
        }
    }

    #[test]
    fn missing_duplicate_and_invalid_entries_never_become_ok() {
        let source: Source = serde_yaml::from_str("kind: https\nid: happ\nurl: https://example.org/sub\nprofiles:\n  - { id: first, remarks: A }\n  - { id: second, remarks: B }\n").unwrap();
        let a = serde_json::json!({"remarks":"A","outbounds":[{"protocol":"vless"}]});
        let entries = select(&source, serde_json::json!([a.clone()])).unwrap();
        assert!(entries[0].document.is_some());
        assert_eq!(entries[1].unavailable_code, "profile_missing");
        assert!(entries[1].document.is_none());
        let entries = select(&source, serde_json::json!([a.clone(), a])).unwrap();
        assert_eq!(entries[0].unavailable_code, "profile_duplicate");
        assert!(entries[0].document.is_none());
        let entries = select(&source, serde_json::json!([{"remarks":"A","outbounds":[]}, {"remarks":"B","outbounds":[{"protocol":"vless"}]}])).unwrap();
        assert_eq!(entries[0].unavailable_code, "profile_invalid");
        assert!(entries[0].document.is_none());
        assert!(entries[1].document.is_some());
        assert!(select(&source, serde_json::json!({"outbounds":[]})).is_err());
    }

    #[test]
    fn legacy_single_object_remains_supported() {
        let source: Source =
            serde_yaml::from_str("kind: file\nid: original\npath: /tmp/profile.json\n").unwrap();
        let document = serde_json::json!({"outbounds":[{"protocol":"vless"}]});
        let entries = select(&source, document.clone()).unwrap();
        assert_eq!(entries[0].source.id(), "original");
        assert_eq!(entries[0].document, Some(document));
        assert!(select(&source, serde_json::json!([])).is_err());
    }

    #[tokio::test]
    async fn rejects_oversize_and_malformed_local_profiles() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profile.json");
        let source = Source::File {
            id: "test".to_string(),
            path: path.clone(),
            expected_exit_ips: Vec::<IpAddr>::new(),
            scenarios: Vec::new(),
            balancers: Vec::new(),
            cascades: Vec::new(),
            cdn: Vec::new(),
            failover: Vec::new(),
        };
        std::fs::write(&path, vec![b' '; MAX_PROFILE + 1]).unwrap();
        assert!(load(&source, Duration::from_secs(5)).await.is_err());
        std::fs::write(&path, b"{not-json").unwrap();
        assert!(load(&source, Duration::from_secs(5)).await.is_err());
        std::fs::write(&path, br#"{"outbounds":[{"protocol":"vless"}]}"#).unwrap();
        assert!(load(&source, Duration::from_secs(5)).await.is_ok());
    }
}
