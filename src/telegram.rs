use crate::{
    config::Telegram,
    incident::{Notice, State, Status},
    source::read_limited,
};
use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde_json::Value;
use std::{fs::File, io::Read, path::Path, time::Duration};

pub struct Sender {
    client: Client,
    url: String,
    chat_id: String,
}

impl Sender {
    pub fn new(config: &Telegram) -> Result<Self> {
        let mut bytes = Vec::new();
        File::open(&config.bot_token_file)
            .context("telegram_secret_read")?
            .take(201)
            .read_to_end(&mut bytes)
            .context("telegram_secret_read")?;
        let token = std::str::from_utf8(&bytes)
            .context("telegram_secret_invalid")?
            .trim();
        if token.is_empty()
            || token.len() > 200
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b':' || b == b'_' || b == b'-')
        {
            bail!("telegram_secret_invalid");
        }
        // Never inherit host proxy environment, and never fall back to a
        // direct Telegram connection when the configured SOCKS proxy fails.
        let mut client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(8));
        if let Some(proxy_url) = &config.proxy_url {
            client =
                client.proxy(reqwest::Proxy::all(proxy_url).context("telegram_proxy_invalid")?);
        }
        Ok(Self {
            client: client.build()?,
            url: format!("https://api.telegram.org/bot{token}/sendMessage"),
            chat_id: config.chat_id.clone(),
        })
    }

    pub async fn deliver_pending(&self, state: &mut State, path: &Path) -> Result<()> {
        for _ in 0..4 {
            let Some(notice) = state.pending.first().cloned() else {
                break;
            };
            if self.send(&notice).await.is_err() {
                eprintln!("ProxySignal: telegram_delivery_failed");
                break;
            }
            // No await between acknowledgement and persistence: cancellation
            // cannot interleave with this write. A process crash still can.
            state.pending.remove(0);
            state.persist(path)?;
        }
        Ok(())
    }

    pub async fn send(&self, notice: &Notice) -> Result<()> {
        let message = if notice.key.starts_with("coverage/") {
            match notice.status {
                Status::Ok => "Покрытие мониторинга восстановлено: OK",
                Status::Failed => "Недоступны обязательные проверки: FAILED",
                Status::Degraded => "Часть проверок недоступна: DEGRADED",
                Status::Unknown => "Достоверность мониторинга не подтверждена: UNKNOWN",
                Status::Unsupported => return Ok(()),
            }
        } else {
            match notice.status {
                Status::Ok => "Восстановлено: OK",
                Status::Failed => "Подтверждённый сбой: FAILED",
                Status::Degraded => "Частичная доступность: DEGRADED",
                Status::Unknown => {
                    "Сбой устранён; полная работоспособность не подтверждена: UNKNOWN"
                }
                Status::Unsupported => return Ok(()),
            }
        };
        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": format!("ProxySignal · {message}\n{}\nВремя (Unix): {}", notice.key, notice.when),
            "disable_web_page_preview": true,
        });
        let response = self
            .client
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .context("telegram_http")?;
        if !response.status().is_success() {
            bail!("telegram_http_status");
        }
        let bytes = read_limited(response, 32 * 1024).await?;
        let value: Value = serde_json::from_slice(&bytes).context("telegram_response_invalid")?;
        if value.get("ok") != Some(&Value::Bool(true)) {
            bail!("telegram_not_accepted");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::incident::{Observation, State};
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
        time::Instant,
    };

    fn local_sender(responses: Vec<(u16, String)>) -> (Sender, thread::JoinHandle<Vec<Value>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = thread::spawn(move || {
            let mut requests = Vec::new();
            for (status, response) in responses {
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                Instant::now() < deadline,
                                "local Telegram request timed out"
                            );
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("local Telegram accept failed: {error}"),
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = Vec::new();
                let mut body_bounds = None;
                loop {
                    let mut buffer = [0; 4096];
                    let read = stream.read(&mut buffer).unwrap();
                    assert!(read > 0, "incomplete local Telegram request");
                    request.extend_from_slice(&buffer[..read]);
                    assert!(request.len() <= 64 * 1024);
                    if body_bounds.is_none() {
                        if let Some(end) = request.windows(4).position(|v| v == b"\r\n\r\n") {
                            let headers = std::str::from_utf8(&request[..end]).unwrap();
                            let length = headers
                                .lines()
                                .filter_map(|line| line.split_once(':'))
                                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                                .unwrap()
                                .1
                                .trim()
                                .parse::<usize>()
                                .unwrap();
                            body_bounds = Some((end + 4, end + 4 + length));
                        }
                    }
                    if let Some((start, end)) = body_bounds {
                        if request.len() >= end {
                            requests.push(serde_json::from_slice(&request[start..end]).unwrap());
                            break;
                        }
                    }
                }
                let response = format!(
                    "HTTP/1.1 {status} Mock\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{response}",
                    response.len()
                );
                // Clients may stop reading after an oversized or rejected reply.
                let _ = stream.write_all(response.as_bytes());
            }
            requests
        });
        let sender = Sender {
            client: Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap(),
            url: format!("http://{address}/sendMessage"),
            chat_id: "-1".to_string(),
        };
        (sender, server)
    }

    fn outage_and_recovery() -> State {
        let mut state = State::default();
        for _ in 0..2 {
            state.observe("profile/a", Observation::new(Status::Failed, "tls"), true);
        }
        state.observe(
            "profile/a",
            Observation::new(Status::Ok, "egress_verified"),
            true,
        );
        assert_eq!(state.pending.len(), 2);
        state
    }

    #[tokio::test]
    async fn telegram_socks5h_uses_remote_dns_and_has_no_direct_fallback() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_address = listener.local_addr().unwrap();
        let proxy = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&[5, 0]).unwrap();
            let mut request = [0; 5];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request[..4], &[5, 1, 0, 3]);
            let mut address = vec![0; usize::from(request[4]) + 2];
            stream.read_exact(&mut address).unwrap();
            assert_eq!(
                &address[..address.len() - 2],
                b"api.telegram.org",
                "DNS must be handled by SOCKS, not by Hostland"
            );
            // Simulate the proxy being unable to establish the destination.
            stream.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
        });
        let dir = tempfile::tempdir().unwrap();
        let token_file = dir.path().join("token");
        std::fs::write(&token_file, "123:abc").unwrap();
        let sender = Sender::new(&Telegram {
            bot_token_file: token_file,
            chat_id: "-1".to_owned(),
            proxy_url: Some(format!("socks5h://{proxy_address}")),
        })
        .unwrap();
        assert!(sender
            .send(&Notice {
                key: "profile/test".to_owned(),
                status: Status::Failed,
                when: 123,
            })
            .await
            .is_err());
        proxy.join().unwrap();
    }

    #[tokio::test]
    async fn required_coverage_loss_message_does_not_claim_vpn_is_down() {
        let (sender, server) = local_sender(vec![(200, r#"{"ok":true}"#.to_string())]);
        sender
            .send(&Notice {
                key: "coverage/happ".to_owned(),
                status: Status::Failed,
                when: 123,
            })
            .await
            .unwrap();
        let messages = server.join().unwrap();
        let text = messages[0]["text"].as_str().unwrap();
        assert!(text.contains("Недоступны обязательные проверки: FAILED"));
        assert!(text.contains("coverage/happ"));
        assert!(!text.contains("Подтверждённый сбой"));
    }

    #[tokio::test]
    async fn delivery_retries_in_order_and_acknowledgements_survive_restart() {
        for failing_index in [0, 1] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("state.json");
            let mut state = outage_and_recovery();
            state.persist(&path).unwrap();
            let mut replies = vec![(200, r#"{"ok":true}"#.to_string()); 3];
            replies[failing_index] = (503, r#"{"ok":false}"#.to_string());
            let (sender, server) = local_sender(replies);
            sender.deliver_pending(&mut state, &path).await.unwrap();
            let mut restarted = State::load(&path).unwrap();
            assert_eq!(restarted.pending.len(), 2 - failing_index);
            assert_eq!(
                restarted.pending[0].status,
                if failing_index == 0 {
                    Status::Failed
                } else {
                    Status::Ok
                }
            );
            sender.deliver_pending(&mut restarted, &path).await.unwrap();
            let mut acknowledged = State::load(&path).unwrap();
            assert!(acknowledged.pending.is_empty());
            sender
                .deliver_pending(&mut acknowledged, &path)
                .await
                .unwrap();
            let requests = server.join().unwrap();
            assert_eq!(requests.len(), 3);
            let expected = if failing_index == 0 {
                ["FAILED", "FAILED", "OK"]
            } else {
                ["FAILED", "OK", "OK"]
            };
            for (request, status) in requests.iter().zip(expected) {
                assert_eq!(request["chat_id"], "-1");
                let text = request["text"].as_str().unwrap();
                assert!(text.contains(status));
                assert!(text.contains("profile/a"));
            }
        }
    }

    #[tokio::test]
    async fn rejected_or_malformed_telegram_replies_leave_the_notice_durable() {
        for response in [
            (200, r#"{"ok":false,"description":"rejected"}"#.to_string()),
            (200, r#"{"ok":"true"}"#.to_string()),
            (200, "not-json".to_string()),
            (
                429,
                r#"{"ok":false,"parameters":{"retry_after":1}}"#.to_string(),
            ),
            (200, " ".repeat(32 * 1024 + 1)),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("state.json");
            let mut state = outage_and_recovery();
            state.persist(&path).unwrap();
            let (sender, server) = local_sender(vec![response]);
            sender.deliver_pending(&mut state, &path).await.unwrap();
            let restarted = State::load(&path).unwrap();
            assert_eq!(restarted.pending.len(), 2);
            assert_eq!(restarted.pending[0].status, Status::Failed);
            assert_eq!(restarted.pending[1].status, Status::Ok);
            assert_eq!(server.join().unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn a_delivery_batch_is_bounded_and_persists_each_acknowledgement() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut state = State::default();
        for key in ["profile/a", "profile/b", "profile/c"] {
            for _ in 0..2 {
                state.observe(key, Observation::new(Status::Failed, "tls"), true);
            }
            state.observe(key, Observation::new(Status::Ok, "egress_verified"), true);
        }
        state.persist(&path).unwrap();
        let (sender, server) = local_sender(vec![(200, r#"{"ok":true}"#.to_string()); 6]);
        sender.deliver_pending(&mut state, &path).await.unwrap();
        let mut restarted = State::load(&path).unwrap();
        assert_eq!(restarted.pending.len(), 2);
        assert_eq!(restarted.pending[0].key, "profile/c");
        assert_eq!(restarted.pending[0].status, Status::Failed);
        sender.deliver_pending(&mut restarted, &path).await.unwrap();
        assert!(State::load(&path).unwrap().pending.is_empty());
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 6);
        for (request, key) in requests.iter().zip([
            "profile/a",
            "profile/a",
            "profile/b",
            "profile/b",
            "profile/c",
            "profile/c",
        ]) {
            assert!(request["text"].as_str().unwrap().contains(key));
        }
    }

    #[tokio::test]
    async fn acknowledgement_storage_failure_stops_further_delivery() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut state = outage_and_recovery();
        state.persist(&path).unwrap();
        let (sender, server) = local_sender(vec![(200, r#"{"ok":true}"#.to_string())]);
        let missing_parent = dir.path().join("missing/state.json");
        assert!(sender
            .deliver_pending(&mut state, &missing_parent)
            .await
            .is_err());
        assert_eq!(server.join().unwrap().len(), 1);
        // An accepted send whose acknowledgement could not be stored may be
        // retried after restart: Telegram offers no idempotency key here.
        let restarted = State::load(&path).unwrap();
        assert_eq!(restarted.pending.len(), 2);
        assert_eq!(restarted.pending[0].status, Status::Failed);
    }

    #[tokio::test]
    async fn stalled_telegram_connection_times_out_without_losing_pending_notices() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut state = outage_and_recovery();
        state.persist(&path).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let sender = Sender {
            client: Client::builder()
                .no_proxy()
                .timeout(Duration::from_millis(100))
                .build()
                .unwrap(),
            url: format!("http://{address}/sendMessage"),
            chat_id: "-1".to_string(),
        };
        let stalled = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            // Keep the accepted connection open without sending HTTP headers.
            std::future::pending::<()>().await;
            drop(stream);
        });
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            sender.deliver_pending(&mut state, &path),
        )
        .await;
        stalled.abort();
        let _ = stalled.await;
        result
            .expect("Telegram request ignored its client timeout")
            .unwrap();
        let restarted = State::load(&path).unwrap();
        assert_eq!(restarted.pending.len(), 2);
        assert_eq!(restarted.pending[0].status, Status::Failed);
        assert_eq!(restarted.pending[1].status, Status::Ok);
    }
}
