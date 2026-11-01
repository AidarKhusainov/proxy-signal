use crate::{
    config::Telegram,
    incident::{Notice, Status},
    source::read_limited,
};
use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde_json::Value;
use std::{fs::File, io::Read, time::Duration};

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
        Ok(Self {
            client: Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(8))
                .build()?,
            url: format!("https://api.telegram.org/bot{token}/sendMessage"),
            chat_id: config.chat_id.clone(),
        })
    }

    pub async fn send(&self, notice: &Notice) -> Result<()> {
        let message = match notice.status {
            Status::Ok => "Восстановлено: OK",
            Status::Failed => "Подтверждённый сбой: FAILED",
            Status::Degraded => "Частичная доступность: DEGRADED",
            _ => return Ok(()),
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
