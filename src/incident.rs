use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Status {
    Ok,
    Degraded,
    Failed,
    Unknown,
    Unsupported,
}

#[derive(Debug, Clone, Copy)]
pub struct Observation {
    pub status: Status,
    pub code: &'static str,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Degraded => "DEGRADED",
            Self::Failed => "FAILED",
            Self::Unknown => "UNKNOWN",
            Self::Unsupported => "UNSUPPORTED",
        }
    }
}

impl Observation {
    pub fn new(status: Status, code: &'static str) -> Self {
        Self { status, code }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    version: u8,
    #[serde(default)]
    records: BTreeMap<String, Record>,
    #[serde(default)]
    pub pending: Vec<Notice>,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    active: Option<Status>,
    streak: u8,
    last_status: Option<Status>,
    last_code: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Notice {
    pub key: String,
    pub status: Status,
    pub when: u64,
}

impl Default for State {
    fn default() -> Self {
        Self {
            version: 1,
            records: BTreeMap::new(),
            pending: Vec::new(),
        }
    }
}

impl State {
    pub fn load(path: &Path) -> Result<Self> {
        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => return Err(error).context("state_metadata"),
        };
        if metadata.len() > 128 * 1024 {
            anyhow::bail!("state_oversize");
        }
        let data = fs::read(path).context("state_read")?;
        let state: State = serde_json::from_slice(&data).context("state_invalid")?;
        if state.version != 1 || state.pending.len() > 128 || state.records.len() > 128 {
            anyhow::bail!("state_version_or_limits");
        }
        Ok(state)
    }

    pub fn observe(&mut self, key: &str, o: Observation, notifications: bool) {
        let record = self.records.entry(key.to_string()).or_default();
        let mut notify = None;
        match o.status {
            Status::Failed | Status::Degraded => {
                record.streak =
                    if record.last_status == Some(o.status) && record.last_code == o.code {
                        record.streak.saturating_add(1)
                    } else {
                        1
                    };
                if record.streak >= 2 && record.active != Some(o.status) {
                    record.active = Some(o.status);
                    notify = Some(o.status);
                }
            }
            Status::Ok => {
                record.streak = 0;
                if record.active.take().is_some() {
                    notify = Some(Status::Ok);
                }
            }
            Status::Unknown | Status::Unsupported => {
                record.streak = 0;
            }
        }
        record.last_status = Some(o.status);
        record.last_code = o.code.to_string();
        if notifications {
            if let Some(status) = notify {
                self.queue(key, status);
            }
        }
    }

    fn queue(&mut self, key: &str, status: Status) {
        // Preserve transition order: delivering "recovered" without its preceding
        // outage would be misleading after a temporary Telegram failure.
        // Oldest events are discarded only if the bounded queue is saturated.
        if self.pending.len() == 128 {
            self.pending.remove(0);
        }
        {
            let when = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            self.pending.push(Notice {
                key: key.to_string(),
                status,
                when,
            });
        }
    }

    pub fn persist(&self, path: &Path) -> Result<()> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .context("state_parent")?;
        let json = serde_json::to_vec(self)?;
        let mut temporary = tempfile::NamedTempFile::new_in(parent).context("state_temp_create")?;
        temporary.write_all(&json)?;
        temporary.as_file().sync_all()?;
        temporary.persist(path).context("state_rename")?;
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn confirms_only_matching_consecutive_failures_and_recovers_once() {
        let mut s = State::default();
        s.observe(
            "profile/a",
            Observation::new(Status::Failed, "timeout"),
            true,
        );
        s.observe("profile/a", Observation::new(Status::Failed, "tls"), true);
        assert!(s.pending.is_empty());
        s.observe("profile/b", Observation::new(Status::Failed, "tls"), true);
        s.observe("profile/a", Observation::new(Status::Failed, "tls"), true);
        assert_eq!(s.pending.len(), 1);
        s.observe(
            "profile/a",
            Observation::new(Status::Unknown, "no_baseline"),
            true,
        );
        assert_eq!(s.pending.len(), 1);
        s.observe(
            "profile/a",
            Observation::new(Status::Ok, "egress_verified"),
            true,
        );
        s.observe(
            "profile/a",
            Observation::new(Status::Ok, "egress_verified"),
            true,
        );
        assert_eq!(s.pending.len(), 2);
        assert_eq!(s.pending[1].status, Status::Ok);
    }

    #[test]
    fn persists_pending_and_incident_between_restarts() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("state.json");
        let mut s = State::default();
        for _ in 0..2 {
            s.observe("profile/a", Observation::new(Status::Failed, "tls"), true);
        }
        s.persist(&file).unwrap();
        let mut loaded = State::load(&file).unwrap();
        loaded.observe("profile/a", Observation::new(Status::Failed, "tls"), true);
        assert_eq!(loaded.pending.len(), 1);
        loaded.observe(
            "profile/a",
            Observation::new(Status::Ok, "egress_verified"),
            true,
        );
        assert_eq!(loaded.pending.len(), 2);
    }
}
