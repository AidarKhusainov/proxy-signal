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
    #[serde(default)]
    active_code: Option<String>,
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
        let mut state: State = serde_json::from_slice(&data).context("state_invalid")?;
        if state.version != 1 || state.pending.len() > 128 || state.records.len() > 256 {
            anyhow::bail!("state_version_or_limits");
        }
        // Old PR versions used raw outbound tags as candidate keys. Never
        // deliver their pending notifications or retain them in persisted state.
        state.records.retain(|key, _| !legacy_candidate_key(key));
        state
            .pending
            .retain(|notice| !legacy_candidate_key(&notice.key));
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
                    record.active_code = Some(o.code.to_string());
                    notify = Some(o.status);
                }
            }
            Status::Ok => {
                record.streak = 0;
                if record.active.take().is_some() {
                    notify = Some(Status::Ok);
                }
                record.active_code = None;
            }
            Status::Unknown | Status::Unsupported => {
                record.streak = 0;
                // Candidate recovery is not evidence of a verified leastPing
                // decision. Retire only a confirmed candidate outage, with an
                // UNKNOWN notice rather than a false OK/recovery message.
                if o.status == Status::Unknown
                    && o.code == "balancer_candidates_healthy_route_unverified"
                    && matches!(
                        record.active_code.as_deref().or_else(|| {
                            (record.last_status == record.active)
                                .then_some(record.last_code.as_str())
                        }),
                        Some("balancer_partial_candidates" | "balancer_all_candidates_failed")
                    )
                {
                    record.active = None;
                    record.active_code = None;
                    notify = Some(Status::Unknown);
                }
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

fn legacy_candidate_key(key: &str) -> bool {
    key.rsplit_once("/candidate/").is_some_and(|(_, suffix)| {
        !matches!(suffix.parse::<usize>(), Ok(index) if index < 8 && suffix == index.to_string())
    })
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
    fn recovers_candidate_outage_without_claiming_verified_balancer_route() {
        let mut state = State::default();
        let key = "balancer/source/pool";
        let degraded = Observation::new(Status::Degraded, "balancer_partial_candidates");
        let recovered = Observation::new(
            Status::Unknown,
            "balancer_candidates_healthy_route_unverified",
        );
        for _ in 0..2 {
            state.observe(key, degraded, true);
        }
        assert_eq!(state.pending.len(), 1);
        state.observe(
            key,
            Observation::new(Status::Unknown, "balancer_incomplete_evidence"),
            true,
        );
        assert_eq!(state.pending.len(), 1); // uncertain candidates cannot close an outage
        state.observe(key, recovered, true);
        state.observe(key, recovered, true);
        assert_eq!(state.pending.len(), 2);
        assert_eq!(state.pending[1].status, Status::Unknown);
        assert_eq!(state.records[key].active, None);

        for _ in 0..2 {
            state.observe(key, degraded, true);
        }
        assert_eq!(state.pending.len(), 3); // a new real outage can be reported

        let mut route_failure = State::default();
        for _ in 0..2 {
            route_failure.observe(
                key,
                Observation::new(Status::Failed, "balancer_route_failed"),
                true,
            );
        }
        route_failure.observe(key, recovered, true);
        assert_eq!(route_failure.pending.len(), 1);
        assert_eq!(route_failure.records[key].active, Some(Status::Failed));

        let mut total_failure = State::default();
        for _ in 0..2 {
            total_failure.observe(
                key,
                Observation::new(Status::Failed, "balancer_all_candidates_failed"),
                true,
            );
        }
        total_failure.observe(key, recovered, true);
        assert_eq!(total_failure.pending[1].status, Status::Unknown);
    }

    #[test]
    fn legacy_candidate_tags_are_removed_from_restored_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut state = State::default();
        for _ in 0..2 {
            state.observe(
                "balancer/source/pool/candidate/private-tag",
                Observation::new(Status::Failed, "candidate_https_failed"),
                true,
            );
        }
        state.observe(
            "balancer/source/pool/candidate/0",
            Observation::new(Status::Failed, "candidate_https_failed"),
            true,
        );
        state.persist(&path).unwrap();
        let restored = State::load(&path).unwrap();
        assert!(restored.pending.is_empty());
        assert_eq!(restored.records.len(), 1);
        assert!(restored
            .records
            .contains_key("balancer/source/pool/candidate/0"));
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
