use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

// A maximum-size validated configuration currently emits 344 records.
const MAX_RECORDS: usize = 512;
const MAX_PENDING: usize = 2 * MAX_RECORDS;
const MAX_STATE_BYTES: usize = 512 * 1024;

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
    pub observed_at: u64,
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
        Self {
            status,
            code,
            observed_at: unix_seconds(),
        }
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
    #[serde(default)]
    last_observed_at: Option<u64>,
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
        if metadata.len() > MAX_STATE_BYTES as u64 {
            anyhow::bail!("state_oversize");
        }
        let data = fs::read(path).context("state_read")?;
        let mut state: State = serde_json::from_slice(&data).context("state_invalid")?;
        if state.version != 1
            || state.pending.len() > MAX_PENDING
            || state.records.len() > MAX_RECORDS
        {
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
                if record.streak >= 2 {
                    let active_code = record.active_code.as_deref().or_else(|| {
                        (record.last_status == record.active).then_some(record.last_code.as_str())
                    });
                    // A later failure must not erase an earlier unresolved
                    // route/hop failure. Mixed causes need complete OK evidence;
                    // a partial recovery can retire only a compatible cause.
                    let code = if record.active.is_some()
                        && active_code.and_then(partial_recovery_code)
                            != partial_recovery_code(o.code)
                    {
                        "mixed_confirmed_causes"
                    } else {
                        o.code
                    };
                    record.active_code = Some(code.to_string());
                    if record.active != Some(o.status) {
                        record.active = Some(o.status);
                        notify = Some(o.status);
                    }
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
                let active_code = record.active_code.as_deref().or_else(|| {
                    (record.last_status == record.active).then_some(record.last_code.as_str())
                });
                if o.status == Status::Unknown
                    && active_code.and_then(partial_recovery_code) == Some(o.code)
                {
                    record.active = None;
                    record.active_code = None;
                    // Retire only the proven failure; never announce complete OK.
                    notify = Some(Status::Unknown);
                }
            }
        }
        record.last_status = Some(o.status);
        record.last_code = o.code.to_string();
        record.last_observed_at = Some(o.observed_at);
        if notifications {
            if let Some(status) = notify {
                self.queue(key, status);
            }
        }
    }

    pub fn expire_stale(&mut self, max_age_seconds: u64) {
        self.expire_stale_at(unix_seconds(), max_age_seconds);
    }

    fn expire_stale_at(&mut self, now: u64, max_age_seconds: u64) {
        for record in self.records.values_mut() {
            let fresh = record
                .last_observed_at
                .and_then(|when| now.checked_sub(when))
                .is_some_and(|age| age <= max_age_seconds);
            if !fresh {
                // Preserve the failure reason from pre-active_code checkpoints
                // before replacing their last observation with UNKNOWN.
                if record.active.is_some()
                    && record.active_code.is_none()
                    && record.last_status == record.active
                {
                    record.active_code = Some(record.last_code.clone());
                }
                record.last_status = Some(Status::Unknown);
                record.last_code = "observation_stale".to_string();
                record.streak = 0;
            }
        }
    }

    fn queue(&mut self, key: &str, status: Status) {
        self.pending.push(Notice {
            key: key.to_string(),
            status,
            when: unix_seconds(),
        });
        if self.pending.len() > MAX_PENDING {
            eprintln!("ProxySignal: telegram_outbox_saturated_history_compacted");
            // Keep the latest pending outage and final state for every target.
            // Recovery must not outlive its pending failure; a recovery alone
            // remains valid when that failure was already acknowledged.
            let mut latest = BTreeMap::<&str, (Option<usize>, usize)>::new();
            for (index, notice) in self.pending.iter().enumerate() {
                let (failure, last) = latest.entry(&notice.key).or_insert((None, index));
                if matches!(notice.status, Status::Failed | Status::Degraded) {
                    *failure = Some(index);
                }
                *last = index;
            }
            let mut keep = vec![false; self.pending.len()];
            for (failure, last) in latest.into_values() {
                if let Some(index) = failure {
                    keep[index] = true;
                }
                keep[last] = true;
            }
            let mut index = 0;
            self.pending.retain(|_| {
                let retained = keep[index];
                index += 1;
                retained
            });
        }
    }

    pub fn persist(&self, path: &Path) -> Result<()> {
        if self.version != 1 || self.pending.len() > MAX_PENDING || self.records.len() > MAX_RECORDS
        {
            anyhow::bail!("state_version_or_limits");
        }
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .context("state_parent")?;
        let json = serde_json::to_vec(self)?;
        if json.len() > MAX_STATE_BYTES {
            anyhow::bail!("state_oversize");
        }
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

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn partial_recovery_code(failure: &str) -> Option<&'static str> {
    match failure {
        "balancer_partial_candidates" | "balancer_all_candidates_failed" => {
            Some("balancer_candidates_healthy_route_unverified")
        }
        // The legacy connection code described verified HTTPS failure only;
        // hop attestation was always UNKNOWN in that release.
        "cascade_https_failed" | "cascade_connection_failed" => {
            Some("cascade_https_healthy_hops_unverified")
        }
        "cdn_endpoint_failed" | "cdn_tunnel_failed" | "cdn_endpoint_and_tunnel_failed" => {
            Some("cdn_endpoint_tunnel_healthy_route_unverified")
        }
        "failover_primary_failed" | "failover_backups_failed" | "failover_partial_backups" => {
            Some("failover_routes_healthy_switch_unverified")
        }
        _ => None,
    }
}

fn legacy_candidate_key(key: &str) -> bool {
    key.rsplit_once("/candidate/").is_some_and(|(_, suffix)| {
        let positional = matches!(
            suffix.parse::<usize>(),
            Ok(index) if index < 8 && suffix == index.to_string()
        );
        // The reserved separator is not accepted in outbound tags. Accept
        // only validated opaque IDs, never old raw tag-based observation keys.
        let opaque = suffix.strip_prefix("id~").is_some_and(|id| {
            !id.is_empty()
                && id.len() <= 64
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
        !positional && !opaque
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
    fn cascade_https_recovery_retires_only_verified_connection_failures() {
        for failure_code in ["cascade_https_failed", "cascade_connection_failed"] {
            let mut state = State::default();
            let key = "cascade/source/chain";
            for _ in 0..2 {
                state.observe(key, Observation::new(Status::Failed, failure_code), true);
            }
            state.observe(
                key,
                Observation::new(Status::Unknown, "cascade_incomplete_evidence"),
                true,
            );
            assert_eq!(state.pending.len(), 1);
            // The original FAILED event may have been persisted by an older
            // release, before the monitor learned the recovery evidence code.
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("state.json");
            state.persist(&path).unwrap();
            let mut state = State::load(&path).unwrap();
            state.observe(
                key,
                Observation::new(Status::Unknown, "cascade_https_healthy_hops_unverified"),
                true,
            );
            assert_eq!(state.pending.len(), 2);
            assert_eq!(state.pending[1].status, Status::Unknown);
            assert_eq!(state.records[key].active, None);
            state.observe(
                key,
                Observation::new(Status::Unknown, "cascade_https_healthy_hops_unverified"),
                true,
            );
            assert_eq!(state.pending.len(), 2);
        }
        let mut hop_failure = State::default();
        let key = "cascade/source/chain";
        for _ in 0..2 {
            hop_failure.observe(
                key,
                Observation::new(Status::Failed, "cascade_hops_failed"),
                true,
            );
        }
        hop_failure.observe(
            key,
            Observation::new(Status::Unknown, "cascade_https_healthy_hops_unverified"),
            true,
        );
        assert_eq!(hop_failure.pending.len(), 1);
        assert_eq!(hop_failure.records[key].active, Some(Status::Failed));
    }

    #[test]
    fn cdn_recovery_requires_endpoint_and_tunnel_evidence() {
        let key = "cdn/source/edge";
        let mut state = State::default();
        for _ in 0..2 {
            state.observe(
                key,
                Observation::new(Status::Degraded, "cdn_endpoint_failed"),
                true,
            );
        }
        state.observe(
            key,
            Observation::new(Status::Unknown, "cdn_incomplete_evidence"),
            true,
        );
        assert_eq!(state.pending.len(), 1);
        state.observe(
            key,
            Observation::new(
                Status::Unknown,
                "cdn_endpoint_tunnel_healthy_route_unverified",
            ),
            true,
        );
        assert_eq!(state.pending[1].status, Status::Unknown);
        let mut route = State::default();
        for _ in 0..2 {
            route.observe(
                key,
                Observation::new(Status::Failed, "cdn_route_failed"),
                true,
            );
        }
        route.observe(
            key,
            Observation::new(
                Status::Unknown,
                "cdn_endpoint_tunnel_healthy_route_unverified",
            ),
            true,
        );
        assert_eq!(route.pending.len(), 1);
    }

    #[test]
    fn failover_recovery_retires_only_proven_route_failures() {
        let key = "failover/source/lab";
        let recovery =
            Observation::new(Status::Unknown, "failover_routes_healthy_switch_unverified");
        for code in ["failover_primary_failed", "failover_backups_failed"] {
            let mut state = State::default();
            for _ in 0..2 {
                state.observe(key, Observation::new(Status::Failed, code), true);
            }
            assert_eq!(state.pending.len(), 1);
            state.observe(
                key,
                Observation::new(Status::Unknown, "failover_incomplete_evidence"),
                true,
            );
            assert_eq!(state.pending.len(), 1);
            let dir = tempfile::tempdir().unwrap();
            let file = dir.path().join("state.json");
            state.persist(&file).unwrap();
            let mut restored = State::load(&file).unwrap();
            restored.observe(key, recovery, true);
            restored.observe(key, recovery, true);
            assert_eq!(restored.pending.len(), 2);
            assert_eq!(restored.pending[1].status, Status::Unknown);
            assert_eq!(restored.records[key].active, None);
        }
        for code in ["failover_switch_failed", "failover_recovery_failed"] {
            let mut state = State::default();
            for _ in 0..2 {
                state.observe(key, Observation::new(Status::Failed, code), true);
            }
            state.observe(key, recovery, true);
            assert_eq!(state.pending.len(), 1);
            assert_eq!(state.records[key].active, Some(Status::Failed));
        }
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
    fn rejects_invalid_opaque_candidate_keys_during_restore() {
        assert!(legacy_candidate_key("balancer/source/pool/candidate/id~"));
        assert!(legacy_candidate_key("balancer/source/pool/candidate/id~invalid/tag"));
        assert!(legacy_candidate_key("balancer/source/pool/candidate/id~invalid.tag"));
        assert!(!legacy_candidate_key("balancer/source/pool/candidate/id~a_B-2"));
        assert!(!legacy_candidate_key("balancer/source/pool/candidate/0"));
    }

    #[test]
    fn opaque_candidate_incident_survives_restart_without_restoring_raw_tags() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let stable = "balancer/source/pool/candidate/id~sweden";
        let raw_tag = "balancer/source/pool/candidate/private-outbound";
        let mut state = State::default();
        for _ in 0..2 {
            state.observe(
                stable,
                Observation::new(Status::Failed, "candidate_https_failed"),
                true,
            );
            state.observe(
                raw_tag,
                Observation::new(Status::Failed, "candidate_https_failed"),
                true,
            );
        }
        state.persist(&path).unwrap();
        let mut restored = State::load(&path).unwrap();
        assert_eq!(restored.records.len(), 1);
        assert!(restored.records.contains_key(stable));
        assert_eq!(restored.pending.len(), 1);
        assert_eq!(restored.pending[0].key, stable);
        restored.observe(
            stable,
            Observation::new(Status::Ok, "candidate_https_verified"),
            true,
        );
        assert_eq!(restored.pending.len(), 2);
        assert_eq!(restored.pending[1].status, Status::Ok);
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

    #[test]
    fn same_severity_failure_reason_survives_restart_without_false_recovery() {
        for (key, initial, replacement, partial_recovery) in [
            (
                "balancer/source/pool",
                "balancer_all_candidates_failed",
                "balancer_route_failed",
                "balancer_candidates_healthy_route_unverified",
            ),
            (
                "cascade/source/chain",
                "cascade_https_failed",
                "cascade_hops_failed",
                "cascade_https_healthy_hops_unverified",
            ),
            (
                "cdn/source/edge",
                "cdn_tunnel_failed",
                "cdn_route_failed",
                "cdn_endpoint_tunnel_healthy_route_unverified",
            ),
            (
                "failover/source/lab",
                "failover_primary_failed",
                "failover_switch_failed",
                "failover_routes_healthy_switch_unverified",
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("state.json");
            let mut state = State::default();
            for code in [initial, initial, replacement, replacement] {
                state.observe(key, Observation::new(Status::Failed, code), true);
            }
            assert_eq!(state.pending.len(), 1);
            state.persist(&path).unwrap();
            let mut restored = State::load(&path).unwrap();
            restored.observe(
                key,
                Observation::new(Status::Unknown, partial_recovery),
                true,
            );
            assert_eq!(restored.records[key].active, Some(Status::Failed), "{key}");
            assert_eq!(restored.pending.len(), 1, "{key}");
        }
    }

    #[test]
    fn later_partial_failure_does_not_erase_an_unverified_prior_failure() {
        let key = "cascade/source/chain";
        let mut state = State::default();
        for code in [
            "cascade_hops_failed",
            "cascade_hops_failed",
            "cascade_https_failed",
            "cascade_https_failed",
        ] {
            state.observe(key, Observation::new(Status::Failed, code), true);
        }
        state.observe(
            key,
            Observation::new(Status::Unknown, "cascade_https_healthy_hops_unverified"),
            true,
        );
        assert_eq!(state.pending.len(), 1);
        assert_eq!(state.records[key].active, Some(Status::Failed));
        state.observe(key, Observation::new(Status::Ok, "cascade_verified"), true);
        assert_eq!(state.pending.len(), 2);
        assert_eq!(state.pending[1].status, Status::Ok);
        assert_eq!(state.records[key].active, None);
    }

    #[test]
    fn unavailable_source_does_not_erase_confirmed_vpn_incident_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut state = State::default();
        for _ in 0..2 {
            state.observe(
                "profile/source",
                Observation::new(Status::Failed, "all_egress_probes_failed"),
                true,
            );
        }
        state.pending.clear(); // The confirmed VPN failure was already acknowledged.
        for _ in 0..2 {
            state.observe(
                "source/source",
                Observation::new(Status::Failed, "source_unavailable"),
                true,
            );
            state.observe(
                "profile/source",
                Observation::new(Status::Unknown, "source_unavailable"),
                true,
            );
        }
        state.persist(&path).unwrap();
        let mut restored = State::load(&path).unwrap();
        assert_eq!(
            restored.records["profile/source"].active,
            Some(Status::Failed)
        );
        assert_eq!(restored.pending.len(), 1);
        assert_eq!(restored.pending[0].key, "source/source");
        restored.observe(
            "profile/source",
            Observation::new(Status::Failed, "all_egress_probes_failed"),
            true,
        );
        assert_eq!(restored.pending.len(), 1); // No duplicate VPN outage.
        restored.observe(
            "profile/source",
            Observation::new(Status::Ok, "egress_verified"),
            true,
        );
        assert_eq!(restored.pending.len(), 2);
        assert_eq!(restored.pending[1].key, "profile/source");
        assert_eq!(restored.pending[1].status, Status::Ok);
    }

    #[test]
    fn every_record_from_a_maximum_sized_configuration_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut state = State::default();
        let mut keys = Vec::new();
        // Current validated maxima: 32 sources, 64 scenarios, 8 balancers
        // with 8 candidates, 8 cascades, 8 CDN cases and 4 failover cases.
        for source in 0..32 {
            keys.push(format!("source/s{source}"));
            keys.push(format!("profile/s{source}"));
        }
        for scenario in 0..64 {
            keys.push(format!("scenario/s{}/c{scenario}", scenario / 8));
        }
        for case in 0..8 {
            for component in ["", "/config", "/candidates", "/route"] {
                keys.push(format!("balancer/s{case}/b{case}{component}"));
            }
            for candidate in 0..8 {
                keys.push(format!("balancer/s{case}/b{case}/candidate/{candidate}"));
            }
            for component in ["", "/config", "/https", "/hops"] {
                keys.push(format!("cascade/s{case}/c{case}{component}"));
            }
            for component in [
                "",
                "/dns",
                "/tls",
                "/http",
                "/endpoint",
                "/config",
                "/tunnel",
                "/route",
            ] {
                keys.push(format!("cdn/s{case}/d{case}{component}"));
            }
        }
        for case in 0..4 {
            for component in ["", "/config", "/primary", "/backup", "/switch", "/recovery"] {
                keys.push(format!("failover/s{case}/f{case}{component}"));
            }
        }
        for key in &keys {
            state.observe(
                key,
                Observation::new(Status::Unknown, "not_observed"),
                false,
            );
        }
        state.persist(&path).unwrap();
        let restored = State::load(&path).unwrap();
        assert_eq!(restored.records.len(), 344);
        for key in keys {
            assert_eq!(restored.records[&key].last_status, Some(Status::Unknown));
        }
    }

    #[test]
    fn oversized_state_does_not_replace_the_last_reloadable_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut state = State::default();
        state.observe("profile/a", Observation::new(Status::Failed, "tls"), true);
        state.persist(&path).unwrap();
        let checkpoint = fs::read(&path).unwrap();
        for index in 0..1024 {
            state.observe(
                &format!("profile/extra-{index}"),
                Observation::new(Status::Unknown, "not_observed"),
                false,
            );
        }
        assert!(state.persist(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), checkpoint);
        let mut restored = State::load(&path).unwrap();
        restored.observe("profile/a", Observation::new(Status::Failed, "tls"), true);
        assert_eq!(restored.pending.len(), 1);
    }

    #[test]
    fn expired_observations_become_unknown_without_recovering_confirmed_incidents() {
        for status in [Status::Ok, Status::Failed, Status::Degraded] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("state.json");
            let mut state = State::default();
            let mut observation = Observation::new(status, "probe_result");
            observation.observed_at = 100;
            for _ in 0..2 {
                state.observe("profile/a", observation, true);
            }
            state.persist(&path).unwrap();
            let mut restored = State::load(&path).unwrap();
            restored.expire_stale_at(161, 60);
            let record = &restored.records["profile/a"];
            assert_eq!(record.last_status, Some(Status::Unknown));
            assert_eq!(record.last_code, "observation_stale");
            assert_eq!(record.last_observed_at, Some(100));
            assert_eq!(record.streak, 0);
            if status == Status::Ok {
                assert_eq!(record.active, None);
                assert!(restored.pending.is_empty());
            } else {
                assert_eq!(record.active, Some(status));
                assert_eq!(restored.pending.len(), 1);
                assert_eq!(restored.pending[0].status, status);
            }
            restored.persist(&path).unwrap();
            let checkpoint = State::load(&path).unwrap();
            assert_eq!(
                checkpoint.records["profile/a"].last_status,
                Some(Status::Unknown)
            );
        }
    }

    #[test]
    fn missing_or_future_observation_times_never_remain_ok() {
        for observed_at in [None, Some(201)] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("state.json");
            let mut fixture = serde_json::json!({
                "version": 1,
                "records": {"profile/a": {
                    "active": null,
                    "streak": 0,
                    "last_status": "OK",
                    "last_code": "egress_verified"
                }},
                "pending": []
            });
            if let Some(when) = observed_at {
                fixture["records"]["profile/a"]["last_observed_at"] = when.into();
            }
            fs::write(&path, serde_json::to_vec(&fixture).unwrap()).unwrap();
            let mut state = State::load(&path).unwrap();
            state.expire_stale_at(200, 60);
            assert_eq!(
                state.records["profile/a"].last_status,
                Some(Status::Unknown)
            );
            assert_eq!(state.records["profile/a"].last_code, "observation_stale");
            assert!(state.pending.is_empty());
        }
    }

    #[test]
    fn only_fresh_failure_streaks_can_confirm_after_restart() {
        for (now, expected_notices) in [(160, 1), (161, 0)] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("state.json");
            let mut state = State::default();
            let mut failure = Observation::new(Status::Failed, "tls");
            failure.observed_at = 100;
            state.observe("profile/a", failure, true);
            state.persist(&path).unwrap();
            let mut restored = State::load(&path).unwrap();
            restored.expire_stale_at(now, 60);
            failure.observed_at = now;
            restored.observe("profile/a", failure, true);
            assert_eq!(restored.pending.len(), expected_notices);
        }
    }

    #[test]
    fn expiring_legacy_records_preserves_the_confirmed_failure_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let fixture = serde_json::json!({
            "version": 1,
            "records": {"cascade/source/chain": {
                "active": "FAILED",
                "streak": 2,
                "last_status": "FAILED",
                "last_code": "cascade_https_failed"
            }},
            "pending": []
        });
        fs::write(&path, serde_json::to_vec(&fixture).unwrap()).unwrap();
        let mut state = State::load(&path).unwrap();
        state.expire_stale_at(200, 60);
        assert_eq!(
            state.records["cascade/source/chain"].active,
            Some(Status::Failed)
        );
        assert_eq!(
            state.records["cascade/source/chain"].last_status,
            Some(Status::Unknown)
        );
        state.observe(
            "cascade/source/chain",
            Observation::new(Status::Unknown, "cascade_https_healthy_hops_unverified"),
            true,
        );
        assert_eq!(state.pending.len(), 1);
        assert_eq!(state.pending[0].status, Status::Unknown);
        assert_eq!(state.records["cascade/source/chain"].active, None);
    }

    #[test]
    fn healthy_backups_retire_partial_outage_without_claiming_observed_switch() {
        let key = "failover/source/lab";
        let mut state = State::default();
        for _ in 0..2 {
            state.observe(
                key,
                Observation::new(Status::Degraded, "failover_partial_backups"),
                true,
            );
        }
        state.observe(
            key,
            Observation::new(Status::Unknown, "failover_routes_healthy_switch_unverified"),
            true,
        );
        assert_eq!(state.pending.len(), 2);
        assert_eq!(state.pending[1].status, Status::Unknown);
        assert_eq!(state.records[key].active, None);
    }

    #[test]
    fn maximum_configuration_outages_and_recoveries_remain_durable_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut state = State::default();
        // The independent configuration-bound regression above establishes
        // that the current source/scenario maxima emit 344 observation keys.
        for _ in 0..2 {
            for index in 0..344 {
                state.observe(
                    &format!("profile/check-{index}"),
                    Observation::new(Status::Failed, "tls"),
                    true,
                );
            }
        }
        state.persist(&path).unwrap();
        let mut restarted = State::load(&path).unwrap();
        assert_eq!(restarted.pending.len(), 344);
        for index in 0..344 {
            restarted.observe(
                &format!("profile/check-{index}"),
                Observation::new(Status::Ok, "egress_verified"),
                true,
            );
        }
        restarted.persist(&path).unwrap();
        let restored = State::load(&path).unwrap();
        assert_eq!(restored.pending.len(), 688);
        for index in 0..344 {
            assert_eq!(
                restored.pending[index].key,
                format!("profile/check-{index}")
            );
            assert_eq!(restored.pending[index].status, Status::Failed);
            assert_eq!(
                restored.pending[344 + index].key,
                format!("profile/check-{index}")
            );
            assert_eq!(restored.pending[344 + index].status, Status::Ok);
        }
    }

    #[test]
    fn saturation_preserves_each_targets_latest_complete_sequence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut state = State::default();
        // This outage was already delivered; its later recovery legitimately
        // has no preceding failure in the pending queue.
        for _ in 0..2 {
            state.observe(
                "profile/delivered",
                Observation::new(Status::Failed, "tls"),
                true,
            );
        }
        state.pending.clear();
        for _ in 0..MAX_PENDING / 4 {
            for key in ["profile/a", "profile/b"] {
                for _ in 0..2 {
                    state.observe(key, Observation::new(Status::Failed, "tls"), true);
                }
                state.observe(key, Observation::new(Status::Ok, "egress_verified"), true);
            }
        }
        assert_eq!(state.pending.len(), MAX_PENDING);
        state.observe(
            "profile/delivered",
            Observation::new(Status::Ok, "egress_verified"),
            true,
        );
        state.persist(&path).unwrap();
        let restored = State::load(&path).unwrap();
        let actual: Vec<_> = restored
            .pending
            .iter()
            .map(|n| (n.key.as_str(), n.status))
            .collect();
        assert_eq!(
            actual,
            vec![
                ("profile/a", Status::Failed),
                ("profile/a", Status::Ok),
                ("profile/b", Status::Failed),
                ("profile/b", Status::Ok),
                ("profile/delivered", Status::Ok),
            ]
        );
    }

    #[test]
    fn saturation_keeps_a_pending_outage_with_its_incoming_recovery() {
        let mut state = State::default();
        for index in 0..MAX_PENDING {
            let status = if index % 2 == 0 {
                Status::Failed
            } else {
                Status::Degraded
            };
            for _ in 0..2 {
                state.observe("profile/a", Observation::new(status, "tls"), true);
            }
        }
        assert_eq!(state.pending.len(), MAX_PENDING);
        state.observe(
            "profile/a",
            Observation::new(Status::Ok, "egress_verified"),
            true,
        );
        assert_eq!(state.pending.len(), 2);
        assert_eq!(state.pending[0].status, Status::Degraded);
        assert_eq!(state.pending[1].status, Status::Ok);
    }
}
