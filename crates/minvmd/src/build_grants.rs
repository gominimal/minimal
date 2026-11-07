//! Build grants (NET-165): the host side's half of a build box's egress.
//!
//! `min` files a box's table here at the box's creation. To ask for a build,
//! the guest names a spec hash and nothing else, and the table says what the
//! build box may reach. A hash the table does not hold opens nothing, and the
//! build follows the box's own rules. Each open grant is a row of the build
//! box's own under a host-side deadline. A guest signal can end a grant
//! early, and nothing extends one.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use minimald_rpc::{BuildGrant, BuildGrantTable, WithdrawBoxRequest};

/// The file the box tables persist to, beside the box registry, so a box
/// that outlives the VM host daemon keeps its table.
pub(crate) const BUILD_TABLES_FILE: &str = "build-tables.json";

/// The persisted tables' format version. A file of any other version is set
/// aside as no tables, and those boxes' builds follow their own rules.
const BUILD_TABLES_FILE_VERSION: u32 = 1;

/// The longest a source fetch keeps its grant.
const FETCH_GRANT_DEADLINE: Duration = Duration::from_secs(60 * 60);

/// The longest a build with open internet keeps its grant.
const BUILD_GRANT_DEADLINE: Duration = Duration::from_secs(6 * 60 * 60);

/// The most grants open at a time, on one VM. Past it a build follows the
/// box's own rules, so a guest that asks in a loop cannot use up the addresses
/// other boxes draw from.
const MAX_OPEN_GRANTS: usize = 32;

/// How often the deadlines are read.
pub(crate) const GRANT_SWEEP_INTERVAL: Duration = Duration::from_secs(15);

/// The deadline of a grant that opens now.
pub(crate) fn grant_deadline(now: Instant, internet: bool) -> Instant {
    now + if internet {
        BUILD_GRANT_DEADLINE
    } else {
        FETCH_GRANT_DEADLINE
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildTablesFile {
    version: u32,
    tables: BTreeMap<boxes::SessionId, BuildGrantTable>,
}

#[derive(Debug)]
struct OpenGrant {
    deadline: Instant,
    withdrawal: WithdrawBoxRequest,
}

#[derive(Debug, Default)]
struct State {
    tables: BTreeMap<boxes::SessionId, BuildGrantTable>,
    open: BTreeMap<String, OpenGrant>,
    /// Counts grants, so each row has a name of its own.
    opened: u64,
}

/// The box tables and the open grants, shared by every clone.
#[derive(Debug, Clone, Default)]
pub struct BuildGrants {
    state: Arc<Mutex<State>>,
    persisted_at: Option<Arc<PathBuf>>,
    sweeping: Arc<AtomicBool>,
}

impl BuildGrants {
    /// The same grants, reading and keeping their tables at `path`.
    pub(crate) fn persisting_to(mut self, path: PathBuf) -> Self {
        let file = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json_lenient::from_slice::<BuildTablesFile>(&bytes).ok())
            .filter(|file| file.version == BUILD_TABLES_FILE_VERSION);
        if let Some(file) = file {
            self.lock().tables = file.tables;
        }
        self.persisted_at = Some(Arc::new(path));
        self
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn persist(&self, tables: BTreeMap<boxes::SessionId, BuildGrantTable>) {
        let Some(path) = &self.persisted_at else {
            return;
        };
        let file = BuildTablesFile {
            version: BUILD_TABLES_FILE_VERSION,
            tables,
        };
        if let Err(error) = crate::box_registry::write_registry_file(path, &file) {
            tracing::warn!(%error, "could not persist the box tables");
        }
    }

    /// Files `table` for the box `session_id`, beside what it already holds:
    /// a table too long for one request line comes in parts.
    pub fn file(&self, session_id: boxes::SessionId, table: BuildGrantTable) {
        let tables = {
            let mut state = self.lock();
            state.tables.entry(session_id).or_default().extend(table);
            state.tables.clone()
        };
        self.persist(tables);
    }

    /// Ends the table of the box `session_id`, which is gone.
    pub fn drop_table(&self, session_id: boxes::SessionId) {
        let tables = {
            let mut state = self.lock();
            if state.tables.remove(&session_id).is_none() {
                return;
            }
            state.tables.clone()
        };
        self.persist(tables);
    }

    /// What the box's table holds for `spec_hash`.
    pub fn lookup(&self, session_id: boxes::SessionId, spec_hash: &str) -> Option<BuildGrant> {
        self.lock().tables.get(&session_id)?.get(spec_hash).cloned()
    }

    /// The name of the next grant's row, or `None` at the cap.
    pub(crate) fn next_row(&self, session_id: boxes::SessionId) -> Option<String> {
        let mut state = self.lock();
        if state.open.len() >= MAX_OPEN_GRANTS {
            return None;
        }
        state.opened += 1;
        Some(format!("build-{session_id}-{}", state.opened))
    }

    /// Records a grant that opened, for its deadline and its close.
    pub(crate) fn opened(&self, withdrawal: WithdrawBoxRequest, deadline: Instant) {
        self.lock().open.insert(
            withdrawal.name.clone(),
            OpenGrant {
                deadline,
                withdrawal,
            },
        );
    }

    /// Ends the grant at the row `grant_row`, handing back its withdrawal. A
    /// name no grant opened is no grant: this withdraws nothing else.
    pub(crate) fn take(&self, grant_row: &str) -> Option<WithdrawBoxRequest> {
        self.lock()
            .open
            .remove(grant_row)
            .map(|grant| grant.withdrawal)
    }

    /// Ends every grant past its deadline at `now`, handing back their
    /// withdrawals.
    pub(crate) fn take_expired(&self, now: Instant) -> Vec<WithdrawBoxRequest> {
        let mut state = self.lock();
        let expired: Vec<String> = state
            .open
            .iter()
            .filter(|(_, grant)| grant.deadline <= now)
            .map(|(name, _)| name.clone())
            .collect();
        expired
            .iter()
            .filter_map(|name| state.open.remove(name))
            .map(|grant| grant.withdrawal)
            .collect()
    }

    /// Runs `start` once, for the thread that reads the deadlines.
    pub(crate) fn start_sweep(&self, start: impl FnOnce()) {
        if !self.sweeping.swap(true, Ordering::SeqCst) {
            start();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(hash: &str, internet: bool) -> BuildGrantTable {
        BTreeMap::from([(
            hash.to_string(),
            BuildGrant {
                sources: vec!["https://downloads.example.org/a.tar.gz".to_string()],
                internet,
            },
        )])
    }

    fn withdrawal(name: &str) -> WithdrawBoxRequest {
        WithdrawBoxRequest {
            name: name.to_string(),
            switch_address: std::net::Ipv4Addr::new(192, 0, 2, 1),
            loopback_address: std::net::Ipv4Addr::new(127, 0, 0, 2),
            box_id: None,
        }
    }

    /// NET-165: a lookup answers only for the box's own table, only for a
    /// hash it holds, and a table ends with its box.
    #[test]
    fn a_hash_outside_the_table_opens_no_grant() {
        let grants = BuildGrants::default();
        let id = boxes::SessionId::mint();
        grants.file(id, table("aa", false));
        assert!(grants.lookup(id, "aa").is_some());
        assert!(grants.lookup(id, "bb").is_none());
        assert!(grants.lookup(boxes::SessionId::mint(), "aa").is_none());
        grants.drop_table(id);
        assert!(grants.lookup(id, "aa").is_none());
    }

    /// NET-165: a table too long for one request line files in parts.
    #[test]
    fn a_table_files_in_parts() {
        let grants = BuildGrants::default();
        let id = boxes::SessionId::mint();
        grants.file(id, table("aa", false));
        grants.file(id, table("bb", false));
        assert!(grants.lookup(id, "aa").is_some());
        assert!(grants.lookup(id, "bb").is_some());
    }

    /// NET-165: a grant ends at its host-side deadline, whatever the guest
    /// does, and a close ends one early. A close of any other name ends
    /// nothing. No verb moves a deadline.
    #[test]
    fn a_grant_ends_at_its_deadline_or_earlier() {
        let grants = BuildGrants::default();
        let now = Instant::now();
        let deadline = grant_deadline(now, false);
        assert_eq!(deadline, now + FETCH_GRANT_DEADLINE);
        assert_eq!(grant_deadline(now, true), now + BUILD_GRANT_DEADLINE);

        grants.opened(withdrawal("build-a-1"), deadline);
        assert!(grants.take_expired(now).is_empty());
        let expired = grants.take_expired(deadline);
        assert_eq!(expired, [withdrawal("build-a-1")]);

        grants.opened(withdrawal("build-a-2"), deadline);
        assert!(grants.take("the-requesters-own-row").is_none());
        assert_eq!(grants.take("build-a-2"), Some(withdrawal("build-a-2")));
        assert!(grants.take_expired(deadline).is_empty(), "it already ended");
    }

    /// NET-165: a guest asking in a loop stops at the cap.
    #[test]
    fn open_grants_stop_at_the_cap() {
        let grants = BuildGrants::default();
        let id = boxes::SessionId::mint();
        let far = Instant::now() + BUILD_GRANT_DEADLINE;
        for _ in 0..MAX_OPEN_GRANTS {
            let row = grants.next_row(id).expect("room under the cap");
            grants.opened(withdrawal(&row), far);
        }
        assert!(grants.next_row(id).is_none());
    }

    /// NET-165: a box's table survives the VM host daemon.
    #[test]
    fn a_table_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(BUILD_TABLES_FILE);
        let id = boxes::SessionId::mint();
        BuildGrants::default()
            .persisting_to(path.clone())
            .file(id, table("aa", true));
        let reloaded = BuildGrants::default().persisting_to(path);
        assert!(
            reloaded
                .lookup(id, "aa")
                .is_some_and(|grant| grant.internet)
        );
    }
}
