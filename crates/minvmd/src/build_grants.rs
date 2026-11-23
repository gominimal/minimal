//! Build grants (NET-165): the host side's half of a build box's egress.
//!
//! `min` files a box's table here at the box's creation. To ask for a build,
//! the guest names a spec hash and nothing else, and the table says what the
//! build box may reach. A hash the table does not hold opens nothing, and the
//! build follows the box's own rules. Each open grant is a row of the build
//! box's own under a host-side deadline. A guest signal can end a grant
//! early, and nothing extends one.
//!
//! Each filing rewrites the persisted tables whole. A grant's deadline lives
//! in this process only: a restart of `minvmd` retires every grant row, so no
//! grant outlives the process that opened it.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use minimald_rpc::{BuildGrant, BuildGrantTable, WithdrawBoxRequest};

/// The file the box tables persist to, beside the box registry, so a box
/// that outlives the VM host daemon keeps its table.
pub(crate) const BUILD_TABLES_FILE: &str = "build-tables.json";

/// The persisted tables' format version. A file of any other version, or one
/// that cannot be read, is set aside as no tables, and those boxes' builds
/// follow their own rules.
const BUILD_TABLES_FILE_VERSION: u32 = 1;

/// The longest a source fetch keeps its grant.
const FETCH_GRANT_DEADLINE: Duration = Duration::from_secs(60 * 60);

/// The longest a build with open internet keeps its grant.
const BUILD_GRANT_DEADLINE: Duration = Duration::from_secs(6 * 60 * 60);

/// The most grants open at a time, on one VM. Past it a build follows the
/// box's own rules, so a guest that asks in a loop cannot use up the addresses
/// other boxes draw from.
const MAX_OPEN_GRANTS: usize = 32;

/// The most ended boxes [`BuildGrants::drop_table`] remembers, so a part of
/// a table filed after its box's end files nothing. The ids come from the
/// guest, so the set is bounded.
const MAX_ENDED_BOXES: usize = 4096;

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
    /// The boxes `min` filed with the network mode `none`.
    #[serde(default)]
    no_network: BTreeSet<boxes::SessionId>,
}

#[derive(Debug)]
struct OpenGrant {
    /// The box the grant opened for, whose table's end ends it too.
    session_id: boxes::SessionId,
    deadline: Instant,
    withdrawal: WithdrawBoxRequest,
    /// The change it opened at ([`State::changes`]).
    opened_at: u64,
    /// The guest daemon's epoch it opened under, when one was known
    /// ([`BuildGrants::note_guest_epoch`]).
    epoch: Option<String>,
}

/// The changes to the tables and the grants so far, at one moment. Take it
/// before reading the in-VM daemon's list, and hand it to
/// [`BuildGrants::end_absent`] with that list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct BuildGrantMark(u64);

#[derive(Debug)]
struct State {
    tables: BTreeMap<boxes::SessionId, BuildGrantTable>,
    /// The boxes `min` filed with the network mode `none`
    /// ([`BuildGrants::file_no_network`]). They get no table and no grant.
    no_network: BTreeSet<boxes::SessionId>,
    /// The change each box's table was last filed at.
    filed_at: BTreeMap<boxes::SessionId, u64>,
    /// Counts filings and grant opens, for [`BuildGrantMark`].
    changes: u64,
    /// This process's own part of every grant's row name, so a row named
    /// before a restart, which the guest can still close, never names a
    /// grant this process opened.
    nonce: String,
    open: BTreeMap<String, OpenGrant>,
    /// The rows [`BuildGrants::next_row`] named whose registration has not
    /// ended yet, by row, with the box each is for. They count toward the
    /// cap as open grants do.
    reserved: BTreeMap<String, boxes::SessionId>,
    /// Counts grants, so each row has a name of its own.
    opened: u64,
    /// The epoch the guest daemon's last good list reported.
    guest_epoch: Option<String>,
    /// The boxes whose table [`BuildGrants::drop_table`] ended in this
    /// process, the most recent [`MAX_ENDED_BOXES`] of them. A box id is
    /// never used again, so a part of a table filed after its box's end is
    /// dropped, never a table.
    ended: BTreeSet<boxes::SessionId>,
    /// The ids in `ended`, oldest first, so the oldest leaves at the bound.
    ended_order: VecDeque<boxes::SessionId>,
}

impl Default for State {
    fn default() -> Self {
        // The last group of a fresh id is its random part.
        let minted = boxes::SessionId::mint().to_string();
        let nonce = minted.rsplit('-').next().unwrap_or(&minted).to_string();
        Self {
            tables: BTreeMap::new(),
            no_network: BTreeSet::new(),
            filed_at: BTreeMap::new(),
            changes: 0,
            nonce,
            open: BTreeMap::new(),
            reserved: BTreeMap::new(),
            opened: 0,
            guest_epoch: None,
            ended: BTreeSet::new(),
            ended_order: VecDeque::new(),
        }
    }
}

impl State {
    /// Remembers that the table of `session_id` ended. Past
    /// [`MAX_ENDED_BOXES`], the oldest id leaves: a late part of a table
    /// arrives within moments of its box's end, not after that many ends.
    fn note_ended(&mut self, session_id: boxes::SessionId) {
        if !self.ended.insert(session_id) {
            return;
        }
        self.ended_order.push_back(session_id);
        while self.ended_order.len() > MAX_ENDED_BOXES {
            if let Some(oldest) = self.ended_order.pop_front() {
                self.ended.remove(&oldest);
            }
        }
    }
}

/// The box tables and the open grants, shared by every clone.
#[derive(Debug, Clone, Default)]
pub struct BuildGrants {
    state: Arc<Mutex<State>>,
    persisted_at: Option<Arc<PathBuf>>,
    /// Serializes a table change with its write, so the last write to land
    /// is of the newest tables.
    persist_turn: Arc<Mutex<()>>,
    sweeping: Arc<AtomicBool>,
}

impl BuildGrants {
    /// The same grants, reading and keeping their tables at `path`. A file
    /// that cannot be read, does not parse or is of another version is set
    /// aside, said as a warn line, and no table reloads. When it cannot be
    /// set aside, this process persists no table, so the file stays as it is.
    pub(crate) fn persisting_to(mut self, path: PathBuf) -> Self {
        match read_tables_file(&path) {
            // A reloaded table counts as filed before any mark, so the
            // second good list that leaves its box out ends it.
            Ok((tables, no_network)) => {
                let mut state = self.lock();
                state.tables = tables;
                state.no_network = no_network;
            }
            Err(why) => {
                if !set_aside_tables_file(&path, &why) {
                    return self;
                }
            }
        }
        self.persisted_at = Some(Arc::new(path));
        self
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Changes the tables with `change` and writes them, both in one persist
    /// turn. `change` answers whether it changed anything to write.
    fn change_tables(&self, change: impl FnOnce(&mut State) -> bool) {
        let _turn = self
            .persist_turn
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let (tables, no_network) = {
            let mut state = self.lock();
            if !change(&mut state) {
                return;
            }
            (state.tables.clone(), state.no_network.clone())
        };
        let Some(path) = &self.persisted_at else {
            return;
        };
        let file = BuildTablesFile {
            version: BUILD_TABLES_FILE_VERSION,
            tables,
            no_network,
        };
        if let Err(error) = crate::box_registry::write_registry_file(path, &file) {
            tracing::warn!(%error, "could not persist the box tables");
        }
    }

    /// Files `table` for the box `session_id`, beside what it already holds:
    /// a table too long for one request line comes in parts. A part for a
    /// box whose table ended files nothing: the box is gone, and its part
    /// arrived after the end.
    pub fn file(&self, session_id: boxes::SessionId, table: BuildGrantTable) {
        self.change_tables(|state| {
            if state.ended.contains(&session_id) {
                tracing::info!(
                    session = %session_id,
                    "dropped a part of a build table that arrived after its box ended"
                );
                return false;
            }
            if state.no_network.contains(&session_id) {
                tracing::info!(
                    session = %session_id,
                    "dropped a part of a build table for a box with no network"
                );
                return false;
            }
            state.tables.entry(session_id).or_default().extend(table);
            state.changes += 1;
            let at = state.changes;
            state.filed_at.insert(session_id, at);
            true
        });
    }

    /// Records that the box `session_id` has the network mode `none`, as `min`
    /// filed it: the box holds no table from here on, and gets no grant.
    pub fn file_no_network(&self, session_id: boxes::SessionId) {
        self.change_tables(|state| {
            if state.ended.contains(&session_id) {
                return false;
            }
            state.tables.remove(&session_id);
            state.filed_at.remove(&session_id);
            state
                .reserved
                .retain(|_, reserved_for| *reserved_for != session_id);
            state.no_network.insert(session_id)
        });
    }

    /// Whether `min` filed the box `session_id` with the network mode `none`.
    pub(crate) fn has_no_network(&self, session_id: boxes::SessionId) -> bool {
        self.lock().no_network.contains(&session_id)
    }

    /// Ends the table of the box `session_id`, which is gone, and every grant
    /// open for it, handing back their withdrawals. A grant whose
    /// registration is still running ends when it lands
    /// ([`Self::opened`]).
    pub fn drop_table(&self, session_id: boxes::SessionId) -> Vec<WithdrawBoxRequest> {
        let mut withdrawals = Vec::new();
        self.change_tables(|state| {
            state.note_ended(session_id);
            state
                .reserved
                .retain(|_, reserved_for| *reserved_for != session_id);
            let ended: Vec<String> = state
                .open
                .iter()
                .filter(|(_, grant)| grant.session_id == session_id)
                .map(|(row, _)| row.clone())
                .collect();
            withdrawals = ended
                .iter()
                .filter_map(|row| state.open.remove(row))
                .map(|grant| grant.withdrawal)
                .collect();
            state.filed_at.remove(&session_id);
            let no_network = state.no_network.remove(&session_id);
            state.tables.remove(&session_id).is_some() || no_network
        });
        withdrawals
    }

    /// The changes so far ([`BuildGrantMark`]).
    pub(crate) fn mark(&self) -> BuildGrantMark {
        BuildGrantMark(self.lock().changes)
    }

    /// Whether any table or grant stands, so a reconcile has something to
    /// end.
    pub(crate) fn holds_any(&self) -> bool {
        let state = self.lock();
        !state.tables.is_empty() || !state.open.is_empty() || !state.no_network.is_empty()
    }

    /// Ends what stands for boxes the in-VM daemon's list `listed` leaves
    /// out, handing back the withdrawals of the grants it ends. `listed` was
    /// read after `mark`. A grant opened at or before `mark` ends: its box
    /// asked for it, so a list that leaves the box out is one the box left,
    /// or one a restarted guest daemon wrote after its builds died. A table
    /// ends when it was last filed at or before `previous`, the mark of the
    /// good list read before this one, and ends the box's reservations and
    /// every grant still open for it with it. `min` files a table once the
    /// in-VM daemon has created the box's record, which its list holds from
    /// then on in every state until the box's teardown. A list read that
    /// began before the filing can still predate the box, so a table is only
    /// read as left over once a whole list read went by after its filing.
    ///
    /// The guest controls its list, so a false absence can end a box's
    /// table and grants while it runs. That only takes network away from
    /// its builds, which then follow the box's own rules.
    pub(crate) fn end_absent(
        &self,
        listed: &BTreeSet<boxes::SessionId>,
        mark: BuildGrantMark,
        previous: Option<BuildGrantMark>,
    ) -> Vec<WithdrawBoxRequest> {
        let mut withdrawals = Vec::new();
        self.change_tables(|state| {
            let ended: Vec<String> = state
                .open
                .iter()
                .filter(|(_, grant)| {
                    !listed.contains(&grant.session_id) && grant.opened_at <= mark.0
                })
                .map(|(row, _)| row.clone())
                .collect();
            withdrawals = ended
                .iter()
                .filter_map(|row| state.open.remove(row))
                .map(|grant| grant.withdrawal)
                .collect();
            let Some(previous) = previous else {
                return false;
            };
            let left: Vec<boxes::SessionId> = state
                .tables
                .keys()
                .filter(|session| !listed.contains(session))
                .filter(|session| {
                    state
                        .filed_at
                        .get(session)
                        .is_none_or(|at| *at <= previous.0)
                })
                .copied()
                .collect();
            for session in &left {
                tracing::info!(
                    session = %session,
                    "ended the build table of a box the VM no longer lists"
                );
                state.tables.remove(session);
                state.filed_at.remove(session);
                state
                    .reserved
                    .retain(|_, reserved_for| reserved_for != session);
                state.note_ended(*session);
                // A grant opened after `mark` outlived the sweep above, and
                // ends with its table, as it does on a drop.
                let rows: Vec<String> = state
                    .open
                    .iter()
                    .filter(|(_, grant)| grant.session_id == *session)
                    .map(|(row, _)| row.clone())
                    .collect();
                withdrawals.extend(
                    rows.iter()
                        .filter_map(|row| state.open.remove(row))
                        .map(|grant| grant.withdrawal),
                );
            }
            // A box filed with no network has no table to end, so the same
            // list ends its record.
            let quiet: Vec<boxes::SessionId> = state
                .no_network
                .iter()
                .filter(|session| !listed.contains(session))
                .copied()
                .collect();
            for session in &quiet {
                state.no_network.remove(session);
            }
            !left.is_empty() || !quiet.is_empty()
        });
        withdrawals
    }

    /// What the box's table holds for `spec_hash`.
    pub fn lookup(&self, session_id: boxes::SessionId, spec_hash: &str) -> Option<BuildGrant> {
        self.lock().tables.get(&session_id)?.get(spec_hash).cloned()
    }

    /// Reserves the next grant's row and names it, or `None` at the cap or
    /// when the box's table has ended. The reservation counts toward the cap
    /// until [`Self::opened`] or [`Self::unreserve`] ends it.
    pub(crate) fn next_row(&self, session_id: boxes::SessionId) -> Option<String> {
        let mut state = self.lock();
        // The table is read under the reservation's own lock, so a table that
        // ends after the caller's lookup leaves nothing to reserve.
        if !state.tables.contains_key(&session_id)
            || state.no_network.contains(&session_id)
            || state.open.len() + state.reserved.len() >= MAX_OPEN_GRANTS
        {
            return None;
        }
        state.opened += 1;
        let row = format!("build-{session_id}-{}-{}", state.nonce, state.opened);
        state.reserved.insert(row.clone(), session_id);
        Some(row)
    }

    /// Ends the reservation of `row`, whose registration failed.
    pub(crate) fn unreserve(&self, row: &str) {
        self.lock().reserved.remove(row);
    }

    /// Records a grant that opened, for its deadline and its close. Returns
    /// whether it stands: `false` when its box's table ended while it
    /// registered, so the caller withdraws it at once.
    pub(crate) fn opened(&self, withdrawal: WithdrawBoxRequest, deadline: Instant) -> bool {
        let mut state = self.lock();
        let Some(session_id) = state.reserved.remove(&withdrawal.name) else {
            return false;
        };
        state.changes += 1;
        let opened_at = state.changes;
        let epoch = state.guest_epoch.clone();
        state.open.insert(
            withdrawal.name.clone(),
            OpenGrant {
                session_id,
                deadline,
                withdrawal,
                opened_at,
                epoch,
            },
        );
        true
    }

    /// Records the epoch `epoch` that the guest daemon's list reported, and
    /// ends every grant opened under an earlier epoch, handing back their
    /// withdrawals. The first epoch reported is taken as the one the open
    /// grants run under. A reservation still registering ends with an epoch
    /// change. A list with no epoch changes nothing.
    pub(crate) fn note_guest_epoch(&self, epoch: Option<&str>) -> Vec<WithdrawBoxRequest> {
        let Some(epoch) = epoch else {
            return Vec::new();
        };
        let mut state = self.lock();
        match state.guest_epoch.as_deref() {
            Some(known) if known == epoch => Vec::new(),
            None => {
                state.guest_epoch = Some(epoch.to_string());
                for grant in state.open.values_mut() {
                    grant.epoch.get_or_insert_with(|| epoch.to_string());
                }
                Vec::new()
            }
            Some(_) => {
                tracing::info!(
                    epoch,
                    "the guest daemon restarted; ending its earlier grants"
                );
                state.guest_epoch = Some(epoch.to_string());
                state.reserved.clear();
                let ended: Vec<String> = state
                    .open
                    .iter()
                    .filter(|(_, grant)| grant.epoch.as_deref() != Some(epoch))
                    .map(|(row, _)| row.clone())
                    .collect();
                ended
                    .iter()
                    .filter_map(|row| state.open.remove(row))
                    .map(|grant| grant.withdrawal)
                    .collect()
            }
        }
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

/// Reads the tables persisted at `path`: none when there is no file yet, and
/// the reason when the file cannot be used.
type PersistedTables = (
    BTreeMap<boxes::SessionId, BuildGrantTable>,
    BTreeSet<boxes::SessionId>,
);

fn read_tables_file(path: &std::path::Path) -> Result<PersistedTables, String> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((BTreeMap::new(), BTreeSet::new()));
        }
        Err(error) => return Err(error.to_string()),
    };
    let file = serde_json_lenient::from_slice::<BuildTablesFile>(&bytes)
        .map_err(|error| error.to_string())?;
    if file.version != BUILD_TABLES_FILE_VERSION {
        return Err(format!(
            "version {}, this build reads {BUILD_TABLES_FILE_VERSION}",
            file.version
        ));
    }
    Ok((file.tables, file.no_network))
}

/// Renames an unusable tables file aside under the `.unusable-<unix seconds>`
/// suffix an unusable registry file takes, naming `why`, so the first write
/// does not replace it. Returns whether it was set aside.
fn set_aside_tables_file(path: &std::path::Path, why: &str) -> bool {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let mut aside = path.as_os_str().to_owned();
    aside.push(format!(".unusable-{stamp}"));
    let aside = PathBuf::from(aside);
    match std::fs::rename(path, &aside) {
        Ok(()) => {
            tracing::warn!(
                path = %path.display(),
                aside = %aside.display(),
                why,
                "the persisted build tables are unusable; they are set aside and no table \
                 reloads, so those boxes' builds follow their own rules"
            );
            true
        }
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                why,
                %error,
                "the persisted build tables are unusable and could not be set aside; no \
                 table reloads and none is persisted by this process"
            );
            false
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
        let id = boxes::SessionId::mint();
        grants.file(id, table("aa", false));
        let now = Instant::now();
        let deadline = grant_deadline(now, false);
        assert_eq!(deadline, now + FETCH_GRANT_DEADLINE);
        assert_eq!(grant_deadline(now, true), now + BUILD_GRANT_DEADLINE);

        let first = grants.next_row(id).expect("room under the cap");
        assert!(grants.opened(withdrawal(&first), deadline));
        assert!(grants.take_expired(now).is_empty());
        let expired = grants.take_expired(deadline);
        assert_eq!(expired, [withdrawal(&first)]);

        let second = grants.next_row(id).expect("room under the cap");
        assert!(grants.opened(withdrawal(&second), deadline));
        assert!(grants.take("the-requesters-own-row").is_none());
        assert_eq!(grants.take(&second), Some(withdrawal(&second)));
        assert!(grants.take_expired(deadline).is_empty(), "it already ended");
    }

    /// NET-165: a guest asking in a loop stops at the cap, and a row still
    /// registering counts toward it, so asks that race cannot pass it.
    #[test]
    fn open_grants_stop_at_the_cap() {
        let grants = BuildGrants::default();
        let id = boxes::SessionId::mint();
        grants.file(id, table("aa", false));
        let far = Instant::now() + BUILD_GRANT_DEADLINE;
        let rows: Vec<String> = (0..MAX_OPEN_GRANTS)
            .map(|_| grants.next_row(id).expect("room under the cap"))
            .collect();
        assert!(grants.next_row(id).is_none(), "reservations hold the cap");

        grants.unreserve(&rows[0]);
        assert!(!grants.opened(withdrawal(&rows[0]), far), "it was released");
        for row in &rows[1..] {
            assert!(grants.opened(withdrawal(row), far));
        }
        let last = grants.next_row(id).expect("the released room");
        assert!(grants.opened(withdrawal(&last), far));
        assert!(grants.next_row(id).is_none());
    }

    /// NET-165: a box's table ends with the box, and so does every grant
    /// open for it, and a grant still registering stands no more. Another
    /// box's grants stay.
    #[test]
    fn a_dropped_table_ends_its_boxs_grants() {
        let grants = BuildGrants::default();
        let (id, other) = (boxes::SessionId::mint(), boxes::SessionId::mint());
        grants.file(id, table("aa", false));
        grants.file(other, table("aa", false));
        let far = Instant::now() + BUILD_GRANT_DEADLINE;
        let open = grants.next_row(id).expect("room under the cap");
        assert!(grants.opened(withdrawal(&open), far));
        let registering = grants.next_row(id).expect("room under the cap");
        let others = grants.next_row(other).expect("room under the cap");
        assert!(grants.opened(withdrawal(&others), far));

        assert_eq!(grants.drop_table(id), [withdrawal(&open)]);
        assert!(grants.lookup(id, "aa").is_none());
        assert!(!grants.opened(withdrawal(&registering), far));
        assert!(grants.take(&open).is_none());
        assert_eq!(grants.take(&others), Some(withdrawal(&others)));
    }

    /// NET-165: a box whose table ended reserves no row, so a grant asked
    /// for after its lookup cannot open once the table is gone.
    #[test]
    fn no_row_is_reserved_after_the_table_ends() {
        let grants = BuildGrants::default();
        let id = boxes::SessionId::mint();
        assert!(grants.next_row(id).is_none(), "no table was filed");
        grants.file(id, table("aa", false));
        assert!(grants.lookup(id, "aa").is_some());
        grants.drop_table(id);
        assert!(grants.next_row(id).is_none(), "the table ended");
    }

    /// NET-165: a part of a table that arrives after its box's table ended
    /// files nothing, so no table stands for a box that is gone.
    #[test]
    fn a_part_filed_after_the_table_ends_files_nothing() {
        let grants = BuildGrants::default();
        let id = boxes::SessionId::mint();
        grants.file(id, table("aa", false));
        grants.drop_table(id);
        grants.file(id, table("bb", false));
        assert!(grants.lookup(id, "aa").is_none());
        assert!(grants.lookup(id, "bb").is_none());
        assert!(grants.next_row(id).is_none(), "no table stands");

        let early = boxes::SessionId::mint();
        grants.drop_table(early);
        grants.file(early, table("aa", false));
        assert!(
            grants.lookup(early, "aa").is_none(),
            "a box that ended before its first part has no table either"
        );
    }

    /// The ended boxes are remembered up to a bound, whatever ids the
    /// guest names: past it, the oldest is forgotten first.
    #[test]
    fn the_ended_boxes_stay_within_their_bound() {
        let grants = BuildGrants::default();
        let first = boxes::SessionId::mint();
        grants.drop_table(first);
        grants.drop_table(first);
        for _ in 0..MAX_ENDED_BOXES {
            grants.drop_table(boxes::SessionId::mint());
        }
        let state = grants.lock();
        assert_eq!(state.ended.len(), MAX_ENDED_BOXES);
        assert_eq!(state.ended_order.len(), MAX_ENDED_BOXES);
        assert!(!state.ended.contains(&first), "the oldest left first");
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

    /// A tables file that does not parse is set aside, not written over, and
    /// no table reloads from it.
    #[test]
    fn an_unusable_tables_file_is_set_aside() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(BUILD_TABLES_FILE);
        std::fs::write(&path, b"{ not json").unwrap();
        let id = boxes::SessionId::mint();
        let grants = BuildGrants::default().persisting_to(path.clone());
        assert!(grants.lookup(id, "aa").is_none());
        let aside: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.starts_with(&format!("{BUILD_TABLES_FILE}.unusable-")))
            .collect();
        assert_eq!(aside.len(), 1, "{aside:?}");

        grants.file(id, table("aa", false));
        let reloaded = BuildGrants::default().persisting_to(path);
        assert!(reloaded.lookup(id, "aa").is_some());
    }

    /// NET-165: a process names its grant rows apart from every other
    /// process's, so a close the guest sends for a row named before a
    /// restart ends no grant this process opened.
    #[test]
    fn a_restarted_process_names_its_grant_rows_apart() {
        let id = boxes::SessionId::mint();
        let before = BuildGrants::default();
        before.file(id, table("aa", false));
        let after = BuildGrants::default();
        after.file(id, table("aa", false));
        let far = Instant::now() + BUILD_GRANT_DEADLINE;
        let stale = before.next_row(id).expect("room under the cap");
        let fresh = after.next_row(id).expect("room under the cap");
        assert_ne!(stale, fresh);
        assert!(after.opened(withdrawal(&fresh), far));
        assert!(after.take(&stale).is_none(), "the stale close ends nothing");
        assert_eq!(after.take(&fresh), Some(withdrawal(&fresh)));
    }

    /// NET-165: a good guest list ends the grants of every box it leaves
    /// out, as after a guest daemon's restart. A box it lists keeps its
    /// grant, and so does a grant opened after the list's mark.
    #[test]
    fn a_guest_list_ends_the_grants_of_the_boxes_it_leaves_out() {
        let grants = BuildGrants::default();
        let (gone, live) = (boxes::SessionId::mint(), boxes::SessionId::mint());
        grants.file(gone, table("aa", true));
        grants.file(live, table("aa", true));
        let far = Instant::now() + BUILD_GRANT_DEADLINE;
        let stale = grants.next_row(gone).expect("room under the cap");
        assert!(grants.opened(withdrawal(&stale), far));
        let kept = grants.next_row(live).expect("room under the cap");
        assert!(grants.opened(withdrawal(&kept), far));
        let mark = grants.mark();
        let late = grants.next_row(gone).expect("room under the cap");
        assert!(grants.opened(withdrawal(&late), far));

        let listed = BTreeSet::from([live]);
        assert_eq!(grants.end_absent(&listed, mark, None), [withdrawal(&stale)]);
        assert!(grants.take(&kept).is_some(), "a listed box keeps its grant");
        assert!(
            grants.take(&late).is_some(),
            "a grant newer than the list stays"
        );
        assert!(
            grants.lookup(gone, "aa").is_some(),
            "a table waits for a whole list read after its filing"
        );
    }

    /// NET-165: a box's table, its end signal lost, ends once a whole good
    /// list read went by after its filing and the next list leaves the box
    /// out. A table filed during that read stays, because its box can
    /// still be starting.
    #[test]
    fn a_table_of_a_box_the_guest_list_leaves_out_ends() {
        let grants = BuildGrants::default();
        let (gone, starting) = (boxes::SessionId::mint(), boxes::SessionId::mint());
        grants.file(gone, table("aa", false));
        let first = grants.mark();
        let none = BTreeSet::new();
        assert!(grants.end_absent(&none, first, None).is_empty());
        assert!(grants.lookup(gone, "aa").is_some());
        grants.file(starting, table("aa", false));
        let second = grants.mark();
        assert!(grants.end_absent(&none, second, Some(first)).is_empty());
        assert!(
            grants.lookup(gone, "aa").is_none(),
            "the left-over table ended"
        );
        assert!(grants.lookup(starting, "aa").is_some());
        assert!(grants.holds_any());
    }

    /// NET-165: a new guest daemon epoch ends the grants opened under the
    /// earlier one, and a grant opened under the new one stays. The first
    /// epoch reported keeps the grants already open.
    #[test]
    fn a_new_guest_epoch_ends_the_earlier_grants() {
        let grants = BuildGrants::default();
        let id = boxes::SessionId::mint();
        grants.file(id, table("aa", true));
        let far = Instant::now() + BUILD_GRANT_DEADLINE;
        let before = grants.next_row(id).expect("room under the cap");
        assert!(grants.opened(withdrawal(&before), far));
        assert!(grants.note_guest_epoch(Some("one")).is_empty());
        assert!(grants.note_guest_epoch(None).is_empty());
        assert!(grants.note_guest_epoch(Some("one")).is_empty());
        let registering = grants.next_row(id).expect("room under the cap");

        assert_eq!(grants.note_guest_epoch(Some("two")), [withdrawal(&before)]);
        assert!(grants.take(&before).is_none());
        assert!(
            !grants.opened(withdrawal(&registering), far),
            "a registration from the earlier epoch stands no more"
        );
        let after = grants.next_row(id).expect("room under the cap");
        assert!(grants.opened(withdrawal(&after), far));
        assert!(grants.note_guest_epoch(Some("two")).is_empty());
        assert_eq!(grants.take(&after), Some(withdrawal(&after)));
    }

    /// NET-165: a box `min` filed with the network mode `none` holds no table
    /// and reserves no grant, whatever table part arrives for it, and the
    /// record survives a restart.
    #[test]
    fn a_box_filed_with_no_network_gets_no_grant() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(BUILD_TABLES_FILE);
        let grants = BuildGrants::default().persisting_to(path.clone());
        let (none, open) = (boxes::SessionId::mint(), boxes::SessionId::mint());
        grants.file(none, table("aa", true));
        grants.file_no_network(none);
        grants.file(none, table("bb", true));
        grants.file(open, table("aa", true));
        assert!(grants.has_no_network(none));
        assert!(grants.lookup(none, "aa").is_none());
        assert!(grants.lookup(none, "bb").is_none());
        assert!(grants.next_row(none).is_none());
        assert!(grants.next_row(open).is_some(), "another box is unchanged");

        let reloaded = BuildGrants::default().persisting_to(path);
        assert!(reloaded.has_no_network(none));
        assert!(reloaded.next_row(none).is_none());

        grants.drop_table(none);
        assert!(!grants.has_no_network(none));
    }

    /// NET-165: a grant opened after the list's mark ends with its box's
    /// table when the same list ends that table, so no grant outlives it.
    #[test]
    fn a_table_the_guest_list_ends_takes_its_late_grants() {
        let grants = BuildGrants::default();
        let gone = boxes::SessionId::mint();
        grants.file(gone, table("aa", false));
        let first = grants.mark();
        let none = BTreeSet::new();
        assert!(grants.end_absent(&none, first, None).is_empty());
        let second = grants.mark();
        let far = Instant::now() + BUILD_GRANT_DEADLINE;
        let late = grants.next_row(gone).expect("room under the cap");
        assert!(grants.opened(withdrawal(&late), far));
        assert_eq!(
            grants.end_absent(&none, second, Some(first)),
            [withdrawal(&late)]
        );
        assert!(grants.lookup(gone, "aa").is_none(), "the table ended");
        assert!(grants.take(&late).is_none(), "the grant ended with it");
        assert!(!grants.holds_any());
    }

    /// NET-165: a grant still registering when the guest list ends its
    /// box's table stands no more, as when the table drops.
    #[test]
    fn a_table_the_guest_list_ends_takes_its_reservations() {
        let grants = BuildGrants::default();
        let gone = boxes::SessionId::mint();
        grants.file(gone, table("aa", false));
        let registering = grants.next_row(gone).expect("room under the cap");
        let first = grants.mark();
        let none = BTreeSet::new();
        assert!(grants.end_absent(&none, first, None).is_empty());
        let second = grants.mark();
        assert!(grants.end_absent(&none, second, Some(first)).is_empty());
        assert!(grants.lookup(gone, "aa").is_none(), "the table ended");
        let far = Instant::now() + BUILD_GRANT_DEADLINE;
        assert!(!grants.opened(withdrawal(&registering), far));
        assert!(!grants.holds_any());
    }
}
