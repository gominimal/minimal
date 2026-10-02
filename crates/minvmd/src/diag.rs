//! The VM host daemon's zone-table dump (NET-138): the table the host
//! answerer answers the box zone from, written as a file a person — or a
//! diagnostic bundle — can read: one row per published namespace, its name
//! under the zone, the address an A lookup may be told, and whether the
//! namespace is running. The same [`BoxRegistry::zone_view`] the answers
//! come from, so a dump and a lookup can never disagree.
//!
//! The dump is this daemon's **own** table, not the machine's answering
//! view: on a host running more than one VM host daemon each writes its own
//! dump beside its own state, and the merged view the holder answers from
//! is the answerer channel's business
//! ([`crate::net::answerer`]), never a file's.
//!
//! It is written once at start — so the file exists and names an empty
//! table before the first box registers — and then on every table change,
//! from the registry's own change pings
//! ([`BoxRegistry::subscribe_table_pings`]), so the file a bundle carries
//! is never staler than the last change the daemon saw. Each write is
//! atomic (a temp file in the same directory, renamed over), so a reader
//! never sees a torn table.

use std::io;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::box_registry::BoxRegistry;

/// The zone table's file name inside this daemon's state dir —
/// `<state>/providers/local-minvmd0[/<vm>/]`, the directory the CLI's
/// diagnostic bundle already walks per VM, so the zone table lands where a
/// bundle's provider listing names it.
pub const ZONE_TABLE_FILE: &str = "zone.json";

/// This daemon's zone-table dump path.
#[must_use]
pub fn zone_table_path() -> PathBuf {
    crate::state::provider_dir().join(ZONE_TABLE_FILE)
}

/// One row of the dump: the name under the zone, the host-answerable
/// address an A lookup is told (`null` when the name is held at an address
/// the host may not be told — the table says the box exists without
/// claiming it is published there), and whether the namespace is running.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct ZoneRowDump {
    /// The full zone name, as the view holds it (`<name>.min.internal`).
    name: String,
    /// The address an A lookup gets, when there is one to tell.
    address: Option<std::net::Ipv4Addr>,
    /// Whether the namespace the name names is running.
    live: bool,
}

/// Starts the zone-table dump: one background thread that writes the table
/// now and on every change, for the daemon's lifetime, the way the answerer
/// and the control socket serve. A thread the host could not spare is the
/// only failure returned, because a dump that cannot be written is a
/// missing diagnostic, never a reason to fail a boot.
///
/// # Errors
///
/// Returns the OS error when the thread cannot be spawned.
pub fn spawn(registry: BoxRegistry) -> io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("minvmd-zone-dump".to_string())
        .spawn(move || dump_loop(registry))
}

/// Writes the table on every change, for as long as the registry pings:
/// subscribed before the first write, so a change that lands during one
/// waits in the channel for the next rather than being missed.
fn dump_loop(registry: BoxRegistry) {
    let pings = registry.subscribe_table_pings();
    loop {
        if let Err(error) = write_table(&registry) {
            tracing::warn!(
                %error,
                "could not write the zone-table dump; the box zone's table is not \
                 on disk for a bundle to carry"
            );
        }
        // The registry outlives its dump thread: its pings end only with
        // the process, so this wait is the daemon's lifetime, one table
        // per change.
        if pings.recv().is_err() {
            return;
        }
    }
}

/// Writes the table once, atomically: a temp file in the dump's own
/// directory, renamed over it, so a reader — a bundle, a person — either
/// sees the whole previous table or the whole new one, never a half of
/// either.
fn write_table(registry: &BoxRegistry) -> io::Result<()> {
    let rows: Vec<ZoneRowDump> = registry
        .zone_view()
        .rows()
        .map(|(name, row)| ZoneRowDump {
            name: name.to_string(),
            address: row.address,
            live: row.live,
        })
        .collect();
    let json = serde_json_lenient::to_vec_pretty(&rows).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the zone table did not serialize: {error}"),
        )
    })?;
    let path = zone_table_path();
    let staging = path.with_extension("tmp");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&staging, json)?;
    std::fs::rename(&staging, &path)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::box_registry::BoxRegistration;

    use super::*;

    /// The written dump, read back: what a bundle's copy of the file holds.
    fn dumped() -> Vec<ZoneRowDump> {
        serde_json_lenient::from_str(
            &std::fs::read_to_string(zone_table_path())
                .expect("the zone-table dump exists where the daemon wrote it"),
        )
        .expect("the zone-table dump parses")
    }

    /// The dump is the answerer's own view, written and re-written: each
    /// row's name, its address (`null` for one the host may not be told, so
    /// the table says the box exists without claiming it is published
    /// there), and its liveness — a stopped namespace is held `live: false`,
    /// never gone — in the name order the view holds.
    #[test]
    fn zone_table_dump_carries_every_row_name_address_and_liveness() {
        let dir = tempfile::TempDir::new().expect("a temp dir for the state base");
        // The state-dir override routes `provider_dir()` — the dump's parent —
        // under the temp base, the same override the daemon's own start
        // applies, so the test writes nowhere outside the temp dir.
        crate::state::set_state_dir_override(
            paths::DaemonAbsPath::try_new(
                dir.path().to_str().expect("the temp dir's path is UTF-8"),
            )
            .expect("the temp dir's path is absolute"),
        );

        let registry = BoxRegistry::new(switch::DEFAULT_SUBNET);
        write_table(&registry).expect("an empty table writes");
        assert!(
            dumped().is_empty(),
            "a fresh table's dump names no rows"
        );

        let web = registry.register(BoxRegistration::new(
            "web",
            Ipv4Addr::new(100, 64, 0, 9),
            Ipv4Addr::new(127, 0, 64, 9),
        ));
        registry.register(BoxRegistration::new(
            "lease-only",
            Ipv4Addr::new(100, 64, 0, 10),
            Ipv4Addr::new(100, 64, 0, 10),
        ));
        write_table(&registry).expect("a full table writes");
        assert_eq!(
            dumped(),
            vec![
                ZoneRowDump {
                    name: "lease-only.min.internal".to_string(),
                    address: None,
                    live: true,
                },
                ZoneRowDump {
                    name: "web.min.internal".to_string(),
                    address: Some(Ipv4Addr::new(127, 0, 64, 9)),
                    live: true,
                },
            ],
            "every row is dumped with its name, address and liveness, in name order"
        );

        // A stopped namespace is held, not gone: the row stays with
        // live: false, the shape a lookup's NODATA answers from.
        assert!(registry.mark_stopped(web.switch_addr()));
        write_table(&registry).expect("a stopped row writes");
        let stopped = dumped();
        assert_eq!(
            stopped
                .iter()
                .find(|row| row.name == "web.min.internal")
                .expect("the stopped row is still held"),
            &ZoneRowDump {
                name: "web.min.internal".to_string(),
                address: Some(Ipv4Addr::new(127, 0, 64, 9)),
                live: false,
            },
            "a stopped namespace dumps live: false"
        );

        // And a withdrawn one takes its name with it.
        assert!(registry.withdraw(web.switch_addr()).is_some());
        write_table(&registry).expect("a withdrawn table writes");
        assert!(
            !dumped()
                .iter()
                .any(|row| row.name == "web.min.internal"),
            "a withdrawn namespace's row is gone from the dump"
        );
    }
}
