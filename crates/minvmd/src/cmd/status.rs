//! `minvmd status` subcommand (R4.3).
//!
//! Reads the daemon state and prints it.
//! A non-blocking advisory read lock is attempted on `lifecycle.lock` to detect
//! concurrent lifecycle transitions; if the lock cannot be acquired the command
//! exits with code 2 (lock contention).
//!
//! With `--row <name>` it reads one box's row through the control socket
//! instead (NET-138) and prints the read-only row verb's reply.
//!
//! Exit codes:
//! - 0 — daemon is Running, or a `--row` read answered with a live box's row
//! - 1 — daemon is stopped (or not yet provisioned), or a `--row` read
//!   answered with the no-row marker
//! - 2 — lock contention; another process is transitioning state

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context as _, Result};
use serde::Serialize;

use crate::lifecycle::Lifecycle;
use crate::metrics::VmMetrics;
use crate::state::{State, StateDir};
use minimald_rpc::{BoxControlReply, BoxControlRequest, BoxRow, ReadRowRequest};

/// Exit classification returned by [`run`].
#[derive(Debug, PartialEq, Eq)]
pub enum StatusExit {
    /// Daemon is `Running` — exit code 0.
    Running,
    /// Daemon is not running — exit code 1.
    Stopped,
    /// Could not acquire the advisory read lock — exit code 2.
    LockContention,
    /// A `--row` read answered with a live box's row — exit code 0.
    Row,
    /// A `--row` read answered with the no-row marker — exit code 1.
    NoRow,
}

impl StatusExit {
    /// Numeric process exit code for this status.
    pub fn code(&self) -> i32 {
        match self {
            Self::Running => 0,
            Self::Stopped => 1,
            Self::LockContention => 2,
            Self::Row => 0,
            Self::NoRow => 1,
        }
    }
}

/// Run the `status` subcommand.
///
/// `json`: if true, print a JSON object; otherwise print a human-readable line.
/// `row`: when `Some(name)`, print the read-only row verb's reply for that
/// box's row instead of the lifecycle report.
pub fn run(json: bool, row: Option<String>) -> Result<StatusExit> {
    match row {
        Some(name) => run_row_read(json, &name),
        None => run_with_state_dir(json, StateDir::default_path()),
    }
}

/// How long the row read waits for the daemon's one reply line before
/// giving up on the socket: the daemon answers the read-only verb from
/// memory, so a read that outlives this is a daemon that is not answering.
const ROW_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// What a `--row` read answered: the row a live box holds, or the no-row
/// marker for a name no live box holds.
enum RowRead {
    /// The read-only row verb's answer for a live box.
    Row(BoxRow),
    /// The read-only row verb's answer for a name no live box holds.
    NoRow { name: String },
}

/// Run a `--row <name>` read (NET-138): ask the VM host daemon for the box's
/// row over its control socket, print the reply, and classify the exit — a
/// row is 0, the no-row marker 1 — so a script can watch a box's row go
/// without parsing the reply.
fn run_row_read(json: bool, name: &str) -> Result<StatusExit> {
    let sock_path = crate::control::resolve_control_sock()
        .context("resolving the VM host daemon's control socket")?;
    let reply = read_box_row(&sock_path, name)?;
    let read = match reply {
        BoxControlReply::Row(row) => RowRead::Row(row),
        BoxControlReply::NoRow { name, .. } => RowRead::NoRow { name },
        // The reply shapes are disjoint, so this arm is a daemon speaking
        // another verb's answer to the read — not the row asked for.
        other => anyhow::bail!(
            "the VM host daemon answered the row read for {name:?} with another \
             verb's reply: {other:?}"
        ),
    };
    println!("{}", row_read_text(&read, json)?);
    Ok(match read {
        RowRead::Row(_) => StatusExit::Row,
        RowRead::NoRow { .. } => StatusExit::NoRow,
    })
}

/// Ask the daemon for the box's row: one JSON request line in, one JSON
/// reply line back, the control protocol's own exchange — so the read
/// answers what the daemon's table holds, never what this process could
/// derive from the state dir.
fn read_box_row(sock_path: &Path, name: &str) -> Result<BoxControlReply> {
    let mut stream = UnixStream::connect(sock_path).with_context(|| {
        format!(
            "connecting the VM host daemon's control socket at {}",
            sock_path.display()
        )
    })?;
    stream
        .set_read_timeout(Some(ROW_READ_TIMEOUT))
        .context("setting the row read's reply timeout")?;
    let mut line = serde_json_lenient::to_string(&BoxControlRequest::ReadRow(ReadRowRequest {
        name: name.to_string(),
    }))
    .context("serialising the row read request")?;
    line.push('\n');
    stream
        .write_all(line.as_bytes())
        .context("writing the row read request")?;
    let mut reply = String::new();
    BufReader::new(&mut stream)
        .read_line(&mut reply)
        .context("reading the row read reply")?;
    if reply.trim().is_empty() {
        anyhow::bail!(
            "the VM host daemon closed its control socket without answering the row read"
        );
    }
    serde_json_lenient::from_str(reply.trim())
        .with_context(|| format!("the VM host daemon's row read reply did not parse: {reply}"))
}

/// The reply's printed text: the `--json` document or the human line, as
/// the reply's own shape either way — the row with the facts the host holds
/// about the box, the no-row marker with the name asked about.
fn row_read_text(read: &RowRead, json: bool) -> Result<String> {
    match read {
        RowRead::Row(row) if json => {
            Ok(serde_json_lenient::to_string(row).context("serialising the box row")?)
        }
        RowRead::NoRow { name } if json => {
            Ok(serde_json_lenient::to_string(&BoxControlReply::NoRow {
                name: name.clone(),
                no_row: true,
            })
            .context("serialising the no-row marker")?)
        }
        RowRead::Row(row) => Ok(format!(
            "box {} switch {} allow [{}] declared [{}] runtime [{}]",
            row.name,
            row.switch_address,
            row.egress_allow_list.join(","),
            ports_text(&row.declared_ports),
            ports_text(&row.runtime_ports),
        )),
        RowRead::NoRow { name } => Ok(format!("no row for {name}")),
    }
}

/// A port list's human spelling: comma-separated, no brackets — the line
/// adds those.
fn ports_text(ports: &[u16]) -> String {
    ports
        .iter()
        .map(|port| port.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn run_with_state_dir(json: bool, dir: std::path::PathBuf) -> Result<StatusExit> {
    let state_dir = StateDir::new(dir).context("opening state dir")?;

    // Non-blocking read lock: detect concurrent state transitions (R4.3).
    // Dropped before effective_state, which may take the write lock to repair
    // stale state (same-process fds would deadlock otherwise).
    {
        let rw = state_dir
            .lifecycle_lock()
            .context("opening lifecycle lock")?;
        if rw.try_read().is_err() {
            return Ok(StatusExit::LockContention);
        }
    }

    let state = state_dir.effective_state().context("reading state")?;

    let uptime_seconds = state.started_at.and_then(|started| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();
        Some(now.saturating_sub(started))
    });

    // Sample live host-visible metrics only for a running VM with a tracked
    // PID (R9.1); reading process stats does not disturb the VM (R9.2).
    let metrics = match (state.lifecycle, state.vmm_pid) {
        (Lifecycle::Running, Some(pid)) => crate::metrics::sample(pid),
        _ => None,
    };

    let (vcpus, ram_mib) = reported_resources(&state);
    let report = build_report(&state, uptime_seconds, vcpus, ram_mib, metrics);

    if json {
        print_json(&report)?;
    } else {
        print_human(&report);
    }

    Ok(match state.lifecycle {
        Lifecycle::Running => StatusExit::Running,
        _ => StatusExit::Stopped,
    })
}

/// The serialised shape of `minvmd status --json` (R4.3 + R9.1). `vcpus` and
/// `ram_mib` are the values the running VM booted with (or the effective
/// next-boot resolution when stopped). `metrics` is `null` unless the VM is
/// running.
#[derive(Debug, Serialize)]
struct StatusReport {
    state: &'static str,
    vmm_pid: Option<u32>,
    uptime_seconds: Option<u64>,
    vcpus: u8,
    ram_mib: u32,
    metrics: Option<VmMetrics>,
}

/// Assemble the report from already-resolved inputs. Pure (no I/O) so the JSON
/// shape is unit-testable without a live VM.
fn build_report(
    state: &State,
    uptime_seconds: Option<u64>,
    vcpus: u8,
    ram_mib: u32,
    metrics: Option<VmMetrics>,
) -> StatusReport {
    StatusReport {
        state: lifecycle_state_str(state.lifecycle),
        vmm_pid: state.vmm_pid,
        uptime_seconds,
        vcpus,
        ram_mib,
        metrics,
    }
}

/// The `vcpus`/`ram_mib` to report. For a *running* VM these are the values it
/// was actually booted with (`State.booted_*`), so the reported figures match
/// the live VM rather than a later `config set`'s next-boot resolution (#747,
/// R2.6). When stopped — or reading a pre-#747 state file with no snapshot —
/// they fall back to the effective (next-boot) resolution, which is the
/// meaningful thing to show for a VM that is not running.
fn reported_resources(state: &State) -> (u8, u32) {
    match (state.lifecycle, state.booted_vcpus, state.booted_ram_mib) {
        // Running with a recorded snapshot: report exactly what the live VM
        // booted with (R2.6).
        (Lifecycle::Running, Some(vcpus), Some(ram_mib)) => (vcpus, ram_mib),
        // Stopped — or a Running VM from a pre-#747 state file with no snapshot —
        // falls back to the effective (next-boot) resolution, resolved from a
        // single config read so the (vcpus, ram_mib) pair cannot tear.
        _ => crate::cmd::effective_resources(),
    }
}

fn lifecycle_state_str(lc: Lifecycle) -> &'static str {
    match lc {
        Lifecycle::NotProvisioned | Lifecycle::Stopped => "stopped",
        Lifecycle::Starting => "starting",
        Lifecycle::Running => "running",
        Lifecycle::Stopping => "stopping",
    }
}

fn print_json(report: &StatusReport) -> Result<()> {
    let json = serde_json_lenient::to_string(report).context("serialising status report")?;
    println!("{json}");
    Ok(())
}

fn print_human(report: &StatusReport) {
    if report.state != "running" {
        println!("{}", report.state);
        return;
    }
    let uptime = report.uptime_seconds.unwrap_or(0);
    let pid = report
        .vmm_pid
        .map(|p| p.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    println!(
        "running (pid={pid}, uptime={uptime}s, vcpus={}, ram={}MiB)",
        report.vcpus, report.ram_mib
    );
    if let Some(m) = &report.metrics {
        println!(
            "  cpu={:.1}% rss={}MiB disk_r={}MiB disk_w={}MiB",
            m.cpu_percent,
            m.resident_bytes / (1024 * 1024),
            m.disk_read_bytes / (1024 * 1024),
            m.disk_written_bytes / (1024 * 1024),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::Lifecycle;
    use crate::state::State;

    fn make_state_dir(tmp: &tempfile::TempDir) -> StateDir {
        StateDir::new(tmp.path().to_path_buf()).expect("StateDir::new")
    }

    #[test]
    fn not_provisioned_exits_stopped() {
        let tmp = tempfile::tempdir().unwrap();
        let exit = run_with_state_dir(false, tmp.path().to_path_buf()).unwrap();
        assert_eq!(exit, StatusExit::Stopped);
    }

    #[test]
    fn stopped_state_exits_stopped() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);
        sd.write_state(&State::stopped()).unwrap();
        let exit = run_with_state_dir(false, tmp.path().to_path_buf()).unwrap();
        assert_eq!(exit, StatusExit::Stopped);
    }

    #[test]
    fn running_state_exits_running() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);
        sd.write_state(&State {
            lifecycle: Lifecycle::Running,
            vmm_pid: Some(12345),
            started_at: Some(1_700_000_000),
            ..State::stopped()
        })
        .unwrap();
        let _lock = sd.try_acquire_alive_lock().unwrap().expect("acquire");
        let exit = run_with_state_dir(false, tmp.path().to_path_buf()).unwrap();
        assert_eq!(exit, StatusExit::Running);
    }

    #[test]
    fn stale_running_state_exits_stopped_and_repairs() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);
        // Running per the state file, but no alive-lock holder.
        sd.write_state(&State {
            lifecycle: Lifecycle::Running,
            vmm_pid: Some(12345),
            started_at: Some(1_700_000_000),
            ..State::stopped()
        })
        .unwrap();
        let exit = run_with_state_dir(false, tmp.path().to_path_buf()).unwrap();
        assert_eq!(exit, StatusExit::Stopped);
        assert_eq!(sd.read_state().unwrap().lifecycle, Lifecycle::Stopped);
    }

    #[test]
    fn starting_state_exits_stopped() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);
        sd.write_state(&State {
            lifecycle: Lifecycle::Starting,
            vmm_pid: None,
            started_at: None,
            ..State::stopped()
        })
        .unwrap();
        let _lock = sd.try_acquire_alive_lock().unwrap().expect("acquire");
        let exit = run_with_state_dir(false, tmp.path().to_path_buf()).unwrap();
        assert_eq!(exit, StatusExit::Stopped);
    }

    #[test]
    fn json_output_contains_required_fields() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);
        sd.write_state(&State {
            lifecycle: Lifecycle::Running,
            vmm_pid: Some(99),
            started_at: Some(0),
            ..State::stopped()
        })
        .unwrap();
        let _lock = sd.try_acquire_alive_lock().unwrap().expect("acquire");
        // run_with_state_dir prints to stdout; verify the exit code at minimum.
        let exit = run_with_state_dir(true, tmp.path().to_path_buf()).unwrap();
        assert_eq!(exit, StatusExit::Running);
    }

    #[test]
    fn lock_contention_exits_2() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);

        // Hold an exclusive write lock and attempt a concurrent status.
        let mut lock = sd.lifecycle_lock().unwrap();
        let _held = lock.write().unwrap();

        let exit = run_with_state_dir(false, tmp.path().to_path_buf()).unwrap();
        assert_eq!(exit, StatusExit::LockContention);
    }

    #[test]
    fn report_schema_when_stopped_has_null_metrics() {
        let report = build_report(&State::stopped(), None, 2, 2048, None);
        let v = serde_json_lenient::to_value(&report).unwrap();
        for key in [
            "state",
            "vmm_pid",
            "uptime_seconds",
            "vcpus",
            "ram_mib",
            "metrics",
        ] {
            assert!(v.get(key).is_some(), "status --json must contain {key}");
        }
        assert_eq!(v["state"], "stopped");
        assert!(v["metrics"].is_null(), "metrics must be null when stopped");
    }

    #[test]
    fn running_reports_booted_snapshot_not_next_boot_resolution() {
        // A VM booted at 2048 MiB / 4 vcpus. Even if `config set` later changed
        // the persisted next-boot values, `status` must report what the live VM
        // actually booted with (R2.6). booted_* set ⇒ no effective_* fallback, so
        // this is deterministic.
        let state = State {
            lifecycle: Lifecycle::Running,
            vmm_pid: Some(1),
            started_at: Some(0),
            booted_vcpus: Some(4),
            booted_ram_mib: Some(2048),
        };
        assert_eq!(reported_resources(&state), (4, 2048));
    }

    #[test]
    fn report_when_running_includes_metrics() {
        let state = State {
            lifecycle: Lifecycle::Running,
            vmm_pid: Some(1),
            started_at: Some(0),
            ..State::stopped()
        };
        let metrics = VmMetrics {
            cpu_percent: 12.5,
            resident_bytes: 1024 * 1024 * 1024,
            disk_read_bytes: 0,
            disk_written_bytes: 0,
        };
        let report = build_report(&state, Some(42), 4, 1024, Some(metrics));
        let v = serde_json_lenient::to_value(&report).unwrap();
        assert_eq!(v["state"], "running");
        assert_eq!(v["vcpus"], 4);
        assert!(
            !v["metrics"].is_null(),
            "metrics must be present when running"
        );
        assert_eq!(v["metrics"]["resident_bytes"], 1024 * 1024 * 1024u64);
    }

    /// A live row as the row read's tests hold it: the shape the read-only
    /// verb answers with.
    fn live_row() -> minimald_rpc::BoxRow {
        minimald_rpc::BoxRow {
            name: "web".to_string(),
            switch_address: "100.64.0.9".parse().unwrap(),
            egress_allow_list: vec!["10.0.0.0/8".to_string()],
            declared_ports: vec![8080],
            runtime_ports: vec![3000, 3001],
        }
    }

    /// The no-row marker's own document shape, so the `--json` text parses
    /// back as the marker and not as a guess at its fields.
    #[derive(serde::Deserialize)]
    struct NoRowShape {
        name: String,
        no_row: bool,
    }

    #[test]
    fn row_read_text_names_the_row_and_the_no_row_marker() {
        let row = RowRead::Row(live_row());
        assert_eq!(
            row_read_text(&row, false).unwrap(),
            "box web switch 100.64.0.9 allow [10.0.0.0/8] declared [8080] runtime [3000,3001]",
            "the human line carries every fact the row read answers with"
        );
        let json: minimald_rpc::BoxRow =
            serde_json_lenient::from_str(&row_read_text(&row, true).unwrap()).unwrap();
        assert_eq!(json, live_row(), "the --json text is the row's own shape");

        let no_row = RowRead::NoRow {
            name: "web".to_string(),
        };
        assert_eq!(
            row_read_text(&no_row, false).unwrap(),
            "no row for web",
            "the human line says the name asked about has no row"
        );
        let json: NoRowShape =
            serde_json_lenient::from_str(&row_read_text(&no_row, true).unwrap()).unwrap();
        assert_eq!(json.name, "web");
        assert!(json.no_row, "the marker keeps the shape its own");
    }

    #[test]
    fn row_read_sends_the_read_and_parses_the_answer() {
        // Serve one canned reply the way the daemon's own control socket
        // answers: one request line in, one reply line back.
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("control.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let (sent_tx, sent_rx) = std::sync::mpsc::channel::<String>();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            std::io::BufReader::new(&mut stream)
                .read_line(&mut line)
                .unwrap();
            sent_tx.send(line).unwrap();
            let mut reply =
                serde_json_lenient::to_string(&minimald_rpc::BoxControlReply::Row(live_row()))
                    .unwrap();
            reply.push('\n');
            use std::io::Write as _;
            stream.write_all(reply.as_bytes()).unwrap();
        });
        let answered = read_box_row(&sock, "web").unwrap();
        server.join().unwrap();

        let sent: minimald_rpc::BoxControlRequest =
            serde_json_lenient::from_str(&sent_rx.recv().unwrap())
                .expect("the row read's request line parses as the control protocol");
        match sent {
            minimald_rpc::BoxControlRequest::ReadRow(request) => assert_eq!(
                request.name, "web",
                "the read asks about the name it was given"
            ),
            other => panic!("the row read sent {other:?}"),
        }
        match answered {
            minimald_rpc::BoxControlReply::Row(row) => {
                assert_eq!(
                    row.switch_address,
                    "100.64.0.9".parse::<std::net::Ipv4Addr>().unwrap()
                );
                assert_eq!(row.runtime_ports, vec![3000, 3001]);
            }
            other => panic!("the row read parsed {other:?}"),
        }
    }
}
