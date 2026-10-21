//! `min mirror status` and `min mirror stop`: the surface that stays for
//! the mirror daemon (MIR-060, MIR-070). Neither starts the daemon
//! (MIR-020); the project commands do, through [`super::ensure_mirror`],
//! whose failure text lives here too.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use mirror_client::{MirrorDirs, MirrorEndpoint, StartError};
use serde::Deserialize;

use super::Handoff;
use crate::autospawn::MirrorHandoff;
use crate::{GlobalArgs, MirrorStatusArgs};

/// The request the status report reads.
const STATUS_PATH: &str = "/-/status";

/// How long `min mirror stop` waits for the host socket to stop answering.
const STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// The daemon's status document, as `GET /-/status` answers it on the host
/// socket. Fields the report does not print are left to the daemon.
#[derive(Debug, Deserialize)]
struct StatusDoc {
    pid: u32,
    host_socket: PathBuf,
    #[serde(default)]
    origins: Vec<OriginDoc>,
    disk: DiskDoc,
    #[serde(default)]
    repositories: Vec<RepositoryDoc>,
}

#[derive(Debug, Deserialize)]
struct OriginDoc {
    origin: String,
    /// Seconds since the epoch of the last successful contact.
    last_contact: Option<u64>,
    last_failure: Option<FailureDoc>,
}

#[derive(Debug, Deserialize)]
struct FailureDoc {
    /// Seconds since the epoch.
    at: u64,
    cause: String,
}

#[derive(Debug, Deserialize)]
struct DiskDoc {
    used_bytes: u64,
    protected_bytes: u64,
    budget_bytes: u64,
}

#[derive(Debug, Deserialize)]
struct RepositoryDoc {
    slug: String,
    #[serde(default)]
    heads: Vec<HeadDoc>,
    /// Seconds since the epoch of the last refresh.
    refreshed_at: Option<u64>,
    last_failure: Option<FailureDoc>,
}

#[derive(Debug, Deserialize)]
struct HeadDoc {
    name: String,
    commit: String,
}

/// `min mirror status`: the lines MIR-060 lists, from the running daemon's
/// own account. Prints `mirror: stopped` and exits 1 when no daemon runs,
/// and never starts one.
pub fn cmd_mirror_status(global: &GlobalArgs, args: MirrorStatusArgs) -> Result<(), anyhow::Error> {
    let dirs = MirrorDirs::resolve(global.minimal_dir.as_deref());
    match status_report(&dirs, args.json, mirror_client::now_secs())? {
        Some(report) => {
            print!("{report}");
            Ok(())
        }
        None => {
            println!("mirror: stopped");
            Err(Handoff::Exit(1).into())
        }
    }
}

/// The status report for the daemon under `dirs`, ending in a newline, or
/// `None` when no daemon runs. With `json` the daemon's document is passed
/// through as it came.
fn status_report(dirs: &MirrorDirs, json: bool, now: u64) -> Result<Option<String>, anyhow::Error> {
    let Some(state) = mirror_client::running(dirs) else {
        return Ok(None);
    };
    let endpoint = MirrorEndpoint::Unix(state.host_socket);
    let reply = mirror_client::blocking::get(&endpoint, STATUS_PATH)
        .context("reading the mirror's status")?;
    if reply.status != 200 {
        bail!(
            "the mirror answered {} to the status request: {}",
            reply.status,
            reply.text()
        );
    }
    if json {
        let mut document =
            String::from_utf8(reply.body).context("the mirror's status document is not UTF-8")?;
        if !document.ends_with('\n') {
            document.push('\n');
        }
        return Ok(Some(document));
    }
    let doc: StatusDoc = serde_json_lenient::from_slice(&reply.body)
        .context("parsing the mirror's status document")?;
    Ok(Some(render(&doc, now)))
}

/// The report's lines, in MIR-060's order: the daemon, its origins, its
/// disk and its repository copies.
fn render(doc: &StatusDoc, now: u64) -> String {
    let mut out = format!(
        "mirror: running (pid {}) at {}\n",
        doc.pid,
        doc.host_socket.display()
    );
    out.push_str("origins:\n");
    if doc.origins.is_empty() {
        out.push_str("  none yet\n");
    }
    for origin in &doc.origins {
        out.push_str(&origin_line(origin, now));
        out.push('\n');
    }
    out.push_str(&format!(
        "disk: {} in use, {} protected, {} budget\n",
        size(doc.disk.used_bytes),
        size(doc.disk.protected_bytes),
        size(doc.disk.budget_bytes)
    ));
    out.push_str("repositories:\n");
    if doc.repositories.is_empty() {
        out.push_str("  none yet\n");
    }
    for repository in &doc.repositories {
        out.push_str(&repository_line(repository, now));
        out.push('\n');
    }
    out
}

/// One origin: reachable with its last contact, or its last failure with
/// the cause when that failure is later than the last contact.
fn origin_line(origin: &OriginDoc, now: u64) -> String {
    let url = format!("https://{}/", origin.origin);
    let last_contact = origin
        .last_contact
        .map_or_else(|| "never".to_string(), |at| ago(at, now));
    match later_failure(origin.last_failure.as_ref(), origin.last_contact) {
        Some(failure) => format!(
            "  {url}    last contact {last_contact}, unreachable {}: {}",
            ago(failure.at, now),
            failure.cause
        ),
        None => format!("  {url}    reachable, last contact {last_contact}"),
    }
}

/// One repository copy: its heads and last refresh, and the last failure
/// with its cause when that failure is later than the refresh.
fn repository_line(repository: &RepositoryDoc, now: u64) -> String {
    let heads = repository
        .heads
        .iter()
        .map(|head| format!("{} {}", head.name, short_commit(&head.commit)))
        .collect::<Vec<_>>()
        .join(" ");
    let refreshed = repository.refreshed_at.map_or_else(
        || "never refreshed".to_string(),
        |at| format!("refreshed {}", ago(at, now)),
    );
    let mut line = format!("  {}   {heads}   {refreshed}", repository.slug);
    if let Some(failure) = later_failure(repository.last_failure.as_ref(), repository.refreshed_at)
    {
        line.push_str(&format!(", last refresh failed: {}", failure.cause));
    }
    line
}

/// A failure that happened after `success`, or after no success at all.
fn later_failure(failure: Option<&FailureDoc>, success: Option<u64>) -> Option<&FailureDoc> {
    failure.filter(|f| success.is_none_or(|at| f.at > at))
}

/// The first eight characters of a commit id.
fn short_commit(commit: &str) -> &str {
    commit.get(..8).unwrap_or(commit)
}

/// How long ago `then` was, in the largest whole unit: `s`, `min`, `h`
/// or `d`.
fn ago(then: u64, now: u64) -> String {
    let secs = now.saturating_sub(then);
    match secs {
        s if s < 60 => format!("{s} s ago"),
        s if s < 3600 => format!("{} min ago", s / 60),
        s if s < 86_400 => format!("{} h ago", s / 3600),
        s => format!("{} d ago", s / 86_400),
    }
}

/// A byte count in GiB from one GiB up, else in MiB, with one decimal.
fn size(bytes: u64) -> String {
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    let bytes = bytes as f64;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes / GIB)
    } else {
        format!("{:.1} MiB", bytes / MIB)
    }
}

/// `min mirror stop`: SIGTERM to the running daemon, then wait for its host
/// socket to stop answering. Prints nothing on success; prints
/// `mirror: stopped` when no daemon runs.
pub fn cmd_mirror_stop(global: &GlobalArgs) -> Result<(), anyhow::Error> {
    let dirs = MirrorDirs::resolve(global.minimal_dir.as_deref());
    let Some(state) = mirror_client::running(&dirs) else {
        println!("mirror: stopped");
        return Ok(());
    };
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(i32::try_from(state.pid).context("the mirror's pid")?),
        nix::sys::signal::Signal::SIGTERM,
    )
    .with_context(|| format!("stopping the mirror (pid {})", state.pid))?;
    let deadline = Instant::now() + STOP_TIMEOUT;
    while mirror_client::socket_answers(&state.host_socket) {
        if Instant::now() >= deadline {
            bail!(
                "the mirror did not stop within {} s.\nRun min mirror status to see its state.",
                STOP_TIMEOUT.as_secs()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}

/// What the daemon a command spawns is told about the mirror (MIR-021,
/// MIR-022), decided without starting it: the running mirror's host socket,
/// an opt-out, or nothing. A client configuration that cannot be read
/// leaves the daemon its environment: the next project command reports the
/// file's fault, and the daemon is not the surface for it.
pub(crate) fn mirror_handoff(global: &GlobalArgs) -> MirrorHandoff {
    let config = match crate::config::read_client_config(global) {
        Ok(config) => config,
        Err(error) => {
            tracing::warn!(%error, "cannot read the client configuration; the daemon keeps its environment's mirror setting");
            return MirrorHandoff::Inherit;
        }
    };
    if !config.mirror.enabled {
        return MirrorHandoff::Off;
    }
    let dirs = MirrorDirs::resolve(global.minimal_dir.as_deref());
    mirror_client::running(&dirs).map_or(MirrorHandoff::Inherit, |state| {
        MirrorHandoff::Socket(state.host_socket)
    })
}

/// The lines a project command prints when the mirror did not start
/// (MIR-020): the cause, the status command, and the opt-out setting in the
/// client configuration file at `config_path`, each on its own line, then
/// whatever else the daemon wrote before it exited.
pub(crate) fn start_failure_lines(error: &StartError, config_path: &Path) -> String {
    let opt_out = format!(
        "Set [mirror] enabled = false in {} to fetch without it.",
        config_path.display()
    );
    let status = "Run min mirror status to see its state.";
    match error {
        StartError::NotInstalled(cause) => {
            format!(
                "{} is not installed: {cause}.\n{opt_out}",
                mirror_client::DAEMON_BIN
            )
        }
        StartError::Exited { cause, rest } => std::iter::once(format!(
            "the mirror did not start: {}.",
            cause.trim_end_matches('.')
        ))
        .chain([status.to_string(), opt_out])
        .chain(rest.iter().cloned())
        .collect::<Vec<_>>()
        .join("\n"),
        StartError::Timeout { socket, timeout } => format!(
            "the mirror did not start: no answer on {} within {} s.\n{status}\n{opt_out}",
            socket.display(),
            timeout.as_secs()
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::os::unix::net::UnixListener;

    use mirror_client::{Lifecycle, MirrorState};

    use super::*;

    /// A mirror "running" under `dirs`: a lifecycle file naming this
    /// process and a listener on the host socket that answers every request
    /// with `response`.
    fn serve(dirs: &MirrorDirs, response: String) {
        std::fs::create_dir_all(&dirs.state).unwrap();
        let listener = UnixListener::bind(dirs.host_socket()).unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                // The request head arrives in several writes; answer once it
                // is whole, so the reply never races the client's last piece.
                // A liveness probe connects and closes without a request; a
                // reply to it fails on the closed socket, harmlessly.
                let mut head = Vec::new();
                let mut chunk = [0u8; 256];
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => head.extend_from_slice(&chunk[..n]),
                    }
                }
                let _ = stream.write_all(response.as_bytes());
            }
        });
        mirror_client::write_state(
            dirs,
            &MirrorState {
                lifecycle: Lifecycle::Running,
                pid: std::process::id(),
                host_socket: dirs.host_socket(),
                door_socket: dirs.door_socket(),
                store: dirs.store.clone(),
                written_at: mirror_client::now_secs(),
            },
        )
        .unwrap();
    }

    const DOC: &str = r#"{"pid":41234,"host_socket":"/s/mirror/host.sock","door_socket":"/s/mirror/door.sock","store":"/c/mirror","origins":[{"origin":"cache.minimal.dev","last_contact":820,"last_failure":null},{"origin":"cache.acme.internal","last_contact":600,"last_failure":{"at":820,"cause":"connection timed out"}}],"disk":{"used_bytes":8804682956,"protected_bytes":7408857907,"budget_bytes":21474836480},"repositories":[{"slug":"github.com/gominimal/pkgs","heads":[{"name":"main","commit":"bd62e6e2a1b2c3d4"}],"refreshed_at":820,"last_failure":null},{"slug":"git.acme.internal/platform/pkgs","heads":[{"name":"main","commit":"5c1e0a77ffff"}],"refreshed_at":600,"last_failure":{"at":900,"cause":"could not resolve host"}}]}"#;

    fn http(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    /// MIR-060: the `mirror:`, `origins:`, `disk:` and `repositories:`
    /// lines in order, one per origin and repository, the later failure
    /// with its cause; a stopped mirror is one line and exit 1.
    #[test]
    fn status_report_fields_and_exit_code() {
        let doc: StatusDoc = serde_json_lenient::from_str(DOC).unwrap();
        let now = 1000;
        assert_eq!(
            render(&doc, now),
            "mirror: running (pid 41234) at /s/mirror/host.sock\n\
             origins:\n  \
               https://cache.minimal.dev/    reachable, last contact 3 min ago\n  \
               https://cache.acme.internal/    last contact 6 min ago, unreachable 3 min ago: connection timed out\n\
             disk: 8.2 GiB in use, 6.9 GiB protected, 20.0 GiB budget\n\
             repositories:\n  \
               github.com/gominimal/pkgs   main bd62e6e2   refreshed 3 min ago\n  \
               git.acme.internal/platform/pkgs   main 5c1e0a77   refreshed 6 min ago, last refresh failed: could not resolve host\n"
        );
        let empty: StatusDoc = serde_json_lenient::from_str(
            r#"{"pid":1,"host_socket":"/h","origins":[],"disk":{"used_bytes":0,"protected_bytes":0,"budget_bytes":1048576},"repositories":[]}"#,
        )
        .unwrap();
        assert_eq!(
            render(&empty, now),
            "mirror: running (pid 1) at /h\norigins:\n  none yet\ndisk: 0.0 MiB in use, 0.0 MiB protected, 1.0 MiB budget\nrepositories:\n  none yet\n"
        );

        let tmp = tempfile::tempdir().unwrap();
        let global = GlobalArgs {
            minimal_dir: Some(tmp.path().to_path_buf()),
            ..GlobalArgs::default()
        };
        let error = cmd_mirror_status(&global, MirrorStatusArgs { json: false }).unwrap_err();
        assert!(
            matches!(error.downcast_ref::<Handoff>(), Some(Handoff::Exit(1))),
            "{error:?}"
        );
    }

    /// `--json` passes the daemon's document through as it came, with a
    /// newline after it, and the plain report is rendered from the same
    /// reply.
    #[test]
    fn status_json_schema() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = MirrorDirs::new(tmp.path().join("state"), tmp.path().join("store"));
        serve(&dirs, http(DOC));
        assert_eq!(
            status_report(&dirs, true, 1000).unwrap().unwrap(),
            format!("{DOC}\n")
        );
        assert!(
            status_report(&dirs, false, 1000)
                .unwrap()
                .unwrap()
                .starts_with("mirror: running (pid 41234) at /s/mirror/host.sock\n")
        );
    }

    /// MIR-020: with no daemon, `status` reports stopped and `stop` returns,
    /// and neither has started one: the state directory stays empty.
    #[test]
    fn status_and_stop_never_start_the_daemon() {
        let tmp = tempfile::tempdir().unwrap();
        let global = GlobalArgs {
            minimal_dir: Some(tmp.path().to_path_buf()),
            ..GlobalArgs::default()
        };
        let dirs = MirrorDirs::resolve(Some(tmp.path()));
        assert!(cmd_mirror_status(&global, MirrorStatusArgs { json: true }).is_err());
        cmd_mirror_stop(&global).unwrap();
        assert!(!dirs.state.exists(), "nothing wrote the mirror's state");
        assert!(mirror_client::running(&dirs).is_none());
    }

    /// MIR-021: the socket a spawned daemon is handed comes from the running
    /// mirror's lifecycle file; without one the daemon keeps its
    /// environment, and an opt-out in the client configuration hands none
    /// whatever runs (MIR-022).
    #[test]
    fn mirror_socket_derived_and_passed_on() {
        let tmp = tempfile::tempdir().unwrap();
        let global = GlobalArgs {
            minimal_dir: Some(tmp.path().join("state")),
            config_dir: Some(tmp.path().join("config")),
            ..GlobalArgs::default()
        };
        assert_eq!(mirror_handoff(&global), MirrorHandoff::Inherit);

        let dirs = MirrorDirs::resolve(Some(&tmp.path().join("state")));
        serve(
            &dirs,
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_string(),
        );
        assert_eq!(
            mirror_handoff(&global),
            MirrorHandoff::Socket(dirs.host_socket())
        );

        let config_dir = tmp.path().join("config/minimal");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("config.toml"),
            "[mirror]\nenabled = false\n",
        )
        .unwrap();
        assert_eq!(mirror_handoff(&global), MirrorHandoff::Off);
    }

    /// MIR-020: the start failure's three lines, the cause first, then the
    /// status command, then the opt-out naming the configuration file, and
    /// the daemon's further lines after them.
    #[test]
    fn mirror_start_failure_fails_command_naming_both_remedies() {
        let config_path = Path::new("/home/u/.config/minimal/config.toml");
        assert_eq!(
            start_failure_lines(
                &StartError::Exited {
                    cause: "git is not installed.".to_string(),
                    rest: vec!["The mirror needs it to copy package repositories.".to_string()],
                },
                config_path
            ),
            "the mirror did not start: git is not installed.\n\
             Run min mirror status to see its state.\n\
             Set [mirror] enabled = false in /home/u/.config/minimal/config.toml to fetch without it.\n\
             The mirror needs it to copy package repositories."
        );
        assert_eq!(
            start_failure_lines(
                &StartError::Timeout {
                    socket: PathBuf::from("/s/mirror/host.sock"),
                    timeout: Duration::from_secs(10),
                },
                config_path
            ),
            "the mirror did not start: no answer on /s/mirror/host.sock within 10 s.\n\
             Run min mirror status to see its state.\n\
             Set [mirror] enabled = false in /home/u/.config/minimal/config.toml to fetch without it."
        );
        assert_eq!(
            start_failure_lines(
                &StartError::NotInstalled(std::io::Error::from(std::io::ErrorKind::NotFound)),
                config_path
            ),
            "minmirrord is not installed: entity not found.\n\
             Set [mirror] enabled = false in /home/u/.config/minimal/config.toml to fetch without it."
        );
    }

    #[test]
    fn ago_and_size_take_the_largest_whole_unit() {
        assert_eq!(ago(990, 1000), "10 s ago");
        assert_eq!(ago(0, 7200), "2 h ago");
        assert_eq!(ago(0, 200_000), "2 d ago");
        assert_eq!(ago(2000, 1000), "0 s ago");
        assert_eq!(size(1024 * 1024 * 1024), "1.0 GiB");
        assert_eq!(size(512 * 1024 * 1024), "512.0 MiB");
        assert_eq!(short_commit("abc"), "abc");
    }
}
