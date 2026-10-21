//! What a client of the mirror daemon needs (spec MIR).
//!
//! The mirror, `minmirrord`, keeps one copy per laptop of the cache objects
//! and repositories its clients fetch. This crate holds the contract the
//! clients share with it without pulling the daemon's own dependencies in:
//! where its directories and sockets are, the lifecycle file it writes, how
//! `min` starts it on demand (MIR-020), the `[mirror]` table of the client
//! configuration file (O3), and a blocking HTTP reader with which the
//! checkout code fetches a repository copy (MIR-013).

use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

pub use common::fetchers::MirrorEndpoint;

/// The environment variable that names the host socket for `min`, `mip` and a
/// native session daemon (MIR-021).
pub const SOCKET_ENV: &str = "MINIMAL_MIRROR_SOCKET";
/// The vsock port the VM host daemon connects to the mirror (MIR-023).
pub const DOOR_PORT: u32 = 7354;
/// The guest command-line token that names the door (MIR-023, MIR-024).
pub const DOOR_TOKEN: &str = "MINIMALD_MIRROR_DOOR";
/// The daemon's binary name.
pub const DAEMON_BIN: &str = "minmirrord";
/// How long a starter waits for the daemon to answer (MIR-020).
pub const START_TIMEOUT: Duration = Duration::from_secs(10);

/// The mirror's directories: its state under the user's state directory and
/// its store under the user's cache directory (MIR-044).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MirrorDirs {
    pub state: PathBuf,
    pub store: PathBuf,
}

impl MirrorDirs {
    /// The directories for this user, honouring a `--minimal-dir` style
    /// override of the state base.
    pub fn resolve(state_base_override: Option<&Path>) -> Self {
        let state_base = match state_base_override {
            Some(dir) => dir.to_path_buf(),
            None => paths::minimal_state_dir()
                .as_utf8_path()
                .as_std_path()
                .to_path_buf(),
        };
        let cache_base = paths::minimal_cache_dir()
            .as_utf8_path()
            .as_std_path()
            .to_path_buf();
        Self {
            state: state_base.join("mirror"),
            store: cache_base.join("mirror"),
        }
    }

    /// Explicit directories, as the daemon receives them on its command line.
    pub fn new(state: PathBuf, store: PathBuf) -> Self {
        Self { state, store }
    }

    /// The host socket: full access, host clients only (MIR-008, MIR-080).
    pub fn host_socket(&self) -> PathBuf {
        self.state.join("host.sock")
    }
    /// The door socket: reads only, which every VM's door connects to.
    pub fn door_socket(&self) -> PathBuf {
        self.state.join("door.sock")
    }
    /// The lifecycle file.
    pub fn state_file(&self) -> PathBuf {
        self.state.join("mirror.toml")
    }
    /// The alive lock the running daemon holds.
    pub fn alive_lock(&self) -> PathBuf {
        self.state.join("mirror.lock")
    }
    /// The daemon's JSON log.
    pub fn log_file(&self) -> PathBuf {
        self.state.join("mirror.log")
    }
    /// Where a detached start sends the daemon's standard error.
    pub fn run_log(&self) -> PathBuf {
        self.state.join("run.log")
    }
    /// The endpoint a host client dials.
    pub fn host_endpoint(&self) -> MirrorEndpoint {
        MirrorEndpoint::Unix(self.host_socket())
    }
}

/// The daemon's lifecycle, as its state file records it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    Stopped,
    Starting,
    Running,
    Stopping,
}

/// The lifecycle file's contents.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirrorState {
    pub lifecycle: Lifecycle,
    pub pid: u32,
    pub host_socket: PathBuf,
    pub door_socket: PathBuf,
    pub store: PathBuf,
    /// Seconds since the Unix epoch when this state was written.
    pub written_at: u64,
}

/// Why the lifecycle file could not be read.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("parse {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
}

/// Reads the lifecycle file; `None` when it does not exist.
pub fn read_state(dirs: &MirrorDirs) -> Result<Option<MirrorState>, StateError> {
    let path = dirs.state_file();
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(StateError::Io { path, source }),
    };
    toml::from_str(&text)
        .map(Some)
        .map_err(|source| StateError::Parse { path, source })
}

/// Writes the lifecycle file by a temporary file renamed into place, so a
/// reader sees the old state or the new one, never a torn write.
pub fn write_state(dirs: &MirrorDirs, state: &MirrorState) -> io::Result<()> {
    fs::create_dir_all(&dirs.state)?;
    let path = dirs.state_file();
    let tmp = path.with_extension("toml.tmp");
    let text = toml::to_string(state).map_err(io::Error::other)?;
    fs::write(&tmp, text)?;
    fs::rename(&tmp, &path)
}

/// The current time as the state file records it.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Whether a process with this id exists.
pub fn process_alive(pid: u32) -> bool {
    // SAFETY: kill with signal 0 performs no action beyond the permission
    // and existence checks; it reads no memory of ours.
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    rc == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Whether the host socket answers a connection now.
pub fn socket_answers(socket: &Path) -> bool {
    UnixStream::connect(socket).is_ok()
}

/// The running daemon's state, or `None` when the state file says stopped,
/// names a process that no longer exists, or names a socket that does not
/// answer (MIR-070).
pub fn running(dirs: &MirrorDirs) -> Option<MirrorState> {
    let state = read_state(dirs).ok().flatten()?;
    (state.lifecycle == Lifecycle::Running
        && process_alive(state.pid)
        && socket_answers(&state.host_socket))
    .then_some(state)
}

/// Why the daemon could not be started.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    /// The daemon's binary was not found beside this program or on `PATH`.
    #[error("{DAEMON_BIN} is not installed: {0}")]
    NotInstalled(io::Error),
    /// The daemon exited before it answered; `cause` is the first line it
    /// wrote to its standard error and `rest` the lines after it (MIR-020).
    #[error("the mirror did not start: {cause}")]
    Exited { cause: String, rest: Vec<String> },
    /// The daemon did not answer within [`START_TIMEOUT`].
    #[error("the mirror did not start: no answer on {socket} within {timeout:?}")]
    Timeout { socket: PathBuf, timeout: Duration },
}

/// The daemon's binary: beside this program when a build put it there, else
/// on `PATH`.
fn daemon_command() -> Command {
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let sibling = dir.join(DAEMON_BIN);
        if sibling.is_file() {
            return Command::new(sibling);
        }
    }
    Command::new(DAEMON_BIN)
}

/// Starts the daemon if it is not running and waits until its host socket
/// answers, bounded by [`START_TIMEOUT`] (MIR-020). Several starters may race
/// here; the daemon's own alive lock leaves one running and every starter
/// sees its socket (MIR-070).
pub fn ensure_running(dirs: &MirrorDirs) -> Result<MirrorState, StartError> {
    if let Some(state) = running(dirs) {
        return Ok(state);
    }
    let mut cmd = daemon_command();
    cmd.arg("run")
        .arg("--detach")
        .arg("--state-dir")
        .arg(&dirs.state)
        .arg("--store")
        .arg(&dirs.store)
        .env_remove(SOCKET_ENV)
        .env_remove("MINIMAL_REMOTE_CACHE_URL")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let output = cmd.output().map_err(StartError::NotInstalled)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let mut lines = stderr.lines().map(str::to_string);
        let cause = lines
            .next()
            .unwrap_or_else(|| format!("exit status {}", output.status));
        return Err(StartError::Exited {
            cause,
            rest: lines.collect(),
        });
    }
    let socket = dirs.host_socket();
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        if let Some(state) = running(dirs) {
            return Ok(state);
        }
        if Instant::now() >= deadline {
            return Err(StartError::Timeout {
                socket,
                timeout: START_TIMEOUT,
            });
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The `[mirror]` table of the client configuration file (O3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MirrorConfig {
    /// Run the mirror on this laptop and read it.
    pub enabled: bool,
    /// The store's budget (MIR-040), as a size with a unit.
    pub max_disk: String,
    /// The age rule (MIR-041), as a whole number of days, hours or minutes.
    pub keep_unused_for: String,
    /// Packages the mirror always keeps (MIR-031).
    pub always: Vec<String>,
    /// Let the mirror's git use the user's credential helpers for registered
    /// repositories (MIR-027).
    pub git_credentials: bool,
    /// `gs://` buckets the mirror reads with the user's Google credentials
    /// (MIR-028).
    pub gcloud_buckets: Vec<String>,
}

impl Default for MirrorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_disk: "20 GiB".to_string(),
            keep_unused_for: "30d".to_string(),
            always: Vec::new(),
            git_credentials: true,
            gcloud_buckets: Vec::new(),
        }
    }
}

/// Why the `[mirror]` table could not be read.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("parse [mirror] in {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
}

impl MirrorConfig {
    /// Reads the `[mirror]` table alone from a configuration file, leaving
    /// every other table to its own reader (MIR-022). A missing file, or a
    /// file without the table, is the default.
    pub fn read_table(config_path: &Path) -> Result<Self, ConfigError> {
        let text = match fs::read_to_string(config_path) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(source) => {
                return Err(ConfigError::Io {
                    path: config_path.to_path_buf(),
                    source,
                });
            }
        };
        let table: toml::Table = toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: config_path.to_path_buf(),
            source,
        })?;
        match table.get("mirror") {
            None => Ok(Self::default()),
            Some(value) => value
                .clone()
                .try_into()
                .map_err(|source| ConfigError::Parse {
                    path: config_path.to_path_buf(),
                    source,
                }),
        }
    }
}

/// A blocking HTTP/1.1 reader for the few requests the checkout code makes
/// from synchronous code: a repository copy's path or bundle (MIR-010).
pub mod blocking {
    use super::*;

    /// An answer: the status and, for a small reply, its body.
    #[derive(Debug)]
    pub struct Reply {
        pub status: u16,
        pub body: Vec<u8>,
    }

    impl Reply {
        /// The body as text, trimmed, for a refusal line.
        pub fn text(&self) -> String {
            String::from_utf8_lossy(&self.body).trim().to_string()
        }
    }

    /// Why a blocking request failed.
    #[derive(Debug, thiserror::Error)]
    pub enum Error {
        #[error("the mirror at {endpoint} did not answer: {source}")]
        Connect {
            endpoint: MirrorEndpoint,
            #[source]
            source: io::Error,
        },
        #[error("the mirror connection failed: {0}")]
        Io(#[from] io::Error),
        #[error("the mirror answered with a malformed response: {0}")]
        Malformed(String),
    }

    enum Stream {
        Unix(UnixStream),
        #[cfg(target_os = "linux")]
        Vsock(vsock::VsockStream),
    }

    impl Read for Stream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self {
                Stream::Unix(s) => s.read(buf),
                #[cfg(target_os = "linux")]
                Stream::Vsock(s) => s.read(buf),
            }
        }
    }

    impl Write for Stream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            match self {
                Stream::Unix(s) => s.write(buf),
                #[cfg(target_os = "linux")]
                Stream::Vsock(s) => s.write(buf),
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            match self {
                Stream::Unix(s) => s.flush(),
                #[cfg(target_os = "linux")]
                Stream::Vsock(s) => s.flush(),
            }
        }
    }

    fn connect(endpoint: &MirrorEndpoint) -> Result<Stream, Error> {
        let connect_err = |source| Error::Connect {
            endpoint: endpoint.clone(),
            source,
        };
        match endpoint {
            MirrorEndpoint::Unix(path) => UnixStream::connect(path)
                .map(Stream::Unix)
                .map_err(connect_err),
            #[cfg(target_os = "linux")]
            MirrorEndpoint::Vsock { cid, port } => {
                vsock::VsockStream::connect_with_cid_port(*cid, *port)
                    .map(Stream::Vsock)
                    .map_err(connect_err)
            }
        }
    }

    struct Head {
        status: u16,
        content_length: Option<u64>,
        chunked: bool,
    }

    fn read_head<R: BufRead>(reader: &mut R) -> Result<Head, Error> {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let status = line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .ok_or_else(|| Error::Malformed(format!("status line {line:?}")))?;
        let mut content_length = None;
        let mut chunked = false;
        loop {
            line.clear();
            if reader.read_line(&mut line)? == 0 {
                return Err(Error::Malformed("headers ended early".to_string()));
            }
            let trimmed = line.trim_end();
            if trimmed.is_empty() {
                break;
            }
            if let Some((name, value)) = trimmed.split_once(':') {
                let value = value.trim();
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.parse().ok();
                } else if name.eq_ignore_ascii_case("transfer-encoding")
                    && value.eq_ignore_ascii_case("chunked")
                {
                    chunked = true;
                }
            }
        }
        Ok(Head {
            status,
            content_length,
            chunked,
        })
    }

    fn send(endpoint: &MirrorEndpoint, path: &str) -> Result<(Head, BufReader<Stream>), Error> {
        let mut stream = connect(endpoint)?;
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: mirror\r\nConnection: close\r\n\r\n"
        )?;
        stream.flush()?;
        let mut reader = BufReader::new(stream);
        let head = read_head(&mut reader)?;
        if head.chunked {
            return Err(Error::Malformed(
                "chunked transfer encoding is not read here".to_string(),
            ));
        }
        Ok((head, reader))
    }

    /// Reads the body into a buffer: the rest of the connection, which the
    /// mirror closes after one answer.
    fn read_body<R: Read>(reader: &mut R, content_length: Option<u64>) -> Result<Vec<u8>, Error> {
        let mut body = Vec::new();
        match content_length {
            Some(n) => reader.take(n).read_to_end(&mut body)?,
            None => reader.read_to_end(&mut body)?,
        };
        Ok(body)
    }

    /// A `GET` whose whole body comes back in memory. For a small answer: a
    /// copy's path, a status document, or a refusal line.
    pub fn get(endpoint: &MirrorEndpoint, path: &str) -> Result<Reply, Error> {
        let (head, mut reader) = send(endpoint, path)?;
        let body = read_body(&mut reader, head.content_length)?;
        Ok(Reply {
            status: head.status,
            body,
        })
    }

    /// A `GET` whose body is written to `dest` when the status is 2xx. On any
    /// other status the body comes back in the reply and `dest` is untouched.
    pub fn get_to_file(endpoint: &MirrorEndpoint, path: &str, dest: &Path) -> Result<Reply, Error> {
        let (head, mut reader) = send(endpoint, path)?;
        if !(200..300).contains(&head.status) {
            let body = read_body(&mut reader, head.content_length)?;
            return Ok(Reply {
                status: head.status,
                body,
            });
        }
        let tmp = dest.with_extension("part");
        {
            let mut file = fs::File::create(&tmp)?;
            match head.content_length {
                Some(n) => io::copy(&mut reader.take(n), &mut file)?,
                None => io::copy(&mut reader, &mut file)?,
            };
            file.sync_all()?;
        }
        fs::rename(&tmp, dest)?;
        Ok(Reply {
            status: head.status,
            body: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    #[test]
    fn dirs_derive_sockets_and_files_from_one_state_dir() {
        let dirs = MirrorDirs::new(PathBuf::from("/s/mirror"), PathBuf::from("/c/mirror"));
        assert_eq!(dirs.host_socket(), PathBuf::from("/s/mirror/host.sock"));
        assert_eq!(dirs.door_socket(), PathBuf::from("/s/mirror/door.sock"));
        assert_eq!(dirs.state_file(), PathBuf::from("/s/mirror/mirror.toml"));
        assert_eq!(
            dirs.host_endpoint(),
            MirrorEndpoint::Unix(dirs.host_socket())
        );
        let resolved = MirrorDirs::resolve(Some(Path::new("/tmp/state-base")));
        assert_eq!(resolved.state, PathBuf::from("/tmp/state-base/mirror"));
    }

    #[test]
    fn state_file_round_trips_and_is_absent_when_never_written() {
        let dir = tempfile::tempdir().unwrap();
        let dirs = MirrorDirs::new(dir.path().join("state"), dir.path().join("store"));
        assert!(read_state(&dirs).unwrap().is_none());
        let state = MirrorState {
            lifecycle: Lifecycle::Running,
            pid: 4242,
            host_socket: dirs.host_socket(),
            door_socket: dirs.door_socket(),
            store: dirs.store.clone(),
            written_at: now_secs(),
        };
        write_state(&dirs, &state).unwrap();
        assert_eq!(read_state(&dirs).unwrap(), Some(state));
    }

    #[test]
    fn a_dead_process_or_silent_socket_reads_as_stopped() {
        let dir = tempfile::tempdir().unwrap();
        let dirs = MirrorDirs::new(dir.path().join("state"), dir.path().join("store"));
        // No process has pid u32::MAX on any supported system.
        write_state(
            &dirs,
            &MirrorState {
                lifecycle: Lifecycle::Running,
                pid: u32::MAX - 1,
                host_socket: dirs.host_socket(),
                door_socket: dirs.door_socket(),
                store: dirs.store.clone(),
                written_at: now_secs(),
            },
        )
        .unwrap();
        assert!(running(&dirs).is_none());
        // Our own pid is alive, but nothing listens on the socket.
        write_state(
            &dirs,
            &MirrorState {
                lifecycle: Lifecycle::Running,
                pid: std::process::id(),
                host_socket: dirs.host_socket(),
                door_socket: dirs.door_socket(),
                store: dirs.store.clone(),
                written_at: now_secs(),
            },
        )
        .unwrap();
        assert!(running(&dirs).is_none());
        // With a listener on the socket the state is live.
        fs::create_dir_all(&dirs.state).unwrap();
        let _listener = UnixListener::bind(dirs.host_socket()).unwrap();
        assert!(running(&dirs).is_some());
    }

    #[test]
    fn mirror_table_reads_alone_and_defaults_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        assert_eq!(
            MirrorConfig::read_table(&path).unwrap(),
            MirrorConfig::default()
        );
        fs::write(&path, "[loadouts]\ndefault_loadouts = [\"dev\"]\n").unwrap();
        assert_eq!(
            MirrorConfig::read_table(&path).unwrap(),
            MirrorConfig::default()
        );
        fs::write(
            &path,
            "[loadouts]\ndefault_loadouts = [\"dev\"]\n[mirror]\nenabled = false\nalways = [\"go\"]\n",
        )
        .unwrap();
        let cfg = MirrorConfig::read_table(&path).unwrap();
        assert!(!cfg.enabled);
        assert_eq!(cfg.always, vec!["go".to_string()]);
        assert_eq!(cfg.max_disk, "20 GiB");
        fs::write(&path, "[mirror]\nunknown = 1\n").unwrap();
        assert!(matches!(
            MirrorConfig::read_table(&path),
            Err(ConfigError::Parse { .. })
        ));
    }

    fn serve_once(socket: PathBuf, response: &'static [u8]) {
        let listener = UnixListener::bind(socket).unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut head = [0u8; 1024];
            let _ = stream.read(&mut head);
            stream.write_all(response).unwrap();
        });
    }

    #[test]
    fn blocking_get_reads_a_content_length_body_and_a_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("m.sock");
        serve_once(
            socket.clone(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nContent-Type: text/plain\r\n\r\n/store/git/x",
        );
        let reply =
            blocking::get(&MirrorEndpoint::Unix(socket.clone()), "/-/git/h/x/-/path").unwrap();
        assert_eq!(reply.status, 200);
        assert_eq!(reply.text(), "/store/git/x");

        let socket = dir.path().join("n.sock");
        serve_once(
            socket.clone(),
            b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 44\r\n\r\nthe mirror could not copy https://h/x: down\n",
        );
        let dest = dir.path().join("bundle");
        let reply =
            blocking::get_to_file(&MirrorEndpoint::Unix(socket), "/-/git/h/x/-/bundle", &dest)
                .unwrap();
        assert_eq!(reply.status, 502);
        assert_eq!(reply.text(), "the mirror could not copy https://h/x: down");
        assert!(!dest.exists());

        let socket = dir.path().join("o.sock");
        serve_once(
            socket.clone(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
        );
        let reply =
            blocking::get_to_file(&MirrorEndpoint::Unix(socket), "/-/git/h/x/-/bundle", &dest)
                .unwrap();
        assert_eq!(reply.status, 200);
        assert_eq!(fs::read(&dest).unwrap(), b"hello");

        let err =
            blocking::get(&MirrorEndpoint::Unix(dir.path().join("none.sock")), "/x").unwrap_err();
        assert!(err.to_string().starts_with("the mirror at "), "{err}");
    }
}
