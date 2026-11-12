//! The Secret Service key store, for a Linux host with no usable TPM
//! (BEP-088, BEP-089).
//!
//! [`SecretService`] generates each proxy key as a software P-256 key and
//! holds its private half in Secret Service through `secret-tool`, as
//! [`signin`](crate::signin) holds the sign-in. Each item has one attribute,
//! `service`, whose value is the role's label in its slot (see
//! [`Role::slot_label`]). Secret Service holds no key non-exportable and
//! has no control per program, so a program running as the proxy's user can
//! read these keys.
//!
//! A locked keyring and a Secret Service that this session cannot reach are
//! [`KeyError::Locked`] and [`KeyError::Unreachable`]. Neither removes or
//! replaces a key: the keys still exist, and the start refuses until the
//! operator unlocks the keyring or starts the proxy from the desktop
//! session.

use std::ffi::OsString;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

use base64::Engine as _;
use p256::{PublicKey, SecretKey};
use zeroize::Zeroizing;

use crate::keys::{HeldKey, KeyError, KeyStore, Role, Slot, missing_in};
use crate::seal::ProxyPublicKey;

/// The program that talks to Secret Service.
pub const SECRET_TOOL: &str = "secret-tool";

/// The one attribute of each item. Its value is the role's slot label.
const ATTRIBUTE: &str = "service";

/// The store name in the log lines.
const STORE: &str = "secret-service";

/// How long one `secret-tool` call can run. A call on a locked keyring
/// can wait on an unlock prompt. When nobody answers it, the start
/// refuses as locked and does not wait forever.
pub const TIMEOUT: Duration = Duration::from_secs(60);

/// How long `run` waits for the output pipes to close after `secret-tool`
/// exits. A process that `secret-tool` started, such as a D-Bus daemon it
/// autolaunched, can hold the pipes open after it. The output that
/// `secret-tool` wrote is in the pipe when it exits, so a short wait reads
/// all of it.
const DRAIN_GRACE: Duration = Duration::from_secs(1);

/// The exit code of a `secret-tool lookup` or `clear` that matched no item.
const NO_MATCH: i32 = 1;

/// Parts of `secret-tool`'s error output that say the keyring is locked:
/// libsecret's "locked object" and "locked collection" errors.
const LOCKED: &[&str] = &["locked object", "locked collection", "collection is locked"];

/// Parts of `secret-tool`'s error output that say this session has no
/// Secret Service: no session bus, or no keyring daemon on it. Each is a
/// phrase from GDBus or the bus, not a bare word that other errors share.
const UNREACHABLE: &[&str] = &[
    "could not connect:",
    "cannot autolaunch d-bus",
    "the name org.freedesktop.secrets was not provided",
    "org.freedesktop.dbus.error.serviceunknown",
    "org.freedesktop.dbus.error.noserver",
    "failed to connect to the message bus",
];

/// The proxy's keys in Secret Service.
#[derive(Debug, Clone)]
pub struct SecretService {
    program: PathBuf,
    leading: Vec<OsString>,
    timeout: Duration,
}

impl Default for SecretService {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretService {
    /// The store that runs `secret-tool` from `PATH`.
    #[must_use]
    pub fn new() -> Self {
        Self::with_program(SECRET_TOOL, Vec::<OsString>::new())
    }

    /// The store that runs `program` with `leading` before each
    /// `secret-tool` argument list. A test gives it a fake `secret-tool`.
    #[must_use]
    pub fn with_program(
        program: impl Into<PathBuf>,
        leading: impl IntoIterator<Item = impl Into<OsString>>,
    ) -> Self {
        Self {
            program: program.into(),
            leading: leading.into_iter().map(Into::into).collect(),
            timeout: TIMEOUT,
        }
    }

    /// The same store, with `timeout` for each `secret-tool` call.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn run(&self, role: Role, args: &[&str], stdin: Option<&[u8]>) -> Result<Output, KeyError> {
        let mut cmd = Command::new(&self.program);
        cmd.args(&self.leading)
            .args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(|err| KeyError::Store {
            role,
            detail: if err.kind() == std::io::ErrorKind::NotFound {
                format!(
                    "`{SECRET_TOOL}` is not installed. Install it (the `libsecret-tools` package on Debian and Ubuntu, `libsecret` on Fedora and Arch)"
                )
            } else {
                format!("`{SECRET_TOOL}` did not run: {err}")
            },
        })?;
        let stdout = drain(child.stdout.take());
        let stderr = drain(child.stderr.take());
        let written = match (stdin, child.stdin.take()) {
            // Dropping the pipe at the end of the arm closes it, so the
            // child sees the end of its input.
            (Some(input), Some(mut pipe)) => pipe.write_all(input),
            _ => Ok(()),
        };
        let status = self.wait(role, &mut child)?;
        let deadline = Instant::now() + DRAIN_GRACE;
        let out = Output {
            status,
            stdout: stdout.collect(deadline),
            stderr: stderr.collect(deadline),
        };
        match written {
            // A `secret-tool` that fails before it reads its input (a locked
            // keyring, no session bus) closes the pipe. Its exit status and
            // error output say why, so the caller sorts them by cause.
            Err(_) if !out.status.success() => Ok(out),
            Err(err) => Err(KeyError::Store {
                role,
                detail: format!("`{SECRET_TOOL}` did not read the key: {err}"),
            }),
            Ok(()) => Ok(out),
        }
    }

    /// Waits for `child` until the timeout. A call that outlives it is
    /// killed and reads as a locked keyring: an unlock prompt that nobody
    /// answered.
    fn wait(&self, role: Role, child: &mut std::process::Child) -> Result<ExitStatus, KeyError> {
        let deadline = Instant::now() + self.timeout;
        loop {
            let finished = child.try_wait().map_err(|err| KeyError::Store {
                role,
                detail: format!("`{SECRET_TOOL}` did not finish: {err}"),
            })?;
            if let Some(status) = finished {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                tracing::warn!(role = %role, timeout_secs = self.timeout.as_secs_f64(), store = STORE, "secret-tool did not finish in time; read as a locked keyring");
                return Err(KeyError::Locked {
                    role,
                    detail: format!(
                        "`{SECRET_TOOL}` did not finish in {} s, so an unlock prompt is still waiting",
                        self.timeout.as_secs()
                    ),
                });
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Whether Secret Service lists an item for `label` that `lookup` did
    /// not return. `search` without `--unlock` lists a locked item without
    /// its secret, so a listed item here is a locked one.
    fn listed(&self, role: Role, label: &str) -> Result<bool, KeyError> {
        let out = self.run(role, &["search", ATTRIBUTE, label], None)?;
        if out.status.success() {
            return Ok(!out.stdout.iter().all(u8::is_ascii_whitespace));
        }
        if out.status.code() == Some(NO_MATCH) && blank(&out.stderr) {
            return Ok(false);
        }
        Err(failure(role, &out))
    }

    /// The private half held for `role` in `slot`, or `None`.
    fn lookup(&self, role: Role, slot: Slot) -> Result<Option<SecretKey>, KeyError> {
        let label = role.slot_label(slot);
        let mut out = self.run(role, &["lookup", ATTRIBUTE, &label], None)?;
        let stdout = Zeroizing::new(std::mem::take(&mut out.stdout));
        if !out.status.success() {
            // `secret-tool lookup` exits 1 with no output when no item
            // matches. A dismissed unlock prompt on a locked keyring gives
            // the same result, so ask whether an item is there.
            if out.status.code() == Some(NO_MATCH) && blank(&out.stderr) {
                if self.listed(role, &label)? {
                    return Err(KeyError::Locked {
                        role,
                        detail: "Secret Service lists the item but did not return its secret"
                            .into(),
                    });
                }
                return Ok(None);
            }
            return Err(failure(role, &out));
        }
        let text = std::str::from_utf8(&stdout).map_err(|_| unreadable(role))?;
        let text = text.trim();
        if text.is_empty() {
            return Ok(None);
        }
        let bytes = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(text)
                .map_err(|_| unreadable(role))?,
        );
        SecretKey::from_slice(&bytes)
            .map(Some)
            .map_err(|_| unreadable(role))
    }

    /// Holds `secret` for `role` in `slot`, in place of any key there.
    fn store(&self, role: Role, slot: Slot, secret: &SecretKey) -> Result<(), KeyError> {
        let label = role.slot_label(slot);
        let bytes = Zeroizing::new(secret.to_bytes().to_vec());
        let encoded =
            Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(bytes.as_slice()));
        let label_arg = format!("--label={label}");
        let out = self.run(
            role,
            &["store", &label_arg, ATTRIBUTE, &label],
            Some(encoded.as_bytes()),
        )?;
        if !out.status.success() {
            return Err(failure(role, &out));
        }
        Ok(())
    }

    /// Removes the item for `role` in `slot`. An empty slot is not an error.
    fn clear(&self, role: Role, slot: Slot) -> Result<(), KeyError> {
        let label = role.slot_label(slot);
        let out = self.run(role, &["clear", ATTRIBUTE, &label], None)?;
        if out.status.success() || (out.status.code() == Some(NO_MATCH) && blank(&out.stderr)) {
            return Ok(());
        }
        Err(failure(role, &out))
    }
}

fn blank(bytes: &[u8]) -> bool {
    bytes.iter().all(u8::is_ascii_whitespace)
}

/// The output of one pipe, which a thread of its own reads.
struct Drain {
    buf: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    done: std::sync::mpsc::Receiver<()>,
}

impl Drain {
    /// What the thread read by `deadline`, or by the end of the pipe if
    /// that is first. A pipe that another process holds open past
    /// `deadline` does not stop the caller: the thread reads on, detached,
    /// until that process closes the pipe.
    fn collect(self, deadline: Instant) -> Vec<u8> {
        let wait = deadline.saturating_duration_since(Instant::now());
        if self.done.recv_timeout(wait).is_err() {
            tracing::warn!(
                store = STORE,
                "an output pipe of secret-tool stayed open after it exited; using the output read so far"
            );
        }
        let mut buf = self
            .buf
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::mem::take(&mut *buf)
    }
}

/// Reads all of `pipe` on its own thread, so a full pipe never blocks the
/// child while the caller waits for it.
fn drain<R: std::io::Read + Send + 'static>(pipe: Option<R>) -> Drain {
    let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let (tx, done) = std::sync::mpsc::channel();
    let shared = std::sync::Arc::clone(&buf);
    std::thread::spawn(move || {
        if let Some(mut pipe) = pipe {
            let mut chunk = [0u8; 4096];
            loop {
                match pipe.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => shared
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .extend_from_slice(&chunk[..n]),
                    Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
            zeroize::Zeroize::zeroize(&mut chunk);
        }
        let _ = tx.send(());
    });
    Drain { buf, done }
}

/// The error for a `secret-tool` run that failed with `out`.
fn failure(role: Role, out: &Output) -> KeyError {
    let detail = String::from_utf8_lossy(&out.stderr).trim().to_owned();
    if detail.is_empty() {
        return KeyError::Store {
            role,
            detail: format!("`{SECRET_TOOL}` failed with no message ({})", out.status),
        };
    }
    sort(role, detail)
}

/// Sorts a `secret-tool` error message by cause.
fn sort(role: Role, detail: String) -> KeyError {
    let lower = detail.to_ascii_lowercase();
    if LOCKED.iter().any(|part| lower.contains(part)) {
        KeyError::Locked { role, detail }
    } else if UNREACHABLE.iter().any(|part| lower.contains(part)) {
        KeyError::Unreachable { role, detail }
    } else {
        KeyError::Store { role, detail }
    }
}

fn unreadable(role: Role) -> KeyError {
    KeyError::Store {
        role,
        detail: "Secret Service holds an item for this key that is not a P-256 private key".into(),
    }
}

fn random_secret() -> Result<SecretKey, getrandom::Error> {
    loop {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut())?;
        if let Ok(secret) = SecretKey::from_slice(bytes.as_ref()) {
            return Ok(secret);
        }
    }
}

/// A software key that Secret Service holds. The private half is in this
/// process's memory while the proxy runs, and zeroed on drop.
pub struct SecretServiceKey {
    role: Role,
    secret: SecretKey,
}

impl std::fmt::Debug for SecretServiceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretServiceKey")
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

impl HeldKey for SecretServiceKey {
    fn role(&self) -> Role {
        self.role
    }

    fn public(&self) -> ProxyPublicKey {
        ProxyPublicKey::from_sec1_bytes(&self.secret.public_key().to_sec1_bytes())
            .expect("a P-256 public key")
    }

    /// `false`: the custody rule of [`custody`](crate::keys::custody) is
    /// the keychain's export flag. A Secret Service key is a software key
    /// by design (BEP-088), and the proxy reports it as such (BEP-090).
    fn exportable(&self) -> bool {
        false
    }

    fn agree(&self, peer: &ProxyPublicKey) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        let peer =
            PublicKey::from_sec1_bytes(&peer.to_sec1_bytes()).map_err(|_| KeyError::Store {
                role: self.role,
                detail: "the peer key is not a P-256 point".into(),
            })?;
        let shared = p256::ecdh::diffie_hellman(self.secret.to_nonzero_scalar(), peer.as_affine());
        Ok(Zeroizing::new(shared.raw_secret_bytes().to_vec()))
    }

    /// The key was read from Secret Service when the store found it, so a
    /// locked or unreachable keyring refused the start there.
    fn probe(&self) -> Result<(), KeyError> {
        Ok(())
    }
}

impl crate::ca::CaKey for SecretServiceKey {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, KeyError> {
        use p256::ecdsa::signature::Signer as _;
        let signature: p256::ecdsa::Signature =
            p256::ecdsa::SigningKey::from(&self.secret).sign(msg);
        Ok(signature.to_der().as_bytes().to_vec())
    }
}

impl KeyStore for SecretService {
    type Key = SecretServiceKey;

    fn find(&self, role: Role) -> Result<Option<SecretServiceKey>, KeyError> {
        let Some(secret) = self.lookup(role, Slot::Held)? else {
            return Ok(None);
        };
        let key = SecretServiceKey { role, secret };
        tracing::info!(role = %role, fingerprint = %key.public().kid(), store = STORE, "loaded a proxy key");
        Ok(Some(key))
    }

    fn generate_in(&self, role: Role, slot: Slot) -> Result<SecretServiceKey, KeyError> {
        let secret = random_secret().map_err(|err| KeyError::Store {
            role,
            detail: format!("the random source failed: {err}"),
        })?;
        self.store(role, slot, &secret)?;
        let key = SecretServiceKey { role, secret };
        tracing::info!(role = %role, fingerprint = %key.public().kid(), store = STORE, "generated a proxy key");
        Ok(key)
    }

    fn remove_in(&self, role: Role, slot: Slot) -> Result<(), KeyError> {
        self.clear(role, slot)
    }

    fn holds_in(&self, role: Role, slot: Slot) -> Result<bool, KeyError> {
        self.lookup(role, slot).map(|secret| secret.is_some())
    }

    fn kid_in(&self, role: Role, slot: Slot) -> Result<Option<String>, KeyError> {
        Ok(self.lookup(role, slot)?.map(|secret| {
            ProxyPublicKey::from_sec1_bytes(&secret.public_key().to_sec1_bytes())
                .expect("a P-256 public key")
                .kid()
        }))
    }

    fn relabel(&self, role: Role, from: Slot, to: Slot) -> Result<(), KeyError> {
        let Some(secret) = self.lookup(role, from)? else {
            return if from == Slot::Held {
                Ok(())
            } else {
                Err(missing_in(role, from))
            };
        };
        // Write the key in `to` first, so a failure leaves it in `from`.
        self.store(role, to, &secret)?;
        self.clear(role, from)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::keys::{StartError, load};

    /// A fake `secret-tool` that keeps each item in a file under `dir`. A
    /// `locked` or `unreachable` file in `dir` makes every call fail as
    /// the real tool does in that state. A `silent-locked` file makes
    /// `lookup` exit 1 with no message, as after a dismissed unlock prompt.
    fn fake(dir: &Path) -> SecretService {
        let script = dir.join("secret-tool");
        let body = format!(
            r#"dir='{dir}'
if [ -e "$dir/unreachable" ]; then
  echo "secret-tool: Cannot autolaunch D-Bus without X11 \$DISPLAY" >&2; exit 1
fi
if [ -e "$dir/locked" ]; then
  echo "secret-tool: Cannot get secret of a locked object" >&2; exit 1
fi
cmd=$1; shift
[ "$cmd" = store ] && shift
name=$2
if [ -e "$dir/silent-locked" ] && [ "$cmd" = lookup ]; then exit 1; fi
case "$cmd" in
  store) cat > "$dir/item.$name" ;;
  lookup) [ -f "$dir/item.$name" ] || exit 1; cat "$dir/item.$name" ;;
  search) [ -f "$dir/item.$name" ] && printf '[/org/freedesktop/secrets/collection/login/1]\nlabel = %s\n' "$name"; exit 0 ;;
  clear) rm -f "$dir/item.$name" ;;
  *) echo "unknown command $cmd" >&2; exit 2 ;;
esac
"#,
            dir = dir.display()
        );
        std::fs::write(&script, body).unwrap();
        // Run the script through `sh`, so no test executes a file another
        // thread can still hold open for writing.
        SecretService::with_program("/bin/sh", [script])
    }

    fn items(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|entry| {
                let name = entry.unwrap().file_name().into_string().unwrap();
                name.strip_prefix("item.").map(str::to_owned)
            })
            .collect();
        names.sort();
        names
    }

    fn kids(store: &SecretService) -> Vec<String> {
        let keys = load(store, &[]).unwrap();
        Role::ALL
            .into_iter()
            .map(|role| keys.get(role).public().kid())
            .collect()
    }

    // BEP-088, BEP-089
    #[test]
    fn keys_are_generated_and_held_in_secret_service() {
        let dir = tempfile::tempdir().unwrap();
        let store = fake(dir.path());
        let first = kids(&store);
        assert_eq!(
            items(dir.path()),
            vec![
                "dev.gominimal.bep.root",
                "dev.gominimal.bep.sealing",
                "dev.gominimal.bep.signing"
            ]
        );
        assert_eq!(kids(&store), first, "a restart loads the held keys");
    }

    // BEP-060, BEP-089
    #[test]
    fn a_replacement_moves_the_new_key_into_the_role() {
        let dir = tempfile::tempdir().unwrap();
        let store = fake(dir.path());
        let first = kids(&store);
        crate::keys::replace(&store, Role::Signing).unwrap();
        let second = kids(&store);
        assert_eq!(first[..2], second[..2]);
        assert_ne!(first[2], second[2]);
        assert_eq!(items(dir.path()).len(), 3);
    }

    fn refuses_start_and_keeps_the_keys(state: &str, expected: &StartError, text: &str) {
        let dir = tempfile::tempdir().unwrap();
        let store = fake(dir.path());
        let first = kids(&store);
        std::fs::write(dir.path().join(state), "").unwrap();
        let err = load(&store, &[]).unwrap_err();
        assert_eq!(&err, expected);
        assert_eq!(err.to_string(), text);
        assert!(!text.contains("--replace-key"));
        std::fs::remove_file(dir.path().join(state)).unwrap();
        assert_eq!(kids(&store), first, "the refused start kept every key");
    }

    // BEP-089
    #[test]
    fn a_locked_secret_service_refuses_start() {
        refuses_start_and_keeps_the_keys(
            "locked",
            &StartError::Locked(Role::Sealing),
            "The proxy did not start: the login keyring is locked, and it holds the proxy's sealing key. Unlock the login keyring, then start the proxy again.",
        );
    }

    // BEP-089
    #[test]
    fn an_unreachable_secret_service_refuses_start() {
        refuses_start_and_keeps_the_keys(
            "unreachable",
            &StartError::Unreachable(Role::Sealing),
            "The proxy did not start: Secret Service cannot be reached from this session, and it holds the proxy's sealing key. Start the proxy from the desktop session that holds the login keyring.",
        );
    }

    // BEP-089
    #[test]
    fn a_tool_that_fails_before_it_reads_the_key_is_sorted_by_cause() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("secret-tool");
        std::fs::write(
            &script,
            "echo 'secret-tool: Cannot create an item in a locked collection' >&2; exit 1\n",
        )
        .unwrap();
        let store = SecretService::with_program("/bin/sh", [script]);
        // More than a pipe buffer holds, so the write fails when the tool
        // exits without reading it.
        let input = vec![b'k'; 1 << 20];
        let out = store
            .run(
                Role::Root,
                &["store", "--label=x", ATTRIBUTE, "x"],
                Some(&input),
            )
            .unwrap();
        assert!(!out.status.success());
        assert!(matches!(
            failure(Role::Root, &out),
            KeyError::Locked {
                role: Role::Root,
                ..
            }
        ));
    }

    // BEP-089
    #[test]
    fn a_pipe_held_open_after_exit_does_not_stop_the_start() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("secret-tool");
        // The background `sleep` keeps stdout and stderr open after the
        // tool exits, as a D-Bus daemon that it autolaunched can.
        std::fs::write(
            &script,
            "sleep 30 &\necho 'secret-tool: Cannot autolaunch D-Bus without X11 $DISPLAY' >&2; exit 1\n",
        )
        .unwrap();
        let store = SecretService::with_program("/bin/sh", [script]);
        let started = Instant::now();
        let out = store
            .run(Role::Root, &["lookup", ATTRIBUTE, "x"], None)
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(matches!(
            failure(Role::Root, &out),
            KeyError::Unreachable {
                role: Role::Root,
                ..
            }
        ));
    }

    #[test]
    fn secret_tool_errors_are_sorted_by_cause() {
        let locked = sort(
            Role::Root,
            "secret-tool: Cannot create an item in a locked collection".into(),
        );
        assert!(matches!(
            locked,
            KeyError::Locked {
                role: Role::Root,
                ..
            }
        ));
        let unreachable = sort(
            Role::Root,
            "secret-tool: The name org.freedesktop.secrets was not provided by any .service files"
                .into(),
        );
        assert!(matches!(
            unreachable,
            KeyError::Unreachable {
                role: Role::Root,
                ..
            }
        ));
        for other in [
            "secret-tool: something else",
            "secret-tool: /home/u/.cache: No such file or directory",
            "secret-tool: the dbus-broker log is unlocked",
        ] {
            assert!(
                matches!(
                    sort(Role::Root, other.into()),
                    KeyError::Store {
                        role: Role::Root,
                        ..
                    }
                ),
                "{other}"
            );
        }
        let no_bus = sort(
            Role::Root,
            "secret-tool: Could not connect: No such file or directory".into(),
        );
        assert!(matches!(no_bus, KeyError::Unreachable { .. }));
    }

    // BEP-089
    #[test]
    fn a_silently_locked_lookup_refuses_start_and_keeps_the_keys() {
        refuses_start_and_keeps_the_keys(
            "silent-locked",
            &StartError::Locked(Role::Sealing),
            "The proxy did not start: the login keyring is locked, and it holds the proxy's sealing key. Unlock the login keyring, then start the proxy again.",
        );
    }

    // BEP-089
    #[test]
    fn a_tool_that_does_not_finish_reads_as_locked() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("secret-tool");
        std::fs::write(&script, "exec sleep 30\n").unwrap();
        let store = SecretService::with_program("/bin/sh", [script])
            .with_timeout(Duration::from_millis(200));
        let started = Instant::now();
        let err = store.lookup(Role::Root, Slot::Held).unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(matches!(
            err,
            KeyError::Locked {
                role: Role::Root,
                ..
            }
        ));
    }

    // BEP-089
    #[test]
    fn a_lookup_that_fails_with_no_message_is_not_an_empty_slot() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("secret-tool");
        std::fs::write(&script, "kill -KILL $$\n").unwrap();
        let store = SecretService::with_program("/bin/sh", [script]);
        let err = store.lookup(Role::Root, Slot::Held).unwrap_err();
        assert!(matches!(
            err,
            KeyError::Store {
                role: Role::Root,
                ..
            }
        ));
        std::fs::write(dir.path().join("secret-tool"), "exit 2\n").unwrap();
        assert!(matches!(
            store.lookup(Role::Root, Slot::Held),
            Err(KeyError::Store { .. })
        ));
    }
}
