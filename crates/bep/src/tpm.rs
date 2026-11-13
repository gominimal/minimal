//! The proxy's Linux key store in the host's TPM 2.0 (BEP-088).
//!
//! The store reaches the TPM through the `tpm2-tools` commands, which it runs
//! as child processes (see `docs/spikes/2026-11-13-bep-tpm-interface.md`).
//! It generates each proxy key under the TPM's storage key, as a P-256 key
//! with `fixedTPM`, `fixedParent` and `noDA`. Each key has its own
//! authorization value of 256 bits from the OS CSPRNG, so a member of the
//! `tss` group that is not the proxy's user cannot use the key.
//!
//! For each role and slot, the store keeps two files in its directory,
//! `~/.minimal/bep/tpm/` by default:
//!
//! * `<label>.key`: the key's public area and its private blob, as the TPM
//!   wrote them. Only the TPM that made the blob can load it.
//! * `<label>.auth`: the key's authorization value. Only the proxy's user
//!   can read it.
//!
//! The store passes the authorization value to `tpm2-tools` on standard
//! input, never in an argument list, which other users of the host can read.
//! It passes it in the `hex:` form, because `tpm2-tools` reads a raw value as
//! a C string and drops every byte from the first zero byte.
//! The shared secret of an ECDH goes through a file in a directory in memory,
//! under `$XDG_RUNTIME_DIR` or `/dev/shm`, and never through the disk. The
//! store uses such a directory only when `statfs` reports `tmpfs` or `ramfs`.
//! A key keeps a saved context of itself while the proxy runs, and loads
//! itself again from its blob when the TPM refuses that context, as it does
//! after a TPM reset.

use std::ffi::OsString;
use std::fs;
use std::io::{self, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::keys::{HeldKey, KeyError, KeyStore, Role, Slot, TpmKept, TpmLost};
use crate::seal::ProxyPublicKey;

/// The TCTI the store uses on a host: the kernel's resource manager, which
/// swaps objects out and flushes what a command leaves behind.
pub const DEVICE_TCTI: &str = "device:/dev/tpmrm0";

/// The length of a key's authorization value, in bytes. The TPM accepts an
/// authorization value as long as the digest of the key's name algorithm,
/// SHA-256.
pub const AUTH_LEN: usize = 32;

/// `TPMA_OBJECT` bits (TPM 2.0 Part 2, 8.3).
pub mod attr {
    /// The key cannot leave this TPM.
    pub const FIXED_TPM: u32 = 1 << 1;
    /// The key cannot move to another parent.
    pub const FIXED_PARENT: u32 = 1 << 4;
    /// The TPM generated the private half.
    pub const SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
    /// The key's authorization value authorizes its use.
    pub const USER_WITH_AUTH: u32 = 1 << 6;
    /// A policy, and not the authorization value, authorizes admin actions.
    pub const ADMIN_WITH_POLICY: u32 = 1 << 7;
    /// A wrong authorization value does not count toward lockout.
    pub const NO_DA: u32 = 1 << 10;
    /// The key can only sign TPM-made data, or decrypt only for the TPM.
    pub const RESTRICTED: u32 = 1 << 16;
    /// The key can decrypt, and so take part in ECDH.
    pub const DECRYPT: u32 = 1 << 17;
    /// The key can sign.
    pub const SIGN: u32 = 1 << 18;

    /// Every attribute that custody needs on each proxy key.
    pub const CUSTODY: u32 =
        FIXED_TPM | FIXED_PARENT | SENSITIVE_DATA_ORIGIN | USER_WITH_AUTH | NO_DA;
}

const TPM_ALG_ECC: u16 = 0x0023;
const TPM_ALG_NULL: u16 = 0x0010;
const TPM_ECC_NIST_P256: u16 = 0x0003;
const FIELD_LEN: usize = 32;

/// The template of a proxy key, as `tpm2_create` takes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyTemplate {
    /// The `-G` value: P-256, with no fixed scheme and no symmetric key.
    pub algorithm: &'static str,
    /// The `TPMA_OBJECT` bits.
    pub attributes: u32,
}

impl KeyTemplate {
    /// The `-a` value: the attribute names that `tpm2-tools` takes.
    #[must_use]
    pub fn attribute_names(&self) -> String {
        const NAMES: [(u32, &str); 9] = [
            (attr::FIXED_TPM, "fixedtpm"),
            (attr::FIXED_PARENT, "fixedparent"),
            (attr::SENSITIVE_DATA_ORIGIN, "sensitivedataorigin"),
            (attr::USER_WITH_AUTH, "userwithauth"),
            (attr::ADMIN_WITH_POLICY, "adminwithpolicy"),
            (attr::NO_DA, "noda"),
            (attr::RESTRICTED, "restricted"),
            (attr::DECRYPT, "decrypt"),
            (attr::SIGN, "sign"),
        ];
        NAMES
            .iter()
            .filter(|(bit, _)| self.attributes & bit != 0)
            .map(|(_, name)| *name)
            .collect::<Vec<_>>()
            .join("|")
    }
}

/// The template the store generates the key for `role` with. The sealing
/// key only agrees, and each CA key only signs.
#[must_use]
pub const fn key_template(role: Role) -> KeyTemplate {
    let usage = match role {
        Role::Sealing => attr::DECRYPT,
        Role::Root | Role::Signing => attr::SIGN,
    };
    KeyTemplate {
        algorithm: "ecc256:null:null",
        attributes: attr::CUSTODY | usage,
    }
}

/// A new authorization value from the OS CSPRNG.
///
/// # Errors
///
/// The OS random source failed.
pub fn new_auth() -> Result<Zeroizing<Vec<u8>>, getrandom::Error> {
    let mut auth = Zeroizing::new(vec![0u8; AUTH_LEN]);
    getrandom::fill(&mut auth)?;
    Ok(auth)
}

/// What the store writes on the standard input of a tool that reads the
/// authorization value as `-p file:-`.
///
/// `tpm2-tools` reads a raw value as a C string and strips trailing newline
/// bytes, so a raw value loses everything from its first zero byte. The
/// `hex:` form carries every byte of the value to the TPM.
fn auth_input(auth: &[u8]) -> Zeroizing<Vec<u8>> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    // The capacity is exact, so the buffer never moves and leaves no copy.
    let mut out = Zeroizing::new(Vec::with_capacity(4 + 2 * auth.len()));
    out.extend_from_slice(b"hex:");
    for byte in auth {
        out.push(HEX[usize::from(byte >> 4)]);
        out.push(HEX[usize::from(byte & 0x0f)]);
    }
    out
}

/// Whether a TPM response code says the authorization value was wrong:
/// `TPM_RC_BAD_AUTH` or `TPM_RC_AUTH_FAIL`, in any session. A reload does
/// not change the answer, so the store does not ask the TPM again.
fn is_auth_failure(code: &str) -> bool {
    let Some(rc) = code
        .strip_prefix("0x")
        .and_then(|hex| u32::from_str_radix(hex, 16).ok())
    else {
        return false;
    };
    // Layer 0 is the TPM itself. Bit 7 marks a format-one code, whose error
    // number is in bits 0 to 5. Bit 6 and bits 8 to 11 name the parameter
    // or the session.
    rc >> 16 == 0 && matches!(rc & 0xbf, 0xa2 | 0x8e)
}

/// Whether a TPM response code says that no TPM can load the key file:
/// `TPM_RC_INTEGRITY` or `TPM_RC_HIERARCHY`, for any handle or parameter.
/// The key file then belongs to a TPM that was cleared, or to another TPM
/// (BEP-089).
fn is_lost_key(code: &str) -> bool {
    let Some(rc) = code
        .strip_prefix("0x")
        .and_then(|hex| u32::from_str_radix(hex, 16).ok())
    else {
        return false;
    };
    // As in `is_auth_failure`: layer 0, format one, error number 0x1f or 0x05.
    rc >> 16 == 0 && matches!(rc & 0xbf, 0x9f | 0x85)
}

/// Sorts a failed load of a key at start (BEP-089). Only an integrity or a
/// hierarchy error loses the key. Every other failure keeps it: a TPM that
/// cannot be reached, that is not ready, or that answers with a temporary
/// response such as `TPM_RC_OBJECT_MEMORY` or `TPM_RC_RETRY` can load the
/// key later, and a replacement would throw away a key that still works.
fn load_error(role: Role, err: ToolError) -> KeyError {
    match err {
        ToolError::Tpm(detail) => {
            let code = detail.rsplit(' ').next().unwrap_or_default();
            let response = format!("TPM response code {code}");
            if is_lost_key(code) {
                KeyError::TpmLost {
                    role,
                    case: TpmLost::NotThisTpm { response },
                }
            } else {
                KeyError::TpmKept {
                    role,
                    case: TpmKept::Unavailable { response },
                }
            }
        }
        ToolError::Other(response) => KeyError::TpmKept {
            role,
            case: TpmKept::Unavailable { response },
        },
    }
}

/// Sorts a failed read of a key file or an authorization file at start
/// (BEP-089). A missing file loses the key, and a file the proxy's user
/// cannot read keeps it.
fn read_error(role: Role, path: &Path, err: &io::Error, missing: TpmLost) -> KeyError {
    match err.kind() {
        io::ErrorKind::NotFound => KeyError::TpmLost {
            role,
            case: missing,
        },
        io::ErrorKind::PermissionDenied => KeyError::TpmKept {
            role,
            case: TpmKept::Unreadable {
                path: path.to_path_buf(),
            },
        },
        _ => KeyError::Store {
            role,
            detail: format!("did not read {}: {err}", path.display()),
        },
    }
}

/// The directory, in memory, for the files that hold an ECDH shared secret:
/// `minimal-bep-tpm` under `runtime`, or `minimal-bep-tpm-<uid>` under `shm`
/// when there is no runtime directory in memory. `in_memory` says whether a
/// directory is on a file system in memory. Only `uid` can use the result.
fn secret_root_in(
    runtime: Option<&Path>,
    shm: &Path,
    uid: u32,
    in_memory: impl Fn(&Path) -> bool,
) -> Result<PathBuf, String> {
    use std::os::unix::fs::MetadataExt as _;
    let path = match runtime {
        Some(dir) if in_memory(dir) => dir.join("minimal-bep-tpm"),
        _ if shm.is_dir() && in_memory(shm) => shm.join(format!("minimal-bep-tpm-{uid}")),
        _ => {
            return Err(format!(
                "XDG_RUNTIME_DIR does not name a directory in memory and {} is not one \
                 either, so the proxy has no directory in memory for the TPM's shared secrets",
                shm.display()
            ));
        }
    };
    match fs::DirBuilder::new().mode(0o700).create(&path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(format!("did not make {}: {err}", path.display())),
    }
    let meta = fs::symlink_metadata(&path)
        .map_err(|err| format!("did not read {}: {err}", path.display()))?;
    if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o077 != 0 {
        return Err(format!(
            "{} is not a directory that only this user can use",
            path.display()
        ));
    }
    Ok(path)
}

/// [`secret_root_in`] for this process: `$XDG_RUNTIME_DIR`, or `/dev/shm`.
fn secret_root() -> Result<PathBuf, String> {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|dir| dir.is_absolute() && dir.is_dir());
    // SAFETY: `geteuid` takes no argument, reads process state and cannot
    // fail.
    let uid = unsafe { libc::geteuid() };
    secret_root_in(runtime.as_deref(), Path::new("/dev/shm"), uid, in_memory)
}

/// Whether `path` is on `tmpfs` or `ramfs`, the file systems that keep
/// their files in memory. A path that `statfs` cannot read is not.
fn in_memory(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `c_path` is a NUL-terminated string that lives for the call,
    // and `stat` points at space for one `statfs` that the call fills.
    if unsafe { libc::statfs(c_path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return false;
    }
    // SAFETY: `statfs` returned 0, so it filled `stat`.
    let stat = unsafe { stat.assume_init() };
    // The type of `f_type` and of the magic numbers differs between libc
    // targets, so compare them as `u64`.
    #[allow(clippy::cast_sign_loss, clippy::unnecessary_cast)]
    let fs_type = stat.f_type as u64;
    #[allow(clippy::cast_sign_loss, clippy::unnecessary_cast)]
    let tmpfs = libc::TMPFS_MAGIC as u64;
    // `RAMFS_MAGIC` from `linux/magic.h`, which `libc` does not export.
    const RAMFS_MAGIC: u64 = 0x8584_58f6;
    fs_type == tmpfs || fs_type == RAMFS_MAGIC
}

/// What the TPM reported for a key in its public area.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPublic {
    /// The `TPMA_OBJECT` bits.
    pub attributes: u32,
    /// The public half.
    pub key: ProxyPublicKey,
}

/// Reads a `TPM2B_PUBLIC` from the start of `bytes`. Returns it and the
/// number of bytes it takes.
///
/// # Errors
///
/// A text that says why `bytes` is not the public area of a P-256 key.
pub fn parse_public(bytes: &[u8]) -> Result<(KeyPublic, usize), String> {
    let mut outer = Reader(bytes);
    let area = outer.sized()?;
    let used = bytes.len() - outer.0.len();
    let mut r = Reader(area);
    if r.u16()? != TPM_ALG_ECC {
        return Err("the key is not an ECC key".into());
    }
    let _name_alg = r.u16()?;
    let attributes = r.u32()?;
    let _auth_policy = r.sized()?;
    // TPMT_SYM_DEF_OBJECT: a key bits and a mode follow an algorithm that
    // is not null.
    if r.u16()? != TPM_ALG_NULL {
        r.u16()?;
        r.u16()?;
    }
    // TPMT_ECC_SCHEME: a hash follows a scheme that is not null.
    if r.u16()? != TPM_ALG_NULL {
        r.u16()?;
    }
    if r.u16()? != TPM_ECC_NIST_P256 {
        return Err("the key is not a P-256 key".into());
    }
    // TPMT_KDF_SCHEME.
    if r.u16()? != TPM_ALG_NULL {
        r.u16()?;
    }
    let x = r.sized()?;
    let y = r.sized()?;
    if x.len() > FIELD_LEN || y.len() > FIELD_LEN {
        return Err("the key's point is too long".into());
    }
    let mut sec1 = vec![0u8; 1 + 2 * FIELD_LEN];
    sec1[0] = 0x04;
    sec1[1 + FIELD_LEN - x.len()..=FIELD_LEN].copy_from_slice(x);
    sec1[1 + 2 * FIELD_LEN - y.len()..].copy_from_slice(y);
    let key = ProxyPublicKey::from_sec1_bytes(&sec1)
        .ok_or_else(|| "the key's point is not on P-256".to_owned())?;
    Ok((KeyPublic { attributes, key }, used))
}

/// Checks that the TPM made `public` with every attribute the template of
/// `role` asks for, so a key that another program put in the store's
/// directory is not used.
///
/// # Errors
///
/// A text that names the missing attributes.
pub fn check_public(role: Role, public: &KeyPublic) -> Result<(), String> {
    let wanted = key_template(role);
    let missing = wanted.attributes & !public.attributes;
    if missing == 0 {
        return Ok(());
    }
    let names = KeyTemplate {
        algorithm: wanted.algorithm,
        attributes: missing,
    }
    .attribute_names();
    Err(format!("the TPM key does not have the attributes {names}"))
}

/// Splits a key file into its `TPM2B_PUBLIC` and its `TPM2B_PRIVATE`, each
/// with its size prefix.
fn split_key_file(bytes: &[u8]) -> Result<(KeyPublic, &[u8], &[u8]), String> {
    let (public, used) = parse_public(bytes)?;
    let (public_blob, rest) = bytes.split_at(used);
    let mut r = Reader(rest);
    r.sized()?;
    if !r.0.is_empty() {
        return Err("the key file has bytes after the private blob".into());
    }
    Ok((public, public_blob, rest))
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.0.len() < n {
            return Err("the key file is too short".into());
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn u16(&mut self) -> Result<u16, String> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, String> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn sized(&mut self) -> Result<&'a [u8], String> {
        let n = self.u16()?;
        self.take(usize::from(n))
    }
}

/// A `TPM2B_ECC_POINT` for `key`, as `tpm2_ecdhzgen -u` reads it.
fn ecc_point(key: &ProxyPublicKey) -> Vec<u8> {
    let sec1 = key.to_sec1_bytes();
    let (x, y) = sec1[1..].split_at(FIELD_LEN);
    let mut out = Vec::with_capacity(2 + 2 * (2 + FIELD_LEN));
    out.extend_from_slice(
        &u16::try_from(2 * (2 + FIELD_LEN))
            .unwrap_or(0)
            .to_be_bytes(),
    );
    for half in [x, y] {
        out.extend_from_slice(&u16::try_from(FIELD_LEN).unwrap_or(0).to_be_bytes());
        out.extend_from_slice(half);
    }
    out
}

/// The x-coordinate of the point that `tpm2_ecdhzgen -o` wrote, as a
/// `TPM2B_ECC_POINT` or as the bare coordinates.
fn shared_x(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    if bytes.len() == 2 * FIELD_LEN {
        return Ok(Zeroizing::new(bytes[..FIELD_LEN].to_vec()));
    }
    let mut outer = Reader(bytes);
    let point = outer.sized()?;
    let x = Reader(point).sized()?;
    if x.len() > FIELD_LEN {
        return Err("the TPM's shared point is too long".into());
    }
    let mut out = Zeroizing::new(vec![0u8; FIELD_LEN]);
    out[FIELD_LEN - x.len()..].copy_from_slice(x);
    Ok(out)
}

/// A DER signature from what `tpm2_sign -f plain` wrote: DER already, or
/// the bare `r || s`.
fn der_signature(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if let Ok(sig) = p256::ecdsa::Signature::from_der(bytes) {
        return Ok(sig.to_der().as_bytes().to_vec());
    }
    p256::ecdsa::Signature::from_slice(bytes)
        .map(|sig| sig.to_der().as_bytes().to_vec())
        .map_err(|_| "the TPM's signature is not an ECDSA P-256 signature".to_owned())
}

/// The response code in a `tpm2-tss` log line, as `0x000009a2`.
fn response_code(stderr: &str) -> Option<&str> {
    let start = stderr.find("ErrorCode (0x")? + "ErrorCode (".len();
    let len = stderr[start..].find(')')?;
    Some(&stderr[start..start + len])
}

/// Why a `tpm2-tools` command failed.
enum ToolError {
    /// The TPM answered with a response code.
    Tpm(String),
    /// The command did not run, or failed before the TPM answered.
    Other(String),
}

impl ToolError {
    fn into_key_error(self, role: Role) -> KeyError {
        match self {
            Self::Tpm(detail) => KeyError::Refused { role, detail },
            Self::Other(detail) => KeyError::Store { role, detail },
        }
    }
}

/// The key store in the TPM.
#[derive(Debug, Clone)]
pub struct TpmStore {
    dir: PathBuf,
    tcti: String,
}

static WORK_DIRS: AtomicU64 = AtomicU64::new(0);

/// Held across one command and its flush when no resource manager stands
/// between the store and the TPM. The flush removes every transient object
/// and session in the TPM, so without this lock it can remove the object
/// that another key's command just loaded.
static NO_RESOURCE_MANAGER: Mutex<()> = Mutex::new(());

/// How long one `tpm2-tools` command can run before the store stops it.
/// A P-256 operation takes well under a second on a TPM, so a command
/// that runs this long is blocked on the device.
const TOOL_DEADLINE: Duration = Duration::from_secs(120);

/// How often the store looks whether a running command finished.
const TOOL_POLL: Duration = Duration::from_millis(5);

/// Removes the `.work-<pid>-<n>` directories and the `<file>.tmp-<pid>`
/// files in `dir` whose process is gone. A proxy that was killed leaves its
/// work directories behind, with copies of key blobs and saved contexts in
/// them. A proxy killed inside `write_private` leaves a temporary file,
/// with an authorization value in it.
///
/// A pid that the kernel gave to another process since keeps its files
/// until that process ends too. They are only left behind longer.
fn sweep_work_dirs(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let work_pid = name
            .strip_prefix(".work-")
            .and_then(|rest| rest.split_once('-'))
            .and_then(|(pid, _)| pid.parse::<u32>().ok());
        let tmp_pid = name
            .rsplit_once(".tmp-")
            .filter(|(stem, _)| !stem.is_empty())
            .and_then(|(_, pid)| pid.parse::<u32>().ok());
        let (pid, is_dir) = match (work_pid, tmp_pid) {
            (Some(pid), _) => (pid, true),
            (None, Some(pid)) => (pid, false),
            (None, None) => continue,
        };
        if pid == std::process::id() || Path::new("/proc").join(pid.to_string()).exists() {
            continue;
        }
        let removed = if is_dir {
            fs::remove_dir_all(entry.path())
        } else {
            fs::remove_file(entry.path())
        };
        match removed {
            Ok(()) => {
                tracing::debug!(path = %entry.path().display(), "removed a stale TPM work file")
            }
            Err(err) => {
                tracing::warn!(path = %entry.path().display(), %err, "could not remove a stale TPM work file")
            }
        }
    }
}

/// A directory that only the proxy's user can read, for one key's saved
/// contexts and the files one command reads and writes. It goes away with
/// its owner.
#[derive(Debug)]
struct WorkDir(PathBuf);

impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

impl TpmStore {
    /// A store that keeps its files in `dir` and reaches the TPM through
    /// `tcti`, which `tpm2-tools` reads from `TPM2TOOLS_TCTI`.
    #[must_use]
    pub fn new(dir: PathBuf, tcti: impl Into<String>) -> Self {
        Self {
            dir,
            tcti: tcti.into(),
        }
    }

    /// `~/.minimal/bep/tpm`, where the proxy keeps its TPM key files.
    #[must_use]
    pub fn default_dir() -> Option<PathBuf> {
        std::env::home_dir().map(|home| home.join(".minimal/bep/tpm"))
    }

    /// The store in [`Self::default_dir`], through [`DEVICE_TCTI`].
    #[must_use]
    pub fn at_home() -> Option<Self> {
        Self::default_dir().map(|dir| Self::new(dir, DEVICE_TCTI))
    }

    /// The directory that holds the key files.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The file that holds the key blob for `role` in `slot`.
    #[must_use]
    pub fn key_path(&self, role: Role, slot: Slot) -> PathBuf {
        self.dir.join(format!("{}.key", role.slot_label(slot)))
    }

    /// The file that holds the authorization value for `role` in `slot`.
    #[must_use]
    pub fn auth_path(&self, role: Role, slot: Slot) -> PathBuf {
        self.dir.join(format!("{}.auth", role.slot_label(slot)))
    }

    fn make_dir(&self) -> io::Result<()> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)
    }

    fn work_dir(&self) -> io::Result<WorkDir> {
        self.make_dir()?;
        work_dir_in(&self.dir)
    }

    /// Runs one `tpm2-tools` command, with `stdin` on its standard input.
    /// Flushes what the command left in the TPM when no resource manager
    /// does it, under a lock that no other command of this process passes.
    fn run(&self, tool: &str, args: &[OsString], stdin: Option<&[u8]>) -> Result<(), ToolError> {
        if self.tcti == DEVICE_TCTI {
            return self.run_once(tool, args, stdin);
        }
        let _guard = NO_RESOURCE_MANAGER
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let result = self.run_once(tool, args, stdin);
        for flag in ["-t", "-l", "-s"] {
            let _ = self.run_once("tpm2_flushcontext", &[flag.into()], None);
        }
        result
    }

    fn run_once(
        &self,
        tool: &str,
        args: &[OsString],
        stdin: Option<&[u8]>,
    ) -> Result<(), ToolError> {
        self.run_within(tool, args, stdin, TOOL_DEADLINE)
    }

    /// Runs one command, and stops it when it runs longer than `deadline`.
    /// A key holds its lock across a command, so a command that blocks on
    /// the TPM must not block every other user of the key for ever.
    fn run_within(
        &self,
        tool: &str,
        args: &[OsString],
        stdin: Option<&[u8]>,
        deadline: Duration,
    ) -> Result<(), ToolError> {
        let mut child = Command::new(tool)
            .args(args)
            .env("TPM2TOOLS_TCTI", &self.tcti)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| {
                ToolError::Other(if err.kind() == io::ErrorKind::NotFound {
                    format!("{tool} is not installed. Install the tpm2-tools package")
                } else {
                    format!("{tool} did not start: {err}")
                })
            })?;
        let started = Instant::now();
        // A tool that fails before it reads its input closes the pipe. Its
        // exit status and its stderr then carry the real reason, so a broken
        // pipe falls through to the wait. The input and stderr move on their
        // own threads, so a tool that blocks cannot block the deadline.
        let (status, write_error, stderr) = std::thread::scope(|scope| {
            let writer = stdin.zip(child.stdin.take()).map(|(input, mut pipe)| {
                scope.spawn(move || {
                    pipe.write_all(input)
                        .err()
                        .filter(|err| err.kind() != io::ErrorKind::BrokenPipe)
                })
            });
            let reader = child.stderr.take().map(|mut pipe| {
                scope.spawn(move || {
                    let mut buf = Vec::new();
                    let _ = io::Read::read_to_end(&mut pipe, &mut buf);
                    buf
                })
            });
            let status = loop {
                match child.try_wait() {
                    Ok(Some(status)) => break Ok(status),
                    Ok(None) if started.elapsed() >= deadline => {
                        let _ = child.kill();
                        let _ = child.wait();
                        break Err(format!(
                            "{tool} did not finish within {} seconds, so the proxy stopped it",
                            deadline.as_secs_f64()
                        ));
                    }
                    Ok(None) => std::thread::sleep(TOOL_POLL),
                    Err(err) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        break Err(format!("{tool} did not finish: {err}"));
                    }
                }
            };
            let write_error = writer.and_then(|w| w.join().ok().flatten());
            let stderr = reader.and_then(|r| r.join().ok()).unwrap_or_default();
            (status, write_error, stderr)
        });
        let status = status.map_err(ToolError::Other)?;
        let output = std::process::Output {
            status,
            stdout: Vec::new(),
            stderr,
        };
        if output.status.success() {
            return match write_error {
                Some(err) => Err(ToolError::Other(format!(
                    "{tool} did not read its input: {err}"
                ))),
                None => Ok(()),
            };
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(match response_code(&stderr) {
            Some(code) => ToolError::Tpm(format!("{tool} failed with TPM response code {code}")),
            None => ToolError::Other(format!(
                "{tool} failed: {}",
                stderr
                    .lines()
                    .rev()
                    .find(|l| !l.trim().is_empty())
                    .unwrap_or("no output")
            )),
        })
    }

    /// Creates the storage key in `work` and saves its context.
    fn primary(&self, work: &Path) -> Result<PathBuf, ToolError> {
        let ctx = work.join("primary.ctx");
        self.run(
            "tpm2_createprimary",
            &args(&["-C", "o", "-g", "sha256", "-G", "ecc256", "-c"], &[&ctx]),
            None,
        )?;
        Ok(ctx)
    }

    /// Loads the key blob under the storage key and saves its context to
    /// `ctx`.
    fn load_into(&self, blob: &KeyBlob, work: &Path, ctx: &Path) -> Result<(), ToolError> {
        let io = |err: io::Error| ToolError::Other(format!("did not write the key blob: {err}"));
        let public = work.join("key.pub");
        let private = work.join("key.priv");
        write_private(&public, &blob.public).map_err(io)?;
        write_private(&private, &blob.private).map_err(io)?;
        let primary = self.primary(work)?;
        let result = self.run(
            "tpm2_load",
            &args(&["-C"], &[&primary])
                .into_iter()
                .chain(args(&["-u"], &[&public]))
                .chain(args(&["-r"], &[&private]))
                .chain(args(&["-c"], &[ctx]))
                .collect::<Vec<_>>(),
            None,
        );
        let _ = fs::remove_file(primary);
        result
    }

    fn read_key(&self, role: Role, slot: Slot) -> Result<Option<Vec<u8>>, KeyError> {
        let path = self.key_path(role, slot);
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(read_error(
                role,
                &path,
                &err,
                TpmLost::MissingKeyFile { path: path.clone() },
            )),
        }
    }

    /// Whether the held key's file is missing beside its authorization
    /// file, with no key file in a side slot that a move can bring back.
    fn lost_key_file(&self, role: Role) -> Result<bool, KeyError> {
        let exists = |path: PathBuf| {
            path.try_exists().map_err(|err| KeyError::Store {
                role,
                detail: format!("did not check for {}: {err}", path.display()),
            })
        };
        Ok(exists(self.auth_path(role, Slot::Held))?
            && !exists(self.key_path(role, Slot::New))?
            && !exists(self.key_path(role, Slot::Old))?)
    }

    fn open(&self, role: Role, bytes: &[u8], auth: Zeroizing<Vec<u8>>) -> Result<TpmKey, KeyError> {
        let (public, public_blob, private_blob) =
            split_key_file(bytes).map_err(|detail| KeyError::Refused { role, detail })?;
        check_public(role, &public).map_err(|detail| KeyError::Refused { role, detail })?;
        let work = self.work_dir().map_err(|err| KeyError::Store {
            role,
            detail: format!("did not make the TPM work directory: {err}"),
        })?;
        let key = TpmKey {
            role,
            public: public.key,
            store: self.clone(),
            blob: KeyBlob {
                public: public_blob.to_vec(),
                private: private_blob.to_vec(),
            },
            auth,
            state: Mutex::new(Loaded(false)),
            work,
        };
        key.load()?;
        Ok(key)
    }

    fn generate_files(&self, role: Role, slot: Slot) -> Result<TpmKey, KeyError> {
        let store_err = |detail: String| KeyError::Store { role, detail };
        let auth =
            new_auth().map_err(|err| store_err(format!("the OS random source failed: {err}")))?;
        let work = self
            .work_dir()
            .map_err(|err| store_err(format!("did not make the TPM work directory: {err}")))?;
        // A failed generation is a store error whatever the TPM answered,
        // as `KeyStore::generate_in` promises.
        let primary = self.primary(&work.0).map_err(|err| match err {
            ToolError::Tpm(detail) | ToolError::Other(detail) => store_err(detail),
        })?;
        let public = work.0.join("new.pub");
        let private = work.0.join("new.priv");
        let template = key_template(role);
        let create_args: Vec<OsString> = args(&["-C"], &[&primary])
            .into_iter()
            .chain(
                [
                    "-g",
                    "sha256",
                    "-G",
                    template.algorithm,
                    "-a",
                    &template.attribute_names(),
                    "-p",
                    "file:-",
                ]
                .map(OsString::from),
            )
            .chain(args(&["-u"], &[&public]))
            .chain(args(&["-r"], &[&private]))
            .collect();
        self.run("tpm2_create", &create_args, Some(&auth_input(&auth)))
            .map_err(|err| match err {
                ToolError::Tpm(detail) | ToolError::Other(detail) => store_err(detail),
            })?;
        let read = |path: &Path| {
            fs::read(path).map_err(|err| store_err(format!("did not read the new TPM key: {err}")))
        };
        let mut bytes = read(&public)?;
        bytes.extend(read(&private)?);
        let key_path = self.key_path(role, slot);
        let auth_path = self.auth_path(role, slot);
        let written =
            write_private(&auth_path, &auth).and_then(|()| write_private(&key_path, &bytes));
        if let Err(err) = written {
            let _ = fs::remove_file(&key_path);
            let _ = fs::remove_file(&auth_path);
            return Err(store_err(format!("did not write the TPM key files: {err}")));
        }
        self.open(role, &bytes, auth).map_err(|err| {
            let _ = fs::remove_file(&key_path);
            let _ = fs::remove_file(&auth_path);
            match err {
                KeyError::Refused { detail, .. } => store_err(detail),
                other => other,
            }
        })
    }
}

/// Writes `bytes` to `path` through a file beside it that only the proxy's
/// user can read, so a reader never sees half a file.
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".tmp-{}", std::process::id()));
    let tmp = PathBuf::from(tmp);
    let written = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written
}

/// A new `.work-<pid>-<n>` directory in `dir`, after the stale ones go.
fn work_dir_in(dir: &Path) -> io::Result<WorkDir> {
    sweep_work_dirs(dir);
    let n = WORK_DIRS.fetch_add(1, Ordering::Relaxed);
    let path = dir.join(format!(".work-{}-{n}", std::process::id()));
    fs::DirBuilder::new().mode(0o700).create(&path)?;
    Ok(WorkDir(path))
}

fn args(flags: &[&str], paths: &[&Path]) -> Vec<OsString> {
    flags
        .iter()
        .map(OsString::from)
        .chain(paths.iter().map(|path| path.as_os_str().to_owned()))
        .collect()
}

#[derive(Debug)]
struct KeyBlob {
    public: Vec<u8>,
    private: Vec<u8>,
}

/// Whether the key's saved context in its work directory is current.
#[derive(Debug)]
struct Loaded(bool);

/// A key that the TPM holds. Only the TPM that made it can load it, and only
/// with its authorization value.
#[derive(Debug)]
pub struct TpmKey {
    role: Role,
    public: ProxyPublicKey,
    store: TpmStore,
    blob: KeyBlob,
    auth: Zeroizing<Vec<u8>>,
    state: Mutex<Loaded>,
    work: WorkDir,
}

impl TpmKey {
    fn context(&self) -> PathBuf {
        self.work.0.join("key.ctx")
    }

    /// Loads the key at start. A key that does not load is kept or lost
    /// (BEP-089).
    fn load(&self) -> Result<(), KeyError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.0 = false;
        self.store
            .load_into(&self.blob, &self.work.0, &self.context())
            .map_err(|err| load_error(self.role, err))?;
        state.0 = true;
        Ok(())
    }

    fn reload(&self, state: &mut Loaded) -> Result<(), KeyError> {
        state.0 = false;
        self.store
            .load_into(&self.blob, &self.work.0, &self.context())
            .map_err(|err| err.into_key_error(self.role))?;
        state.0 = true;
        Ok(())
    }

    /// Runs `op` with the key's saved context. When the TPM refuses a
    /// context that an earlier command saved, loads the key again from its
    /// blob and runs `op` once more.
    fn with_context<T>(&self, op: impl Fn(&Path) -> Result<T, ToolError>) -> Result<T, KeyError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fresh = !state.0;
        if fresh {
            self.reload(&mut state)?;
        }
        match op(&self.context()) {
            Ok(value) => Ok(value),
            Err(ToolError::Tpm(detail))
                if !fresh && !detail.rsplit(' ').next().is_some_and(is_auth_failure) =>
            {
                self.reload(&mut state)?;
                op(&self.context()).map_err(|err| err.into_key_error(self.role))
            }
            Err(err) => Err(err.into_key_error(self.role)),
        }
    }

    fn io_error(err: &io::Error) -> ToolError {
        ToolError::Other(format!("did not use the TPM work directory: {err}"))
    }
}

impl HeldKey for TpmKey {
    fn role(&self) -> Role {
        self.role
    }

    fn public(&self) -> ProxyPublicKey {
        self.public
    }

    fn exportable(&self) -> bool {
        false
    }

    fn agree(&self, peer: &ProxyPublicKey) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        let peer_path = self.work.0.join("peer.point");
        // The shared secret goes to a directory in memory, never to the
        // disk under the key files. The directory goes away with the call.
        let secrets = secret_root()
            .and_then(|root| {
                work_dir_in(&root)
                    .map_err(|err| format!("did not make a directory in {}: {err}", root.display()))
            })
            .map_err(|detail| KeyError::Store {
                role: self.role,
                detail,
            })?;
        let out = secrets.0.join("z.point");
        let auth = auth_input(&self.auth);
        self.with_context(|ctx| {
            write_private(&peer_path, &ecc_point(peer)).map_err(|e| Self::io_error(&e))?;
            let _ = fs::remove_file(&out);
            let args: Vec<OsString> = args(&["-c"], &[ctx])
                .into_iter()
                .chain(["-p", "file:-"].map(OsString::from))
                .chain(args(&["-u"], &[&peer_path]))
                .chain(args(&["-o"], &[&out]))
                .collect();
            let ran = self.store.run("tpm2_ecdhzgen", &args, Some(&auth));
            let read = ran.and_then(|()| fs::read(&out).map_err(|e| Self::io_error(&e)));
            let _ = fs::remove_file(&out);
            let bytes = Zeroizing::new(read?);
            shared_x(&bytes).map_err(ToolError::Other)
        })
    }

    fn probe(&self) -> Result<(), KeyError> {
        match self.role {
            Role::Sealing => self.agree(&self.public).map(drop),
            Role::Root | Role::Signing => crate::ca::CaKey::sign(self, b"bep key probe").map(drop),
        }
    }
}

impl crate::ca::CaKey for TpmKey {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, KeyError> {
        let digest_path = self.work.0.join("msg.digest");
        let out = self.work.0.join("msg.sig");
        let digest = Sha256::digest(msg);
        let auth = auth_input(&self.auth);
        self.with_context(|ctx| {
            write_private(&digest_path, &digest).map_err(|e| Self::io_error(&e))?;
            let _ = fs::remove_file(&out);
            let args: Vec<OsString> = args(&["-c"], &[ctx])
                .into_iter()
                .chain(
                    [
                        "-p", "file:-", "-g", "sha256", "-s", "ecdsa", "-d", "-f", "plain",
                    ]
                    .map(OsString::from),
                )
                .chain(args(&["-o"], &[&out]))
                .chain([digest_path.as_os_str().to_owned()])
                .collect();
            self.store.run("tpm2_sign", &args, Some(&auth))?;
            let bytes = fs::read(&out).map_err(|e| Self::io_error(&e))?;
            der_signature(&bytes).map_err(ToolError::Other)
        })
    }
}

impl TpmStore {
    /// Puts back the authorization file of the key in `slot` when a move
    /// stopped half way. `relabel` moves the authorization file first and
    /// the key file second, so a proxy that dies between the two leaves the
    /// key file in one slot and its authorization file, with no key file
    /// beside it, in another. Only one move runs for a role at a time, so a
    /// single such authorization file belongs to the key in `slot`.
    fn recover_auth(&self, role: Role, slot: Slot) -> Result<(), KeyError> {
        let exists = |path: &Path| {
            path.try_exists().map_err(|err| KeyError::Store {
                role,
                detail: format!("did not check for {}: {err}", path.display()),
            })
        };
        let auth = self.auth_path(role, slot);
        if !exists(&self.key_path(role, slot))? || exists(&auth)? {
            return Ok(());
        }
        let mut orphans = Vec::new();
        for other in [Slot::Held, Slot::New, Slot::Old] {
            if other == slot {
                continue;
            }
            let other_auth = self.auth_path(role, other);
            if exists(&other_auth)? && !exists(&self.key_path(role, other))? {
                orphans.push(other_auth);
            }
        }
        let [orphan] = orphans.as_slice() else {
            return Ok(());
        };
        fs::rename(orphan, &auth).map_err(|err| KeyError::Store {
            role,
            detail: format!("did not restore the TPM key's authorization file: {err}"),
        })?;
        tracing::warn!(
            role = %role,
            from = %orphan.display(),
            to = %auth.display(),
            store = "tpm",
            "restored an authorization file that an interrupted key move left behind"
        );
        Ok(())
    }
}

impl KeyStore for TpmStore {
    type Key = TpmKey;

    fn find(&self, role: Role) -> Result<Option<TpmKey>, KeyError> {
        self.recover_auth(role, Slot::Held)?;
        let Some(bytes) = self.read_key(role, Slot::Held)? else {
            // BEP-089: an authorization file alone is a key whose key file
            // is gone. A move that stopped part way leaves the key file in
            // a side slot, and the start moves it back.
            if self.lost_key_file(role)? {
                return Err(KeyError::TpmLost {
                    role,
                    case: TpmLost::MissingKeyFile {
                        path: self.key_path(role, Slot::Held),
                    },
                });
            }
            return Ok(None);
        };
        let auth_path = self.auth_path(role, Slot::Held);
        let auth = fs::read(&auth_path).map(Zeroizing::new).map_err(|err| {
            read_error(
                role,
                &auth_path,
                &err,
                TpmLost::MissingAuthFile {
                    path: auth_path.clone(),
                },
            )
        })?;
        let key = self.open(role, &bytes, auth)?;
        tracing::info!(
            role = %role,
            fingerprint = %key.public.kid(),
            store = "tpm",
            "loaded a proxy key from the TPM"
        );
        Ok(Some(key))
    }

    fn generate_in(&self, role: Role, slot: Slot) -> Result<TpmKey, KeyError> {
        let key = self.generate_files(role, slot)?;
        tracing::info!(
            role = %role,
            fingerprint = %key.public.kid(),
            store = "tpm",
            "generated a proxy key in the TPM"
        );
        Ok(key)
    }

    fn remove_in(&self, role: Role, slot: Slot) -> Result<(), KeyError> {
        for path in [self.key_path(role, slot), self.auth_path(role, slot)] {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(KeyError::Store {
                        role,
                        detail: format!("did not remove {}: {err}", path.display()),
                    });
                }
            }
        }
        Ok(())
    }

    fn holds_in(&self, role: Role, slot: Slot) -> Result<bool, KeyError> {
        self.key_path(role, slot)
            .try_exists()
            .map_err(|err| KeyError::Store {
                role,
                detail: format!("did not check for the TPM key file: {err}"),
            })
    }

    fn kid_in(&self, role: Role, slot: Slot) -> Result<Option<String>, KeyError> {
        let Some(bytes) = self.read_key(role, slot)? else {
            return Ok(None);
        };
        parse_public(&bytes)
            .map(|(public, _)| Some(public.key.kid()))
            .map_err(|detail| KeyError::Refused { role, detail })
    }

    fn relabel(&self, role: Role, from: Slot, to: Slot) -> Result<(), KeyError> {
        let (key_from, key_to) = (self.key_path(role, from), self.key_path(role, to));
        self.recover_auth(role, from)?;
        if !self.holds_in(role, from)? {
            if from == Slot::Held {
                return Ok(());
            }
            return Err(KeyError::Store {
                role,
                detail: "the store holds no key to move".into(),
            });
        }
        let moved =
            fs::rename(self.auth_path(role, from), self.auth_path(role, to)).and_then(|()| {
                fs::rename(&key_from, &key_to).inspect_err(|_| {
                    let _ = fs::rename(self.auth_path(role, to), self.auth_path(role, from));
                })
            });
        moved.map_err(|err| KeyError::Store {
            role,
            detail: format!("did not move the TPM key files: {err}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    /// A `TPM2B_PUBLIC` for an unrestricted P-256 key with `attributes`, as
    /// `tpm2_create` writes it.
    fn public_area(attributes: u32, key: &ProxyPublicKey) -> Vec<u8> {
        let sec1 = key.to_sec1_bytes();
        let mut area = Vec::new();
        area.extend_from_slice(&TPM_ALG_ECC.to_be_bytes());
        area.extend_from_slice(&0x000Bu16.to_be_bytes());
        area.extend_from_slice(&attributes.to_be_bytes());
        area.extend_from_slice(&0u16.to_be_bytes());
        area.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        area.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        area.extend_from_slice(&TPM_ECC_NIST_P256.to_be_bytes());
        area.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        for half in [&sec1[1..=FIELD_LEN], &sec1[1 + FIELD_LEN..]] {
            area.extend_from_slice(&(FIELD_LEN as u16).to_be_bytes());
            area.extend_from_slice(half);
        }
        let mut out = (area.len() as u16).to_be_bytes().to_vec();
        out.extend(area);
        out
    }

    fn some_public() -> ProxyPublicKey {
        crate::seal::ProxyKey::generate().expect("a key").public()
    }

    // BEP-088: each key is fixed to the TPM, exempt from lockout, and needs
    // its own authorization value of at least 128 bits.
    #[test]
    fn tpm_key_template_is_fixed_exempt_from_lockout_and_needs_authorization() {
        for role in Role::ALL {
            let template = key_template(role);
            for bit in [
                attr::FIXED_TPM,
                attr::FIXED_PARENT,
                attr::NO_DA,
                attr::USER_WITH_AUTH,
                attr::SENSITIVE_DATA_ORIGIN,
            ] {
                assert_ne!(template.attributes & bit, 0, "{role}: bit {bit:#x}");
            }
            assert_eq!(template.attributes & attr::RESTRICTED, 0, "{role}");
            let names = template.attribute_names();
            for name in [
                "fixedtpm",
                "fixedparent",
                "noda",
                "userwithauth",
                "sensitivedataorigin",
            ] {
                assert!(names.split('|').any(|n| n == name), "{role}: {names}");
            }
            assert!(template.algorithm.starts_with("ecc256:"));
        }
        assert_ne!(key_template(Role::Sealing).attributes & attr::DECRYPT, 0);
        assert_ne!(key_template(Role::Root).attributes & attr::SIGN, 0);
        assert_ne!(key_template(Role::Signing).attributes & attr::SIGN, 0);

        // A public area the TPM reports with every attribute passes, and one
        // without `noDA`, `fixedTPM` or `fixedParent` is refused.
        let key = some_public();
        let full = public_area(key_template(Role::Root).attributes, &key);
        let (public, used) = parse_public(&full).expect("a public area");
        assert_eq!(used, full.len());
        assert_eq!(public.key, key);
        check_public(Role::Root, &public).expect("every attribute");
        for missing in [
            attr::NO_DA,
            attr::FIXED_TPM,
            attr::FIXED_PARENT,
            attr::USER_WITH_AUTH,
        ] {
            let area = public_area(key_template(Role::Root).attributes & !missing, &key);
            let (public, _) = parse_public(&area).expect("a public area");
            assert!(check_public(Role::Root, &public).is_err(), "{missing:#x}");
        }

        // The authorization value is at least 128 bits, new each time.
        let a = new_auth().expect("random");
        let b = new_auth().expect("random");
        assert!(a.len() * 8 >= 128);
        assert_ne!(*a, *b);

        // Only the proxy's user can read the authorization file.
        let dir = tempfile::tempdir().expect("tempdir");
        let store = TpmStore::new(dir.path().join("tpm"), DEVICE_TCTI);
        store.make_dir().expect("dir");
        let path = store.auth_path(Role::Sealing, Slot::Held);
        write_private(&path, &a).expect("write");
        let mode = fs::metadata(&path).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let dir_mode = fs::metadata(store.dir())
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700);
        assert_eq!(fs::read(&path).expect("read"), *a);

        // The tools get every byte of the value, in the hex form.
        assert_auth_input_is_hex(&a);
    }

    fn assert_auth_input_is_hex(auth: &[u8]) {
        let input = auth_input(auth);
        let hex = input.strip_prefix(b"hex:").expect("the hex: prefix");
        assert_eq!(hex.len(), 2 * auth.len());
        assert!(hex.iter().all(|b| b.is_ascii_hexdigit()), "{input:?}");
        let decoded: Vec<u8> = hex
            .chunks(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("ascii"), 16).expect("hex")
            })
            .collect();
        assert_eq!(decoded, auth);
    }

    // `tpm2-tools` reads a raw authorization value as a C string, so a zero
    // byte or a trailing newline would cut it short. The tools get the hex
    // form, which holds neither.
    #[test]
    fn an_authorization_value_reaches_the_tools_whole_in_hex() {
        let mut auth = [0x5au8; AUTH_LEN];
        auth[0] = 0x00;
        auth[7] = 0x00;
        auth[AUTH_LEN - 2] = b'\r';
        auth[AUTH_LEN - 1] = b'\n';
        assert_auth_input_is_hex(&auth);
        assert_eq!(
            &auth_input(&[0x00, 0x0a, 0xff])[..],
            b"hex:000aff".as_slice()
        );
        let input = auth_input(&auth);
        assert!(!input.contains(&0));
        assert!(!input.ends_with(b"\n"));
    }

    // A wrong authorization value is not worth a second try after a reload.
    #[test]
    fn an_authorization_failure_is_not_retried() {
        for code in ["0x000009a2", "0x0000098e", "0x000001a2", "0x000000a2"] {
            assert!(is_auth_failure(code), "{code}");
        }
        for code in [
            "0x00000128",
            "0x00000922",
            "0x000b0009a2",
            "0x00000902",
            "x",
        ] {
            assert!(!is_auth_failure(code), "{code}");
        }
    }

    // The ECDH shared secret goes to a directory in memory that only the
    // proxy's user can use, under the runtime directory when there is one.
    #[test]
    fn the_shared_secret_directory_is_in_memory_and_private() {
        use std::os::unix::fs::MetadataExt as _;
        let runtime = tempfile::tempdir().expect("tempdir");
        let shm = tempfile::tempdir().expect("tempdir");
        let uid = fs::metadata(runtime.path()).expect("meta").uid();

        let root =
            secret_root_in(Some(runtime.path()), shm.path(), uid, |_| true).expect("runtime");
        assert_eq!(root, runtime.path().join("minimal-bep-tpm"));
        let mode = fs::metadata(&root).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        // A second call finds the same directory.
        assert_eq!(
            secret_root_in(Some(runtime.path()), shm.path(), uid, |_| true).expect("again"),
            root
        );

        let root = secret_root_in(None, shm.path(), uid, |_| true).expect("shm");
        assert_eq!(root, shm.path().join(format!("minimal-bep-tpm-{uid}")));

        // A runtime directory on the disk is passed over for `shm`.
        let on_disk = runtime.path().to_path_buf();
        let root = secret_root_in(Some(runtime.path()), shm.path(), uid, |dir| dir != on_disk)
            .expect("shm, not the runtime directory on the disk");
        assert_eq!(root, shm.path().join(format!("minimal-bep-tpm-{uid}")));
        // With neither directory in memory, the store refuses.
        let err = secret_root_in(Some(runtime.path()), shm.path(), uid, |_| false)
            .expect_err("no directory in memory");
        assert!(err.contains("XDG_RUNTIME_DIR"), "{err}");
        // `/proc` is not in memory in the sense the store needs.
        assert!(!in_memory(Path::new("/proc")));
        assert!(!in_memory(Path::new("/no/such/directory")));

        let missing = shm.path().join("missing");
        let err =
            secret_root_in(None, &missing, uid, |_| true).expect_err("no directory in memory");
        assert!(err.contains("XDG_RUNTIME_DIR"), "{err}");

        // A directory that another user can read is refused.
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).expect("chmod");
        assert!(secret_root_in(None, shm.path(), uid, |_| true).is_err());
        // A directory that another user owns is refused.
        assert!(secret_root_in(Some(runtime.path()), shm.path(), uid + 1, |_| true).is_err());
    }

    // A tool that exits before it reads its input still reports the TPM's
    // response code from its stderr.
    #[test]
    fn a_tool_that_exits_before_its_input_reports_its_response_code() {
        let store = TpmStore::new(PathBuf::from("/nonexistent"), DEVICE_TCTI);
        let script = "echo 'ErrorCode (0x000009a2)' >&2; exit 1";
        let input = vec![0u8; 4 << 20];
        match store.run_once("sh", &args(&["-c", script], &[]), Some(&input)) {
            Err(ToolError::Tpm(detail)) => assert!(detail.ends_with("0x000009a2"), "{detail}"),
            Err(ToolError::Other(detail)) => panic!("lost the response code: {detail}"),
            Ok(()) => panic!("expected a failure"),
        }
    }

    // A tool that blocks is stopped at its deadline, and its key's lock
    // does not wait on it for ever.
    #[test]
    fn a_tool_that_runs_past_its_deadline_is_stopped() {
        let store = TpmStore::new(PathBuf::from("/nonexistent"), DEVICE_TCTI);
        let started = Instant::now();
        let result = store.run_within(
            "sh",
            &args(&["-c", "exec sleep 30"], &[]),
            Some(&[0u8; 16]),
            Duration::from_millis(200),
        );
        assert!(started.elapsed() < Duration::from_secs(10));
        match result {
            Err(ToolError::Other(detail)) => {
                assert!(detail.contains("did not finish within"), "{detail}")
            }
            Err(ToolError::Tpm(detail)) => panic!("unexpected response code: {detail}"),
            Ok(()) => panic!("expected a failure"),
        }
    }

    // A work directory that a killed proxy left behind goes away when the
    // store next makes one. A live process keeps its own.
    #[test]
    fn a_stale_work_directory_is_swept_when_the_store_opens_a_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = TpmStore::new(dir.path().to_path_buf(), DEVICE_TCTI);
        // pid_max is at most 2^22, so this process cannot exist.
        let stale = dir.path().join(".work-4294967294-0");
        let live = dir
            .path()
            .join(format!(".work-{}-999999", std::process::id()));
        for path in [&stale, &live] {
            fs::create_dir_all(path).expect("mkdir");
            fs::write(path.join("ctx"), b"x").expect("write");
        }
        let work = store.work_dir().expect("work dir");
        assert!(!stale.exists());
        assert!(live.exists());
        assert!(work.0.exists());
    }

    // A temporary file that a proxy killed inside `write_private` left
    // behind holds an authorization value. It goes away with the stale
    // work directories. A live process keeps its own.
    #[test]
    fn a_stale_temporary_auth_file_is_swept_when_the_store_opens_a_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = TpmStore::new(dir.path().to_path_buf(), DEVICE_TCTI);
        let stale = dir.path().join("sealing.auth.tmp-4294967294");
        let live = dir
            .path()
            .join(format!("sealing.auth.tmp-{}", std::process::id()));
        let other = dir.path().join("sealing.auth");
        for path in [&stale, &live, &other] {
            fs::write(path, b"auth").expect("write");
        }
        let _work = store.work_dir().expect("work dir");
        assert!(!stale.exists());
        assert!(live.exists());
        assert!(other.exists());
    }

    // A proxy that dies between the two renames of a move leaves the key
    // file in one slot and its authorization file in the other. The next
    // look at the key puts the authorization file back beside it.
    #[test]
    fn an_interrupted_move_gets_its_authorization_file_back() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = TpmStore::new(dir.path().to_path_buf(), DEVICE_TCTI);
        let role = Role::Sealing;
        fs::write(store.key_path(role, Slot::Held), b"key").expect("write");
        fs::write(store.auth_path(role, Slot::Old), b"auth").expect("write");
        store.recover_auth(role, Slot::Held).expect("recover");
        assert_eq!(
            fs::read(store.auth_path(role, Slot::Held)).expect("read"),
            b"auth"
        );
        assert!(!store.auth_path(role, Slot::Old).exists());

        // A complete move goes on as before, and the orphan check leaves a
        // key that has its own authorization file alone.
        store.relabel(role, Slot::Held, Slot::Old).expect("relabel");
        assert!(store.key_path(role, Slot::Old).exists());
        assert!(store.auth_path(role, Slot::Old).exists());
        assert!(!store.key_path(role, Slot::Held).exists());

        // A crash after the first rename of New to Held: the next relabel
        // of New finishes the move.
        fs::write(store.key_path(role, Slot::New), b"new").expect("write");
        fs::write(store.auth_path(role, Slot::Held), b"new-auth").expect("write");
        fs::remove_file(store.auth_path(role, Slot::Old)).expect("rm");
        fs::remove_file(store.key_path(role, Slot::Old)).expect("rm");
        store.relabel(role, Slot::New, Slot::Held).expect("relabel");
        assert_eq!(
            fs::read(store.key_path(role, Slot::Held)).expect("read"),
            b"new"
        );
        assert_eq!(
            fs::read(store.auth_path(role, Slot::Held)).expect("read"),
            b"new-auth"
        );
    }

    #[test]
    fn a_key_file_splits_into_its_public_and_private_blobs() {
        let key = some_public();
        let public = public_area(key_template(Role::Sealing).attributes, &key);
        let mut file = public.clone();
        file.extend_from_slice(&[0, 3, 1, 2, 3]);
        let (parsed, public_blob, private_blob) = split_key_file(&file).expect("split");
        assert_eq!(parsed.key, key);
        assert_eq!(public_blob, public.as_slice());
        assert_eq!(private_blob, &[0, 3, 1, 2, 3]);
        file.push(9);
        assert!(split_key_file(&file).is_err());
    }

    #[test]
    fn tpm_outputs_read_as_the_proxy_expects() {
        assert_eq!(
            response_code(
                "ERROR:esys:src/tss2-esys/api/Esys_Sign.c:3 Esys_Sign_Finish() Received a non-TPM Error ErrorCode (0x000009a2)"
            ),
            Some("0x000009a2")
        );
        assert_eq!(response_code("Tss2_Tcti_Swtpm_Init() Cannot connect"), None);

        let key = some_public();
        let point = ecc_point(&key);
        assert_eq!(point.len(), 2 + 2 * (2 + FIELD_LEN));
        let sec1 = key.to_sec1_bytes();
        assert_eq!(*shared_x(&point).expect("x"), sec1[1..=FIELD_LEN].to_vec());
        assert_eq!(
            *shared_x(&sec1[1..]).expect("x"),
            sec1[1..=FIELD_LEN].to_vec()
        );

        let raw = [7u8; 64];
        let der = der_signature(&raw).expect("der");
        assert_eq!(der_signature(&der).expect("der"), der);
    }

    /// A key file and an authorization file for `role` in the held slot,
    /// as `tpm2_create` and the store write them.
    fn write_key_files(store: &TpmStore, role: Role) {
        let mut file = public_area(key_template(role).attributes, &some_public());
        file.extend_from_slice(&[0, 3, 1, 2, 3]);
        fs::write(store.key_path(role, Slot::Held), file).expect("write key file");
        fs::write(store.auth_path(role, Slot::Held), [7u8; AUTH_LEN]).expect("write auth file");
    }

    fn start_error(store: &TpmStore) -> crate::keys::StartError {
        match crate::keys::load(store, &[]) {
            Err(err) => err,
            Ok(_) => panic!("expected the start to be refused"),
        }
    }

    // BEP-089: a TPM that cannot be reached, or that answers that it cannot
    // load an object now, keeps the key and names no replacement.
    #[test]
    fn an_unreachable_tpm_refuses_start_and_keeps_the_key() {
        use crate::keys::StartError;
        let dir = tempfile::tempdir().expect("tempdir");
        // No TPM answers at this path. Whether or not `tpm2-tools` is
        // installed, the load fails before a TPM answers.
        let store = TpmStore::new(dir.path().to_path_buf(), "device:/nonexistent/tpmrm0");
        write_key_files(&store, Role::Sealing);
        let err = start_error(&store);
        let StartError::TpmKept {
            role: Role::Sealing,
            case: TpmKept::Unavailable { response },
        } = &err
        else {
            panic!("expected a kept key, got {err:?}");
        };
        assert_eq!(
            err.to_string(),
            format!(
                "The proxy did not start: the TPM cannot load the proxy's sealing key now ({response}). The key is kept; start the proxy again when the TPM is available."
            )
        );
        assert!(!err.to_string().contains("--replace-key"));
        assert!(store.key_path(Role::Sealing, Slot::Held).exists());
        assert!(store.auth_path(Role::Sealing, Slot::Held).exists());

        // A temporary response keeps the key too, as does any response
        // that does not say the key is lost.
        for code in ["0x00000902", "0x00000922", "0x00000100", "0x000009a2"] {
            let err = load_error(
                Role::Root,
                ToolError::Tpm(format!("tpm2_load failed with TPM response code {code}")),
            );
            assert_eq!(
                err,
                KeyError::TpmKept {
                    role: Role::Root,
                    case: TpmKept::Unavailable {
                        response: format!("TPM response code {code}"),
                    },
                }
            );
            assert_eq!(
                StartError::from_store(err).to_string(),
                format!(
                    "The proxy did not start: the TPM cannot load the proxy's root key now (TPM response code {code}). The key is kept; start the proxy again when the TPM is available."
                )
            );
        }
    }

    // BEP-089: a missing key file, a missing authorization file, and a key
    // file that the TPM refuses as not its own are lost keys. Each refusal
    // names the replacement for its role.
    #[test]
    fn a_tpm_key_the_tpm_cannot_load_refuses_start() {
        use crate::keys::StartError;
        let dir = tempfile::tempdir().expect("tempdir");
        let store = TpmStore::new(dir.path().to_path_buf(), "device:/nonexistent/tpmrm0");

        write_key_files(&store, Role::Root);
        let auth = store.auth_path(Role::Root, Slot::Held);
        fs::remove_file(&auth).expect("rm auth");
        let err = start_error(&store);
        assert_eq!(
            err,
            StartError::TpmLost {
                role: Role::Root,
                case: TpmLost::MissingAuthFile { path: auth.clone() },
            }
        );
        assert_eq!(
            err.to_string(),
            format!(
                "The proxy did not start: the authorization file of the proxy's root key is missing: {}. Run `bep --replace-key root` to make a new one. Boxes created before then must be re-created.",
                auth.display()
            )
        );

        write_key_files(&store, Role::Root);
        let key = store.key_path(Role::Root, Slot::Held);
        fs::remove_file(&key).expect("rm key");
        let err = start_error(&store);
        assert_eq!(
            err,
            StartError::TpmLost {
                role: Role::Root,
                case: TpmLost::MissingKeyFile { path: key.clone() },
            }
        );
        assert_eq!(
            err.to_string(),
            format!(
                "The proxy did not start: the key file of the proxy's root key is missing: {}. Run `bep --replace-key root` to make a new one. Boxes created before then must be re-created.",
                key.display()
            )
        );
        // The refusal removes nothing.
        assert!(auth.exists());

        // TPM_RC_INTEGRITY and TPM_RC_HIERARCHY, for any parameter or
        // handle, say the key file is not this TPM's.
        for code in ["0x0000009f", "0x000001df", "0x00000085", "0x000002c5"] {
            let err = load_error(
                Role::Signing,
                ToolError::Tpm(format!("tpm2_load failed with TPM response code {code}")),
            );
            assert_eq!(
                err,
                KeyError::TpmLost {
                    role: Role::Signing,
                    case: TpmLost::NotThisTpm {
                        response: format!("TPM response code {code}"),
                    },
                }
            );
            assert_eq!(
                StartError::from_store(err).to_string(),
                "The proxy did not start: this TPM no longer holds the proxy's signing key. Run `bep --replace-key signing` to make a new one. Boxes created before then must be re-created."
            );
        }
    }

    // BEP-089: a key file or an authorization file that the proxy's user
    // cannot read is intact, so the start keeps the key and names no
    // replacement.
    #[test]
    fn an_unreadable_tpm_key_file_refuses_start_and_keeps_the_key() {
        use crate::keys::StartError;
        let denied = io::Error::from(io::ErrorKind::PermissionDenied);
        let path = PathBuf::from("/home/u/.minimal/bep/tpm/sealing.auth");
        let err = read_error(
            Role::Sealing,
            &path,
            &denied,
            TpmLost::MissingAuthFile { path: path.clone() },
        );
        assert_eq!(
            StartError::from_store(err).to_string(),
            "The proxy did not start: this user cannot read /home/u/.minimal/bep/tpm/sealing.auth, which holds the proxy's sealing key. The key is kept."
        );

        // Through a start, for each of the two files. Mode bits do not stop
        // root, so this half runs only for another user.
        let dir = tempfile::tempdir().expect("tempdir");
        let store = TpmStore::new(dir.path().to_path_buf(), "device:/nonexistent/tpmrm0");
        write_key_files(&store, Role::Sealing);
        for path in [
            store.key_path(Role::Sealing, Slot::Held),
            store.auth_path(Role::Sealing, Slot::Held),
        ] {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).expect("chmod");
            if fs::read(&path).is_ok() {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
                continue;
            }
            let err = start_error(&store);
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
            assert_eq!(
                err,
                StartError::TpmKept {
                    role: Role::Sealing,
                    case: TpmKept::Unreadable { path: path.clone() },
                }
            );
            assert_eq!(
                err.to_string(),
                format!(
                    "The proxy did not start: this user cannot read {}, which holds the proxy's sealing key. The key is kept.",
                    path.display()
                )
            );
            assert!(path.exists());
        }
    }
}
