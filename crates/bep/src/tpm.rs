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

use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::keys::{HeldKey, KeyError, KeyStore, Role, Slot};
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
    pub const CUSTODY: u32 = FIXED_TPM | FIXED_PARENT | SENSITIVE_DATA_ORIGIN | USER_WITH_AUTH | NO_DA;
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
    out.extend_from_slice(&u16::try_from(2 * (2 + FIELD_LEN)).unwrap_or(0).to_be_bytes());
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
        let n = WORK_DIRS.fetch_add(1, Ordering::Relaxed);
        let path = self
            .dir
            .join(format!(".work-{}-{n}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(WorkDir(path))
    }

    /// Runs one `tpm2-tools` command, with `stdin` on its standard input.
    /// Flushes what the command left in the TPM when no resource manager
    /// does it.
    fn run(&self, tool: &str, args: &[OsString], stdin: Option<&[u8]>) -> Result<(), ToolError> {
        let result = self.run_once(tool, args, stdin);
        if self.tcti != DEVICE_TCTI {
            for flag in ["-t", "-l", "-s"] {
                let _ = self.run_once("tpm2_flushcontext", &[flag.into()], None);
            }
        }
        result
    }

    fn run_once(&self, tool: &str, args: &[OsString], stdin: Option<&[u8]>) -> Result<(), ToolError> {
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
        if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
            pipe.write_all(input)
                .map_err(|err| ToolError::Other(format!("{tool} did not read its input: {err}")))?;
        }
        let output = child
            .wait_with_output()
            .map_err(|err| ToolError::Other(format!("{tool} did not finish: {err}")))?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(match response_code(&stderr) {
            Some(code) => ToolError::Tpm(format!("{tool} failed with TPM response code {code}")),
            None => ToolError::Other(format!(
                "{tool} failed: {}",
                stderr.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("no output")
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
        match fs::read(self.key_path(role, slot)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(KeyError::Store {
                role,
                detail: format!("did not read the TPM key file: {err}"),
            }),
        }
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
        let auth = new_auth().map_err(|err| store_err(format!("the OS random source failed: {err}")))?;
        let work = self
            .work_dir()
            .map_err(|err| store_err(format!("did not make the TPM work directory: {err}")))?;
        let primary = self.primary(&work.0).map_err(|err| err.into_key_error(role))?;
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
        self.run("tpm2_create", &create_args, Some(&auth))
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
        let written = write_private(&auth_path, &auth).and_then(|()| write_private(&key_path, &bytes));
        if let Err(err) = written {
            let _ = fs::remove_file(&key_path);
            let _ = fs::remove_file(&auth_path);
            return Err(store_err(format!("did not write the TPM key files: {err}")));
        }
        self.open(role, &bytes, auth).inspect_err(|_| {
            let _ = fs::remove_file(&key_path);
            let _ = fs::remove_file(&auth_path);
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

    fn load(&self) -> Result<(), KeyError> {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        self.reload(&mut state)
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
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let fresh = !state.0;
        if fresh {
            self.reload(&mut state)?;
        }
        match op(&self.context()) {
            Ok(value) => Ok(value),
            Err(ToolError::Tpm(_)) if !fresh => {
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
        let out = self.work.0.join("z.point");
        self.with_context(|ctx| {
            write_private(&peer_path, &ecc_point(peer)).map_err(|e| Self::io_error(&e))?;
            let _ = fs::remove_file(&out);
            let args: Vec<OsString> = args(&["-c"], &[ctx])
                .into_iter()
                .chain(["-p", "file:-"].map(OsString::from))
                .chain(args(&["-u"], &[&peer_path]))
                .chain(args(&["-o"], &[&out]))
                .collect();
            self.store.run("tpm2_ecdhzgen", &args, Some(&self.auth))?;
            let bytes = Zeroizing::new(fs::read(&out).map_err(|e| Self::io_error(&e))?);
            let _ = fs::remove_file(&out);
            shared_x(&bytes).map_err(ToolError::Other)
        })
    }

    fn probe(&self) -> Result<(), KeyError> {
        match self.role {
            Role::Sealing => self.agree(&self.public).map(drop),
            Role::Root | Role::Signing => {
                crate::ca::CaKey::sign(self, b"bep key probe").map(drop)
            }
        }
    }
}

impl crate::ca::CaKey for TpmKey {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, KeyError> {
        let digest_path = self.work.0.join("msg.digest");
        let out = self.work.0.join("msg.sig");
        let digest = Sha256::digest(msg);
        self.with_context(|ctx| {
            write_private(&digest_path, &digest).map_err(|e| Self::io_error(&e))?;
            let _ = fs::remove_file(&out);
            let args: Vec<OsString> = args(&["-c"], &[ctx])
                .into_iter()
                .chain(
                    ["-p", "file:-", "-g", "sha256", "-s", "ecdsa", "-d", "-f", "plain"]
                        .map(OsString::from),
                )
                .chain(args(&["-o"], &[&out]))
                .chain([digest_path.as_os_str().to_owned()])
                .collect();
            self.store.run("tpm2_sign", &args, Some(&self.auth))?;
            let bytes = fs::read(&out).map_err(|e| Self::io_error(&e))?;
            der_signature(&bytes).map_err(ToolError::Other)
        })
    }
}

impl KeyStore for TpmStore {
    type Key = TpmKey;

    fn find(&self, role: Role) -> Result<Option<TpmKey>, KeyError> {
        let Some(bytes) = self.read_key(role, Slot::Held)? else {
            return Ok(None);
        };
        let auth = fs::read(self.auth_path(role, Slot::Held))
            .map(Zeroizing::new)
            .map_err(|err| KeyError::Refused {
                role,
                detail: format!("did not read the TPM key's authorization file: {err}"),
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
        if !self.holds_in(role, from)? {
            if from == Slot::Held {
                return Ok(());
            }
            return Err(KeyError::Store {
                role,
                detail: "the store holds no key to move".into(),
            });
        }
        let moved = fs::rename(self.auth_path(role, from), self.auth_path(role, to))
            .and_then(|()| {
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
            for name in ["fixedtpm", "fixedparent", "noda", "userwithauth", "sensitivedataorigin"] {
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
        for missing in [attr::NO_DA, attr::FIXED_TPM, attr::FIXED_PARENT, attr::USER_WITH_AUTH] {
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
        let dir_mode = fs::metadata(store.dir()).expect("meta").permissions().mode();
        assert_eq!(dir_mode & 0o777, 0o700);
        assert_eq!(fs::read(&path).expect("read"), *a);
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
            response_code("ERROR:esys:src/tss2-esys/api/Esys_Sign.c:3 Esys_Sign_Finish() Received a non-TPM Error ErrorCode (0x000009a2)"),
            Some("0x000009a2")
        );
        assert_eq!(response_code("Tss2_Tcti_Swtpm_Init() Cannot connect"), None);

        let key = some_public();
        let point = ecc_point(&key);
        assert_eq!(point.len(), 2 + 2 * (2 + FIELD_LEN));
        let sec1 = key.to_sec1_bytes();
        assert_eq!(*shared_x(&point).expect("x"), sec1[1..=FIELD_LEN].to_vec());
        assert_eq!(*shared_x(&sec1[1..]).expect("x"), sec1[1..=FIELD_LEN].to_vec());

        let raw = [7u8; 64];
        let der = der_signature(&raw).expect("der");
        assert_eq!(der_signature(&der).expect("der"), der);
    }
}
