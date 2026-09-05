//! Host-side collectors for the `min bug` diagnostic bundle.
//!
//! Each collector is independent: it reads what it can, adds entries to the
//! [`BundleWriter`], and returns an error only for genuinely unexpected
//! failures (an absent file is data, not an error). The orchestrator records
//! collector errors in the manifest and moves on.

use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use anyhow::Context as _;
use serde::Serialize;

use super::redact::is_env_value_allowlisted;
use diagnostics::redact::{masked_process_env, redact_toml};
use diagnostics::{BundleWriter, Redaction, open_regular_nofollow};

/// Cap on entries in a recursive state-dir listing; a runaway tree (huge
/// session workspaces) is truncated with a marker line, not walked forever.
const LISTING_MAX_ENTRIES: usize = 100_000;

/// Everything the host collectors need, resolved once so collection is a
/// pure function of these paths plus the filesystem.
pub struct DiagPaths {
    /// `<config>/minimal`.
    pub config: PathBuf,
    /// `<state>/minimal` (or the `--minimal-dir` override).
    pub state: PathBuf,
    /// `<cache>/minimal`.
    pub cache: PathBuf,
    /// Where `min mesh join` writes its enrolment file.
    pub mesh_enrolment: PathBuf,
    /// The invoking directory (disk-full there breaks the bundle write).
    pub cwd: PathBuf,
}

// ── host/system.json ─────────────────────────────────────────────────────────

pub async fn system(w: &mut BundleWriter, paths: &DiagPaths) -> Result<(), anyhow::Error> {
    // Which filesystems matter is this binary's policy: the state dir, the
    // cache dir, and the invoking directory the archive is written into.
    let info = diagnostics::system_info(&[&paths.state, &paths.cache, &paths.cwd]).await;
    let json = serde_json_lenient::to_vec_pretty(&info).context("serializing system info")?;
    w.add_bytes("host/system.json", &json, Redaction::None)
        .await
}

// ── host/terminal.json ───────────────────────────────────────────────────────

/// The terminal `min bug` itself ran on. Interactive rendering complaints
/// (#950) cannot be judged without it, and it costs three ioctls.
pub async fn terminal(w: &mut BundleWriter) -> Result<(), anyhow::Error> {
    let info = diagnostics::terminal_info();
    let json = serde_json_lenient::to_vec_pretty(&info).context("serializing terminal info")?;
    w.add_bytes("host/terminal.json", &json, Redaction::None)
        .await
}

// ── host/env.json ────────────────────────────────────────────────────────────

pub async fn env(w: &mut BundleWriter) -> Result<(), anyhow::Error> {
    let env = masked_process_env(is_env_value_allowlisted);
    let json = serde_json_lenient::to_vec_pretty(&env).context("serializing env")?;
    w.add_bytes("host/env.json", &json, Redaction::Keys).await
}

// ── config/ ──────────────────────────────────────────────────────────────────

pub async fn config(w: &mut BundleWriter, paths: &DiagPaths) -> Result<(), anyhow::Error> {
    add_redacted_toml(
        w,
        &paths.config.join("config.toml"),
        "config/config.toml.redacted",
    )
    .await;
    add_redacted_toml(
        w,
        &paths.config.join("user_policy.toml"),
        "config/user_policy.toml.redacted",
    )
    .await;

    // Both loadout layouts: `<name>.toml` and `<name>/loadout.toml`. Only
    // the definition file either way — the rest of a loadout's directory
    // ($LOADOUT_ROOT assets, hook scripts) is the user's own content and
    // has never been collected.
    match tokio::fs::read_dir(paths.config.join("loadouts")).await {
        Ok(mut entries) => loop {
            match entries.next_entry().await {
                Ok(Some(entry)) => {
                    let path = entry.path();
                    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                        continue;
                    };
                    // `DirEntry::file_type` does not follow symlinks, and
                    // that is the point: descending into a symlinked
                    // `<name>/` would read a `loadout.toml` from wherever
                    // it pointed, and `open_regular_nofollow` could not
                    // stop it — `O_NOFOLLOW` guards only the final
                    // component. A symlinked directory is therefore not a
                    // directory here, matching the daemon-side refusal of
                    // a symlinked hook anchor.
                    let is_dir = match entry.file_type().await {
                        Ok(ft) => ft.is_dir(),
                        Err(e) => {
                            w.skip(
                                format!("config/loadouts/{name}"),
                                format!("unreadable: {e}"),
                            );
                            continue;
                        }
                    };
                    if is_dir {
                        let file = path.join(sessions::client::disk::LOADOUT_FILE_NAME);
                        // Existence only. Whether this is a *safe* file to
                        // read is `add_redacted_toml`'s call, and it makes
                        // it independently — a symlinked `loadout.toml` is
                        // refused at open and the refusal recorded, the
                        // same way a symlinked `<name>.toml` is below.
                        if tokio::fs::metadata(&file).await.is_ok_and(|m| m.is_file()) {
                            add_redacted_toml(
                                w,
                                &file,
                                &format!(
                                    "config/loadouts/{name}/{}.redacted",
                                    sessions::client::disk::LOADOUT_FILE_NAME
                                ),
                            )
                            .await;
                        }
                    } else if path.extension().is_some_and(|e| e == "toml") {
                        add_redacted_toml(w, &path, &format!("config/loadouts/{name}.redacted"))
                            .await;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    w.skip("config/loadouts/", format!("listing interrupted: {e}"));
                    break;
                }
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => w.skip("config/loadouts/", format!("unreadable: {e}")),
    }

    // mTLS material: cert/CA metadata only, private key never touched.
    w.skip(
        "config/client.key",
        "private key material — never collected",
    );
    let certs: std::collections::BTreeMap<&str, Option<FileMeta>> = [
        (
            "client.pem",
            file_meta(&paths.config.join("client.pem")).await,
        ),
        ("ca.pem", file_meta(&paths.config.join("ca.pem")).await),
    ]
    .into_iter()
    .collect();
    let json = serde_json_lenient::to_vec_pretty(&certs).context("serializing cert metadata")?;
    w.add_bytes("config/client-cert.json", &json, Redaction::ListingOnly)
        .await?;

    // Mesh enrolment holds only a host:port endpoint. No-follow like every
    // other content read: it ships verbatim, so a symlink here would
    // exfiltrate an arbitrary file byte-for-byte.
    match read_string_nofollow(&paths.mesh_enrolment).await {
        Ok(content) => {
            w.add_bytes("config/mesh-enrolment", content.as_bytes(), Redaction::None)
                .await?
        }
        Err(e) if is_not_found(&e) => {}
        Err(e) => w.skip("config/mesh-enrolment", format!("unreadable: {e:#}")),
    }
    Ok(())
}

/// Adds a TOML file with values redacted; a missing file is silently fine,
/// an unparseable, unreadable, or symlinked one is withheld with a manifest
/// note (the no-follow discipline covers content reads, not just log tails —
/// a symlinked "config" file must not steer unrelated data into the bundle).
async fn add_redacted_toml(w: &mut BundleWriter, src: &Path, dest: &str) {
    let content = match read_string_nofollow(src).await {
        Ok(c) => c,
        Err(e) if is_not_found(&e) => return,
        Err(e) => {
            w.skip(dest, format!("unreadable: {e:#}"));
            return;
        }
    };
    match redact_toml(&content) {
        Ok(redacted) => {
            if let Err(e) = w
                .add_bytes(dest, redacted.as_bytes(), Redaction::Keys)
                .await
            {
                w.skip(dest, format!("bundling failed: {e}"));
            }
        }
        Err(e) => w.skip(
            dest,
            format!("withheld: does not parse as TOML, cannot redact safely: {e}"),
        ),
    }
}

/// Reads a regular file to a string without following symlinks.
async fn read_string_nofollow(src: &Path) -> Result<String, anyhow::Error> {
    use tokio::io::AsyncReadExt as _;
    let (mut file, _) = open_regular_nofollow(src).await?;
    let mut content = String::new();
    file.read_to_string(&mut content)
        .await
        .with_context(|| format!("reading {}", src.display()))?;
    Ok(content)
}

#[derive(Serialize)]
struct FileMeta {
    bytes: u64,
    mtime_unix: Option<u64>,
}

async fn file_meta(path: &Path) -> Option<FileMeta> {
    let meta = tokio::fs::metadata(path).await.ok()?;
    Some(FileMeta {
        bytes: meta.len(),
        mtime_unix: meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs()),
    })
}

// ── state/ ───────────────────────────────────────────────────────────────────

pub async fn state(w: &mut BundleWriter, paths: &DiagPaths) -> Result<(), anyhow::Error> {
    // Recursive listing: names, sizes, and metadata only — session workspace
    // *contents* stay on the user's machine. The walk is synchronous, so it
    // runs on a blocking thread: a wedged filesystem must strand that
    // thread, not the worker whose collect_step! timeout is the failsafe.
    let state_dir = paths.state.clone();
    let listing =
        tokio::task::spawn_blocking(move || diagnostics::listing(&state_dir, LISTING_MAX_ENTRIES))
            .await
            .context("listing worker")?
            .context("listing state dir")?;
    w.add_bytes(
        "state/listing.txt",
        listing.text.as_bytes(),
        Redaction::ListingOnly,
    )
    .await
}

// ── logs/ ────────────────────────────────────────────────────────────────────

/// How many rotated files per log prefix make it into the bundle.
const LOG_FILES_PER_PREFIX: usize = 5;

/// The one phrasing that asserts a file simply is not there.
///
/// A skip may only carry it when nothing in the bundle — at any nesting level
/// — holds the path it names. [`explain_absent_log_prefixes`] is where that is
/// decided for the log prefixes; the constant exists so the invariant test can
/// find every skip that makes the claim.
const NO_SUCH_FILES: &str = "no files with this prefix";

/// Where the daemon behind a log prefix runs — which decides whether the
/// absence of its files under `<state>/logs` is the whole story.
#[derive(Debug, Clone, Copy)]
enum Locality {
    /// A host process. Nothing under `<state>/logs` means nothing was written.
    Host,
    /// Not necessarily a host process at all: on macOS minimald runs *inside*
    /// the microVM and logs to the guest data volume, so its records reach the
    /// bundle through the per-provider guest fetch and never through this
    /// directory. "Not here" is then a fact about this directory only.
    HostOrGuest,
}

/// One searched log prefix and where its writer lives. Only obtainable from
/// [`LOG_PREFIXES`], so a caller cannot invent a prefix with the wrong
/// locality.
#[derive(Debug, Clone, Copy)]
pub struct LogPrefix {
    name: &'static str,
    locality: Locality,
}

/// The prefixes [`logs`] harvests from `<state>/logs`.
const LOG_PREFIXES: [LogPrefix; 2] = [
    LogPrefix {
        name: "minimald.log",
        locality: Locality::HostOrGuest,
    },
    LogPrefix {
        name: "minvmd.log",
        locality: Locality::Host,
    },
];

/// What the provider loop established about the daemon's own logs reaching
/// the bundle by another route — the fact a host-side absence has to be read
/// against.
///
/// Every variant is a distinct epistemic state, because the skip reason is a
/// claim and only two of these license the strong one. "The listing failed"
/// is not "there are none", and "a bundle arrived" is not "the logs are in
/// it": collapsing either into its neighbour is how the manifest ends up
/// asserting something the archive does not back.
#[derive(Debug, Clone, Copy)]
pub enum DaemonLogSources<'a> {
    /// The provider directory could not be listed, so whether any daemon
    /// logged elsewhere is *unknown*. Absence may not be claimed.
    ProvidersUnknown,
    /// No provider instance exists, so no daemon could have logged elsewhere.
    NoProviders,
    /// Providers exist, but none yielded a daemon bundle this run.
    NoneFetched,
    /// These providers' nested bundles verified and were observed to hold
    /// `logs/minimald.log*`. Non-empty by construction.
    Nested(&'a [&'a str]),
    /// A nested bundle arrived from these providers, but this run could not
    /// confirm it holds the daemon's logs — truncated, failed verification,
    /// or verified with no such entry. Non-empty by construction.
    NestedUnconfirmed(&'a [&'a str]),
}

/// Collects the host-side log tails.
///
/// Prefixes that matched no file are *reported back* through `absent` rather
/// than skipped on the spot: whether "nothing under `<state>/logs`" also means
/// "nothing in this bundle" depends on what the provider loop finds
/// afterwards, and the shared collector contract (`collect_step!`) fixes this
/// signature's return type at `Result<(), _>`.
/// [`explain_absent_log_prefixes`] records those skips once the answer is in.
///
/// `tail_bytes` is the per-file cap, already validated by the caller against
/// [`diagnostics::MAX_LOG_TAIL_BYTES`].
pub async fn logs(
    w: &mut BundleWriter,
    paths: &DiagPaths,
    tail_bytes: u64,
    absent: &mut Vec<LogPrefix>,
) -> Result<(), anyhow::Error> {
    let log_dir = paths.state.join("logs");
    // Absence and inaccessibility are different facts: "no log directory"
    // may only be claimed on a real NotFound, never on EACCES or I/O errors.
    match tokio::fs::metadata(&log_dir).await {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // No log dir at all — nothing ever detached. Absence is data.
            w.skip("logs/", "no log directory — no daemon has ever logged here");
        }
        Err(e) => w.skip("logs/", format!("unreadable: {e}")),
        Ok(_) => {
            for prefix in LOG_PREFIXES {
                let files =
                    diagnostics::newest_rotated(&log_dir, prefix.name, LOG_FILES_PER_PREFIX).await;
                if files.is_empty() {
                    absent.push(prefix);
                    continue;
                }
                for path in files {
                    let name = path.file_name().unwrap_or_default().to_string_lossy();
                    let dest = format!("logs/{name}");
                    if let Err(e) = w.add_file_tail(&dest, &path, tail_bytes).await {
                        w.skip(&dest, format!("unreadable: {e}"));
                    }
                }
            }
        }
    }

    // Provider-scoped logs. run.log: the detached supervisor's stderr
    // redirect (panics, the final error print of a failed boot). boot.log:
    // the VMM's hvc0 console capture — kernel prints and the guest pid-1's
    // stdout, the only evidence when the guest wedges before (or its
    // transport dies after) the daemon is reachable.
    for (name, dir) in provider_dirs(&paths.state).await? {
        for log_name in ["run.log", "boot.log"] {
            let dest = format!("providers/{name}/{log_name}");
            match w
                .add_file_tail(&dest, &dir.join(log_name), tail_bytes)
                .await
            {
                Ok(()) => {}
                Err(e) if is_not_found(&e) => w.skip(&dest, "absent"),
                Err(e) => w.skip(&dest, format!("unreadable: {e}")),
            }
        }
    }

    // The legend for everything above, plus the daemon logs that arrive
    // nested from the guest: two overlapping copies of the same output, each
    // systematically missing what the other has.
    w.add_bytes(
        "logs/PROVENANCE.txt",
        LOG_PROVENANCE.as_bytes(),
        Redaction::None,
    )
    .await
}

/// Records the skips [`logs`] held back, now that the provider loop has said
/// whether the daemon's own logs reached the bundle another way.
///
/// The plain absence claim ([`NO_SUCH_FILES`]) is made only where it is true
/// of the *bundle*, not merely of `<state>/logs`. On macOS a `min bug` run
/// finds no `minimald.log*` on the host — the daemon lives inside the microVM
/// — while the very same bundle nests those logs under
/// `providers/<name>/guest/`. A manifest that answers "no files with this
/// prefix" there teaches a reader to stop looking, which is how a real
/// incident's daemon logs went unread with 178 KB of them on the volume.
pub fn explain_absent_log_prefixes(
    w: &mut BundleWriter,
    paths: &DiagPaths,
    absent: &[LogPrefix],
    sources: DaemonLogSources<'_>,
) {
    let log_dir = paths.state.join("logs");
    let log_dir = log_dir.display();
    // Where in the bundle a named provider's nested daemon bundle sits.
    let carriers = |providers: &[&str]| {
        providers
            .iter()
            .map(|p| format!("providers/{p}/guest/daemon-diag.tar.zst"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    for prefix in absent {
        let reason = match (prefix.locality, sources) {
            // A host process that wrote nothing here wrote nothing anywhere —
            // including when the provider listing failed, which says nothing
            // about a host writer. And with no provider instance there is no
            // guest to have logged in either. Both are genuine absence.
            (Locality::Host, _) | (Locality::HostOrGuest, DaemonLogSources::NoProviders) => {
                format!("{NO_SUCH_FILES} in {log_dir}")
            }
            // The listing failed, so whether a guest daemon logged elsewhere
            // was never established. Saying "absent" here would be asserting
            // the one thing this run did not find out.
            (Locality::HostOrGuest, DaemonLogSources::ProvidersUnknown) => format!(
                "none in {log_dir}, and whether any exist elsewhere is unknown — the \
                 provider directory could not be listed this run (see the `providers` \
                 error in this manifest). Where minimald runs inside the microVM it \
                 logs to the guest data volume, not to this host"
            ),
            (Locality::HostOrGuest, DaemonLogSources::Nested(providers)) => format!(
                "none in {log_dir} — where minimald runs inside the microVM it logs \
                 to the guest data volume, not to this host. Its own logs are in \
                 this bundle, nested in {} (see logs/PROVENANCE.txt)",
                carriers(providers)
            ),
            // A bundle came back, so "no daemon bundle was fetched" would be
            // false; but it was truncated, failed its checks, or held no such
            // entry, so naming it as the carrier would be false too.
            (Locality::HostOrGuest, DaemonLogSources::NestedUnconfirmed(providers)) => format!(
                "none in {log_dir} — where minimald runs inside the microVM it logs \
                 to the guest data volume, not to this host. A daemon bundle was \
                 collected at {}, but this run could not confirm it carries them; \
                 see the guest.* entries in this manifest (see logs/PROVENANCE.txt)",
                carriers(providers)
            ),
            (Locality::HostOrGuest, DaemonLogSources::NoneFetched) => format!(
                "none in {log_dir} — where minimald runs inside the microVM it logs to \
                 the guest data volume, not to this host, and no daemon bundle was \
                 fetched this run; see providers/*/guest/ for why"
            ),
        };
        w.skip(format!("logs/{}*", prefix.name), reason);
    }
}

/// Which log is which, and what each one systematically lacks.
///
/// Two overlapping copies of the daemon's output can reach a bundle, and
/// nothing in the archive said so: a reader who found the same lines in both
/// had no way to know that the console holds the boot prologue and shutdown
/// epilogue the volume appender can never see, nor that the two are no longer
/// diffable without normalising format.
const LOG_PROVENANCE: &str = "\
Log provenance
==============

Where each log in this bundle came from, how long it is kept, and what it is
known to be missing. Two overlapping copies of the daemon's output can appear
here: they are not duplicates, and neither is a superset of the other.

providers/<name>/boot.log
  source     the VMM's hvc0 console, mirrored to this file by the VMM child
  retention  truncated at every boot (created afresh per boot) — only the
             current boot is present
  format     human-readable tracing output
  holds      the boot prologue: every record written before the state volume
             is mounted (pseudo filesystems mounted, switch to the upstream
             rootfs, writable state volume mounted, cache + state relocated),
             and the shutdown epilogue after the volume appender is released
             (state volume quiesced, connections drained, the final close)
  lacks      nothing observed; a measured incident window showed no console
             record absent under saturation

providers/<name>/guest/daemon-diag.tar.zst -> logs/minimald.log.<date>
  source     the on-volume file appender inside the guest, attached once the
             state volume mounts
  retention  daily rotation, 14 files
  format     JSON lines
  lacks      the boot prologue (the appender does not exist yet) and the
             shutdown epilogue (it is released before the volume is quiesced,
             so a clean shutdown's last records exist only on the console)

providers/<name>/guest/volume-logs/*
  source     the same on-volume appender, read straight off the ext4 image by
             the degraded-mode harvest when the daemon could not be reached
  lacks      the same as above, and may be torn mid-write

An absent minimald.log* under logs/ is a fact about this host's state
directory, not about the daemon: where minimald runs inside the microVM it
never writes there. manifest.json's skip entry for that prefix names whichever
of the sources above carries it instead.

Over the window the console and the volume appender share, their records
match — but the console is human-format and the volume log is JSON lines, so
comparing them requires normalising one to the other first.
";

/// True when an `add_file_tail` failure was a plain missing file.
fn is_not_found(err: &anyhow::Error) -> bool {
    err.chain()
        .filter_map(|c| c.downcast_ref::<std::io::Error>())
        .any(|io| io.kind() == std::io::ErrorKind::NotFound)
}

// ── providers/local-<kind><n>/ discovery ───────────────────────────────────────────

/// Provider instance dirs under `<state>/providers`, sorted. Empty when the
/// providers dir doesn't exist (nothing was ever spawned); any other
/// filesystem error is an `Err` — "no daemon was ever spawned here" must
/// never be claimed on the strength of an EACCES.
pub async fn provider_dirs(state: &Path) -> Result<Vec<(String, PathBuf)>, std::io::Error> {
    let mut entries = match tokio::fs::read_dir(state.join("providers")).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut dirs: Vec<(String, PathBuf)> = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        if !entry.file_type().await.is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if name.starts_with("local-") {
            dirs.push((name, entry.path()));
        }
    }
    dirs.sort();
    Ok(dirs)
}

/// Non-log per-provider evidence: what the instance dir holds, its raw
/// lifecycle state, and whether anything is still alive behind it (R7.6).
///
/// `run.log`/`boot.log` are deliberately *not* collected here — [`logs`]
/// already tail-caps them for every discovered provider, and a second copy
/// would be a duplicate archive entry.
pub async fn provider_files(
    w: &mut BundleWriter,
    name: &str,
    dir: &Path,
) -> Result<(), anyhow::Error> {
    // Shallow inventory of the instance dir: which sockets, locks, keys and
    // images exist. Metadata only — the walk is synchronous, so it runs on a
    // blocking thread like every other listing.
    let listing_dir = dir.to_path_buf();
    let listing = tokio::task::spawn_blocking(move || {
        diagnostics::listing(&listing_dir, LISTING_MAX_ENTRIES)
    })
    .await
    .context("provider listing worker")?;
    let dest = format!("providers/{name}/dir-listing.txt");
    match listing {
        Ok(listing) => {
            w.add_bytes(&dest, listing.text.as_bytes(), Redaction::ListingOnly)
                .await?
        }
        Err(e) => w.skip(&dest, format!("unreadable: {e:#}")),
    }

    w.skip(
        format!("providers/{name}/ssh_host_ed25519_key"),
        "private key material — never collected",
    );

    // Lifecycle state, verbatim (nothing sensitive: enum + pid + timestamp).
    //
    // Read through the same `O_NOFOLLOW` discipline as every other bundled
    // file: `tokio::fs::read` would follow a symlink planted here and copy an
    // unrelated readable host file into a bundle meant for sharing.
    let dest = format!("providers/{name}/minvmd.toml");
    match diagnostics::open_regular_nofollow(&dir.join("minvmd.toml")).await {
        Ok((mut file, _)) => {
            let mut bytes = Vec::new();
            match tokio::io::AsyncReadExt::read_to_end(&mut file, &mut bytes).await {
                Ok(_) => w.add_bytes(&dest, &bytes, Redaction::None).await?,
                Err(e) => w.skip(&dest, format!("unreadable: {e}")),
            }
        }
        Err(e) => match e.downcast_ref::<std::io::Error>() {
            Some(io) if io.kind() == std::io::ErrorKind::NotFound => {}
            _ => w.skip(&dest, format!("unreadable: {e:#}")),
        },
    }

    let status_dir = dir.to_path_buf();
    let status = tokio::task::spawn_blocking(move || provider_status(&status_dir))
        .await
        .context("provider status worker")?;
    let json = serde_json_lenient::to_vec_pretty(&status).context("serializing provider status")?;
    w.add_bytes(
        &format!("providers/{name}/status.json"),
        &json,
        Redaction::None,
    )
    .await
}

#[derive(Serialize)]
struct ProviderStatus {
    /// Raw lifecycle from `minvmd.toml` — never repaired/written back.
    state: Option<toml::Table>,
    state_read_error: Option<String>,
    /// A live minvmd (or its VMM child) holds `minvmd.lock`.
    minvmd_alive: Option<bool>,
    /// A live native minimald holds `minimald.lock`.
    minimald_alive: Option<bool>,
}

/// Reads the provider's lifecycle state and probes the advisory locks.
///
/// Deliberately *not* `StateDir::effective_state()`, which repairs stale state
/// by writing `Stopped` back — a diagnostic must never mutate what it reads.
/// Synchronous (file locks and `std::fs`); callers run it on a blocking thread.
fn provider_status(dir: &Path) -> ProviderStatus {
    // `StateDir::new` runs `create_dir_all`, so probing a provider whose
    // directory had been deleted would recreate it — leaving ghost state
    // behind and making this collector a mutation, which the paragraph above
    // says it must never be.
    let state_dir = minvmd::state::StateDir::open_existing(dir.to_path_buf());
    let (state, state_read_error) = match std::fs::read_to_string(state_dir.state_path()) {
        Ok(s) => match s.parse::<toml::Table>() {
            Ok(table) => (Some(table), None),
            Err(e) => (None, Some(e.to_string())),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (None, None),
        Err(e) => (None, Some(e.to_string())),
    };
    ProviderStatus {
        state,
        state_read_error,
        minvmd_alive: state_dir.daemon_alive().ok(),
        minimald_alive: state_dir.minimald_alive().ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tokio::io::AsyncReadExt as _;
    use tokio_stream::StreamExt as _;

    /// Every entry path in a tar+zstd blob.
    async fn entry_paths(bytes: &[u8]) -> Vec<String> {
        let decoder = async_compression::tokio::bufread::ZstdDecoder::new(bytes);
        let mut entries = async_tar::Archive::new(decoder).entries().unwrap();
        let mut paths = Vec::new();
        while let Some(entry) = entries.next().await {
            paths.push(
                entry
                    .unwrap()
                    .path()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
            );
        }
        paths
    }

    /// Unpacks a written bundle to `bundle-relative path -> contents`.
    async fn unpack(out: &Path, root: &str) -> BTreeMap<String, Vec<u8>> {
        let bytes = tokio::fs::read(out).await.unwrap();
        let decoder = async_compression::tokio::bufread::ZstdDecoder::new(&bytes[..]);
        let mut entries = async_tar::Archive::new(decoder).entries().unwrap();
        let mut files = BTreeMap::new();
        while let Some(entry) = entries.next().await {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().into_owned();
            let mut contents = Vec::new();
            entry.read_to_end(&mut contents).await.unwrap();
            files.insert(
                path.strip_prefix(&format!("{root}/"))
                    .unwrap_or(&path)
                    .to_string(),
                contents,
            );
        }
        files
    }

    fn paths(state: &Path) -> DiagPaths {
        DiagPaths {
            config: state.join("config"),
            state: state.to_path_buf(),
            cache: state.join("cache"),
            mesh_enrolment: state.join("enrolment"),
            cwd: state.to_path_buf(),
        }
    }

    /// Records the held-back skips for `sources` over both log prefixes and
    /// returns the manifest's `what -> reason` map.
    async fn reasons_for(sources: DaemonLogSources<'_>) -> BTreeMap<String, String> {
        let dir = tempfile::TempDir::new().unwrap();
        let out = dir.path().join("diag.tar.zst");
        let mut w = BundleWriter::create(&out, "r", "v").await.unwrap();
        explain_absent_log_prefixes(&mut w, &paths(dir.path()), &LOG_PREFIXES, sources);
        w.finish(chrono::Utc::now(), std::time::Duration::ZERO)
            .await
            .unwrap();
        let files = unpack(&out, "r").await;
        let manifest: serde_json_lenient::Value =
            serde_json_lenient::from_slice(&files["manifest.json"]).unwrap();
        manifest["skipped"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| {
                (
                    s["what"].as_str().unwrap().to_string(),
                    s["reason"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    }

    /// The strong claim ([`NO_SUCH_FILES`]) is licensed by only some of the
    /// states a run can end in. A run that could not list the provider
    /// directory has not established absence, it has established nothing —
    /// and "I did not find out" recorded as "it is not there" is the same
    /// defect as the one this whole path exists to correct.
    #[tokio::test]
    async fn plain_absence_is_claimed_only_where_the_run_established_it() {
        let all = [
            DaemonLogSources::ProvidersUnknown,
            DaemonLogSources::NoProviders,
            DaemonLogSources::NoneFetched,
            DaemonLogSources::Nested(&["local-minvmd0"]),
            DaemonLogSources::NestedUnconfirmed(&["local-minvmd0"]),
        ];

        // minvmd is a host process wherever the providers are: nothing under
        // <state>/logs is the whole story in every state.
        for sources in all {
            let reasons = reasons_for(sources).await;
            assert!(
                reasons["logs/minvmd.log*"].starts_with(NO_SUCH_FILES),
                "a host-only writer's absence is plain absence under {sources:?}: {reasons:?}"
            );
        }

        // minimald may be inside the microVM, so only a *settled* empty
        // provider list rules out its logs having gone elsewhere.
        for sources in all {
            let reasons = reasons_for(sources).await;
            let claims_absence = reasons["logs/minimald.log*"].starts_with(NO_SUCH_FILES);
            let established = matches!(sources, DaemonLogSources::NoProviders);
            assert_eq!(
                claims_absence,
                established,
                "{sources:?} must {} claim absence: {reasons:?}",
                if established { "" } else { "not" }
            );
        }
    }

    /// Naming a carrier is a claim too. A bundle that arrived truncated or
    /// failed its checks may be offered as somewhere to look, never as the
    /// answer — sending a reader to a file that does not hold what they were
    /// told it holds recreates the dead end in the other direction.
    #[tokio::test]
    async fn only_a_confirmed_nested_bundle_is_named_as_the_carrier() {
        let carrier = "providers/local-minvmd0/guest/daemon-diag.tar.zst";

        let confirmed = reasons_for(DaemonLogSources::Nested(&["local-minvmd0"])).await;
        let reason = &confirmed["logs/minimald.log*"];
        assert!(reason.contains(carrier), "got: {reason}");
        assert!(reason.contains("are in this bundle"), "got: {reason}");

        let unconfirmed =
            reasons_for(DaemonLogSources::NestedUnconfirmed(&["local-minvmd0"])).await;
        let reason = &unconfirmed["logs/minimald.log*"];
        assert!(reason.contains(carrier), "got: {reason}");
        assert!(reason.contains("could not confirm"), "got: {reason}");
        assert!(
            !reason.contains("are in this bundle"),
            "an unconfirmed carrier must not be asserted as the answer: {reason}"
        );
    }

    /// True when a skip's `what` — a bundle path, possibly a `*` suffix glob —
    /// names `path`.
    fn names(what: &str, path: &str) -> bool {
        match what.strip_suffix('*') {
            Some(prefix) => path.starts_with(prefix),
            None => path == what,
        }
    }

    /// The manifest's contract is that an absent file is always explainable,
    /// and a reader who trusts it stops looking. So no skip may claim plain
    /// absence for something the bundle is *carrying* — including inside a
    /// nested bundle, which is exactly where the guest daemon's logs arrive
    /// while `<state>/logs` on a macOS host holds none of them.
    ///
    /// The invariant is the fix; the wording is only its expression, so this
    /// asserts over every skip rather than over one message.
    #[tokio::test]
    async fn no_skip_claims_absence_for_a_path_the_bundle_carries() {
        let state = tempfile::TempDir::new().unwrap();
        // The macOS shape: a log directory with neither prefix in it, because
        // minimald is inside the microVM and minvmd never ran detached.
        std::fs::create_dir_all(state.path().join("logs")).unwrap();
        let paths = paths(state.path());

        let out_dir = tempfile::TempDir::new().unwrap();
        let out = out_dir.path().join("diag.tar.zst");
        let mut w = BundleWriter::create(&out, "r", "v").await.unwrap();

        let mut absent = Vec::new();
        logs(&mut w, &paths, diagnostics::LOG_TAIL_CAP, &mut absent)
            .await
            .unwrap();
        assert_eq!(absent.len(), 2, "both prefixes matched nothing on the host");

        // The guest fetch nested the daemon's own bundle, which carries the
        // very files the host state dir lacks.
        let nested = crate::diag::guest::tests::pack(&[
            ("manifest.json", b"{}"),
            ("logs/minimald.log.2026-07-16", b"guest daemon log\n"),
        ])
        .await;
        w.add_bytes(
            "providers/local-minvmd0/guest/daemon-diag.tar.zst",
            &nested,
            Redaction::None,
        )
        .await
        .unwrap();

        explain_absent_log_prefixes(
            &mut w,
            &paths,
            &absent,
            DaemonLogSources::Nested(&["local-minvmd0"]),
        );
        w.finish(chrono::Utc::now(), std::time::Duration::ZERO)
            .await
            .unwrap();

        let files = unpack(&out, "r").await;
        let mut carried: Vec<String> = files.keys().cloned().collect();
        for (path, bytes) in &files {
            if path.ends_with(".tar.zst") {
                carried.extend(entry_paths(bytes).await);
            }
        }

        let manifest: serde_json_lenient::Value =
            serde_json_lenient::from_slice(&files["manifest.json"]).unwrap();
        let skipped = manifest["skipped"].as_array().unwrap();
        for skip in skipped {
            let (what, reason) = (
                skip["what"].as_str().unwrap(),
                skip["reason"].as_str().unwrap(),
            );
            if !reason.starts_with(NO_SUCH_FILES) {
                continue;
            }
            assert!(
                !carried.iter().any(|p| names(what, p)),
                "manifest claims `{what}` is absent ({reason:?}), but the bundle \
                 carries it: {carried:?}"
            );
        }

        // Non-vacuous in both directions: the claim is still made where it is
        // true, and the prefix the guest carries points at its carrier.
        let reason = |what: &str| {
            skipped
                .iter()
                .find(|s| s["what"] == what)
                .unwrap_or_else(|| panic!("no skip for {what}: {skipped:?}"))["reason"]
                .as_str()
                .unwrap()
                .to_string()
        };
        assert!(
            reason("logs/minvmd.log*").starts_with(NO_SUCH_FILES),
            "a host-only daemon's absence is still plain absence"
        );
        assert!(
            reason("logs/minimald.log*")
                .contains("providers/local-minvmd0/guest/daemon-diag.tar.zst"),
            "the skip must name where the logs actually are"
        );
    }

    /// A reader cannot tell the console mirror and the on-volume appender
    /// apart, or know what each is missing, unless the bundle says so.
    #[tokio::test]
    async fn the_log_provenance_note_distinguishes_the_two_daemon_log_sources() {
        let state = tempfile::TempDir::new().unwrap();
        let out_dir = tempfile::TempDir::new().unwrap();
        let out = out_dir.path().join("diag.tar.zst");
        let mut w = BundleWriter::create(&out, "r", "v").await.unwrap();
        logs(
            &mut w,
            &paths(state.path()),
            diagnostics::LOG_TAIL_CAP,
            &mut Vec::new(),
        )
        .await
        .unwrap();
        w.finish(chrono::Utc::now(), std::time::Duration::ZERO)
            .await
            .unwrap();

        let files = unpack(&out, "r").await;
        let note = String::from_utf8(files["logs/PROVENANCE.txt"].clone()).unwrap();
        for expected in [
            "providers/<name>/boot.log",
            "hvc0 console",
            "truncated at every boot",
            "on-volume file appender",
            "JSON lines",
            "boot prologue",
            "shutdown epilogue",
        ] {
            assert!(
                note.contains(expected),
                "provenance note lacks {expected:?}"
            );
        }
    }
}
