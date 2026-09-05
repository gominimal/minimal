//! Integration tests for `min bug` (the diagnostic bundle command).
//!
//! Each test runs `cmd_bug` against a real minimald `TestServer` (or a
//! deliberately empty state dir) and unpacks the resulting tarball to assert
//! the bundle contract: what's collected, what's redacted, what the manifest
//! records for everything that's missing, and how the command degrades when
//! the daemon is unreachable.

mod common;

use std::collections::BTreeMap;
use std::path::Path;

use common::setup;
use minimal::GlobalArgs;
use minimal::diag::{BugArgs, cmd_bug};

/// Unpacks a `.tar.zst` bundle and returns `path-inside-archive -> contents`
/// (paths include the bundle's root directory).
async fn unpack(path: &Path) -> BTreeMap<String, Vec<u8>> {
    let bytes = tokio::fs::read(path).await.unwrap();
    let decoder = async_compression::tokio::bufread::ZstdDecoder::new(&bytes[..]);
    let out = tempfile::TempDir::new().unwrap();
    async_tar::Archive::new(decoder)
        .unpack(out.path().to_path_buf())
        .await
        .unwrap();

    let mut files = BTreeMap::new();
    fn walk(base: &Path, dir: &Path, files: &mut BTreeMap<String, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(base, &path, files);
            } else {
                let rel = path.strip_prefix(base).unwrap().to_string_lossy().into();
                files.insert(rel, std::fs::read(&path).unwrap());
            }
        }
    }
    walk(out.path(), out.path(), &mut files);
    files
}

/// Finds the single entry whose bundle-relative path ends with `suffix`.
fn find<'a>(files: &'a BTreeMap<String, Vec<u8>>, suffix: &str) -> Option<&'a Vec<u8>> {
    files
        .iter()
        .find(|(path, _)| path.ends_with(suffix))
        .map(|(_, contents)| contents)
}

/// A config dir with loadouts holding a canary secret, to prove
/// redaction. One of each layout — `dev.toml` and `vc/loadout.toml` —
/// so a directory-layout loadout is proved to be collected *and*
/// redacted, not quietly skipped.
fn fake_config_dir() -> tempfile::TempDir {
    let dir = tempfile::TempDir::new().unwrap();
    let root = dir.path().join("minimal");
    std::fs::create_dir_all(root.join("loadouts/vc")).unwrap();
    std::fs::write(
        root.join("config.toml"),
        "[loadouts]\ndefault_loadouts = [\"dev\"]\n",
    )
    .unwrap();
    std::fs::write(
        root.join("loadouts/dev.toml"),
        "packages = [\"ripgrep\"]\n\n[vars]\nGITHUB_TOKEN = \"canary-secret-value\"\n",
    )
    .unwrap();
    std::fs::write(
        root.join("loadouts/vc/loadout.toml"),
        "packages = [\"fd\"]\n\n[vars]\nGITLAB_TOKEN = \"canary-secret-value\"\n",
    )
    .unwrap();
    dir
}

fn global_args(state: &Path, config: &Path) -> GlobalArgs {
    GlobalArgs {
        repo_dir: None,
        minimal_dir: Some(state.to_path_buf()),
        config_dir: Some(config.to_path_buf()),
        provider: None,
        no_input: false,
    }
}

fn bug_args(out: &Path) -> BugArgs {
    BugArgs {
        output: Some(out.to_path_buf()),
        no_guest: false,
        guest_timeout_secs: 60,
        log_tail_bytes: diagnostics::LOG_TAIL_CAP,
    }
}

#[tokio::test]
async fn bug_without_daemon_still_produces_a_bundle() {
    let state = tempfile::TempDir::new().unwrap();
    let config = tempfile::TempDir::new().unwrap();
    let args = global_args(state.path(), config.path());

    let out_dir = tempfile::TempDir::new().unwrap();
    let out = out_dir.path().join("diag.tar.zst");
    cmd_bug(&args, bug_args(&out)).await.unwrap();

    let files = unpack(&out).await;
    let manifest: serde_json_lenient::Value =
        serde_json_lenient::from_slice(find(&files, "manifest.json").expect("manifest")).unwrap();
    assert_eq!(manifest["schema_version"], 1);
    assert!(!manifest["collected"].as_array().unwrap().is_empty());

    // Host collection ran even though nothing else exists.
    assert!(find(&files, "host/system.json").is_some());
    assert!(find(&files, "host/env.json").is_some());
    assert!(find(&files, "host/dirs.txt").is_some());
    assert!(find(&files, "state/listing.txt").is_some());

    // Nothing was ever spawned: the provider and log absences are recorded
    // as skips, not silently missing and not errors.
    let skipped_whats: Vec<&str> = manifest["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["what"].as_str().unwrap())
        .collect();
    assert!(
        skipped_whats.contains(&"providers/"),
        "expected a providers/ skip note: {skipped_whats:?}"
    );
    assert!(
        skipped_whats.contains(&"logs/"),
        "expected a logs/ skip note: {skipped_whats:?}"
    );
}

/// R2.10: the bundle describes the terminal `min bug` ran on. A rendering
/// complaint is unjudgeable without it (#950), so the entry is unconditional
/// — under `cargo test` the streams are pipes, and "not a terminal" is
/// exactly the finding that separates a CI run from a real session.
#[tokio::test]
async fn the_invoking_terminal_is_described() {
    let state = tempfile::TempDir::new().unwrap();
    let config = tempfile::TempDir::new().unwrap();
    let out_dir = tempfile::TempDir::new().unwrap();
    let out = out_dir.path().join("diag.tar.zst");
    cmd_bug(&global_args(state.path(), config.path()), bug_args(&out))
        .await
        .unwrap();

    let files = unpack(&out).await;
    let terminal: serde_json_lenient::Value =
        serde_json_lenient::from_slice(find(&files, "host/terminal.json").expect("terminal.json"))
            .unwrap();

    for name in ["stdin", "stdout", "stderr"] {
        let stream = &terminal[name];
        let tty = stream["tty"].as_bool().expect("tty is probed as a bool");
        if tty {
            // A terminal reports the size that explains its wrapping — but a
            // failed `TIOCGWINSZ` is a null size, not a broken bundle, and the
            // probe is specified best-effort. Demand well-formedness, not
            // presence.
            let size = &stream["size"];
            assert!(
                size.is_null() || (size["rows"].is_u64() && size["cols"].is_u64()),
                "a terminal's size is either absent or complete: {stream}"
            );
        } else {
            assert!(
                stream["size"].is_null() && stream["device"].is_null(),
                "a pipe has no size or device to report: {stream}"
            );
        }
    }
}

/// A project laid out under `.minimal/`.
fn fake_project() -> tempfile::TempDir {
    let dir = tempfile::TempDir::new().unwrap();
    let config = dir.path().join(".minimal");
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(
        config.join("minimal.toml"),
        "[tasks.build]\nexec = \"true\"\n",
    )
    .unwrap();
    dir
}

/// Runs `min bug` against `repo_dir` and returns the unpacked bundle.
async fn bundle_for_project(repo_dir: Option<&Path>) -> BTreeMap<String, Vec<u8>> {
    let state = tempfile::TempDir::new().unwrap();
    let config = tempfile::TempDir::new().unwrap();
    let out_dir = tempfile::TempDir::new().unwrap();
    let out = out_dir.path().join("diag.tar.zst");
    let mut args = global_args(state.path(), config.path());
    args.repo_dir = repo_dir.map(Path::to_path_buf);
    cmd_bug(&args, bug_args(&out)).await.unwrap();
    unpack(&out).await
}

/// #1211: a bundle has to say which project it came from. Without it, two
/// bundles from one machine and two checkouts read identically and the report
/// lands on the wrong project. The identity is in the manifest — the first
/// file a reader opens — as well as in the bundle.
#[tokio::test]
async fn the_bundle_names_the_project_it_came_from() {
    let project = fake_project();
    let files = bundle_for_project(Some(project.path())).await;

    let manifest: serde_json_lenient::Value =
        serde_json_lenient::from_slice(find(&files, "manifest.json").expect("manifest")).unwrap();
    let scope = &manifest["project"];
    assert_eq!(
        scope["state"], "identified",
        "unattributable bundle: {scope}"
    );
    assert_eq!(
        scope["name"],
        project.path().file_name().unwrap().to_str().unwrap()
    );
    assert_eq!(scope["config"], ".minimal/minimal.toml");
    // Agreement between the two outputs is not enough on its own: both could
    // name the same wrong directory. Pin the values themselves.
    assert_eq!(
        Path::new(scope["root"].as_str().expect("a root")),
        std::fs::canonicalize(project.path()).unwrap()
    );

    let report: serde_json_lenient::Value =
        serde_json_lenient::from_slice(find(&files, "project/project.json").expect("project.json"))
            .unwrap();
    assert_eq!(report["name"], scope["name"], "the two must not disagree");
    assert_eq!(report["root"], scope["root"]);
    assert_eq!(report["config"], scope["config"]);
    // The field that separates "minimal read no config" from "minimal read the
    // config one level up", so it has to be the directory the command really
    // ran from — not the project root it resolved to.
    assert_eq!(
        Path::new(report["invoked_from"].as_str().expect("an invocation dir")),
        std::fs::canonicalize(std::env::current_dir().unwrap()).unwrap()
    );
}

/// `ProjectIdentity::root` is documented as an absolute path on the producing
/// host, and a bundle is read on a different machine than it was made on — so
/// whatever `--repo-dir` was typed, the recorded root has to be resolved, not
/// echoed. A path threaded through `..` stands in for the general case: the
/// resolver accepts it, and it would otherwise be written down verbatim.
#[tokio::test]
async fn the_recorded_project_root_is_resolved_not_echoed() {
    let project = fake_project();
    let detour = project.path().join(".minimal").join("..");
    let files = bundle_for_project(Some(&detour)).await;

    let manifest: serde_json_lenient::Value =
        serde_json_lenient::from_slice(find(&files, "manifest.json").expect("manifest")).unwrap();
    let root = manifest["project"]["root"].as_str().expect("a root");
    assert!(
        !root.contains(".."),
        "the root must be resolved, not echoed back: {root}"
    );
    assert_eq!(
        Path::new(root),
        std::fs::canonicalize(project.path()).unwrap(),
        "the root must name the project directory itself"
    );
}

/// R2.11: a malformed config is reported as malformed, without quoting the
/// line it choked on — because that line is a line of the user's config, and
/// a TOML parse error prints it verbatim. A bundle gets shared; a secret on
/// the offending line would ride along in the manifest header, outside every
/// redaction policy the collectors apply, and in the one field a reader is
/// guaranteed to look at.
#[tokio::test]
async fn a_malformed_config_is_reported_without_quoting_it() {
    let project = tempfile::TempDir::new().unwrap();
    let config = project.path().join(".minimal");
    std::fs::create_dir_all(&config).unwrap();
    // Invalid TOML with the secret on the very line the parser rejects, so
    // any error text that quotes its context carries the secret with it.
    std::fs::write(
        config.join("minimal.toml"),
        "[tasks.build]\ntoken = \"canary-secret-value\" this is not toml\n",
    )
    .unwrap();

    let files = bundle_for_project(Some(project.path())).await;
    let manifest: serde_json_lenient::Value =
        serde_json_lenient::from_slice(find(&files, "manifest.json").expect("manifest")).unwrap();
    let scope = &manifest["project"];

    assert_eq!(scope["state"], "unknown", "unparseable is not identified");
    let reason = scope["reason"].as_str().expect("a reason");
    assert!(
        reason.contains("not valid TOML"),
        "malformed must be reported as malformed: {reason}"
    );

    // The whole point: the fact of the malformation travels, its contents do
    // not — anywhere in the bundle, manifest and skip reasons included.
    for (path, contents) in &files {
        assert!(
            !String::from_utf8_lossy(contents).contains("canary-secret-value"),
            "a rejected config line leaked into {path}"
        );
    }
}

/// `min bug` is run from wherever the user is standing. Outside a project,
/// the manifest records that as a finding with a reason, rather than leaving
/// the reader to guess which project the bundle belongs to.
#[tokio::test]
async fn a_bundle_collected_outside_a_project_says_so() {
    let elsewhere = tempfile::TempDir::new().unwrap();
    let files = bundle_for_project(Some(elsewhere.path())).await;

    let manifest: serde_json_lenient::Value =
        serde_json_lenient::from_slice(find(&files, "manifest.json").expect("manifest")).unwrap();
    let scope = &manifest["project"];
    assert_eq!(scope["state"], "unknown");
    assert!(
        scope["reason"]
            .as_str()
            .is_some_and(|r| r.contains(mfile::MFILE_NAME)),
        "the absence must be explainable: {scope}"
    );
    assert!(find(&files, "project/project.json").is_none());

    let skipped: Vec<&str> = manifest["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["what"].as_str().unwrap())
        .collect();
    assert!(
        skipped.contains(&"project/project.json"),
        "project/project.json absent without a reason"
    );
}

#[tokio::test]
async fn planted_secrets_never_reach_the_bundle() {
    let state = tempfile::TempDir::new().unwrap();
    let config = fake_config_dir();
    let args = global_args(state.path(), config.path());

    // A symlinked "loadout" pointing outside the config dir: TOML-shaped so
    // it would survive redaction if the collector followed the link.
    let outside = tempfile::TempDir::new().unwrap();
    let target = outside.path().join("outside.toml");
    std::fs::write(&target, "stolen = \"symlink-target-contents\"\n").unwrap();
    std::os::unix::fs::symlink(&target, config.path().join("minimal/loadouts/evil.toml")).unwrap();

    // The same attack through the directory layout: a symlinked
    // `<name>/` whose target holds a `loadout.toml`. `O_NOFOLLOW`
    // cannot stop this one — it guards only the final component — so
    // the collector must decline to descend into the link at all.
    let outside_dir = outside.path().join("evildir");
    std::fs::create_dir_all(&outside_dir).unwrap();
    std::fs::write(
        outside_dir.join("loadout.toml"),
        "stolen = \"symlink-target-contents\"\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(&outside_dir, config.path().join("minimal/loadouts/evildir"))
        .unwrap();

    let out_dir = tempfile::TempDir::new().unwrap();
    let out = out_dir.path().join("diag.tar.zst");
    cmd_bug(&args, bug_args(&out)).await.unwrap();

    let files = unpack(&out).await;

    // The symlink was refused at open, its target never read, and the
    // refusal recorded.
    assert!(find(&files, "evil.toml.redacted").is_none());
    // The symlinked directory was never descended into.
    assert!(find(&files, "evildir/loadout.toml.redacted").is_none());
    for contents in files.values() {
        assert!(
            !contents
                .windows(b"symlink-target-contents".len())
                .any(|w| w == b"symlink-target-contents"),
            "symlink target leaked into the bundle"
        );
    }

    // The loadout is included with its env-var value masked; keys and
    // non-secret values survive so the config is still diagnosable.
    let loadout = find(&files, "loadouts/dev.toml.redacted").expect("redacted loadout");
    let loadout = String::from_utf8_lossy(loadout);
    assert!(loadout.contains("GITHUB_TOKEN"), "keys survive: {loadout}");
    assert!(loadout.contains("ripgrep"), "packages survive: {loadout}");
    assert!(
        loadout.contains("<redacted:len=19>"),
        "masked value records its length: {loadout}"
    );

    // The directory layout is collected under its own directory, and
    // redacted by the same path — a loadout kept in git must not be a
    // hole in the bundle's masking.
    let vc = find(&files, "loadouts/vc/loadout.toml.redacted")
        .expect("redacted directory-layout loadout");
    let vc = String::from_utf8_lossy(vc);
    assert!(vc.contains("GITLAB_TOKEN"), "keys survive: {vc}");
    assert!(vc.contains("fd"), "packages survive: {vc}");
    assert!(
        vc.contains("<redacted:len=19>"),
        "masked value records its length: {vc}"
    );

    // The canary value never appears anywhere in the archive.
    for (path, contents) in &files {
        assert!(
            !contents
                .windows(b"canary-secret-value".len())
                .any(|window| window == b"canary-secret-value"),
            "secret value leaked into the bundle at {path}"
        );
    }

    // Key material is never collected, and that is recorded.
    assert!(find(&files, "client.key").is_none());
    let manifest: serde_json_lenient::Value =
        serde_json_lenient::from_slice(find(&files, "manifest.json").expect("manifest")).unwrap();
    assert!(
        manifest["skipped"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["what"].as_str().unwrap().contains("evil.toml")),
        "refused symlink must be recorded as a skip: {}",
        manifest["skipped"]
    );
    assert!(
        manifest["skipped"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["what"].as_str().unwrap().contains("client.key")),
        "client.key skip must be recorded: {}",
        manifest["skipped"]
    );
}

#[tokio::test]
async fn logs_collects_newest_five_per_prefix_and_provider_logs() {
    let state = tempfile::TempDir::new().unwrap();
    let config = tempfile::TempDir::new().unwrap();

    let log_dir = state.path().join("logs");
    std::fs::create_dir_all(&log_dir).unwrap();
    for day in 1..=7 {
        // Older dates get explicitly older mtimes: selection is
        // modified-time order, not filename order.
        let path = log_dir.join(format!("minimald.log.2026-07-{day:02}"));
        std::fs::write(&path, format!("day {day}\n")).unwrap();
        std::fs::File::open(&path)
            .unwrap()
            .set_modified(
                std::time::SystemTime::now() - std::time::Duration::from_secs((8 - day) * 100),
            )
            .unwrap();
    }

    let provider = state.path().join("providers/local-minvmd0");
    std::fs::create_dir_all(&provider).unwrap();
    std::fs::write(provider.join("run.log"), "supervisor stderr\n").unwrap();
    // boot.log deliberately absent — recorded as a skip, not an error.
    // Non-`local-` entries are not provider instances and must be ignored.
    let stray = state.path().join("providers/remote-x");
    std::fs::create_dir_all(&stray).unwrap();
    std::fs::write(stray.join("run.log"), "not a local provider\n").unwrap();

    let args = global_args(state.path(), config.path());
    let out_dir = tempfile::TempDir::new().unwrap();
    let out = out_dir.path().join("diag.tar.zst");
    cmd_bug(&args, bug_args(&out)).await.unwrap();

    let files = unpack(&out).await;
    let collected_logs: Vec<&String> = files
        .keys()
        .filter(|p| p.contains("logs/minimald.log."))
        .collect();
    assert_eq!(
        collected_logs.len(),
        5,
        "newest five per prefix: {collected_logs:?}"
    );
    assert!(
        find(&files, "logs/minimald.log.2026-07-07").is_some()
            && find(&files, "logs/minimald.log.2026-07-02").is_none(),
        "newest-first rotation order: {collected_logs:?}"
    );

    assert!(find(&files, "providers/local-minvmd0/run.log").is_some());
    assert!(find(&files, "providers/remote-x/run.log").is_none());
    let manifest: serde_json_lenient::Value =
        serde_json_lenient::from_slice(find(&files, "manifest.json").expect("manifest")).unwrap();
    let skipped = manifest["skipped"].as_array().unwrap();
    assert!(
        skipped
            .iter()
            .any(|s| s["what"] == "providers/local-minvmd0/boot.log" && s["reason"] == "absent"),
        "absent boot.log is a skip: {skipped:?}"
    );
    assert_eq!(manifest["errors"].as_array().unwrap().len(), 0, "no errors");
}

/// The `--log-tail-bytes` cap reaches every log the collector bundles — the
/// rotated host logs and the provider-scoped ones — and the manifest labels
/// each capped file so a reader can tell a truncated log from a short one.
#[tokio::test]
async fn a_custom_tail_cap_applies_to_every_log() {
    let state = tempfile::TempDir::new().unwrap();
    let config = tempfile::TempDir::new().unwrap();

    let log_dir = state.path().join("logs");
    std::fs::create_dir_all(&log_dir).unwrap();
    std::fs::write(log_dir.join("minimald.log.2026-07-21"), "x".repeat(500)).unwrap();
    let provider = state.path().join("providers/local-minvmd0");
    std::fs::create_dir_all(&provider).unwrap();
    std::fs::write(provider.join("run.log"), "y".repeat(500)).unwrap();

    let out_dir = tempfile::TempDir::new().unwrap();
    let out = out_dir.path().join("diag.tar.zst");
    let mut args = bug_args(&out);
    args.log_tail_bytes = 100;
    cmd_bug(&global_args(state.path(), config.path()), args)
        .await
        .unwrap();

    let files = unpack(&out).await;
    for suffix in [
        "logs/minimald.log.2026-07-21",
        "providers/local-minvmd0/run.log",
    ] {
        let contents = find(&files, suffix).unwrap_or_else(|| panic!("missing {suffix}"));
        assert_eq!(contents.len(), 100, "{suffix} honors the requested cap");
    }

    let manifest: serde_json_lenient::Value =
        serde_json_lenient::from_slice(find(&files, "manifest.json").expect("manifest")).unwrap();
    let capped: Vec<&serde_json_lenient::Value> = manifest["collected"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["redaction"] == "tail-capped")
        .collect();
    assert_eq!(capped.len(), 2, "both logs recorded as tail-capped");
    // Today the applied cap is only recoverable from a capped entry's own
    // byte count; the manifest has no field naming it outright.
    assert!(
        capped.iter().all(|e| e["bytes"] == 100),
        "a capped entry's size is the cap: {capped:?}"
    );
}

/// R5.1–R5.3: the incident collectors (net/procs/power) land in the bundle,
/// and interface MACs are masked to their vendor OUI. No daemon needed — these
/// capture host state.
#[tokio::test]
async fn incident_collectors_land_and_mask_macs() {
    let state = tempfile::TempDir::new().unwrap();
    let config = tempfile::TempDir::new().unwrap();
    let out_dir = tempfile::TempDir::new().unwrap();
    let out = out_dir.path().join("diag.tar.zst");
    cmd_bug(&global_args(state.path(), config.path()), bug_args(&out))
        .await
        .unwrap();
    let files = unpack(&out).await;

    for suffix in [
        "host/process-tree.txt",
        "host/net/listening.txt",
        "host/net/interfaces.txt",
        "host/net/routes.txt",
        "host/power.txt",
    ] {
        assert!(
            find(&files, suffix).is_some(),
            "missing incident capture: {suffix}"
        );
    }

    // The panic-report capture is macOS-only: everywhere else the bundle
    // still accounts for it, as a skip rather than a silent absence.
    let manifest: serde_json_lenient::Value =
        serde_json_lenient::from_slice(find(&files, "manifest.json").expect("manifest")).unwrap();
    let panic_skipped = manifest["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["what"].as_str().unwrap().ends_with("panic.txt"));
    assert!(
        find(&files, "host/panic.txt").is_some() || panic_skipped,
        "panic reports are either captured or recorded as skipped"
    );

    // R5.1: no full MAC survives in the interfaces capture — every one is
    // masked to its OUI, so a 17-char `xx:xx:xx:xx:xx:xx` token never appears.
    let interfaces = String::from_utf8_lossy(find(&files, "host/net/interfaces.txt").unwrap());
    for tok in interfaces.split_whitespace() {
        let is_mac = tok.len() == 17
            && tok.bytes().enumerate().all(|(i, b)| {
                if i % 3 == 2 {
                    b == b':'
                } else {
                    b.is_ascii_hexdigit()
                }
            });
        assert!(!is_mac, "un-masked MAC leaked into interfaces.txt: {tok}");
    }
}

/// R7.1–R7.3: against a live daemon the probe completes every stage, the
/// daemon's own bundle is nested raw and passes its bounded-decode checks,
/// and the redaction guarantees hold across both layers.
#[tokio::test]
async fn bug_with_daemon_nests_a_verified_guest_bundle() {
    let (_daemon, mut args) = setup().await;
    let config = fake_config_dir();
    args.config_dir = Some(config.path().to_path_buf());

    let out_dir = tempfile::TempDir::new().unwrap();
    let out = out_dir.path().join("diag.tar.zst");
    cmd_bug(&args, bug_args(&out)).await.unwrap();

    let files = unpack(&out).await;
    let manifest: serde_json_lenient::Value =
        serde_json_lenient::from_slice(find(&files, "manifest.json").expect("manifest")).unwrap();

    // R7.1: every stage of the probe reached the live daemon, and the
    // connection it opened was the one the download reused.
    let probe: serde_json_lenient::Value = serde_json_lenient::from_slice(
        find(&files, "local-minimald0/socket-probe.json").expect("probe"),
    )
    .unwrap();
    for stage in ["stat", "connect", "handshake", "get_version"] {
        assert_eq!(probe[stage]["outcome"], "ok", "stage {stage}: {probe}");
    }
    assert!(probe["version"]["long_version"].is_string());

    // R7.6: liveness status for the discovered provider.
    assert!(find(&files, "local-minimald0/status.json").is_some());
    assert!(find(&files, "local-minimald0/dir-listing.txt").is_some());

    // R7.3: the daemon bundle is nested raw (it decompresses on its own) and
    // carries the Unit 6 manifest.
    let nested = find(&files, "guest/daemon-diag.tar.zst").expect("nested guest bundle");
    let nested_path = out_dir.path().join("nested.tar.zst");
    std::fs::write(&nested_path, nested).unwrap();
    let guest_files = unpack(&nested_path).await;
    let guest_manifest: serde_json_lenient::Value = serde_json_lenient::from_slice(
        find(&guest_files, "manifest.json").expect("guest manifest"),
    )
    .unwrap();
    assert_eq!(guest_manifest["schema_version"], 1);
    let guest_meta: serde_json_lenient::Value =
        serde_json_lenient::from_slice(find(&guest_files, "meta.json").expect("guest meta"))
            .unwrap();
    assert_eq!(guest_meta["in_microvm"], false);

    // The verification passed: no check recorded a failure against it.
    let errors = manifest["errors"].as_array().unwrap();
    assert!(
        !errors
            .iter()
            .any(|e| e["collector"].as_str().unwrap().starts_with("guest.")),
        "guest collection recorded an error: {errors:?}"
    );

    // Redaction holds across layers: the loadout canary appears nowhere, in
    // the host bundle or the nested one, and key material is never collected.
    for layer in [&files, &guest_files] {
        for (path, contents) in layer.iter() {
            assert!(
                !contents
                    .windows(b"canary-secret-value".len())
                    .any(|window| window == b"canary-secret-value"),
                "secret value leaked into the bundle at {path}"
            );
        }
    }
    assert!(find(&files, "client.key").is_none());
    let skipped = manifest["skipped"].as_array().unwrap();
    assert!(
        skipped
            .iter()
            .any(|s| s["what"].as_str().unwrap().contains("client.key")),
        "client.key skip must be recorded: {skipped:?}"
    );
}

/// R7.1, R7.5: a socket file nothing listens on — the classic
/// stale-socket-after-crash state — fails at the connect stage, and the
/// volume fallback leaves its stall-dating record.
#[tokio::test]
async fn bug_with_stale_socket_reports_the_connect_stage_and_falls_back() {
    let state = tempfile::TempDir::new().unwrap();
    let config = tempfile::TempDir::new().unwrap();
    let provider = state.path().join("providers/local-minvmd0");
    std::fs::create_dir_all(&provider).unwrap();
    drop(std::os::unix::net::UnixListener::bind(provider.join("ssh.sock")).unwrap());
    // A data volume the fallback can date, standing in for a real image.
    std::fs::write(provider.join("data-vol.raw"), [0u8; 4096]).unwrap();

    let out_dir = tempfile::TempDir::new().unwrap();
    let out = out_dir.path().join("diag.tar.zst");
    cmd_bug(&global_args(state.path(), config.path()), bug_args(&out))
        .await
        .unwrap();

    let files = unpack(&out).await;
    let probe: serde_json_lenient::Value = serde_json_lenient::from_slice(
        find(&files, "local-minvmd0/socket-probe.json").expect("probe"),
    )
    .unwrap();
    assert_eq!(probe["stat"]["outcome"], "ok");
    assert_ne!(probe["connect"]["outcome"], "ok");
    assert!(
        probe["handshake"]["outcome"]
            .as_str()
            .unwrap()
            .starts_with("skipped"),
        "the handshake must not be attempted after a failed connect: {probe}"
    );

    let error = find(&files, "guest/error.txt").expect("guest error note");
    assert!(
        String::from_utf8_lossy(error).contains("daemon not reachable"),
        "got: {}",
        String::from_utf8_lossy(error)
    );

    let volume: serde_json_lenient::Value = serde_json_lenient::from_slice(
        find(&files, "guest/volume-meta.json").expect("volume meta"),
    )
    .unwrap();
    assert_eq!(volume["exists"], true);
    assert_eq!(volume["bytes"], 4096);
    assert!(volume["mtime_unix"].is_u64(), "the stall-dating signal");
    assert!(find(&files, "daemon-diag.tar.zst").is_none());
}

/// R7.4: `--no-guest` skips *all* daemon contact, including the probe — which
/// handshakes — even when a healthy daemon is right there.
#[tokio::test]
async fn bug_no_guest_makes_no_daemon_contact() {
    let (_daemon, args) = setup().await;

    let out_dir = tempfile::TempDir::new().unwrap();
    let out = out_dir.path().join("diag.tar.zst");
    let no_guest = BugArgs {
        no_guest: true,
        ..bug_args(&out)
    };
    cmd_bug(&args, no_guest).await.unwrap();

    let files = unpack(&out).await;
    let error = find(&files, "guest/error.txt").expect("guest skip note");
    assert!(
        String::from_utf8_lossy(error).contains("--no-guest"),
        "got: {}",
        String::from_utf8_lossy(error)
    );
    // No probe record: the probe handshakes, so its absence is the proof that
    // nothing touched the daemon.
    assert!(find(&files, "socket-probe.json").is_none());
    assert!(find(&files, "daemon-diag.tar.zst").is_none());
    // Host-side per-provider collection still ran.
    assert!(find(&files, "local-minimald0/status.json").is_some());
}
