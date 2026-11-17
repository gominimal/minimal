//! Integration tests for `min bug` (the diagnostic bundle command).
//!
//! Each test runs `cmd_bug` against a real minimald `TestServer` (or a
//! deliberately empty state dir) and unpacks the resulting tarball to assert
//! the bundle contract: what's collected, what's redacted, what the manifest
//! records for everything that's missing, and how the command degrades when
//! the daemon is unreachable.

// The in-process daemon's async bodies are deep: rustc's default query depth (128)
// overflows computing their layout (`queries overflow the depth limit!`), as the
// daemon crates themselves already declare.
#![recursion_limit = "256"]
mod common;

use std::collections::BTreeMap;
use std::path::Path;

use common::setup;
use minimal::GlobalArgs;
use minimal::diag::answerer;
use minimal::diag::upload::DEFAULT_ENDPOINT;
use minimal::diag::{BugArgs, PortalArgs, cmd_bug};

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
        vm: None,
    }
}

fn bug_args(out: &Path) -> BugArgs {
    BugArgs {
        output: Some(out.to_path_buf()),
        no_guest: false,
        guest_timeout_secs: 60,
        log_tail_bytes: diagnostics::LOG_TAIL_CAP,
        upload: false,
        portal: PortalArgs {
            context: None,
            security: false,
            endpoint: DEFAULT_ENDPOINT.to_string(),
        },
    }
}

/// `--security` only means something on an upload. Refused before collecting,
/// so a reporter never reads a local bundle as a report made in private.
#[tokio::test]
async fn security_without_upload_is_refused_and_collects_nothing() {
    let state = tempfile::TempDir::new().unwrap();
    let config = tempfile::TempDir::new().unwrap();
    let args = global_args(state.path(), config.path());

    let out_dir = tempfile::TempDir::new().unwrap();
    let out = out_dir.path().join("diag.tar.zst");
    let mut bug = bug_args(&out);
    bug.portal.security = true;

    // Boxed: `cmd_bug` is a large future (clippy::large_futures).
    let err = Box::pin(cmd_bug(&args, bug)).await.unwrap_err().to_string();
    assert!(err.contains("needs --upload"), "{err}");
    assert!(!out.exists(), "a refused run must write no bundle");
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

    // Nothing was ever spawned: the host and log absences are recorded
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

/// The bundle describes the host's answerer service (`minzoned`): the
/// version and SHA-256 of the installed copy and of the copy `min` ships,
/// and the service manager's view of the service. A part this host cannot
/// give is a skip that says why, never a silent gap. Under `cargo test`
/// neither copy is usually present, so each copy carries its reason.
#[tokio::test]
async fn the_answerer_service_is_described() {
    let state = tempfile::TempDir::new().unwrap();
    let config = tempfile::TempDir::new().unwrap();
    let out_dir = tempfile::TempDir::new().unwrap();
    let out = out_dir.path().join("diag.tar.zst");
    cmd_bug(&global_args(state.path(), config.path()), bug_args(&out))
        .await
        .unwrap();

    let files = unpack(&out).await;
    let manifest: serde_json_lenient::Value =
        serde_json_lenient::from_slice(find(&files, "manifest.json").expect("manifest")).unwrap();
    let errors = manifest["errors"].to_string();
    assert!(
        !errors.contains("host.answerer"),
        "the answerer collector does not fail: {errors}"
    );

    let report: serde_json_lenient::Value =
        serde_json_lenient::from_slice(find(&files, "host/answerer.json").expect("answerer.json"))
            .unwrap();
    for copy in ["installed", "shipped"] {
        let entry = &report[copy];
        let errors = entry["errors"].as_array().expect("errors is a list");
        for field in ["version", "sha256"] {
            let value = &entry[field];
            assert!(
                value.as_str().is_some_and(|v| !v.is_empty()) || !errors.is_empty(),
                "the {copy} copy's {field} is present or an error says why: {entry}"
            );
        }
        if let Some(sha) = entry["sha256"].as_str() {
            assert_eq!(sha.len(), 64, "a SHA-256 is 64 hex digits: {sha}");
        }
    }
    assert!(
        report["same_bytes"].is_null()
            == (report["installed"]["sha256"].is_null() || report["shipped"]["sha256"].is_null()),
        "the copies are compared only when both hash: {report}"
    );

    // The service state is a transcript, or a skip that says why.
    let skips: Vec<(String, String)> = manifest["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            (
                s["what"].as_str().unwrap().to_string(),
                s["reason"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    let mut entries = vec!["host/answerer-service.txt"];
    if !cfg!(target_os = "macos") {
        entries.push("host/answerer-journal.txt");
    }
    for entry in entries {
        match find(&files, entry) {
            Some(text) => {
                let text = String::from_utf8_lossy(text);
                assert!(
                    text.starts_with("$ "),
                    "a transcript names its command: {text}"
                );
            }
            None => {
                let (_, reason) = skips
                    .iter()
                    .find(|(what, _)| what == entry)
                    .unwrap_or_else(|| panic!("{entry} is collected or skipped: {skips:?}"));
                assert!(reason.contains("did not run"), "{entry}: {reason}");
            }
        }
    }
    // macOS: the service's log, or a skip that says why it is absent.
    if cfg!(target_os = "macos") && find(&files, answerer::LOG_ENTRY).is_none() {
        let (_, reason) = skips
            .iter()
            .find(|(what, _)| what == answerer::LOG_ENTRY)
            .unwrap_or_else(|| panic!("the log is collected or skipped: {skips:?}"));
        assert!(
            reason.starts_with("absent") || reason.starts_with("unreadable"),
            "{reason}"
        );
    }
}

/// A fixture `minzoned` that prints `version` for `--version`.
fn fixture_program(dir: &Path, name: &str, version: &str) -> String {
    use std::os::unix::fs::PermissionsExt as _;
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\necho '{version}'\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path.to_str().unwrap().to_string()
}

/// A command that prints the fixture file `name` holding `text`.
fn fixture_transcript(dir: &Path, name: &str, text: &str) -> answerer::CommandSpec {
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    answerer::CommandSpec {
        program: "cat".to_string(),
        args: vec![path.to_str().unwrap().to_string()],
    }
}

/// Collects the answerer entries from `sources` alone, and returns the
/// unpacked bundle and its manifest's skips.
async fn answerer_bundle(
    sources: &answerer::AnswererSources,
) -> (BTreeMap<String, Vec<u8>>, Vec<(String, String)>) {
    let out_dir = tempfile::TempDir::new().unwrap();
    let out = out_dir.path().join("diag.tar.zst");
    let mut w = diagnostics::BundleWriter::create(&out, "r", "v")
        .await
        .unwrap();
    answerer::answerer_from(&mut w, sources, diagnostics::LOG_TAIL_CAP)
        .await
        .unwrap();
    w.finish(chrono::Utc::now(), std::time::Duration::ZERO)
        .await
        .unwrap();
    let files = unpack(&out).await;
    let manifest: serde_json_lenient::Value =
        serde_json_lenient::from_slice(find(&files, "manifest.json").expect("manifest")).unwrap();
    let skips = manifest["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            (
                s["what"].as_str().unwrap().to_string(),
                s["reason"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    (files, skips)
}

/// The answerer service as a host that will not start it shows it: an
/// installed copy and a shipped copy that differ, a service manager that
/// reports exit 1, a journal, and a log with the service's last words. The
/// bundle carries each copy's version and SHA-256, both transcripts and
/// the log, byte for byte.
#[tokio::test]
async fn the_answerer_service_is_described_from_fixtures() {
    use sha2::Digest as _;
    let dir = tempfile::TempDir::new().unwrap();
    let installed = fixture_program(dir.path(), "installed-minzoned", "minzoned 0.9.0");
    let shipped = fixture_program(dir.path(), "shipped-minzoned", "minzoned 1.0.0");
    let service_text =
        "system/dev.gominimal.zone = {\n\tstate = not running\n\tlast exit code = 1\n}\n";
    let journal_text = "2026-11-17T10:00:00+0000 host systemd[1]: minzoned.service: Failed with result 'exit-code'.\n";
    let log_text = "2026-11-17T10:00:00Z ERROR minzoned: no socket named Listener\n";
    let log = dir.path().join("minzoned.log");
    std::fs::write(&log, log_text).unwrap();
    let unit = dir.path().join("dev.gominimal.zone.plist");
    std::fs::write(
        &unit,
        format!(
            "<key>StandardErrorPath</key>\n<string>{}</string>\n",
            log.display()
        ),
    )
    .unwrap();
    let sources = answerer::AnswererSources {
        installed: Some(installed.clone()),
        shipped: Some(shipped.clone()),
        service: fixture_transcript(dir.path(), "service.txt", service_text),
        journal: Some(fixture_transcript(dir.path(), "journal.txt", journal_text)),
        log: Some(answerer::LogSource {
            path: log.to_str().unwrap().to_string(),
            unit: unit.to_str().unwrap().to_string(),
        }),
    };
    let (files, skips) = answerer_bundle(&sources).await;
    assert!(skips.is_empty(), "nothing is skipped: {skips:?}");

    let report: serde_json_lenient::Value =
        serde_json_lenient::from_slice(find(&files, "host/answerer.json").expect("answerer.json"))
            .unwrap();
    for (copy, path, version) in [
        ("installed", &installed, "minzoned 0.9.0"),
        ("shipped", &shipped, "minzoned 1.0.0"),
    ] {
        let entry = &report[copy];
        let sha = hex::encode(sha2::Sha256::digest(std::fs::read(path).unwrap()));
        assert_eq!(entry["path"].as_str(), Some(path.as_str()), "{entry}");
        assert_eq!(entry["version"].as_str(), Some(version), "{entry}");
        assert_eq!(entry["sha256"].as_str(), Some(sha.as_str()), "{entry}");
        assert_eq!(entry["errors"].as_array().map(Vec::len), Some(0), "{entry}");
    }
    assert_eq!(report["same_bytes"].as_bool(), Some(false), "{report}");

    for (entry, text) in [
        ("host/answerer-service.txt", service_text),
        ("host/answerer-journal.txt", journal_text),
    ] {
        let got = String::from_utf8_lossy(find(&files, entry).expect(entry)).into_owned();
        assert!(
            got.starts_with("$ cat "),
            "{entry} names its command: {got}"
        );
        assert!(got.contains(text), "{entry} holds the transcript: {got}");
        assert!(got.ends_with("--- exit status: 0 ---\n"), "{entry}: {got}");
    }
    assert_eq!(
        find(&files, answerer::LOG_ENTRY).map(|b| String::from_utf8_lossy(b).into_owned()),
        Some(log_text.to_string()),
        "the bundle holds the service's log"
    );
}

/// A log that is not there is a skip that says why. A unit from before
/// the log names none, and the skip names the command that adds it.
#[tokio::test]
async fn the_answerer_service_is_described_when_its_log_is_absent() {
    let dir = tempfile::TempDir::new().unwrap();
    let log = dir
        .path()
        .join("minzoned.log")
        .to_str()
        .unwrap()
        .to_string();
    let unit = dir.path().join("dev.gominimal.zone.plist");
    let mut sources = answerer::AnswererSources {
        installed: None,
        shipped: None,
        service: fixture_transcript(dir.path(), "service.txt", "state = running\n"),
        journal: None,
        log: Some(answerer::LogSource {
            path: log.clone(),
            unit: unit.to_str().unwrap().to_string(),
        }),
    };
    let skip_of = |skips: &[(String, String)]| {
        skips
            .iter()
            .find(|(what, _)| what == answerer::LOG_ENTRY)
            .map(|(_, reason)| reason.clone())
            .unwrap_or_else(|| panic!("the log is skipped: {skips:?}"))
    };

    // No unit at all: the service is not installed.
    let (_, skips) = answerer_bundle(&sources).await;
    let reason = skip_of(&skips);
    assert!(reason.contains("not installed"), "{reason}");

    // A unit from before the log.
    std::fs::write(&unit, "<key>ProgramArguments</key>\n").unwrap();
    let (files, skips) = answerer_bundle(&sources).await;
    assert!(find(&files, answerer::LOG_ENTRY).is_none());
    let reason = skip_of(&skips);
    assert!(
        reason.contains("predates its log") && reason.contains("min finalize-install"),
        "{reason}"
    );

    // A unit that names the log, whose file is gone.
    std::fs::write(
        &unit,
        format!("<key>StandardErrorPath</key>\n<string>{log}</string>\n"),
    )
    .unwrap();
    let (_, skips) = answerer_bundle(&sources).await;
    let reason = skip_of(&skips);
    assert!(
        reason.contains(&log) && reason.contains("min finalize-install"),
        "{reason}"
    );

    // No log source: no entry and no skip.
    sources.log = None;
    let (files, skips) = answerer_bundle(&sources).await;
    assert!(find(&files, answerer::LOG_ENTRY).is_none());
    assert!(
        skips.iter().all(|(what, _)| what != answerer::LOG_ENTRY),
        "{skips:?}"
    );
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

    // The retired key is never collected, and no skip names it (NET-109).
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
        !manifest["skipped"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["what"].as_str().unwrap().contains("client.key")),
        "the retired client.key must not be recorded as a skip: {}",
        manifest["skipped"]
    );
}

#[tokio::test]
async fn logs_collects_newest_five_per_prefix_and_host_logs() {
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

    let host_dir = state.path().join("providers/local-minvmd0");
    std::fs::create_dir_all(&host_dir).unwrap();
    std::fs::write(host_dir.join("run.log"), "supervisor stderr\n").unwrap();
    // The zone-table dump (NET-138): the table the VM host daemon's
    // answerer answered from, under the name the daemon writes — the
    // bundle carries the table itself, not just its name in the dir
    // listing.
    let zone_table = "[\n  {\n    \"name\": \"web.min.internal\",\n    \"address\": \"127.0.64.9\",\n    \"live\": true\n  }\n]";
    std::fs::write(host_dir.join(minvmd::diag::ZONE_TABLE_FILE), zone_table).unwrap();
    // boot.log deliberately absent — recorded as a skip, not an error.
    // A native host carries no zone dump either: same skip.
    let native = state.path().join("providers/local-minimald0");
    std::fs::create_dir_all(&native).unwrap();
    std::fs::write(native.join("run.log"), "native daemon stderr\n").unwrap();
    // Non-`local-` entries are not hosts and must be ignored.
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
    // The zone table rides the bundle beside the logs, whole — a table
    // this small is never tail-capped — and by its daemon-given name.
    let zone = find(
        &files,
        &format!("providers/local-minvmd0/{}", minvmd::diag::ZONE_TABLE_FILE),
    )
    .expect("the zone-table dump is bundled");
    assert_eq!(
        String::from_utf8_lossy(zone),
        zone_table,
        "the dump is copied, not summarized"
    );
    let manifest: serde_json_lenient::Value =
        serde_json_lenient::from_slice(find(&files, "manifest.json").expect("manifest")).unwrap();
    let skipped = manifest["skipped"].as_array().unwrap();
    assert!(
        skipped
            .iter()
            .any(|s| s["what"] == "providers/local-minvmd0/boot.log" && s["reason"] == "absent"),
        "absent boot.log is a skip: {skipped:?}"
    );
    assert!(
        skipped.iter().any(|s| {
            s["what"]
                == format!(
                    "providers/local-minimald0/{}",
                    minvmd::diag::ZONE_TABLE_FILE
                )
                && s["reason"] == "absent"
        }),
        "a provider instance with no zone dump records its absence the \
         same way a missing log does: {skipped:?}"
    );
    assert_eq!(manifest["errors"].as_array().unwrap().len(), 0, "no errors");
}

/// The `--log-tail-bytes` cap reaches every log the collector bundles — the
/// rotated host logs and the host-scoped ones — and the manifest labels
/// each capped file so a reader can tell a truncated log from a short one.
#[tokio::test]
async fn a_custom_tail_cap_applies_to_every_log() {
    let state = tempfile::TempDir::new().unwrap();
    let config = tempfile::TempDir::new().unwrap();

    let log_dir = state.path().join("logs");
    std::fs::create_dir_all(&log_dir).unwrap();
    std::fs::write(log_dir.join("minimald.log.2026-07-21"), "x".repeat(500)).unwrap();
    let host_dir = state.path().join("providers/local-minvmd0");
    std::fs::create_dir_all(&host_dir).unwrap();
    std::fs::write(host_dir.join("run.log"), "y".repeat(500)).unwrap();

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

    // R7.6: liveness status for the discovered host.
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
        !skipped
            .iter()
            .any(|s| s["what"].as_str().unwrap().contains("client.key")),
        "the retired client.key must not be recorded as a skip: {skipped:?}"
    );
}

/// R7.1, R7.5: a socket file nothing listens on — the classic
/// stale-socket-after-crash state — fails at the connect stage, and the
/// volume fallback leaves its stall-dating record.
#[tokio::test]
async fn bug_with_stale_socket_reports_the_connect_stage_and_falls_back() {
    let state = tempfile::TempDir::new().unwrap();
    let config = tempfile::TempDir::new().unwrap();
    let host_dir = state.path().join("providers/local-minvmd0");
    std::fs::create_dir_all(&host_dir).unwrap();
    drop(std::os::unix::net::UnixListener::bind(host_dir.join("ssh.sock")).unwrap());
    // A data volume the fallback can date, standing in for a real image.
    std::fs::write(host_dir.join("data-vol.raw"), [0u8; 4096]).unwrap();

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
    assert!(
        volume["allocated_bytes"].is_u64(),
        "the allocated size must be recorded: {volume}"
    );
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
    // Host-side per-host collection still ran.
    assert!(find(&files, "local-minimald0/status.json").is_some());
}

/// An invalid link table is reported as such, without the table header the
/// parser quotes, the same reduction a malformed config gets.
#[tokio::test]
async fn an_invalid_link_table_is_reported_without_quoting_it() {
    let project = tempfile::TempDir::new().unwrap();
    let config = project.path().join(".minimal");
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(
        config.join("minimal.toml"),
        "[upstream]\nrepo = \"https://example.invalid/up.git\"\n\n\
         [[upstream.sideload]]\nbranch = \"canary-secret-value\"\n",
    )
    .unwrap();

    let files = bundle_for_project(Some(project.path())).await;
    let manifest: serde_json_lenient::Value =
        serde_json_lenient::from_slice(find(&files, "manifest.json").expect("manifest")).unwrap();
    let scope = &manifest["project"];

    assert_eq!(scope["state"], "unknown", "unparseable is not identified");
    let reason = scope["reason"].as_str().expect("a reason");
    assert!(
        reason.contains("invalid [upstream] or sideload table"),
        "an invalid link must be reported as such: {reason}"
    );
    assert!(
        !reason.contains("[[upstream.sideload]]") && !reason.contains(" at line "),
        "the reason must not quote the table or its line: {reason}"
    );
    for (path, contents) in &files {
        assert!(
            !String::from_utf8_lossy(contents).contains("canary-secret-value"),
            "a rejected config line leaked into {path}"
        );
    }
}
