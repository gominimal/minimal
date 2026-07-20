//! Integration tests for `min bug` (the diagnostic bundle command).
//!
//! Each test runs `cmd_bug` against temp state/config dirs and unpacks the
//! resulting tarball to assert the bundle contract: what's collected, what's
//! redacted, and what the manifest records for everything that's missing.
//! No daemon is involved — the command must be useful on a machine where
//! nothing was ever spawned.

use std::collections::BTreeMap;
use std::path::Path;

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

/// A config dir with a loadout holding a canary secret, to prove redaction.
fn fake_config_dir() -> tempfile::TempDir {
    let dir = tempfile::TempDir::new().unwrap();
    let root = dir.path().join("minimal");
    std::fs::create_dir_all(root.join("loadouts")).unwrap();
    std::fs::write(
        root.join("config.toml"),
        "[loadouts]\ndefault_loadouts = [\"dev\"]\n",
    )
    .unwrap();
    std::fs::write(
        root.join("loadouts/dev.toml"),
        "name = \"dev\"\npackages = [\"ripgrep\"]\n\n[vars]\nGITHUB_TOKEN = \"canary-secret-value\"\n",
    )
    .unwrap();
    dir
}

fn global_args(state: &Path, config: &Path) -> GlobalArgs {
    GlobalArgs {
        repo_dir: None,
        minimal_dir: Some(state.to_path_buf()),
        config_dir: Some(config.to_path_buf()),
        minvmd: false,
    }
}

fn bug_args(out: &Path) -> BugArgs {
    BugArgs {
        output: Some(out.to_path_buf()),
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
    let manifest: serde_json::Value =
        serde_json::from_slice(find(&files, "manifest.json").expect("manifest")).unwrap();
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

    let out_dir = tempfile::TempDir::new().unwrap();
    let out = out_dir.path().join("diag.tar.zst");
    cmd_bug(&args, bug_args(&out)).await.unwrap();

    let files = unpack(&out).await;

    // The symlink was refused at open, its target never read, and the
    // refusal recorded.
    assert!(find(&files, "evil.toml.redacted").is_none());
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
    let manifest: serde_json::Value =
        serde_json::from_slice(find(&files, "manifest.json").expect("manifest")).unwrap();
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

    let provider = state.path().join("providers/local-0");
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

    assert!(find(&files, "providers/local-0/run.log").is_some());
    assert!(find(&files, "providers/remote-x/run.log").is_none());
    let manifest: serde_json::Value =
        serde_json::from_slice(find(&files, "manifest.json").expect("manifest")).unwrap();
    let skipped = manifest["skipped"].as_array().unwrap();
    assert!(
        skipped
            .iter()
            .any(|s| s["what"] == "providers/local-0/boot.log" && s["reason"] == "absent"),
        "absent boot.log is a skip: {skipped:?}"
    );
    assert_eq!(manifest["errors"].as_array().unwrap().len(), 0, "no errors");
}
