//! Integration tests for `min bug` (the diagnostic bundle command).
//!
//! Each test runs `cmd_bug` against a real minimald `TestServer` (or a
//! deliberately empty state dir) and unpacks the resulting tarball to assert
//! the bundle contract: what's collected, what's redacted, and how the
//! command degrades when the daemon is missing.

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

fn bug_args(out: &Path, no_guest: bool) -> BugArgs {
    BugArgs {
        output: Some(out.to_path_buf()),
        no_guest,
        guest_timeout_secs: 60,
    }
}

#[tokio::test]
async fn bug_with_daemon_bundles_guest_diag_and_redacts_secrets() {
    let (_daemon, mut args) = setup().await;
    let config = fake_config_dir();
    args.config_dir = Some(config.path().to_path_buf());

    let out_dir = tempfile::TempDir::new().unwrap();
    let out = out_dir.path().join("diag.tar.zst");
    cmd_bug(&args, bug_args(&out, false)).await.unwrap();

    let files = unpack(&out).await;

    // The manifest is present and records collected entries.
    let manifest: serde_json::Value =
        serde_json::from_slice(find(&files, "manifest.json").expect("manifest")).unwrap();
    assert_eq!(manifest["schema_version"], 1);
    assert!(!manifest["collected"].as_array().unwrap().is_empty());

    // The socket probe completed every stage against the live daemon.
    let probe: serde_json::Value =
        serde_json::from_slice(find(&files, "local-0/socket-probe.json").expect("probe")).unwrap();
    for stage in ["stat", "connect", "handshake", "get_version"] {
        assert_eq!(probe[stage]["outcome"], "ok", "stage {stage}: {probe}");
    }
    assert!(probe["version"]["long_version"].is_string());

    // The daemon's own bundle is nested raw and unpacks to a valid archive
    // with its meta.json.
    let nested = find(&files, "guest/daemon-diag.tar.zst").expect("guest bundle");
    let nested_path = out_dir.path().join("nested.tar.zst");
    std::fs::write(&nested_path, nested).unwrap();
    let guest_files = unpack(&nested_path).await;
    let meta: serde_json::Value =
        serde_json::from_slice(find(&guest_files, "meta.json").expect("guest meta")).unwrap();
    assert_eq!(meta["in_microvm"], false);

    // The loadout is included with its env-var value masked; the canary
    // never appears anywhere in the bundle.
    let loadout = find(&files, "loadouts/dev.toml.redacted").expect("redacted loadout");
    let loadout = String::from_utf8_lossy(loadout);
    assert!(loadout.contains("GITHUB_TOKEN"), "keys survive: {loadout}");
    assert!(loadout.contains("ripgrep"), "packages survive: {loadout}");
    for contents in files.values() {
        assert!(
            !contents
                .windows(b"canary-secret-value".len())
                .any(|window| window == b"canary-secret-value"),
            "secret value leaked into the bundle"
        );
    }

    // Key material is never collected, and that is recorded.
    assert!(find(&files, "client.key").is_none());
    let skipped = manifest["skipped"].as_array().unwrap();
    assert!(
        skipped
            .iter()
            .any(|s| s["what"].as_str().unwrap().contains("client.key")),
        "client.key skip must be recorded: {skipped:?}"
    );
}

#[tokio::test]
async fn bug_without_daemon_still_produces_a_bundle() {
    let state = tempfile::TempDir::new().unwrap();
    let config = tempfile::TempDir::new().unwrap();
    let args = GlobalArgs {
        repo_dir: None,
        minimal_dir: Some(state.path().to_path_buf()),
        config_dir: Some(config.path().to_path_buf()),
        minvmd: false,
    };

    let out_dir = tempfile::TempDir::new().unwrap();
    let out = out_dir.path().join("diag.tar.zst");
    cmd_bug(&args, bug_args(&out, false)).await.unwrap();

    let files = unpack(&out).await;
    let manifest: serde_json::Value =
        serde_json::from_slice(find(&files, "manifest.json").expect("manifest")).unwrap();

    // Nothing was ever spawned: the providers skip is recorded and host
    // collection still ran.
    assert!(
        manifest["skipped"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["what"] == "providers/"),
        "expected a providers/ skip note: {}",
        manifest["skipped"]
    );
    assert!(find(&files, "host/system.json").is_some());
    assert!(find(&files, "state/listing.txt").is_some());

    // Host network capture: interfaces (MACs masked to their OUI) and the
    // routing table. Hosts without ip/ifconfig/netstat (minimal containers)
    // degrade to a recorded collector error instead — assert one or the
    // other, never silence.
    let collector_error = |name: &str| {
        manifest["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["collector"] == name)
    };
    match find(&files, "host/net/interfaces.txt") {
        Some(contents) => {
            let interfaces = String::from_utf8_lossy(contents);
            let mac_shaped = |tok: &str| {
                tok.len() == 17
                    && tok.bytes().enumerate().all(|(i, b)| match i % 3 {
                        2 => b == b':',
                        _ => b.is_ascii_hexdigit(),
                    })
            };
            assert!(
                !interfaces
                    .split_whitespace()
                    .any(|tok| mac_shaped(tok.trim_end_matches(','))),
                "no full MAC address may survive masking: {interfaces}"
            );
        }
        None => assert!(
            collector_error("host.net.interfaces"),
            "interfaces absent without a collector error: {}",
            manifest["errors"]
        ),
    }
    assert!(
        find(&files, "host/net/routes.txt").is_some() || collector_error("host.net.routes"),
        "routes absent without a collector error: {}",
        manifest["errors"]
    );
}

#[tokio::test]
async fn bug_with_stale_socket_reports_the_connect_stage() {
    let state = tempfile::TempDir::new().unwrap();
    let config = tempfile::TempDir::new().unwrap();
    // A provider dir with a socket file nothing listens on — the classic
    // stale-socket-after-crash state.
    let provider = state.path().join("providers/local-0");
    std::fs::create_dir_all(&provider).unwrap();
    drop(std::os::unix::net::UnixListener::bind(provider.join("ssh.sock")).unwrap());

    let args = GlobalArgs {
        repo_dir: None,
        minimal_dir: Some(state.path().to_path_buf()),
        config_dir: Some(config.path().to_path_buf()),
        minvmd: false,
    };

    let out_dir = tempfile::TempDir::new().unwrap();
    let out = out_dir.path().join("diag.tar.zst");
    cmd_bug(&args, bug_args(&out, false)).await.unwrap();

    let files = unpack(&out).await;
    let probe: serde_json::Value =
        serde_json::from_slice(find(&files, "local-0/socket-probe.json").expect("probe")).unwrap();
    assert_eq!(probe["stat"]["outcome"], "ok");
    assert_ne!(probe["connect"]["outcome"], "ok");

    let error = find(&files, "guest/error.txt").expect("guest error note");
    assert!(
        String::from_utf8_lossy(error).contains("daemon not reachable"),
        "got: {}",
        String::from_utf8_lossy(error)
    );
}

#[tokio::test]
async fn bug_no_guest_skips_daemon_contact() {
    let (_daemon, args) = setup().await;

    let out_dir = tempfile::TempDir::new().unwrap();
    let out = out_dir.path().join("diag.tar.zst");
    cmd_bug(&args, bug_args(&out, true)).await.unwrap();

    let files = unpack(&out).await;
    let error = find(&files, "guest/error.txt").expect("guest skip note");
    assert!(
        String::from_utf8_lossy(error).contains("--no-guest"),
        "got: {}",
        String::from_utf8_lossy(error)
    );
    assert!(find(&files, "daemon-diag.tar.zst").is_none());
}
