//! Convention-discovered gate that no Rust source carries a placeholder or
//! a remote fetch where a remedy is spelled.
//!
//! The classifier's advisories once told a person to `curl` the privileged
//! step from `raw.githubusercontent.com` and fill in `<cohort address>` and
//! `<node-plane address>` by hand (#2128). Every remedy now names the
//! installed CLI's own verb, `min finalize-install`, which carries the step
//! itself. This test keeps it that way: it reads every `.rs` file under
//! `crates/` and every `.sh` file under `scripts/` and fails on any of the
//! retired spellings, wherever they are — a remedy string, a fixture that
//! pins one, or a doc comment that recommends one. The one file spared is
//! the installer rehearsal, `scripts/install_test.sh`, which names the
//! spellings to assert their absence from the step's output.
//!
//! The `common` crate is outside the darwin-native scope `just test` runs,
//! so on macOS this gate runs only through `just test-cross`; the Linux
//! lanes run it natively.

use std::path::{Path, PathBuf};

/// The spellings a remedy must never carry again.
const RETIRED: &[&str] = &[
    "<cohort address>",
    "<node-plane address>",
    "<the account minimald runs as>",
    "raw.githubusercontent.com/gominimal/minimal",
];

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/common; the workspace root is two up.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root two levels above crates/common")
        .to_path_buf()
}

fn sources_with(dir: &Path, extension: &str, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("a readable directory") {
        let path = entry.expect("a readable entry").path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            sources_with(&path, extension, out);
        } else if path.extension().is_some_and(|ext| ext == extension) {
            out.push(path);
        }
    }
}

#[test]
fn no_rust_remedy_carries_a_placeholder_or_a_remote_fetch() {
    let mut sources = Vec::new();
    sources_with(&repo_root().join("crates"), "rs", &mut sources);
    assert!(sources.len() > 10, "the walk found the workspace's sources");
    sources_with(&repo_root().join("scripts"), "sh", &mut sources);
    let this = Path::new(file!())
        .file_name()
        .expect("this file has a name")
        .to_owned();
    let spared = [this.as_os_str(), "install_test.sh".as_ref()];
    let mut hits = Vec::new();
    for path in sources {
        if path.file_name().is_some_and(|name| spared.contains(&name)) {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("a readable source");
        for (number, line) in text.lines().enumerate() {
            for retired in RETIRED {
                if line.contains(retired) {
                    hits.push(format!("{}:{}: {retired}", path.display(), number + 1));
                }
            }
        }
    }
    assert!(
        hits.is_empty(),
        "a remedy names `min finalize-install`, never a placeholder or a fetch:\n{}",
        hits.join("\n")
    );
}
