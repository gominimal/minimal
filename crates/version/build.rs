//! Derive the shared human-facing version string for the minimal binaries and
//! expose it as `MINIMAL_VERSION` / `MINIMAL_LONG_VERSION` for `src/lib.rs`.
//!
//! The scheme itself lives in `src/scheme.rs` (included textually here, and
//! unit-tested through `lib.rs` under `cfg(test)`); this file only gathers its
//! inputs. In short: `MINIMAL_RELEASE_VERSION` wins when set (a release build
//! on an untagged commit, so the tag can come last); otherwise `git describe`
//! against `v*` tags supplies the commit count and hash on top of the
//! workspace `package.version`, the declared next release; with no tag or no
//! git, `package.version` alone. `--match 'v*'` scopes describe to version
//! tags so the many `release-<sha>` tags this repo also carries are ignored.

use std::path::PathBuf;
use std::process::Command;

#[path = "src/scheme.rs"]
mod scheme;

fn main() {
    emit_rerun_triggers();

    let cargo_version = std::env::var("CARGO_PKG_VERSION").unwrap();
    let release_version = std::env::var("MINIMAL_RELEASE_VERSION")
        .ok()
        .filter(|v| !v.is_empty());
    let describe = describe();
    let short_hash = short_hash();
    let dirty = is_dirty();

    let derived = scheme::derive(&scheme::Inputs {
        release_version: release_version.as_deref(),
        cargo_version: &cargo_version,
        describe: describe.as_deref(),
        short_hash: short_hash.as_deref(),
        dirty,
    })
    .unwrap_or_else(|msg| panic!("{msg}"));

    if dirty == Some(true) && std::env::var("PROFILE").as_deref() == Ok("release") {
        println!("cargo::warning=Building a release binary from an unclean working tree!!");
        println!("cargo::warning=Always build production binaries from a clean checkout.");
    }

    println!("cargo:rustc-env=MINIMAL_VERSION={}", derived.version);
    println!(
        "cargo:rustc-env=MINIMAL_LONG_VERSION={}",
        derived.long_version
    );
}

/// `git describe` scoped to `v*` version tags. `None` on any failure (no matching
/// tag reachable, shallow clone with tags absent, or not a git repo).
fn describe() -> Option<String> {
    non_empty_stdout(&["describe", "--tags", "--match", "v*", "--abbrev=8"])
}

/// Short HEAD hash, used only to keep untagged dev builds identifiable.
fn short_hash() -> Option<String> {
    non_empty_stdout(&["rev-parse", "--short=8", "HEAD"])
}

/// `Some(true)`/`Some(false)` when git is available, `None` when it isn't.
fn is_dirty() -> Option<bool> {
    let out = Command::new("git")
        .args(["status", "--porcelain=v1"])
        .output()
        .ok()?;
    out.status.success().then_some(!out.stdout.is_empty())
}

/// Recompute when HEAD moves, a tag is added, the index changes, or the release
/// override changes. Watching the git dir this way keeps the version fresh
/// without rerunning on every build.
/// Caveat: a raw *unstaged* edit touches neither HEAD nor the index, so the
/// `.dirty` marker only refreshes on the next git operation (or source change).
fn emit_rerun_triggers() {
    println!("cargo:rerun-if-env-changed=MINIMAL_RELEASE_VERSION");
    let Some(git_dir) = absolute_git_dir() else {
        // No git (e.g. a source tarball): nothing to watch; version is the fallback.
        return;
    };
    // `refs/tags` (a dir) catches loose tag creation; `packed-refs` catches packed
    // tags; `HEAD`/`index` catch checkouts and staging.
    for entry in ["HEAD", "index", "packed-refs", "refs/tags"] {
        let path = git_dir.join(entry);
        if path.exists() {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
    // The concrete ref HEAD points at (e.g. refs/heads/main) changes on each commit.
    if let Ok(head) = std::fs::read_to_string(git_dir.join("HEAD"))
        && let Some(target) = head.strip_prefix("ref:").map(str::trim)
    {
        let refp = git_dir.join(target);
        if refp.exists() {
            println!("cargo:rerun-if-changed={}", refp.display());
        }
    }
}

/// Absolute path to the git dir, resolving worktrees and separate git dirs.
fn absolute_git_dir() -> Option<PathBuf> {
    non_empty_stdout(&["rev-parse", "--absolute-git-dir"]).map(PathBuf::from)
}

/// Run `git <args>` and return trimmed stdout, or `None` on failure/empty output.
fn non_empty_stdout(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_string())
}
