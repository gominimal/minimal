//! Derive the shared human-facing version string for the minimal binaries and
//! expose it as `MINIMAL_VERSION` / `MINIMAL_LONG_VERSION` for `src/lib.rs`.
//!
//! Source of truth is `git describe` against `v*` tags (the SemVer release
//! tags), NOT the Cargo `version` field:
//!
//! - HEAD is exactly `v1.2.3` (clean)       -> `1.2.3`
//! - N commits past `v1.2.3`                 -> `1.2.4-dev.<N>.g<hash>`
//! - N commits past a pre-release `v1.2.3-rc1` -> `1.2.3-rc1.dev.<N>.g<hash>`
//! - dirty working tree                      -> `+dirty` build metadata appended
//! - no `v*` tag reachable, or no git repo   -> the crate's Cargo version (fallback)
//!
//! Commits past a release are encoded as a **pre-release** (`-dev.<N>.g<hash>`),
//! not build metadata, so they order correctly under SemVer 2.0: a build N
//! commits past `v1.2.3` sorts ABOVE `1.2.3` and BELOW the next release. Build
//! metadata (anything after `+`) would instead be ignored in precedence, making
//! every post-release build compare equal to the release. `<N>` is a numeric
//! pre-release identifier, so more commits => higher version. In CI, `<N>` is
//! the workflow run number (`GITHUB_RUN_NUMBER`) rather than the git-describe
//! commit count, so it matches the release/build number operators reference;
//! the run number is monotonic, so ordering still holds. `--match 'v*'` scopes
//! describe to version tags so the many `release-<sha>` tags this repo also
//! carries are ignored.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    emit_rerun_triggers();

    let cargo_version = std::env::var("CARGO_PKG_VERSION").unwrap();
    let dirty = is_dirty();

    let (version, long_version) = match describe() {
        Some(desc) => {
            let v = to_semver(&desc, dirty.unwrap_or(false));
            (v.clone(), v)
        }
        // No v* tag reachable (or no git): the version is just the Cargo version.
        // The long form still carries the commit id when git is available, so a
        // dev build off an untagged tree stays identifiable.
        None => {
            let long = match (short_hash(), dirty) {
                (Some(hash), Some(d)) => {
                    format!("{cargo_version} ({}{hash})", if d { "dirty " } else { "" })
                }
                _ => cargo_version.clone(),
            };
            (cargo_version, long)
        }
    };

    if dirty == Some(true) && std::env::var("PROFILE").as_deref() == Ok("release") {
        println!("cargo::warning=Building a release binary from an unclean working tree!!");
        println!("cargo::warning=Always build production binaries from a clean checkout.");
    }

    println!("cargo:rustc-env=MINIMAL_VERSION={version}");
    println!("cargo:rustc-env=MINIMAL_LONG_VERSION={long_version}");
}

/// Turn `git describe --tags --match 'v*'` output into a SemVer string that
/// orders correctly (see the module docs).
///
/// - `v1.2.3`               -> `1.2.3`
/// - `v1.2.3-5-g86ce5c3a`   -> `1.2.4-dev.5.g86ce5c3a`   (release base: bump patch)
/// - `v1.2.3-rc1-5-gabc123` -> `1.2.3-rc1.dev.5.gabc123` (pre-release base: extend)
///
/// A dirty tree appends `+dirty` build metadata. Shapes that don't match the
/// `-<count>-g<hash>` describe suffix (e.g. a pre-release tag sitting exactly on
/// HEAD) pass through verbatim.
fn to_semver(describe: &str, dirty: bool) -> String {
    let core = describe.strip_prefix('v').unwrap_or(describe);
    let mut out = match core.rsplitn(3, '-').collect::<Vec<_>>()[..] {
        [hash, commit_count, base]
            if commit_count.bytes().all(|b| b.is_ascii_digit())
                && hash
                    .strip_prefix('g')
                    .is_some_and(|h| !h.is_empty() && h.bytes().all(|b| b.is_ascii_hexdigit())) =>
        {
            // A dev build `count` commits past tag `base`. Encode as a pre-release
            // so it sorts above `base` but below the next release. In CI, prefer
            // the workflow run number over the git-describe commit count so the
            // counter matches the release/build number operators reference; fall
            // back to the commit count for local builds.
            let run_number = ci_run_number();
            let count = run_number.as_deref().unwrap_or(commit_count);
            if base.contains('-') {
                // `base` already carries a pre-release (e.g. `0.5.0-rc1`); extend it,
                // so `0.5.0-rc1.dev.N` > `0.5.0-rc1` and < `0.5.0`.
                format!("{base}.dev.{count}.{hash}")
            } else if let Some(next) = bump_patch(base) {
                // Released tag `X.Y.Z`: this build is heading toward `X.Y.(Z+1)`.
                format!("{next}-dev.{count}.{hash}")
            } else {
                // `base` isn't a plain `X.Y.Z`; still emit a pre-release off it.
                format!("{base}-dev.{count}.{hash}")
            }
        }
        _ => core.to_string(),
    };
    if dirty {
        // Pre-release uses `-`, so build metadata always starts a fresh `+` group.
        out.push_str("+dirty");
    }
    out
}

/// The CI build number to use in place of the git-describe commit count.
///
/// Reads `GITHUB_RUN_NUMBER` (set by GitHub Actions), so the counter in the
/// version string matches the release/build number operators reference when
/// triaging, rather than the git-describe "commits since tag" count. `None`
/// outside CI, or when the value is empty or non-numeric, leaving the commit
/// count in place. The run number is monotonic, so it preserves the pre-release
/// ordering (higher build => higher version).
fn ci_run_number() -> Option<String> {
    let n = std::env::var("GITHUB_RUN_NUMBER").ok()?;
    let n = n.trim();
    (!n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())).then(|| n.to_string())
}

/// Increment the patch of a plain `X.Y.Z` (all-numeric) core, e.g. `1.2.3` ->
/// `1.2.4`. `None` if `v` isn't exactly three numeric dot-separated components.
fn bump_patch(v: &str) -> Option<String> {
    let parts: Vec<&str> = v.split('.').collect();
    let [major, minor, patch] = parts[..] else {
        return None;
    };
    let all_numeric = [major, minor, patch]
        .iter()
        .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    let patch: u64 = patch.parse().ok()?;
    all_numeric.then(|| format!("{major}.{minor}.{}", patch + 1))
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

/// Recompute when HEAD moves, a tag is added, or the index changes. Watching the
/// git dir this way keeps the version fresh without rerunning on every build.
/// Caveat: a raw *unstaged* edit touches neither HEAD nor the index, so the
/// `.dirty` marker only refreshes on the next git operation (or source change).
fn emit_rerun_triggers() {
    // The version counter reads this in CI (see `ci_run_number`); recompute when
    // it changes so a rebuilt binary reports the run number it was built under.
    println!("cargo:rerun-if-env-changed=GITHUB_RUN_NUMBER");

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
