use std::process::Command;
fn main() {
    // Tolerate non-git contexts (sandboxed builds see a worktree whose gitfile
    // points at an unreachable host path; release channels build from tarballs):
    // fall back to "unknown" instead of panicking.
    let git_hash = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=GIT_HASH={}", git_hash);

    let is_clean = std::process::Command::new("git")
        .args(["status", "--porcelain=v1"])
        .output()
        .map(|o| o.stdout.is_empty())
        .unwrap_or(false);
    if !is_clean && std::env::var("PROFILE").unwrap() == "release" {
        println!("cargo::warning=Building a release binary from an unclean working tree!!");
        println!("cargo::warning=Always build production binaries from a clean checkout.");
    }

    println!(
        "cargo:rustc-env=LONG_VERSION={} ({}{})",
        std::env::var("CARGO_PKG_VERSION").unwrap().as_str(),
        if is_clean { "" } else { "dirty " },
        git_hash,
    );
}
