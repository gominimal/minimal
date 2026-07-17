use std::process::Command;
fn main() {
    // git may be unavailable (source tarball, a worktree whose .git is not
    // mounted inside a cross container): degrade to an empty hash rather than
    // panicking the build.
    let git_hash = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    println!("cargo:rustc-env=GIT_HASH={git_hash}");

    let is_clean = std::process::Command::new("git")
        .args(["status", "--porcelain=v1"])
        .output()
        .map(|o| o.stdout.is_empty())
        .unwrap_or(false);
    if !is_clean && std::env::var("PROFILE").unwrap() == "release" {
        println!("cargo::warning=Building a release binary from an unclean working tree!!");
        println!("cargo::warning=Always build production binaries from a clean checkout.");
    }

    let hash_suffix = if git_hash.is_empty() {
        String::new()
    } else {
        format!(" ({}{git_hash})", if is_clean { "" } else { "dirty " })
    };
    println!(
        "cargo:rustc-env=LONG_VERSION={}{hash_suffix}",
        std::env::var("CARGO_PKG_VERSION").unwrap().as_str(),
    );
}
