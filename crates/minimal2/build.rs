use std::process::Command;
fn main() {
    let output = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .unwrap();
    let git_hash = String::from_utf8(output.stdout).unwrap();
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
        git_hash.strip_suffix("\n").unwrap(),
    );
}
