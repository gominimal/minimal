//! Build script for `minvmd`.
//!
//! Wires up the link search path and rpath for libkrun and emits the
//! `minvmd_libkrun` cfg that gates the real (libkrun-linking) implementation.
//! Without that cfg the crate compiles to a runtime-bailing stub and never
//! links libkrun.
//!
//! - **macOS**: libkrun is always linked (Hypervisor.framework backend). The
//!   prefix defaults to `/opt/homebrew/lib` (the Homebrew tap install location);
//!   override with `LIBKRUN_PREFIX`.
//! - **Linux**: libkrun (KVM backend) is linked only when it is actually present
//!   — detected via `LIBKRUN_PREFIX` or a scan of the usual library dirs. Stock
//!   Linux CI without libkrun installed therefore still builds the stub, so the
//!   Linux-only workflow stays green; a Linux host *with* libkrun builds the
//!   real implementation with a plain `cargo build -p minvmd`.
//! - **Other targets**: stub only; never links libkrun.

use std::path::Path;

fn main() {
    println!("cargo:rerun-if-env-changed=LIBKRUN_PREFIX");
    // Declared so `#[cfg(minvmd_libkrun)]` does not trip the unexpected-cfgs
    // lint under `-D warnings`.
    println!("cargo::rustc-check-cfg=cfg(minvmd_libkrun)");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    let prefix = match target_os.as_str() {
        // macOS always links libkrun: it is the only VM backend on the platform
        // and the existing proof artifacts assume it is provisioned.
        "macos" => Some(
            std::env::var("LIBKRUN_PREFIX").unwrap_or_else(|_| "/opt/homebrew/lib".to_string()),
        ),
        // Linux links libkrun only when it can be found, so a host without it
        // (e.g. the stock Ubuntu CI runners) still builds the no-op stub.
        "linux" => find_libkrun_prefix(),
        _ => None,
    };

    if let Some(prefix) = prefix {
        println!("cargo:rustc-link-search=native={prefix}");
        println!("cargo:rustc-link-arg=-Wl,-rpath,{prefix}");
        println!("cargo::rustc-cfg=minvmd_libkrun");
    }
}

/// Locate the directory holding `libkrun.so` on Linux.
///
/// Honours `LIBKRUN_PREFIX` first (set it when libkrun lives outside the
/// standard search dirs), then scans the usual locations. Returns `None` when
/// libkrun is not installed, which selects the stub build.
fn find_libkrun_prefix() -> Option<String> {
    if let Ok(prefix) = std::env::var("LIBKRUN_PREFIX")
        && !prefix.is_empty()
    {
        return Some(prefix);
    }

    const CANDIDATES: &[&str] = &[
        "/usr/local/lib",
        "/usr/lib",
        "/usr/lib64",
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib/aarch64-linux-gnu",
    ];

    CANDIDATES
        .iter()
        .find(|dir| dir_has_libkrun(dir))
        .map(|dir| (*dir).to_string())
}

/// True when `dir` contains a `libkrun.so*` file (the bare `.so` link or a
/// versioned soname such as `libkrun.so.1`).
fn dir_has_libkrun(dir: &str) -> bool {
    let Ok(entries) = std::fs::read_dir(Path::new(dir)) else {
        return false;
    };
    entries.filter_map(Result::ok).any(|entry| {
        entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with("libkrun.so"))
    })
}
