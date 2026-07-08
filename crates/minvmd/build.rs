//! Build script for `minvmd`.
//!
//! Wires up the link search path and rpath for libkrun and emits the
//! `minvmd_libkrun` cfg that gates the real (libkrun-linking) implementation.
//! Without that cfg the crate compiles to a runtime-bailing stub and never
//! links libkrun.
//!
//! The rpath leads with a binary-relative entry (`$ORIGIN` / `@loader_path`) so a
//! relocated binary prefers libkrun shipped next to it, then falls back to the
//! absolute prefix. That prefix is recorded except on a Linux `--release` build,
//! whose prefix is an ephemeral path that must not leak; macOS keeps it (stable
//! `/opt/homebrew/lib`) and Linux adds [`LINUX_LIB_DIRS`]. See [`emit_rpaths`].
//!
//! dyld only consults these rpaths for an `@rpath/` load command. macOS links
//! libkrun by its absolute Homebrew install name, so the release workflow
//! rewrites minvmd's load command to `@rpath/libkrun.1.dylib` post-build.
//!
//! Gated behind the `libkrun` cargo feature (ON by default). With it OFF every
//! target builds the stub and links nothing — how the `minimal` CLI depends on
//! this crate (`default-features = false`) without inheriting libkrun's `#[link]`
//! load command. Per-platform behaviour below applies only with the feature on:
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

/// Standard system directories that may hold `libkrun.so` on Linux. Used both to
/// detect libkrun at build time (`find_libkrun_prefix`) and to seed a release
/// binary's rpath, so a target with a system-installed libkrun resolves it (and
/// its `libkrunfw.so.5` sibling, via the loader's default search) without any
/// bundling. Entries that don't exist on a given host are skipped harmlessly by
/// both the build-time scan and the runtime loader.
const LINUX_LIB_DIRS: &[&str] = &[
    "/usr/local/lib",
    "/usr/lib",
    "/usr/lib64",
    "/usr/lib/x86_64-linux-gnu",
    "/usr/lib/aarch64-linux-gnu",
];

fn main() {
    println!("cargo:rerun-if-env-changed=LIBKRUN_PREFIX");
    // Declared so `#[cfg(minvmd_libkrun)]` does not trip the unexpected-cfgs
    // lint under `-D warnings`.
    println!("cargo::rustc-check-cfg=cfg(minvmd_libkrun)");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    // Real backend is opt-in via the `libkrun` feature (default on; the `minimal`
    // CLI opts out). Off => stub, and no dependent binary inherits libkrun's
    // `#[link]`. Cargo reruns build scripts on feature changes automatically.
    let want_libkrun = std::env::var_os("CARGO_FEATURE_LIBKRUN").is_some();

    let prefix = want_libkrun
        .then(|| match target_os.as_str() {
            // macOS: the only VM backend on the platform; always present.
            "macos" => {
                Some(std::env::var("LIBKRUN_PREFIX").unwrap_or_else(|_| "/opt/homebrew/lib".into()))
            }
            // Linux: link only when found, else stub (e.g. stock Ubuntu CI).
            "linux" => find_libkrun_prefix(),
            _ => None,
        })
        .flatten();

    if let Some(prefix) = prefix {
        println!("cargo:rustc-link-search=native={prefix}");
        emit_rpaths(&target_os, &prefix);
        println!("cargo::rustc-cfg=minvmd_libkrun");
    }
}

/// Runtime library search paths (rpath) baked into the binary, in the order dyld
/// tries them — binary-relative FIRST, so a libkrun shipped next to the binary
/// wins over any system or Homebrew copy.
fn emit_rpaths(target_os: &str, prefix: &str) {
    let is_release = std::env::var("PROFILE").as_deref() == Ok("release");

    // 1. Binary-relative: finds a libkrun shipped alongside a relocated binary
    //    (e.g. a dev build with the dylib next to it). dyld honours it only for an
    //    `@rpath/` load command — the macOS release rewrites minvmd's to that. The
    //    macOS *release* stages the dylib in a `lib/` sibling of `bin/` and
    //    retargets this very entry to `@loader_path/../lib` post-build (see
    //    release.yml), so the same rpath covers the dev layout here and the ship
    //    layout there. Recorded verbatim (literal argv token, no shell expansion).
    rpath(if target_os == "macos" {
        "@loader_path"
    } else {
        "$ORIGIN"
    });

    // 2. Absolute {prefix}: fallback when entry 1 misses. Dropped on a Linux
    //    --release build (ephemeral path, must not leak); kept for dev (resolve
    //    where materialized) and macOS release (stable /opt/homebrew/lib).
    if !is_release || target_os == "macos" {
        rpath(prefix);
    }

    // 3. Linux system lib dirs: resolve a system-installed libkrun without
    //    bundling. Stable paths; nonexistent ones are skipped by the loader.
    if target_os == "linux" {
        LINUX_LIB_DIRS.iter().for_each(|dir| rpath(dir));
    }
}

/// Emit a single rpath entry via the linker.
fn rpath(path: &str) {
    println!("cargo:rustc-link-arg=-Wl,-rpath,{path}");
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

    LINUX_LIB_DIRS
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
