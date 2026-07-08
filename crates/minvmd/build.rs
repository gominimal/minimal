//! Build script for `minvmd`.
//!
//! Wires up the link search path and rpath for libkrun and emits the
//! `minvmd_libkrun` cfg that gates the real (libkrun-linking) implementation.
//! Without that cfg the crate compiles to a runtime-bailing stub and never
//! links libkrun.
//!
//! The rpath leads with a binary-relative entry (`$ORIGIN` / `@loader_path`) so
//! a relocated release binary prefers libkrun's shared objects shipped next to
//! it, and only then falls back to the absolute libkrun prefix. The prefix is
//! recorded except for a Linux `--release` build (its prefix is an ephemeral
//! build path that must not leak). A macOS release keeps the prefix because it
//! is the stable Homebrew lib dir (`/opt/homebrew/lib`), so a host that has
//! `brew install slp/krun/libkrun` but is missing the shipped dylib still
//! resolves libkrun. On Linux the standard system lib dirs ([`LINUX_LIB_DIRS`])
//! are added too, so a target with a system-installed libkrun resolves it
//! without bundling. See [`emit_rpaths`] for the full ordering.
//!
//! dyld only consults these rpaths for a load command that begins with
//! `@rpath/`. macOS links libkrun by its own (absolute Homebrew) install name,
//! so the release workflow rewrites minvmd's load command to
//! `@rpath/libkrun.1.dylib` with `install_name_tool` after the build — that is
//! what activates the `@loader_path`-first search above.
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
        emit_rpaths(&target_os, &prefix);
        println!("cargo::rustc-cfg=minvmd_libkrun");
    }
}

/// Record the runtime library search paths (rpath) baked into the binary. The
/// dynamic loader tries them in the order emitted here, so binary-relative comes
/// FIRST: a libkrun shipped next to the binary must win over any system or
/// Homebrew copy.
fn emit_rpaths(target_os: &str, prefix: &str) {
    let is_release = std::env::var("PROFILE").as_deref() == Ok("release");

    // 1. Binary-relative (`@loader_path` on macOS, `$ORIGIN` on Linux) — FIRST,
    //    so a RELOCATED binary prefers libkrun's shared objects shipped alongside
    //    it (e.g. the release-staged `bin/libkrun.1.dylib` next to minvmd). dyld
    //    honours this only for an `@rpath/...` load command; on macOS the release
    //    workflow rewrites minvmd's absolute Homebrew load command to
    //    `@rpath/libkrun.1.dylib` (install_name_tool) precisely so this entry
    //    takes effect. Reaches the linker as a literal argv token (no shell
    //    expansion here), so it is recorded verbatim.
    rpath(if target_os == "macos" {
        "@loader_path"
    } else {
        "$ORIGIN"
    });

    // 2. Absolute `{prefix}` — a FALLBACK consulted only when the binary-relative
    //    lookup above misses. Recorded EXCEPT for a Linux `--release` build:
    //   - Non-release (dev + every e2e CI run use `target/debug/minvmd`): resolve
    //     libkrun where it was materialized, no LD_LIBRARY_PATH needed.
    //   - macOS release: KEEP it. On Apple Silicon the prefix is the canonical
    //     Homebrew lib dir (`/opt/homebrew/lib`) — a stable system path identical
    //     on any target with `brew install slp/krun/libkrun`, so a host missing
    //     the shipped dylib still resolves libkrun. dyld consults this rpath when
    //     the load command is `@rpath/...` (see entry 1), and ignores it
    //     harmlessly when the install name is already absolute.
    //   - Linux release: DROP it — the prefix is an ephemeral build path (e.g.
    //     `$HOME/.krun`) that must not leak into the artifact; entries 1 and 3
    //     cover that binary instead.
    if !is_release || target_os == "macos" {
        rpath(prefix);
    }

    // 3. Standard system lib dirs on Linux — lets a target with a system-installed
    //    libkrun resolve it without bundling (the counterpart to macOS reusing the
    //    Homebrew prefix in entry 1). Stable absolute paths, so safe in a release
    //    artifact; nonexistent dirs are skipped by the loader.
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
