//! Build script for `minvmd`.
//!
//! On macOS, wires up the link search path and rpath for libkrun. The libkrun
//! prefix defaults to `/opt/homebrew/lib` (the Homebrew tap install location
//! used by `~/code/min-ctl`); override with the `LIBKRUN_PREFIX` env var.
//!
//! On Linux this is a no-op — the crate compiles to a runtime-bailing stub
//! per R1.1 and never links libkrun.

fn main() {
    println!("cargo:rerun-if-env-changed=LIBKRUN_PREFIX");

    if std::env::var_os("CARGO_CFG_TARGET_OS").as_deref() != Some("macos".as_ref()) {
        return;
    }

    let prefix =
        std::env::var("LIBKRUN_PREFIX").unwrap_or_else(|_| "/opt/homebrew/lib".to_string());
    println!("cargo:rustc-link-search=native={prefix}");
    println!("cargo:rustc-link-arg=-Wl,-rpath,{prefix}");
}
