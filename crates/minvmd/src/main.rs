//! minvmd — macOS host broker. Brings up the Linux VM via krunkit; bridges UDS
//! traffic between `minimal` on the host and `minimald` inside the VM.
//! Not present on Linux installs.

// The broker is macOS-only, but the modules are gated to `macos` *or* `test` so
// the unit tests still compile and run on Linux CI. No production caller is
// wired into the dispatch yet, so the surface is dead on the plain bin build —
// hence the `allow(dead_code)` on the modules that would otherwise warn.
#[cfg(any(target_os = "macos", test))]
#[allow(dead_code)]
mod broker;
#[cfg(any(target_os = "macos", test))]
mod config;
#[cfg(any(target_os = "macos", test))]
#[allow(dead_code)]
mod debug_shell;
#[cfg(any(target_os = "macos", test))]
mod error;
#[cfg(any(target_os = "macos", test))]
mod image;
#[cfg(target_os = "macos")]
mod launchd;
#[cfg(any(target_os = "macos", test))]
#[allow(dead_code)]
mod lifecycle;
#[cfg(any(target_os = "macos", test))]
mod uds;

#[cfg(test)]
mod test_support;

// All CLI surface and command dispatch is macOS-only; it lives in one module so
// the platform gate appears once here rather than scattered across each item.
#[cfg(target_os = "macos")]
mod cli;

#[cfg(target_os = "macos")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    cli::run().await
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("minvmd: macOS-only; this binary is a no-op on this platform");
}
