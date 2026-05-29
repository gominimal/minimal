//! Local test helpers.
//!
//! minvmd's tests need an isolated `MINIMAL_HOME` and serial execution; the few
//! pieces they use are inlined here rather than pulled from a shared crate,
//! compiled only under `cfg(test)`.

#![cfg(test)]

use std::path::Path;
use std::sync::Mutex;
use tempfile::TempDir;

/// Re-export so test modules can write `test_support::serial_test::serial`.
pub use serial_test;

/// Serialises any access to process-wide state (env vars, on-disk caches).
static STATE_MUTEX: Mutex<()> = Mutex::new(());

/// Run `f` with `MINIMAL_HOME` pointed at a fresh tempdir. The directory is
/// removed on return; the env var is restored to its previous value.
pub fn with_isolated_home<F: FnOnce(&Path)>(f: F) {
    let _guard = STATE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = TempDir::new().expect("tempdir");
    let prev = std::env::var_os("MINIMAL_HOME");

    // SAFETY: `set_var`/`remove_var` are race-y across threads. The static
    // mutex above serialises all callers within this process.
    unsafe {
        std::env::set_var("MINIMAL_HOME", tmp.path());
    }

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(tmp.path())));

    unsafe {
        match prev {
            Some(v) => std::env::set_var("MINIMAL_HOME", v),
            None => std::env::remove_var("MINIMAL_HOME"),
        }
    }

    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}
