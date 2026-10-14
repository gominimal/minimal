//! Shared version identity for the minimal binaries (`min`, `mip`, `minimald`,
//! `minvmd`), derived at build time so all four report one version: the
//! `MINIMAL_RELEASE_VERSION` override for release builds, otherwise `git
//! describe` against `v*` tags on top of the workspace `package.version`. See
//! `scheme.rs` for the exact scheme and `build.rs` for how its inputs are read.

/// Compact version — a SemVer string such as `0.5.4` or `0.6.0-dev.10.g8e7e72c2`,
/// or the crate's Cargo version when no `v*` tag is reachable. Shown by `-V`.
pub const VERSION: &str = env!("MINIMAL_VERSION");

/// Verbose version shown by `--version`; carries the commit id for untagged dev
/// builds. Equal to [`VERSION`] once a `v*` tag is reachable.
pub const LONG_VERSION: &str = env!("MINIMAL_LONG_VERSION");

// The derivation is compiled into the build script (`build.rs` includes the
// same file); here it exists only so its unit tests run under `cargo test`.
#[cfg(test)]
mod scheme;
