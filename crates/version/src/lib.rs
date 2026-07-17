//! Shared version identity for the minimal binaries (`min`, `mip`, `minimald`,
//! `minvmd`), derived at build time from `git describe` against `v*` tags so all
//! four report one version. See `build.rs` for the exact scheme.

/// Compact version — a SemVer string such as `1.2.3` or `1.2.4-dev.5.g86ce5c3a`,
/// or the crate's Cargo version when no `v*` tag is reachable. Shown by `-V`.
pub const VERSION: &str = env!("MINIMAL_VERSION");

/// Verbose version shown by `--version`; carries the commit id for untagged dev
/// builds. Equal to [`VERSION`] once a `v*` tag is reachable.
pub const LONG_VERSION: &str = env!("MINIMAL_LONG_VERSION");
