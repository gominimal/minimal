//! The version derivation shared by `build.rs` and the unit tests.
//!
//! `build.rs` includes this file textually (`#[path]`), and `lib.rs` compiles
//! it only under `cfg(test)`, so the pure logic is unit-testable while the
//! build script stays dependency-free and the shipped crate carries none of it.
//!
//! Precedence, highest first:
//!
//! 1. `MINIMAL_RELEASE_VERSION`, when set: the release version, verbatim. A
//!    release build on an untagged commit reports `0.6.0`, not
//!    `0.6.0-dev.7.g<hash>`, so the release tag can be cut *after* the build
//!    has been staged and smoked instead of before it. It must equal the
//!    workspace `package.version`; a mismatch fails the build rather than
//!    shipping a binary that disagrees with its own Cargo metadata.
//! 2. `git describe` against `v*` tags, with `package.version` as the base of
//!    every dev build. `package.version` is the *declared* next release
//!    (linted against the commits since the last tag by
//!    `scripts/next-version.sh --check`), so `git describe` supplies only the
//!    commit count and hash:
//!    - HEAD is exactly `v0.5.4`                    -> `0.5.4`
//!    - N commits past `v0.5.4`, declared `0.6.0`   -> `0.6.0-dev.N.g<hash>`
//!    - N commits past `v0.6.0-rc1`, declared `0.6.0` -> `0.6.0-rc1.dev.N.g<hash>`
//!    - declared `0.6.0-rc2`, N commits past any tag -> `0.6.0-rc2.dev.N.g<hash>`
//! 3. No `v*` tag reachable, or no git: `package.version` (the long form still
//!    carries the commit id when git is available).
//!
//! A dirty working tree appends `+dirty` build metadata in every case, the
//! release override included: the marker is how a binary built off an
//! unclean tree admits it.
//!
//! Commits past a release are encoded as a **pre-release** (`-dev.<N>.g<hash>`),
//! not build metadata, so they order correctly under SemVer 2.0: a build N
//! commits past `v0.5.4` sorts ABOVE `0.5.4` and BELOW the declared next
//! release. Build metadata (anything after `+`) would instead be ignored in
//! precedence, making every post-release build compare equal to the release.
//! `<N>` is a numeric pre-release identifier, so more commits => higher
//! version. Extending a pre-release tag (`0.6.0-rc1.dev.N`) keeps a build past
//! `v0.6.0-rc1` above that tag and below `0.6.0`; a plain `0.6.0-dev.N` would
//! sort below `0.6.0-rc1` (`dev` < `rc`).

/// What `build.rs` gathers from the environment and git.
pub struct Inputs<'a> {
    /// `MINIMAL_RELEASE_VERSION`, when set and non-empty.
    pub release_version: Option<&'a str>,
    /// `CARGO_PKG_VERSION`: the workspace `package.version`, the declared next
    /// release and the fallback when git cannot answer.
    pub cargo_version: &'a str,
    /// `git describe --tags --match 'v*'` output, when a tag is reachable.
    pub describe: Option<&'a str>,
    /// Short HEAD hash, when git is available.
    pub short_hash: Option<&'a str>,
    /// `Some(true)`/`Some(false)` when git is available, `None` when it isn't.
    pub dirty: Option<bool>,
}

/// The two strings the binaries report: `-V` and `--version`.
#[derive(Debug)]
pub struct Derived {
    pub version: String,
    pub long_version: String,
}

/// Derive the version strings; `Err` carries a build-failing message.
pub fn derive(inputs: &Inputs<'_>) -> Result<Derived, String> {
    let dirty = inputs.dirty == Some(true);

    if let Some(release) = inputs.release_version {
        if release != inputs.cargo_version {
            return Err(format!(
                "MINIMAL_RELEASE_VERSION={release} does not match the workspace \
                 package.version {} — bump Cargo.toml (scripts/next-version.sh --check \
                 says which version the commits since the last tag require) or fix \
                 the override; a release binary must not disagree with its Cargo metadata",
                inputs.cargo_version
            ));
        }
        let version = with_dirty(release.to_string(), dirty);
        return Ok(Derived {
            long_version: version.clone(),
            version,
        });
    }

    if let Some(describe) = inputs.describe {
        let version = to_semver(describe, inputs.cargo_version, dirty);
        return Ok(Derived {
            long_version: version.clone(),
            version,
        });
    }

    // No v* tag reachable (or no git): the version is just the Cargo version.
    // The long form still carries the commit id when git is available, so a
    // dev build off an untagged tree stays identifiable.
    let cargo_version = inputs.cargo_version.to_string();
    let long_version = match (inputs.short_hash, inputs.dirty) {
        (Some(hash), Some(d)) => {
            format!("{cargo_version} ({}{hash})", if d { "dirty " } else { "" })
        }
        _ => cargo_version.clone(),
    };
    Ok(Derived {
        version: cargo_version,
        long_version,
    })
}

/// Turn `git describe --tags --match 'v*'` output into a SemVer string that
/// orders correctly (see the module docs), with `declared` (the workspace
/// `package.version`) as the base of a dev build.
///
/// - `v0.5.4`                            -> `0.5.4`
/// - `v0.5.4-5-g86ce5c3a`, declared `0.6.0`     -> `0.6.0-dev.5.g86ce5c3a`
/// - `v0.6.0-rc1-5-gabc123`, declared `0.6.0`   -> `0.6.0-rc1.dev.5.gabc123`
/// - `v0.5.4-5-gabc123`, declared `0.6.0-rc2`   -> `0.6.0-rc2.dev.5.gabc123`
///
/// Shapes that don't match the `-<count>-g<hash>` describe suffix (a tag
/// sitting exactly on HEAD) pass through verbatim, declared version ignored.
fn to_semver(describe: &str, declared: &str, dirty: bool) -> String {
    let core = describe.strip_prefix('v').unwrap_or(describe);
    let out = match core.rsplitn(3, '-').collect::<Vec<_>>()[..] {
        [hash, count, base]
            if count.bytes().all(|b| b.is_ascii_digit())
                && hash
                    .strip_prefix('g')
                    .is_some_and(|h| !h.is_empty() && h.bytes().all(|b| b.is_ascii_hexdigit())) =>
        {
            // A dev build `count` commits past tag `base`, heading toward the
            // declared version. Encode as a pre-release so it sorts above the
            // tag and below the declared release.
            if declared.contains('-') {
                // The declared version is itself a pre-release (`0.6.0-rc2`):
                // extend it, so `0.6.0-rc2.dev.N` > `0.6.0-rc1` and < `0.6.0-rc2`.
                format!("{declared}.dev.{count}.{hash}")
            } else if base.contains('-') && semver_core(base) == declared {
                // Past a pre-release tag of the declared version (`v0.6.0-rc1`
                // toward `0.6.0`): extend the tag, so the build stays above it.
                format!("{base}.dev.{count}.{hash}")
            } else {
                format!("{declared}-dev.{count}.{hash}")
            }
        }
        _ => core.to_string(),
    };
    with_dirty(out, dirty)
}

/// `0.6.0-rc1` -> `0.6.0`: the version core, pre-release and build metadata
/// stripped.
fn semver_core(v: &str) -> &str {
    let v = v.split('+').next().unwrap_or(v);
    v.split('-').next().unwrap_or(v)
}

/// Append the `+dirty` build-metadata marker. Pre-release uses `-`, so build
/// metadata always starts a fresh `+` group.
fn with_dirty(mut v: String, dirty: bool) -> String {
    if dirty {
        v.push_str("+dirty");
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs<'a>(
        release_version: Option<&'a str>,
        cargo_version: &'a str,
        describe: Option<&'a str>,
        dirty: Option<bool>,
    ) -> Inputs<'a> {
        Inputs {
            release_version,
            cargo_version,
            describe,
            short_hash: Some("8e7e72c2"),
            dirty,
        }
    }

    fn version(i: &Inputs<'_>) -> String {
        derive(i).expect("derives").version
    }

    #[test]
    fn release_override_wins_over_describe() {
        let d = derive(&inputs(
            Some("0.6.0"),
            "0.6.0",
            Some("v0.5.4-10-g8e7e72c2"),
            Some(false),
        ))
        .expect("derives");
        assert_eq!(d.version, "0.6.0");
        assert_eq!(d.long_version, "0.6.0");
    }

    #[test]
    fn release_override_must_match_package_version() {
        let err = derive(&inputs(Some("0.6.0"), "0.5.5", None, Some(false))).unwrap_err();
        assert!(err.contains("MINIMAL_RELEASE_VERSION=0.6.0"), "{err}");
        assert!(err.contains("package.version 0.5.5"), "{err}");
    }

    #[test]
    fn release_override_keeps_the_dirty_marker() {
        assert_eq!(
            version(&inputs(
                Some("0.6.0"),
                "0.6.0",
                Some("v0.5.4-10-g8e7e72c2"),
                Some(true)
            )),
            "0.6.0+dirty"
        );
    }

    #[test]
    fn exact_tag_passes_through_stripped_of_v() {
        assert_eq!(
            version(&inputs(None, "0.5.4", Some("v0.5.4"), Some(false))),
            "0.5.4"
        );
        // The declared version is ignored on an exact tag: the tag is the truth.
        assert_eq!(
            version(&inputs(None, "0.6.0", Some("v0.5.4"), Some(false))),
            "0.5.4"
        );
        assert_eq!(
            version(&inputs(None, "0.6.0-rc1", Some("v0.6.0-rc1"), Some(false))),
            "0.6.0-rc1"
        );
    }

    #[test]
    fn dev_build_uses_the_declared_version_not_a_patch_bump() {
        assert_eq!(
            version(&inputs(
                None,
                "0.6.0",
                Some("v0.5.4-10-g8e7e72c2"),
                Some(false)
            )),
            "0.6.0-dev.10.g8e7e72c2"
        );
        assert_eq!(
            version(&inputs(
                None,
                "0.5.5",
                Some("v0.5.4-10-g8e7e72c2"),
                Some(false)
            )),
            "0.5.5-dev.10.g8e7e72c2"
        );
    }

    #[test]
    fn dev_build_past_a_prerelease_tag_of_the_declared_version_extends_the_tag() {
        // `0.6.0-rc1.dev.3` > `0.6.0-rc1` and < `0.6.0`; a plain `0.6.0-dev.3`
        // would sort below the rc.
        assert_eq!(
            version(&inputs(
                None,
                "0.6.0",
                Some("v0.6.0-rc1-3-gabc123"),
                Some(false)
            )),
            "0.6.0-rc1.dev.3.gabc123"
        );
        // A pre-release tag of an OLDER version is just a tag: dev off the declared.
        assert_eq!(
            version(&inputs(
                None,
                "0.6.0",
                Some("v0.5.1-rc1-3-gabc123"),
                Some(false)
            )),
            "0.6.0-dev.3.gabc123"
        );
    }

    #[test]
    fn dev_build_toward_a_declared_prerelease_extends_the_declared_version() {
        assert_eq!(
            version(&inputs(
                None,
                "0.6.0-rc2",
                Some("v0.6.0-rc1-3-gabc123"),
                Some(false)
            )),
            "0.6.0-rc2.dev.3.gabc123"
        );
    }

    #[test]
    fn dirty_tree_appends_build_metadata() {
        assert_eq!(
            version(&inputs(
                None,
                "0.6.0",
                Some("v0.5.4-10-g8e7e72c2"),
                Some(true)
            )),
            "0.6.0-dev.10.g8e7e72c2+dirty"
        );
        assert_eq!(
            version(&inputs(None, "0.5.4", Some("v0.5.4"), Some(true))),
            "0.5.4+dirty"
        );
    }

    #[test]
    fn describe_without_the_count_hash_suffix_passes_through() {
        // Not a `-<count>-g<hash>` tail: no commit count, hash not hex.
        assert_eq!(
            version(&inputs(None, "0.6.0", Some("v0.5.4-x-gzzz"), Some(false))),
            "0.5.4-x-gzzz"
        );
    }

    #[test]
    fn no_tag_falls_back_to_the_package_version() {
        let d = derive(&inputs(None, "0.6.0", None, Some(false))).expect("derives");
        assert_eq!(d.version, "0.6.0");
        assert_eq!(d.long_version, "0.6.0 (8e7e72c2)");

        let d = derive(&inputs(None, "0.6.0", None, Some(true))).expect("derives");
        assert_eq!(d.version, "0.6.0");
        assert_eq!(d.long_version, "0.6.0 (dirty 8e7e72c2)");

        // No git at all: nothing to add to the long form.
        let d = derive(&Inputs {
            release_version: None,
            cargo_version: "0.6.0",
            describe: None,
            short_hash: None,
            dirty: None,
        })
        .expect("derives");
        assert_eq!(d.version, "0.6.0");
        assert_eq!(d.long_version, "0.6.0");
    }
}
