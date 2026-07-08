//! Package-level [`Composable`] implementation.
//!
//! [`PackageComposable`] materializes the runtime env contribution a
//! single package injects — one item per entry in the package's
//! `env_state_wiring` attr — tagging each with
//! [`Source::Package`] carrying the package name.
//!
//! Where a project's [`ProjectComposable`] contributes what the
//! codebase says every developer needs, a package composable
//! contributes what a *dependency* says it needs to run (e.g. Go
//! packages inject `GOCACHE`, npm packages inject `NPM_CONFIG_CACHE`,
//! etc.). One is authored on the developer's side; the other is
//! authored by whoever ships the package.
//!
//! # Scope
//!
//! Reads three attrs off a package's `BuildSpec.attrs`:
//! - `env_state_wiring` → one var per entry, value
//!   `/state/<prefix>`.
//! - `env_dir_mappings` and `env_file_mappings` → one patch per
//!   entry (source == dest == the `path` field). Since minimal is
//!   copy-based, both attrs collapse into the same [`Patch`]
//!   primitive; the dir-vs-file distinction is irrelevant at the
//!   composition layer.
//!
//! `class = 'Credential` entries on either mapping attr are
//! **dropped** by the extractor; the future secrets strategy will
//! route them through a separate path. `read_only` is discarded
//! (no meaning under copy semantics). `class = 'State` entries
//! flow through unchanged as regular patches, gate-able via
//! [`PatchPolicy`].
//!
//! [`Composable`]: sessions::core::compose::Composable
//! [`Source::Package`]: sessions::core::source::Source::Package
//! [`ProjectComposable`]: crate::ProjectComposable
//! [`Patch`]: sessions::core::primitives::Patch
//! [`PatchPolicy`]: sessions::core::policy::PatchPolicy

use sessions::core::compose::{Composable, Contribution, Error};
use sessions::core::primitives::{Patch, PatchDest, ResolvedVar, VarValue};
use sessions::core::source::{ProvenancedPatch, ProvenancedVar, Source};

/// One `env_state_wiring` entry: an env var the package wants
/// pointed at a `/state/<prefix>` directory in the sandbox.
///
/// Mirrors the shape read by `graph::env_setup::SetupForPackages`
/// out of `BuildSpec.attrs.env_state_wiring`; the extraction from
/// a `decode::AttrValue` map lives at the call site (in the crate
/// that owns the graph), keeping `mfile` free of a
/// `graph`/`decode` dep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateWiring {
    /// The env var name to set inside the session.
    pub env_var: String,
    /// The subdirectory under `/state` this var should point at.
    /// The composed value is `/state/<prefix>` verbatim.
    pub prefix: String,
}

/// The runtime-env contribution of a single package, ready to feed
/// [`SessionComposer::add`]. One [`PackageComposable`] per package
/// in the transitive closure that has at least one non-empty
/// contribution field.
///
/// The `package_name` identifies the source in provenance
/// ([`Source::Package`]); `state_wiring` produces env vars, and
/// `fs_mapping_paths` produces patches (copy-shape, source == dest).
/// Each entry in `fs_mapping_paths` is a single path used verbatim
/// as both the host-side source and the sandbox-home-relative
/// destination; extraction from
/// `BuildSpec.attrs.env_dir_mappings` / `env_file_mappings` lives
/// at the call site (the crate that owns the graph), which is
/// also responsible for dropping `class = 'Credential` entries
/// per the future-secrets deferral. Directory vs file distinction
/// is irrelevant at the composition layer — both flatten to a
/// single copy patch.
///
/// [`SessionComposer::add`]: sessions::daemon::composer::SessionComposer::add
/// [`Source::Package`]: sessions::core::source::Source::Package
#[derive(Debug, Clone)]
pub struct PackageComposable {
    package_name: String,
    state_wiring: Vec<StateWiring>,
    fs_mapping_paths: Vec<String>,
}

impl PackageComposable {
    /// Build a package composable from a package name and its
    /// extracted runtime-env attr entries. The caller is
    /// responsible for reading these off `BuildSpec.attrs` (and
    /// dropping `class = 'Credential` mappings) — this type stays
    /// graph-agnostic.
    ///
    /// `fs_mappings` is a list of paths, each used verbatim as
    /// both host source and sandbox-home-relative destination.
    #[must_use]
    pub fn new(
        package_name: impl Into<String>,
        state_wiring: Vec<StateWiring>,
        fs_mappings: Vec<String>,
    ) -> Self {
        Self {
            package_name: package_name.into(),
            state_wiring,
            fs_mapping_paths: fs_mappings,
        }
    }

    /// The package's name (as it appears in the graph). Exposed so
    /// callers routing package composables into the session
    /// composer can log/report which package produced which item.
    #[must_use]
    pub fn package_name(&self) -> &str {
        &self.package_name
    }
}

impl Composable for PackageComposable {
    /// Materialize the package's runtime-env contribution: one
    /// [`ProvenancedVar`] per state-wiring entry (value
    /// `/state/<prefix>`) and one [`ProvenancedPatch`] per
    /// fs-mapping entry (source == dest == the mapping's `path`).
    /// Every produced item is tagged [`Source::Package`] carrying
    /// the package name. The `env` closure is unused — vars are
    /// [`VarValue::Specified`], and patch sources aren't resolved
    /// at contribution time.
    ///
    /// # Errors
    ///
    /// Returns a [`Composable::Error`] if a mapping's `path` fails
    /// [`PatchDest`]'s validation (empty, contains `..`, etc.) —
    /// treated as a package-declaration bug that should surface
    /// loudly rather than dropping the entry silently.
    ///
    /// [`Source::Package`]: sessions::core::source::Source::Package
    /// [`VarValue::Specified`]: sessions::core::primitives::VarValue::Specified
    fn contribute(
        self,
        _env: &dyn Fn(&str) -> Result<String, std::env::VarError>,
    ) -> Result<Contribution, Error> {
        let source = Source::Package {
            name: self.package_name,
        };
        let mut c = Contribution::new();
        for StateWiring { env_var, prefix } in self.state_wiring {
            // /state/<prefix> — matches the format
            // SetupForPackages::build writes today at
            // crates/graph/src/env_setup.rs.
            let value = format!("/state/{prefix}");
            // `resolve_with` short-circuits for `Specified`, so the
            // env closure is never consulted; a pass-through no-op
            // is safe.
            let resolved = ResolvedVar::resolve_with(env_var, VarValue::specified(value), |_| {
                Err(std::env::VarError::NotPresent)
            })?;
            c.push_var(ProvenancedVar::new(resolved, source.clone()));
        }
        for path in self.fs_mapping_paths {
            let dest = PatchDest::try_new(&path)?;
            c.push_patch(ProvenancedPatch::new(
                Patch::new(path, dest),
                source.clone(),
            ));
        }
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sessions::core::source::Provenanced;

    /// A package whose attrs declare `env_state_wiring` for GOCACHE +
    /// GOMODCACHE contributes two vars, each pointed at the
    /// corresponding `/state/<prefix>` path, tagged with the
    /// package's name in provenance.
    #[test]
    fn contribute_maps_state_wiring_to_slash_state_vars() {
        let comp = PackageComposable::new(
            "go",
            vec![
                StateWiring {
                    env_var: "GOCACHE".into(),
                    prefix: "gocache".into(),
                },
                StateWiring {
                    env_var: "GOMODCACHE".into(),
                    prefix: "gomodcache".into(),
                },
            ],
            Vec::new(),
        );

        // env closure is never consulted for Specified-shaped vars —
        // pass a poisoned lookup that would fail loudly if it were.
        let env = |_: &str| Err(std::env::VarError::NotPresent);
        let contribution = comp.contribute(&env).expect("contribute succeeds");

        assert_eq!(contribution.vars().len(), 2);
        let expected_source = Source::Package { name: "go".into() };

        let by_name: std::collections::HashMap<_, _> = contribution
            .vars()
            .iter()
            .map(|pv| (pv.var().name(), pv.var().value()))
            .collect();
        assert_eq!(by_name.get("GOCACHE").copied(), Some("/state/gocache"));
        assert_eq!(
            by_name.get("GOMODCACHE").copied(),
            Some("/state/gomodcache")
        );
        for pv in contribution.vars() {
            assert_eq!(pv.source(), &expected_source);
        }
    }

    /// A package with no runtime-env entries contributes an empty
    /// [`Contribution`]. Guards the closure-time walk against a
    /// panic when a package doesn't set any of the three attrs —
    /// the common case, since most packages contribute nothing.
    #[test]
    fn no_state_wiring_yields_empty_contribution() {
        let comp = PackageComposable::new("bash", vec![], vec![]);
        let env = |_: &str| Err(std::env::VarError::NotPresent);
        let contribution = comp.contribute(&env).expect("contribute succeeds");
        assert!(contribution.is_empty());
    }

    /// A package whose attrs declare `env_dir_mappings` or
    /// `env_file_mappings` (post credential-filter) contributes
    /// patches where `source == dest == path`, tagged with the
    /// package's name.
    #[test]
    fn contribute_maps_fs_mappings_to_patches() {
        let comp = PackageComposable::new(
            "claude-code",
            Vec::new(),
            vec![
                "~/.claude".to_string(),
                "~/.config/claude/settings.json".to_string(),
            ],
        );
        let env = |_: &str| Err(std::env::VarError::NotPresent);
        let contribution = comp.contribute(&env).expect("contribute succeeds");

        assert_eq!(contribution.patches().len(), 2);
        assert!(contribution.vars().is_empty());
        let sources: std::collections::BTreeSet<&str> = contribution
            .patches()
            .iter()
            .map(|pp| pp.patch().source())
            .collect();
        assert!(sources.contains("~/.claude"));
        assert!(sources.contains("~/.config/claude/settings.json"));
        let expected_source = Source::Package {
            name: "claude-code".into(),
        };
        for pp in contribution.patches() {
            assert_eq!(pp.source(), &expected_source);
            assert_eq!(
                pp.patch().source(),
                pp.patch().dest().as_sandbox_path().as_str(),
                "package fs_mappings should have source == dest",
            );
        }
    }

    /// Package composables that share an env-var name but disagree
    /// on the resolved value are *not* rejected by `contribute` on
    /// its own — the conflict check runs post-gate in the composer
    /// pipeline. This test documents the boundary: `contribute` is
    /// pure per-source materialization, cross-source disagreement
    /// isn't its job.
    #[test]
    fn contribute_does_not_check_cross_source_conflicts() {
        // Two independent composables both name GOCACHE, but the
        // point of the test is that each *individually* materializes
        // without complaint. The composer will surface any conflict
        // between them.
        let a = PackageComposable::new(
            "go",
            vec![StateWiring {
                env_var: "GOCACHE".into(),
                prefix: "gocache".into(),
            }],
            Vec::new(),
        );
        let b = PackageComposable::new(
            "go2",
            vec![StateWiring {
                env_var: "GOCACHE".into(),
                prefix: "different".into(),
            }],
            Vec::new(),
        );
        let env = |_: &str| Err(std::env::VarError::NotPresent);
        assert!(a.contribute(&env).is_ok());
        assert!(b.contribute(&env).is_ok());
    }
}
