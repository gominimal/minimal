//! Project-level [`Composable`] implementation.
//!
//! [`ProjectComposable`] pairs a project's [`Session`] block with its
//! project path, tagging every primitive it produces with
//! [`Source::Project`]. Mirrors [`Loadout`]'s materialization
//! exactly — the only difference is provenance and the absence of a
//! per-block name.
//!
//! [`Session`]: crate::Session
//! [`Composable`]: sessions::core::compose::Composable
//! [`Source::Project`]: sessions::core::source::Source::Project
//! [`Loadout`]: sessions::core::loadout::Loadout

use paths::HostPath;
use sessions::core::compose::{Composable, Contribution, Error, contribute_primitives};
use sessions::core::source::Source;

use crate::Session;

/// A project's `[session]` block paired with its project path,
/// ready to feed [`SessionComposer::add`] on the daemon side.
///
/// The `project_path` is only used to build the
/// [`Source::Project`] provenance tag; the `session` carries the
/// actual primitives.
///
/// [`SessionComposer::add`]: sessions::daemon::composer::SessionComposer::add
/// [`Source::Project`]: sessions::core::source::Source::Project
#[derive(Debug, Clone)]
pub struct ProjectComposable {
    project_path: HostPath,
    session: Session,
}

impl ProjectComposable {
    /// Pair a session block with its project path.
    #[must_use]
    pub fn new(project_path: HostPath, session: Session) -> Self {
        Self {
            project_path,
            session,
        }
    }
}

impl Composable for ProjectComposable {
    /// Materialize the block as a [`Contribution`], tagging every
    /// primitive with [`Source::Project`].
    ///
    /// Var resolution uses the composer-supplied `env` closure — an
    /// [`Inherit`]-shaped var whose lookup fails on the daemon
    /// today surfaces as a hard [`Error`]. Routing daemon-side
    /// unresolvable inherits back to the client as pending items is
    /// a downstream concern for the composer, not this trait impl.
    ///
    /// [`Source::Project`]: sessions::core::source::Source::Project
    /// [`Inherit`]: sessions::core::primitives::VarValue::Inherit
    fn contribute(
        self,
        env: &dyn Fn(&str) -> Result<String, std::env::VarError>,
    ) -> Result<Contribution, Error> {
        let source = Source::Project {
            path: self.project_path,
        };
        // Session transition scripts declared in a project `[session]`
        // block are composed like any other primitive. Unlike a
        // loadout's, they face the user's `[hooks]` policy before they
        // will run — a project is not the user, and a hook is arbitrary
        // code. That gate is the composer's; nothing is dropped here.
        contribute_primitives(
            &source,
            self.session.packages,
            self.session.vars,
            self.session.vars_lenient,
            self.session.patches,
            self.session.lifecycle_hooks,
            env,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;
    use sessions::core::source::Provenanced;

    /// A fully-populated `[session]` block contributes every domain,
    /// tagged with [`Source::Project`] carrying the project path.
    /// This is the base case: at least one item per domain, no
    /// resolution failures.
    #[test]
    fn contribute_populates_every_domain_with_project_provenance() {
        let mf: crate::File = toml::from_str(indoc! {
            r#"
            [session]
            packages = ["rustc", "cargo"]
            patches = [
                { dest = "~/.cargo/config.toml", source = "config/cargo.toml" },
            ]

            [session.vars]
            RUST_LOG         = "info"
            CARGO_TERM_COLOR = "always"

            [[session.lifecycle_hooks]]
            on_activate = { type = "inline", value = "cargo check --workspace >/dev/null 2>&1 || true" }
            "#
        })
        .unwrap();
        let session = mf.session.expect("populated block parses");
        let path = HostPath::try_new("/some/project").unwrap();
        let comp = ProjectComposable::new(path.clone(), session);

        // Never touched — no Inherit-shaped vars in this fixture.
        let env = |_: &str| Err(std::env::VarError::NotPresent);
        let contribution = comp.contribute(&env).expect("contribute succeeds");

        assert_eq!(contribution.vars().len(), 2);
        assert_eq!(contribution.patches().len(), 1);
        assert_eq!(contribution.packages().len(), 2);
        // A declared project hook is accepted and composed — the feature
        // is disabled downstream (output + execution), not by dropping it
        // here.
        assert_eq!(contribution.lifecycle_hooks().len(), 1);

        // Provenance is Source::Project everywhere, carrying the
        // path this composable was constructed with.
        let expected_source = Source::Project { path };
        for pv in contribution.vars() {
            assert_eq!(pv.source(), &expected_source);
        }
        for pp in contribution.patches() {
            assert_eq!(pp.source(), &expected_source);
        }
        for pp in contribution.packages() {
            assert_eq!(pp.source(), &expected_source);
        }
        for ph in contribution.lifecycle_hooks() {
            assert_eq!(ph.source(), &expected_source);
        }
    }

    /// A var with `{ inherit = true }` whose env lookup returns
    /// [`NotPresent`] surfaces the [`ResolutionFailure`] as a
    /// composition [`Error`], mirroring [`Loadout::contribute`].
    /// This is expected: daemon-side pending routing lives in the
    /// composer, not the trait impl. Documents the current failure
    /// mode so a future PR that adds pending routing has a test to
    /// flip.
    ///
    /// [`NotPresent`]: std::env::VarError::NotPresent
    /// [`ResolutionFailure`]: sessions::core::primitives::VarError::ResolutionFailure
    /// [`Loadout::contribute`]: sessions::core::loadout::Loadout::contribute
    #[test]
    fn inherit_without_env_surfaces_as_error() {
        let mf: crate::File = toml::from_str(indoc! {
            r#"
            [session.vars]
            DATABASE_URL = { inherit = true }
            "#
        })
        .unwrap();
        let session = mf.session.expect("populated block parses");
        let comp = ProjectComposable::new(HostPath::try_new("/proj").unwrap(), session);

        let env = |_: &str| Err(std::env::VarError::NotPresent);
        let err = comp.contribute(&env).expect_err("inherit lookup fails");
        // Error propagates as the composer's Var domain, matching
        // Loadout's behavior for the same input.
        assert!(matches!(err, Error::Var { .. }));
    }

    /// A `{ inherit = true, default = "..." }` var whose env lookup
    /// returns [`NotPresent`] falls back to the default without
    /// erroring — same as loadout semantics. Confirms
    /// [`ResolvedVar::resolve_with`]'s branching flows through
    /// unchanged.
    ///
    /// [`NotPresent`]: std::env::VarError::NotPresent
    /// [`ResolvedVar::resolve_with`]: sessions::core::primitives::ResolvedVar::resolve_with
    #[test]
    fn inherit_with_default_falls_back_when_absent() {
        let mf: crate::File = toml::from_str(indoc! {
            r#"
            [session.vars]
            DATABASE_URL = { inherit = true, default = "postgres://localhost/dev" }
            "#
        })
        .unwrap();
        let session = mf.session.expect("populated block parses");
        let comp = ProjectComposable::new(HostPath::try_new("/proj").unwrap(), session);

        let env = |_: &str| Err(std::env::VarError::NotPresent);
        let contribution = comp.contribute(&env).expect("fallback resolves");
        assert_eq!(contribution.vars().len(), 1);
        assert_eq!(
            contribution.vars()[0].var().value(),
            "postgres://localhost/dev"
        );
    }
}
