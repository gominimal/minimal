//! User policy: what the user permits projects and packages to do
//! within their session.
//!
//! [`UserPolicy`] bundles the per-domain policies — [`VarsPolicy`] for
//! environment variables and [`PatchPolicy`] for file patches. Both
//! gate *non-user* declarations only; user-origin declarations from a
//! [`Loadout`] are subject to each domain's `ignore` rule but bypass
//! `allow` / `deny`.
//!
//! Kept separate from [`Loadout`] on purpose: the user's policy is
//! about what they let other sources contribute, not about what *they*
//! contribute. Composing multiple Loadouts doesn't compose policy.
//!
//! [`Loadout`]: crate::loadout::Loadout
//!
//! # Example
//!
//! ```toml
//! [vars]
//! allow  = ["MY_APP_*", "RUST_*"]
//! deny   = ["AWS_*", "*_TOKEN"]
//! ignore = ["_*"]
//!
//! [patches]
//! allow  = ["~/.config/**", "/etc/xdg/**"]
//! deny   = ["~/.ssh/**", "**/*.pem"]
//! ignore = ["**/.DS_Store"]
//! ```

use crate::patches::PatchPolicy;
use crate::vars::VarsPolicy;

/// The user's policy for what projects and packages may contribute to a
/// session.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UserPolicy {
    #[serde(default, skip_serializing_if = "vars_policy_is_default")]
    vars: VarsPolicy,
    #[serde(default, skip_serializing_if = "patch_policy_is_default")]
    patches: PatchPolicy,
}

impl UserPolicy {
    /// Construct an empty policy — equivalent to [`Default::default`].
    /// Build it up via [`Self::with_vars`] and [`Self::with_patches`]:
    ///
    /// ```
    /// use sessions::policy::UserPolicy;
    /// use sessions::vars::{VarNameGlobs, VarsPolicy};
    ///
    /// let p = UserPolicy::empty().with_vars(
    ///     VarsPolicy::empty()
    ///         .with_allow(VarNameGlobs::try_new(["MY_APP_*"]).unwrap()),
    /// );
    /// assert_eq!(p.vars().allow().raw_patterns(), &["MY_APP_*"]);
    /// ```
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Replace the variables policy.
    #[must_use]
    pub fn with_vars(self, vars: VarsPolicy) -> Self {
        Self { vars, ..self }
    }

    /// Replace the patches policy.
    #[must_use]
    pub fn with_patches(self, patches: PatchPolicy) -> Self {
        Self { patches, ..self }
    }

    /// The variables policy in effect.
    #[must_use]
    pub fn vars(&self) -> &VarsPolicy {
        &self.vars
    }

    /// The patches policy in effect.
    #[must_use]
    pub fn patches(&self) -> &PatchPolicy {
        &self.patches
    }
}

fn vars_policy_is_default(p: &VarsPolicy) -> bool {
    p == &VarsPolicy::default()
}

fn patch_policy_is_default(p: &PatchPolicy) -> bool {
    p == &PatchPolicy::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vars::VarNameGlobs;

    #[test]
    fn empty_round_trips_through_toml() {
        let p = UserPolicy::empty();
        let s = toml::to_string(&p).unwrap();
        let parsed: UserPolicy = toml::from_str(&s).unwrap();
        assert_eq!(parsed, p);
    }

    #[test]
    fn deserializes_with_both_sections() {
        let src = r#"
            [vars]
            allow = ["MY_APP_*"]
            deny  = ["AWS_*"]

            [patches]
            allow = ["~/.config/**"]
            deny  = ["~/.ssh/**"]
        "#;
        let p: UserPolicy = toml::from_str(src).unwrap();
        assert_eq!(p.vars().allow().raw_patterns(), &["MY_APP_*"]);
        assert_eq!(p.vars().deny().raw_patterns(), &["AWS_*"]);
        assert_eq!(p.patches().allow().raw_patterns(), &["~/.config/**"]);
        assert_eq!(p.patches().deny().raw_patterns(), &["~/.ssh/**"]);
    }

    #[test]
    fn deserializes_with_only_one_section() {
        let src = r#"
            [vars]
            allow = ["X"]
        "#;
        let p: UserPolicy = toml::from_str(src).unwrap();
        assert_eq!(p.vars().allow().raw_patterns(), &["X"]);
        assert_eq!(p.patches(), &PatchPolicy::default());
    }

    #[test]
    fn skips_default_sections_on_serialize() {
        let p = UserPolicy::empty()
            .with_vars(VarsPolicy::empty().with_allow(VarNameGlobs::try_new(["X"]).unwrap()));
        let s = toml::to_string(&p).unwrap();
        assert!(s.contains("[vars"), "expected vars section, got: {s}");
        assert!(
            !s.contains("[patches"),
            "expected no patches section, got: {s}"
        );
    }
}
