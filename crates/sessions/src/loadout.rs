//! User-level loadout: packages, variables, patches, and lifecycle
//! hooks the user wants in their session.
//!
//! # Example: helix + zellij with the user's dotfiles
//!
//! Top-level keys (`packages`, `patches`) come first because every key
//! following a `[section]` header in TOML is scoped to that section
//! until the next header; an empty line is *not* a scope reset.
//!
//! ```toml
//! packages = ["helix", "zellij"]
//!
//! # `dest` paths are inside the sandbox; `source` paths are on the host.
//! # `~` on either side is expanded at apply time (sandbox-home for dest,
//! # host-home for source).
//! patches = [
//!     # Helix: single config files plus a themes directory.
//!     { dest = "~/.config/helix/config.toml",
//!       source = "~/dotfiles/helix/config.toml" },
//!     { dest = "~/.config/helix/languages.toml",
//!       source = "~/dotfiles/helix/languages.toml" },
//!     { dest = "~/.config/helix/themes/",
//!       source = { base = "~/dotfiles/helix/themes", patterns = ["**/*.toml"] } },
//!
//!     # Zellij: single config file plus a layouts directory.
//!     { dest = "~/.config/zellij/config.kdl",
//!       source = "~/dotfiles/zellij/config.kdl" },
//!     { dest = "~/.config/zellij/layouts/",
//!       source = { base = "~/dotfiles/zellij/layouts", patterns = ["**/*.kdl"] } },
//! ]
//!
//! [vars]
//! EDITOR    = "hx"
//! VISUAL    = "hx"
//! TERM      = { inherit = true, default = "xterm-256color" }
//! COLORTERM = { inherit = true }
//!
//! # Warm helix's tree-sitter grammar cache the first time the session
//! # comes up. Best-effort; failures don't tank activation.
//! [[lifecycle_hooks]]
//! on_activate = { type = "inline", value = "hx --grammar fetch >/dev/null 2>&1 || true" }
//! ```

use std::collections::BTreeMap;

use crate::lifecyclehook::LifecycleHook;
use crate::patches::{Patch, Patches};
use crate::vars::{LenientVarEntry, StrictVarName, VarName, VarValue};

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Loadout {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    // Packages to be installed
    // TODO: Newtype for `Package`?
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    packages: Vec<String>,
    /// Variables with POSIX-shaped names — the common case.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    vars: BTreeMap<StrictVarName, VarValue>,
    /// Variables with Linux-permissive names — explicit opt-in for the
    /// rare case where a non-POSIX name is necessary.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    vars_lenient: Vec<LenientVarEntry>,
    /// Patches contributed by this loadout.
    #[serde(default, skip_serializing_if = "Patches::is_empty")]
    patches: Patches,
    /// Scripts run at session-level transition points.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    lifecycle_hooks: Vec<LifecycleHook>,
}

impl Loadout {
    /// Construct an empty loadout. Build it up via the additive
    /// `with_*` methods:
    ///
    /// ```
    /// use sessions::loadout::Loadout;
    /// use sessions::vars::{StrictVarName, VarValue};
    ///
    /// let l = Loadout::empty()
    ///     .with_package("helix")
    ///     .with_var(StrictVarName::try_new("EDITOR").unwrap(), VarValue::specified("hx"));
    /// assert_eq!(l.packages(), &["helix"]);
    /// assert_eq!(l.vars().len(), 1);
    /// ```
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Append a package dependency.
    #[must_use]
    pub fn with_package(self, package: impl Into<String>) -> Self {
        let mut new = self;
        new.packages.push(package.into());
        new
    }

    /// Insert a strict-name variable. Replaces any existing entry with
    /// the same name (consistent with [`std::collections::BTreeMap`]
    /// semantics).
    #[must_use]
    pub fn with_var(self, name: StrictVarName, value: VarValue) -> Self {
        let mut new = self;
        new.vars.insert(name, value);
        new
    }

    /// Append a lenient-name variable.
    #[must_use]
    pub fn with_var_lenient(self, entry: LenientVarEntry) -> Self {
        let mut new = self;
        new.vars_lenient.push(entry);
        new
    }

    /// Append a patch.
    #[must_use]
    pub fn with_patch(self, patch: Patch) -> Self {
        Self {
            patches: self.patches.with_patch(patch),
            ..self
        }
    }

    /// Append a lifecycle hook.
    #[must_use]
    pub fn with_lifecycle_hook(self, hook: LifecycleHook) -> Self {
        let mut new = self;
        new.lifecycle_hooks.push(hook);
        new
    }

    /// Packages this loadout requires.
    #[must_use]
    pub fn packages(&self) -> &[String] {
        &self.packages
    }

    /// Variables with POSIX-shaped names (raw wire-form accessor).
    #[must_use]
    pub fn vars(&self) -> &BTreeMap<StrictVarName, VarValue> {
        &self.vars
    }

    /// Variables with Linux-permissive names (raw wire-form accessor).
    #[must_use]
    pub fn vars_lenient(&self) -> &[LenientVarEntry] {
        &self.vars_lenient
    }

    /// Iterate over every variable this loadout declares — strict and
    /// lenient unified into a single stream of
    /// `(`[`VarName`]`, &`[`VarValue`]`)` pairs.
    ///
    /// Hides the wire-form asymmetry between [`Self::vars`] and
    /// [`Self::vars_lenient`]; callers that simply want "all variables
    /// to apply" should reach for this rather than merging the two
    /// fields themselves.
    ///
    /// Iteration order is strict-first (in [`StrictVarName`] order via
    /// the underlying [`BTreeMap`]), then lenient (in declaration order).
    pub fn all_vars(&self) -> impl Iterator<Item = (VarName, &VarValue)> {
        let strict = self
            .vars
            .iter()
            .map(|(n, v)| (VarName::Strict(n.clone()), v));
        let lenient = self
            .vars_lenient
            .iter()
            .map(|e| (VarName::Lenient(e.name().clone()), e.value()));
        strict.chain(lenient)
    }

    /// Patches contributed by this loadout.
    #[must_use]
    pub fn patches(&self) -> &Patches {
        &self.patches
    }

    /// Lifecycle hooks attached to this loadout.
    #[must_use]
    pub fn lifecycle_hooks(&self) -> &[LifecycleHook] {
        &self.lifecycle_hooks
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecyclehook::HookScript;
    use crate::patches::{FileSet, PatchDest};
    use crate::vars::LenientVarName;

    #[test]
    fn all_vars_yields_strict_then_lenient() {
        let src = r#"
            [vars]
            EDITOR = "vim"
            LANG = { inherit = true, default = "C" }

            [[vars_lenient]]
            name = "weird-thing"
            value = "x"
        "#;
        let l: Loadout = toml::from_str(src).unwrap();
        let collected: Vec<_> = l
            .all_vars()
            .map(|(n, v)| (n.as_str().to_owned(), v.clone()))
            .collect();
        assert_eq!(collected.len(), 3);

        // BTreeMap order on the strict side: EDITOR before LANG.
        assert_eq!(collected[0].0, "EDITOR");
        assert!(matches!(collected[0].1, VarValue::Specified { .. }));
        assert_eq!(collected[1].0, "LANG");
        assert!(matches!(
            collected[1].1,
            VarValue::InheritWithDefault { .. }
        ));

        // Lenient comes after strict, in declaration order.
        assert_eq!(collected[2].0, "weird-thing");
    }

    #[test]
    fn all_vars_distinguishes_strict_from_lenient() {
        let src = r#"
            [vars]
            EDITOR = "vim"

            [[vars_lenient]]
            name = "EDITOR"     # same spelling, different realm
            value = "emacs"
        "#;
        let l: Loadout = toml::from_str(src).unwrap();
        let collected: Vec<_> = l.all_vars().collect();
        assert!(matches!(collected[0].0, VarName::Strict(_)));
        assert!(matches!(collected[1].0, VarName::Lenient(_)));
    }

    #[test]
    fn default_loadout_is_empty() {
        let l = Loadout::default();
        assert!(l.packages().is_empty());
        assert_eq!(l.all_vars().count(), 0);
        assert!(l.patches().is_empty());
        assert!(l.lifecycle_hooks().is_empty());
    }

    #[test]
    fn lenient_var_entry_round_trips_through_toml() {
        let src = r#"
            [[vars_lenient]]
            name = "weird-thing"
            value = "x"
        "#;
        let l: Loadout = toml::from_str(src).unwrap();
        let entry = &l.vars_lenient()[0];
        assert_eq!(
            entry.name(),
            &LenientVarName::try_new("weird-thing").unwrap()
        );
        assert!(matches!(entry.value(), VarValue::Specified { value } if value == "x"),);
    }

    #[test]
    fn builder_surface_assembles_every_field() {
        let hook = LifecycleHook::builder()
            .with_on_activate(HookScript::inline("echo hi"))
            .build()
            .unwrap();
        let patch = Patch::new(
            FileSet::try_new(None, ["a"]).unwrap(),
            PatchDest::try_new("/a").unwrap(),
        );

        let l = Loadout::empty()
            .with_package("helix")
            .with_package("zellij")
            .with_var(
                StrictVarName::try_new("EDITOR").unwrap(),
                VarValue::specified("hx"),
            )
            .with_var_lenient(
                LenientVarEntry::try_new("weird-thing", VarValue::specified("x")).unwrap(),
            )
            .with_patch(patch)
            .with_lifecycle_hook(hook);

        assert_eq!(l.packages(), &["helix", "zellij"]);
        assert_eq!(l.vars().len(), 1);
        assert_eq!(l.vars_lenient().len(), 1);
        assert_eq!(l.patches().len(), 1);
        assert_eq!(l.lifecycle_hooks().len(), 1);
    }

    #[test]
    fn with_var_replaces_existing_strict_entry() {
        let name = StrictVarName::try_new("EDITOR").unwrap();
        let l = Loadout::empty()
            .with_var(name.clone(), VarValue::specified("hx"))
            .with_var(name.clone(), VarValue::specified("vim"));
        assert_eq!(l.vars().len(), 1);
        assert_eq!(l.vars().get(&name), Some(&VarValue::specified("vim")));
    }

    #[test]
    fn full_loadout_round_trips_through_toml() {
        // Exercise every field at once: packages, both strict and lenient
        // vars, patches with multiple source shapes, and a lifecycle hook.
        let src = r#"
            packages = ["helix", "zellij"]

            patches = [
                { dest = "/etc/foo", source = "./foo" },
                { dest = "/etc/bar", source = ["b1", "b2"] },
                { dest = "/themes/", source = { base = "./themes", patterns = ["**/*.toml"] } },
            ]

            [vars]
            EDITOR = "hx"
            LANG   = { inherit = true, default = "C" }

            [[vars_lenient]]
            name  = "weird-thing"
            value = "x"

            [[lifecycle_hooks]]
            on_activate = { type = "inline", value = "echo hi" }
        "#;
        let original: Loadout = toml::from_str(src).unwrap();
        let serialized = toml::to_string(&original).unwrap();
        let parsed: Loadout = toml::from_str(&serialized).unwrap();

        assert_eq!(parsed.packages(), &["helix", "zellij"]);
        assert_eq!(parsed.patches().len(), 3);
        assert_eq!(parsed.vars().len(), 2);
        assert_eq!(parsed.vars_lenient().len(), 1);
        assert_eq!(parsed.lifecycle_hooks().len(), 1);

        // The original-vs-parsed equality check would require Loadout: Eq,
        // which it isn't (Patches / VarValue / LifecycleHook all skip it).
        // Re-serialize and compare strings instead — same effect, no derive
        // creep.
        let reserialized = toml::to_string(&parsed).unwrap();
        assert_eq!(serialized, reserialized);
    }
}
