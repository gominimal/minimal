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
//! # `~`-expansion is split by realm:
//! #   - `source` `~` is expanded at gate time against the host home
//! #     (via the composer's `HOME` env lookup —
//! #     `std::env::var("HOME")` by default).
//! #   - `dest` `~` is left unexpanded by the gate. `PatchDest` is
//! #     validated as sandbox-home-relative; any expansion of a leading
//! #     `~` happens in the sandbox runtime against the sandbox home,
//! #     not here.
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

use nutype::nutype;

use crate::core::lifecyclehook::LifecycleHook;
use crate::core::primitives::{LenientVarEntry, Patch, Patches, StrictVarName, VarName, VarValue};

/// A loadout's identifier — trimmed, non-empty, and free of path
/// separators and NUL bytes.
///
/// Names appear in user-facing contexts (selection menus, error
/// messages) and may be used as filesystem-key fragments by the loader,
/// so they're constrained at construction time rather than at point of
/// use.
#[nutype(
    sanitize(trim),
    validate(not_empty, predicate = |s: &str| !s.contains(['/', '\\', '\0'])),
    derive(
        Clone, Debug, Display, AsRef, PartialEq, Eq, Hash, PartialOrd, Ord,
        Serialize, Deserialize,
    ),
)]
pub struct LoadoutName(String);

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Loadout {
    /// Identifier — user-facing, used in selection and error messages.
    name: LoadoutName,
    /// Free-form description, shown alongside the name in user-facing
    /// contexts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    /// Packages to bring into the session.
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
    /// Construct a loadout with a pre-validated name. Build it up via
    /// the additive `with_*` methods:
    ///
    /// ```
    /// use sessions::core::loadout::{Loadout, LoadoutName};
    /// use sessions::core::primitives::{StrictVarName, VarValue};
    ///
    /// let l = Loadout::new(LoadoutName::try_new("dev").unwrap())
    ///     .with_package("helix")
    ///     .with_var(StrictVarName::try_new("EDITOR").unwrap(), VarValue::specified("hx"));
    /// assert_eq!(l.packages(), &["helix"]);
    /// assert_eq!(l.vars().len(), 1);
    /// ```
    #[must_use]
    pub fn new(name: LoadoutName) -> Self {
        Self {
            name,
            description: None,
            packages: Vec::new(),
            vars: BTreeMap::new(),
            vars_lenient: Vec::new(),
            patches: Patches::empty(),
            lifecycle_hooks: Vec::new(),
        }
    }

    /// Set a free-form description.
    #[must_use]
    pub fn with_description(self, description: impl Into<String>) -> Self {
        Self {
            description: Some(description.into()),
            ..self
        }
    }

    /// The loadout's identifier.
    #[must_use]
    pub fn name(&self) -> &LoadoutName {
        &self.name
    }

    /// The loadout's free-form description, if any.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
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
    pub fn with_patch(mut self, patch: Patch) -> Self {
        self.patches.push(patch);
        self
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

impl crate::core::compose::Composable for Loadout {
    /// Materialize the loadout as a [`Contribution`](crate::core::compose::Contribution),
    /// tagging every primitive with [`Source::UserLoadout`].
    ///
    /// Inherited / default-bearing var values are resolved via `env`
    /// at this point.
    ///
    /// [`Source::UserLoadout`]: crate::core::source::Source::UserLoadout
    fn contribute(
        self,
        env: &dyn Fn(&str) -> Result<String, std::env::VarError>,
    ) -> Result<crate::core::compose::Contribution, crate::core::compose::Error> {
        use crate::core::compose::Contribution;
        use crate::core::primitives::ResolvedVar;
        use crate::core::source::{
            ProvenancedHook, ProvenancedPackage, ProvenancedPatch, ProvenancedVar, Source,
        };

        let source = Source::UserLoadout {
            name: self.name.into_inner(),
        };
        let mut c = Contribution::new();

        for (name, value) in self.vars {
            let resolved = ResolvedVar::resolve_with(name.into_inner(), value, env)?;
            c.push_var(ProvenancedVar::new(resolved, source.clone()));
        }
        for entry in self.vars_lenient {
            let (name, value) = entry.into_parts();
            let resolved = ResolvedVar::resolve_with(name.into_inner(), value, env)?;
            c.push_var(ProvenancedVar::new(resolved, source.clone()));
        }
        for patch in self.patches {
            c.push_patch(ProvenancedPatch::new(patch, source.clone()));
        }
        for pkg in self.packages {
            c.push_package(ProvenancedPackage::new(pkg, source.clone()));
        }
        for hook in self.lifecycle_hooks {
            c.push_hook(ProvenancedHook::new(hook, source.clone()));
        }
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::lifecyclehook::HookScript;
    use crate::core::primitives::{LenientVarName, PatchDest};

    #[test]
    fn all_vars_yields_strict_then_lenient() {
        let src = r#"
            name = "dev"

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
            name = "dev"

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
    fn loadout_name_rejects_empty_and_path_chars() {
        assert!(LoadoutName::try_new("").is_err());
        assert!(LoadoutName::try_new("   ").is_err()); // trimmed → empty
        assert!(LoadoutName::try_new("a/b").is_err());
        assert!(LoadoutName::try_new("a\\b").is_err());
        assert!(LoadoutName::try_new("a\0b").is_err());
        let n = LoadoutName::try_new("  dev  ").unwrap();
        assert_eq!(n.as_ref(), "dev");
    }

    #[test]
    fn name_and_description_accessors_round_trip_through_builder() {
        let l = Loadout::new(LoadoutName::try_new("dev").unwrap())
            .with_description("primary dev session");
        assert_eq!(l.name().as_ref(), "dev");
        assert_eq!(l.description(), Some("primary dev session"));
    }

    #[test]
    fn default_loadout_is_empty() {
        let l = Loadout::new(LoadoutName::try_new("Test").unwrap());
        assert!(l.packages().is_empty());
        assert_eq!(l.all_vars().count(), 0);
        assert!(l.patches().is_empty());
        assert!(l.lifecycle_hooks().is_empty());
    }

    #[test]
    fn lenient_var_entry_round_trips_through_toml() {
        let src = r#"
            name = "dev"

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
        let patch = Patch::new("a", PatchDest::try_new("a").unwrap());

        let l = Loadout::new(LoadoutName::try_new("Test").unwrap())
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
        let l = Loadout::new(LoadoutName::try_new("Test").unwrap())
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
            name        = "dev"
            description = "Editor + terminal multiplexer"
            packages    = ["helix", "zellij"]

            patches = [
                { dest = "etc/foo", source = "./foo" },
                { dest = "etc/bar", source = ["b1", "b2"] },
                { dest = "themes/", source = "./themes/**/*.toml" },
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

        assert_eq!(parsed.name().as_ref(), "dev");
        assert_eq!(parsed.description(), Some("Editor + terminal multiplexer"));
        assert_eq!(parsed.packages(), &["helix", "zellij"]);
        // Row 2 (`source = ["b1", "b2"]`) fans out into two patches, so the
        // three rows yield four Patch entries.
        assert_eq!(parsed.patches().len(), 4);
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
