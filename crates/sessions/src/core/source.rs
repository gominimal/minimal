//! Provenance: which source contributed a primitive.
//!
//! [`Source`] describes the origin (user loadout / project / package) of
//! every item that flows through the composer. The [`Provenanced`] trait
//! is what makes policy `check` methods source-aware; each `ProvenancedX`
//! wrapper pairs a primitive with its origin so the composer can carry
//! both through together.

use core::fmt;

use paths::HostPath;

use crate::core::primitives::{Patch, ResolvedVar};

/// Where a contribution came from — the provenance attached to every
/// item that flows through the composer.
///
/// `Source` is what makes the origin-aware allow step possible
/// ([`VarsPolicy::check`](crate::core::policy::VarsPolicy::check) /
/// [`ExpandedPatchesPolicy::check`](crate::core::policy::ExpandedPatchesPolicy::check)
/// inspect this) and what error messages name when an item is rejected.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Source {
    /// The user's own [`Loadout`](crate::core::loadout::Loadout). Bypasses
    /// `allow`/`deny` checks (only `ignore` still applies).
    UserLoadout { name: String },
    /// A project's `minimal.toml`, identified by the path of the
    /// config file.
    Project { path: HostPath },
    /// A specific package's declaration, identified by package name.
    Package { name: String },
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UserLoadout { name } => write!(f, "user loadout `{name}`"),
            Self::Project { path } => write!(f, "project `{path}`"),
            Self::Package { name } => write!(f, "package `{name}`"),
        }
    }
}

/// Trait for types that know which [`Source`] contributed them.
///
/// The composer takes `T: Provenanced` so policy `check` methods can
/// query the source without the caller having to thread it through
/// alongside the item.
pub trait Provenanced {
    /// The [`Source`] this item came from.
    fn source(&self) -> &Source;
}

/// A [`ResolvedVar`] tagged with its [`Source`] for the composer.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProvenancedVar {
    var: ResolvedVar,
    source: Source,
}

impl ProvenancedVar {
    /// Construct a [`ProvenancedVar`] from a resolved variable and its
    /// origin.
    #[must_use]
    pub fn new(var: ResolvedVar, source: Source) -> Self {
        Self { var, source }
    }

    /// The wrapped [`ResolvedVar`].
    #[must_use]
    pub fn var(&self) -> &ResolvedVar {
        &self.var
    }

    /// Consume and return the inner var and source.
    #[must_use]
    pub fn into_parts(self) -> (ResolvedVar, Source) {
        (self.var, self.source)
    }
}

impl Provenanced for ProvenancedVar {
    fn source(&self) -> &Source {
        &self.source
    }
}

/// A [`Patch`] tagged with its [`Source`] for the composer.
///
/// `follow_symlinks` overrides the compose-level default for this
/// specific patch's walk. `None` means "use the compose default";
/// `Some(v)` wins. Populated by [`Loadout::contribute`] from
/// [`Loadout::follow_symlinks`]; non-loadout contributors emit
/// `None` and inherit the default.
///
/// [`Loadout::contribute`]: crate::core::loadout::Loadout::contribute
/// [`Loadout::follow_symlinks`]: crate::core::loadout::Loadout::follow_symlinks
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProvenancedPatch {
    patch: Patch,
    source: Source,
    follow_symlinks: Option<bool>,
}

impl ProvenancedPatch {
    /// Construct a [`ProvenancedPatch`] with no per-item
    /// follow-symlinks override; the walker uses the compose default.
    #[must_use]
    pub fn new(patch: Patch, source: Source) -> Self {
        Self {
            patch,
            source,
            follow_symlinks: None,
        }
    }

    /// Set the per-patch follow-symlinks override. Owned-builder
    /// form so a caller building `ProvenancedPatch` inline reads
    /// linearly.
    #[must_use]
    pub fn with_follow_symlinks(mut self, follow_symlinks: Option<bool>) -> Self {
        self.follow_symlinks = follow_symlinks;
        self
    }

    /// The wrapped [`Patch`].
    #[must_use]
    pub fn patch(&self) -> &Patch {
        &self.patch
    }

    /// The per-patch follow-symlinks override (`None` = inherit
    /// the compose default).
    #[must_use]
    pub fn follow_symlinks(&self) -> Option<bool> {
        self.follow_symlinks
    }

    /// Consume and return the inner patch, source, and follow-symlinks override.
    #[must_use]
    pub fn into_parts(self) -> (Patch, Source, Option<bool>) {
        (self.patch, self.source, self.follow_symlinks)
    }
}

impl Provenanced for ProvenancedPatch {
    fn source(&self) -> &Source {
        &self.source
    }
}

/// A package name tagged with its [`Source`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProvenancedPackage {
    package: String,
    source: Source,
}

impl ProvenancedPackage {
    /// Construct a [`ProvenancedPackage`] from a package name and its
    /// origin.
    #[must_use]
    pub fn new(package: impl Into<String>, source: Source) -> Self {
        Self {
            package: package.into(),
            source,
        }
    }

    /// The package name used to identify it in the graph.
    #[must_use]
    pub fn package(&self) -> &str {
        &self.package
    }

    /// Consume the [`ProvenancedPackage`] and return `(package, source)`.
    #[must_use]
    pub fn into_parts(self) -> (String, Source) {
        (self.package, self.source)
    }
}

impl Provenanced for ProvenancedPackage {
    fn source(&self) -> &Source {
        &self.source
    }
}

/// A [`LifecycleHook`](crate::core::lifecyclehook::LifecycleHook) tagged with
/// its [`Source`].
///
/// Lifecycle hooks run inside the sandbox (or its equivalent isolated
/// environment), so they don't go through the policy gate — they
/// pass through resolution unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenancedHook {
    hook: crate::core::lifecyclehook::LifecycleHook,
    source: Source,
}

impl ProvenancedHook {
    /// Construct a [`ProvenancedHook`] from a hook declaration and its
    /// origin.
    #[must_use]
    pub fn new(hook: crate::core::lifecyclehook::LifecycleHook, source: Source) -> Self {
        Self { hook, source }
    }

    /// The wrapped [`LifecycleHook`](crate::core::lifecyclehook::LifecycleHook).
    #[must_use]
    pub fn hook(&self) -> &crate::core::lifecyclehook::LifecycleHook {
        &self.hook
    }

    /// Consume the [`ProvenancedHook`] and return `(hook, source)`.
    #[must_use]
    pub fn into_parts(self) -> (crate::core::lifecyclehook::LifecycleHook, Source) {
        (self.hook, self.source)
    }
}

impl Provenanced for ProvenancedHook {
    fn source(&self) -> &Source {
        &self.source
    }
}

// ---------------------------------------------------------------------------
// Wire → domain conversions
// ---------------------------------------------------------------------------

impl From<crate::wire::primitives::WireSource> for Source {
    fn from(s: crate::wire::primitives::WireSource) -> Self {
        match s {
            crate::wire::primitives::WireSource::UserLoadout { name } => Self::UserLoadout { name },
            crate::wire::primitives::WireSource::Project { path } => Self::Project { path },
            crate::wire::primitives::WireSource::Package { name } => Self::Package { name },
        }
    }
}

impl From<crate::wire::primitives::WirePackageRef> for ProvenancedPackage {
    fn from(p: crate::wire::primitives::WirePackageRef) -> Self {
        Self::new(p.name, p.source.into())
    }
}

/// Fallible because the inner wire `LifecycleHook` may have all three
/// callbacks absent, which the domain type rejects.
impl TryFrom<crate::wire::primitives::WireProvenancedHook> for ProvenancedHook {
    type Error = crate::core::lifecyclehook::Error;
    fn try_from(h: crate::wire::primitives::WireProvenancedHook) -> Result<Self, Self::Error> {
        let hook: crate::core::lifecyclehook::LifecycleHook = h.hook.try_into()?;
        Ok(Self::new(hook, h.source.into()))
    }
}
