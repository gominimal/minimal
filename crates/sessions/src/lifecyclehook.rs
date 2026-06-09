//! Lifecycle hooks: scripts run on activation, destruction, or failure of a host resource.
//!
//! A [`LifecycleHook`] groups up to three scripts (one per transition point) and
//! guarantees that at least one is present — an empty hook is a no-op and is
//! rejected at construction time. Build hooks programmatically through
//! [`LifecycleHook::builder`] or deserialize them from configuration; both paths
//! enforce the same invariant.

use camino::Utf8PathBuf;
use paths::ConfigRelPath;

/// Errors produced when constructing a [`LifecycleHook`].
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No hook script was provided.
    ///
    /// Returned by [`LifecycleHookBuilder::build`] (and therefore by
    /// deserialization) when none of `on_activate`, `on_destroy`, or
    /// `on_failure` is set.
    #[error("At least one of on_activate, on_destroy, or on_failure must be specified")]
    EmptyLifecycleHook,
}

/// A script executed by a lifecycle hook.
///
/// Either the script body provided directly ([`Inline`](Self::Inline)) or a
/// path to a script file on disk ([`External`](Self::External)).
///
/// External scripts are [`ConfigRelPath`]s — anchored to the directory of the
/// `minimal.toml` they were decoded from. Absolute paths are rejected at
/// deserialization. To run an arbitrary host path, the executor binds the
/// `ConfigRelPath` against the known config directory.
///
/// Serialized with adjacent tagging — the wire form is a table with `type` and
/// `value` keys:
///
/// ```toml
/// on_activate = { type = "inline",   value = "echo hi"   }
/// on_failure  = { type = "external", value = "./run.sh"  }
/// ```
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "lowercase")]
pub enum HookScript {
    /// Script body stored inline.
    Inline(String),
    /// Path to a script file on disk, relative to the config directory.
    External(ConfigRelPath),
}

impl HookScript {
    /// Construct an [`Inline`](Self::Inline) script.
    #[must_use]
    pub fn inline(s: impl Into<String>) -> Self {
        Self::Inline(s.into())
    }

    /// Construct an [`External`](Self::External) script.
    ///
    /// # Errors
    ///
    /// Returns [`paths::Error::IsAbsolute`] if `p` is an absolute path;
    /// external script paths are anchored to the config directory.
    pub fn try_external(p: impl Into<Utf8PathBuf>) -> Result<Self, paths::Error> {
        Ok(Self::External(ConfigRelPath::try_new(p)?))
    }
}

/// A set of scripts to run at lifecycle transition points of a host resource.
///
/// At least one of `on_activate`, `on_destroy`, or `on_failure` must be set.
/// This invariant is enforced both by [`LifecycleHookBuilder::build`] and by
/// `serde` deserialization — there is no way to construct a `LifecycleHook`
/// with all three fields empty.
///
/// # Example — programmatic construction
///
/// ```
/// use sessions::lifecyclehook::{HookScript, LifecycleHook};
///
/// let hook = LifecycleHook::builder()
///     .with_on_activate(HookScript::Inline("echo activated".into()))
///     .build()
///     .expect("on_activate is set");
///
/// assert!(hook.on_activate().is_some());
/// assert!(hook.on_destroy().is_none());
/// assert!(hook.on_failure().is_none());
///
/// // An empty hook is rejected:
/// assert!(LifecycleHook::builder().build().is_err());
/// ```
///
/// # Example — TOML deserialization
///
/// ```
/// use sessions::lifecyclehook::{HookScript, LifecycleHook};
///
/// let src = r#"
/// on_activate = { type = "inline", value = "echo hello" }
/// on_failure  = { type = "external", value = "./cleanup.sh" }
/// "#;
///
/// let hook: LifecycleHook = toml::from_str(src).unwrap();
/// assert!(matches!(hook.on_activate(), Some(HookScript::Inline(s)) if s == "echo hello"));
/// assert!(matches!(hook.on_failure(), Some(HookScript::External(_))));
/// assert!(hook.on_destroy().is_none());
///
/// // Deserializing an empty hook fails:
/// assert!(toml::from_str::<LifecycleHook>("").is_err());
/// ```
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "LifecycleHookBuilder", into = "LifecycleHookBuilder")]
pub struct LifecycleHook {
    description: Option<String>,
    on_activate: Option<HookScript>,
    on_destroy: Option<HookScript>,
    on_failure: Option<HookScript>,
}

impl LifecycleHook {
    /// Returns a fresh [`LifecycleHookBuilder`].
    #[must_use]
    pub fn builder() -> LifecycleHookBuilder {
        LifecycleHookBuilder::default()
    }

    /// The script to run on activation, if any.
    #[must_use]
    pub fn on_activate(&self) -> Option<&HookScript> {
        self.on_activate.as_ref()
    }

    /// The script to run on destruction, if any.
    #[must_use]
    pub fn on_destroy(&self) -> Option<&HookScript> {
        self.on_destroy.as_ref()
    }

    /// The script to run when activation fails, if any.
    #[must_use]
    pub fn on_failure(&self) -> Option<&HookScript> {
        self.on_failure.as_ref()
    }
}

impl TryFrom<LifecycleHookBuilder> for LifecycleHook {
    type Error = Error;
    fn try_from(builder: LifecycleHookBuilder) -> Result<Self, Self::Error> {
        builder.build()
    }
}

/// Builder for [`LifecycleHook`].
///
/// Doubles as the on-the-wire deserialization shape for `LifecycleHook` — every
/// field is optional, and validation runs at [`build`](Self::build) time.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct LifecycleHookBuilder {
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    on_activate: Option<HookScript>,
    #[serde(skip_serializing_if = "Option::is_none")]
    on_destroy: Option<HookScript>,
    #[serde(skip_serializing_if = "Option::is_none")]
    on_failure: Option<HookScript>,
}

impl LifecycleHookBuilder {
    /// Sets the script to run on activation.
    #[must_use]
    pub fn with_on_activate(self, on_activate: HookScript) -> Self {
        Self {
            on_activate: Some(on_activate),
            ..self
        }
    }

    /// Sets the script to run when activation fails.
    #[must_use]
    pub fn with_on_failure(self, on_failure: HookScript) -> Self {
        Self {
            on_failure: Some(on_failure),
            ..self
        }
    }

    /// Sets the script to run on destruction.
    #[must_use]
    pub fn with_on_destroy(self, on_destroy: HookScript) -> Self {
        Self {
            on_destroy: Some(on_destroy),
            ..self
        }
    }

    /// Consumes the builder and produces a [`LifecycleHook`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyLifecycleHook`] if none of `on_activate`,
    /// `on_destroy`, or `on_failure` has been set.
    pub fn build(self) -> Result<LifecycleHook, Error> {
        if self.on_activate.is_none() && self.on_destroy.is_none() && self.on_failure.is_none() {
            return Err(Error::EmptyLifecycleHook);
        }
        Ok(LifecycleHook {
            description: self.description,
            on_activate: self.on_activate,
            on_destroy: self.on_destroy,
            on_failure: self.on_failure,
        })
    }
}

impl From<LifecycleHook> for LifecycleHookBuilder {
    fn from(value: LifecycleHook) -> Self {
        Self {
            description: value.description,
            on_activate: value.on_activate,
            on_destroy: value.on_destroy,
            on_failure: value.on_failure,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_rejects_all_none() {
        assert!(matches!(
            LifecycleHook::builder().build(),
            Err(Error::EmptyLifecycleHook),
        ));
    }

    #[test]
    fn builder_accepts_only_on_activate() {
        let hook = LifecycleHook::builder()
            .with_on_activate(HookScript::Inline("a".into()))
            .build()
            .unwrap();
        assert!(hook.on_activate().is_some());
        assert!(hook.on_destroy().is_none());
        assert!(hook.on_failure().is_none());
    }

    #[test]
    fn toml_deserializes_full_hook() {
        let src = r#"
            on_activate = { type = "inline",   value = "echo activated" }
            on_destroy  = { type = "external", value = "./teardown.sh" }
            on_failure  = { type = "inline",   value = "echo failed" }
        "#;
        let hook: LifecycleHook = toml::from_str(src).unwrap();
        assert!(matches!(hook.on_activate(), Some(HookScript::Inline(s)) if s == "echo activated"));
        assert!(matches!(
            hook.on_destroy(),
            Some(HookScript::External(p)) if p.as_str() == "./teardown.sh"
        ));
        assert!(matches!(hook.on_failure(), Some(HookScript::Inline(s)) if s == "echo failed"));
    }

    #[test]
    fn toml_deserializes_partial_hook() {
        let src = r#"
            on_activate = { type = "inline", value = "echo hi" }
        "#;
        let hook: LifecycleHook = toml::from_str(src).unwrap();
        assert!(hook.on_activate().is_some());
        assert!(hook.on_destroy().is_none());
        assert!(hook.on_failure().is_none());
    }

    #[test]
    fn toml_rejects_empty_hook() {
        let err = toml::from_str::<LifecycleHook>("").unwrap_err();
        assert!(
            err.to_string().contains("on_activate"),
            "expected validation error, got: {err}",
        );
    }

    #[test]
    fn serde_round_trip_through_toml() {
        let original = LifecycleHook::builder()
            .with_on_activate(HookScript::Inline("echo hi".into()))
            .with_on_failure(HookScript::External(
                ConfigRelPath::try_new("./fail.sh").unwrap(),
            ))
            .build()
            .unwrap();

        let serialized = toml::to_string(&original).unwrap();
        let parsed: LifecycleHook = toml::from_str(&serialized).unwrap();

        assert!(matches!(parsed.on_activate(), Some(HookScript::Inline(s)) if s == "echo hi"));
        assert!(matches!(
            parsed.on_failure(),
            Some(HookScript::External(p)) if p.as_str() == "./fail.sh"
        ));
        assert!(parsed.on_destroy().is_none());
    }

    #[test]
    fn hook_script_try_external_helper() {
        let s = HookScript::try_external("./run.sh").unwrap();
        assert!(matches!(s, HookScript::External(ref p) if p.as_str() == "./run.sh"));
    }

    #[test]
    fn hook_script_try_external_rejects_absolute() {
        let err = HookScript::try_external("/abs").unwrap_err();
        assert!(matches!(err, paths::Error::IsAbsolute(_)), "got: {err:?}");
    }

    #[test]
    fn hook_script_external_round_trips_through_toml_in_isolation() {
        // Pin the External wire form independent of the full LifecycleHook
        // round-trip — if the ConfigRelPath serde shape changes underneath
        // us, this test fires first.
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Wrap {
            hook: HookScript,
        }
        let original = Wrap {
            hook: HookScript::try_external("./run.sh").unwrap(),
        };
        let s = toml::to_string(&original).unwrap();
        let parsed: Wrap = toml::from_str(&s).unwrap();
        assert!(matches!(parsed.hook, HookScript::External(ref p) if p.as_str() == "./run.sh"),);
    }

    #[test]
    fn external_rejects_absolute_path_at_deserialize() {
        let src = r#"
            on_activate = { type = "external", value = "/etc/hook.sh" }
        "#;
        let err = toml::from_str::<LifecycleHook>(src).unwrap_err();
        assert!(
            err.to_string().contains("relative"),
            "expected realm error, got: {err}",
        );
    }

    #[test]
    fn serde_omits_unset_fields() {
        let hook = LifecycleHook::builder()
            .with_on_activate(HookScript::Inline("x".into()))
            .build()
            .unwrap();
        let serialized = toml::to_string(&hook).unwrap();
        assert!(serialized.contains("on_activate"));
        assert!(!serialized.contains("on_destroy"));
        assert!(!serialized.contains("on_failure"));
    }
}
