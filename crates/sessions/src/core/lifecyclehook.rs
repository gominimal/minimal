//! Lifecycle hooks: scripts run at a session's state transitions.
//!
//! A [`LifecycleHook`] groups up to four scripts (one per transition point)
//! and guarantees that at least one is present — an empty hook is a no-op and
//! is rejected at construction time. Build hooks programmatically through
//! [`LifecycleHook::builder`] or deserialize them from configuration; both
//! paths enforce the same invariant.
//!
//! Each script carries its own [`timeout`](HookScript::timeout), defaulting to
//! [`DEFAULT_HOOK_TIMEOUT`] and capped at [`MAX_HOOK_TIMEOUT`]. The cap is a
//! denial-of-service bound: a hook is arbitrary code contributed by a project,
//! so an unbounded timeout would let one hold a session open (or block its
//! teardown) indefinitely.

use std::time::Duration;

use camino::Utf8PathBuf;
use paths::ConfigRelPath;

/// Timeout applied to a hook script that doesn't declare one.
pub const DEFAULT_HOOK_TIMEOUT: Duration = Duration::from_mins(1);

/// Hard ceiling on a hook script's declared timeout. Rejected at
/// deserialization rather than clamped, so a declaration that can't be
/// honored fails loudly where it is written instead of behaving differently
/// from what it says.
pub const MAX_HOOK_TIMEOUT: Duration = Duration::from_mins(5);

/// Errors produced when constructing a [`LifecycleHook`] or a
/// [`HookScript`].
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No hook script was provided.
    ///
    /// Returned by [`LifecycleHookBuilder::build`] (and therefore by
    /// deserialization) when none of `on_activate`, `on_destroy`,
    /// `on_attach`, or `on_detach` is set.
    #[error(
        "at least one of on_activate, on_destroy, on_attach, or on_detach \
         must be specified"
    )]
    EmptyLifecycleHook,

    /// The removed `on_failure` transition was declared.
    ///
    /// Named explicitly rather than folded into an unknown-field error: the
    /// key parsed silently before this variant existed, so a hook file
    /// carrying it would otherwise lose a script without saying so.
    #[error("`on_failure` is no longer a lifecycle transition; use `on_destroy` instead")]
    OnFailureRemoved,

    /// A script declared a timeout above [`MAX_HOOK_TIMEOUT`].
    #[error(
        "hook timeout of {got}s exceeds the maximum of {}s",
        MAX_HOOK_TIMEOUT.as_secs()
    )]
    TimeoutTooLarge {
        /// The declared timeout, in seconds.
        got: u64,
    },

    /// A script declared a zero timeout, which would kill it before it
    /// could run.
    #[error("hook timeout must be greater than zero")]
    TimeoutZero,

    /// An external script's path failed [`ConfigRelPath`]'s validation —
    /// it was absolute, or contained a `..` component.
    #[error("external hook script path: {0}")]
    Path(#[from] paths::Error),
}

/// Which flavor of script a [`HookScript`] carries. The `type` field of
/// the wire form.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HookScriptType {
    /// Script body stored inline.
    Inline,
    /// Path to a script file on disk, relative to the config directory.
    External,
}

/// The body of a lifecycle hook script: either the script itself or a
/// path to it.
///
/// External scripts are [`ConfigRelPath`]s — anchored at stage time to the
/// directory that owns the file they were decoded from (a loadout's script
/// directory, or the project root). Absolute paths and `..` components are
/// rejected at deserialization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HookScriptBody {
    /// Script body stored inline.
    Inline(String),
    /// Path to a script file on disk, relative to its anchor.
    External(ConfigRelPath),
}

/// A script executed at one lifecycle transition, plus the timeout it runs
/// under.
///
/// Serialized as a table with `type`, `value`, and an optional `timeout` in
/// whole seconds:
///
/// ```toml
/// on_activate = { type = "inline",   value = "echo hi"  }
/// on_destroy  = { type = "external", value = "./run.sh", timeout = 120 }
/// ```
///
/// The three keys sit at one level, so this is a struct with a `type`
/// discriminator rather than an adjacently-tagged enum: serde's adjacent
/// tagging recognizes exactly the tag and content keys and silently skips
/// anything beside them, which would make `timeout` parse cleanly and do
/// nothing. [`HookScriptRepr`] therefore validates the whole table and
/// rejects unknown keys.
///
/// # Example
///
/// ```
/// use sessions::core::lifecyclehook::{HookScript, HookScriptBody, DEFAULT_HOOK_TIMEOUT};
///
/// let s: HookScript = toml::from_str("type = \"inline\"\nvalue = \"echo hi\"\n").unwrap();
/// assert!(matches!(s.body(), HookScriptBody::Inline(b) if b == "echo hi"));
/// assert_eq!(s.timeout(), DEFAULT_HOOK_TIMEOUT);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "HookScriptRepr", into = "HookScriptRepr")]
pub struct HookScript {
    body: HookScriptBody,
    timeout: Duration,
}

impl HookScript {
    /// Construct an inline script with the default timeout.
    #[must_use]
    pub fn inline(s: impl Into<String>) -> Self {
        Self {
            body: HookScriptBody::Inline(s.into()),
            timeout: DEFAULT_HOOK_TIMEOUT,
        }
    }

    /// Construct an external script with the default timeout.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Path`] if `p` is absolute or contains a `..`
    /// component; external script paths are anchored to a config directory.
    pub fn try_external(p: impl Into<Utf8PathBuf>) -> Result<Self, Error> {
        Ok(Self {
            body: HookScriptBody::External(ConfigRelPath::try_new(p)?),
            timeout: DEFAULT_HOOK_TIMEOUT,
        })
    }

    /// Override the timeout.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TimeoutZero`] for a zero timeout, or
    /// [`Error::TimeoutTooLarge`] above [`MAX_HOOK_TIMEOUT`].
    pub fn with_timeout(self, timeout: Duration) -> Result<Self, Error> {
        validate_timeout(timeout)?;
        Ok(Self { timeout, ..self })
    }

    /// The script body.
    #[must_use]
    pub fn body(&self) -> &HookScriptBody {
        &self.body
    }

    /// How long the script may run before it is killed.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Consume the script and return `(body, timeout)`.
    #[must_use]
    pub fn into_parts(self) -> (HookScriptBody, Duration) {
        (self.body, self.timeout)
    }
}

/// Reject a timeout outside `(0, MAX_HOOK_TIMEOUT]`.
fn validate_timeout(timeout: Duration) -> Result<(), Error> {
    if timeout.is_zero() {
        return Err(Error::TimeoutZero);
    }
    if timeout > MAX_HOOK_TIMEOUT {
        return Err(Error::TimeoutTooLarge {
            got: timeout.as_secs(),
        });
    }
    Ok(())
}

/// The on-the-wire (and on-disk) shape of a [`HookScript`].
///
/// `deny_unknown_fields` is deliberate: the whole reason this type exists
/// rather than an adjacently-tagged enum is that a misplaced key used to be
/// skipped in silence. A typo like `timout = 120` must be an error, not a
/// script that quietly runs with the default.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookScriptRepr {
    /// Which flavor of script `value` holds.
    #[serde(rename = "type")]
    pub script_type: HookScriptType,
    /// The inline body, or the relative path to the script file.
    pub value: String,
    /// Timeout in whole seconds. Absent means [`DEFAULT_HOOK_TIMEOUT`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
}

impl TryFrom<HookScriptRepr> for HookScript {
    type Error = Error;

    fn try_from(repr: HookScriptRepr) -> Result<Self, Self::Error> {
        let timeout = repr
            .timeout
            .map_or(DEFAULT_HOOK_TIMEOUT, Duration::from_secs);
        validate_timeout(timeout)?;
        let body = match repr.script_type {
            HookScriptType::Inline => HookScriptBody::Inline(repr.value),
            HookScriptType::External => {
                HookScriptBody::External(ConfigRelPath::try_new(repr.value)?)
            }
        };
        Ok(Self { body, timeout })
    }
}

impl From<HookScript> for HookScriptRepr {
    fn from(s: HookScript) -> Self {
        let (script_type, value) = match s.body {
            HookScriptBody::Inline(body) => (HookScriptType::Inline, body),
            HookScriptBody::External(path) => (HookScriptType::External, path.as_str().to_owned()),
        };
        // Only emit `timeout` when it differs from the default, so a
        // round-trip of an undeclared timeout stays undeclared.
        let timeout = (s.timeout != DEFAULT_HOOK_TIMEOUT).then_some(s.timeout.as_secs());
        Self {
            script_type,
            value,
            timeout,
        }
    }
}

/// Scripts run at a session's lifecycle transition points.
///
/// At least one of `on_activate`, `on_destroy`, `on_attach`, or
/// `on_detach` must be set; the empty case is rejected by both the builder
/// and `serde` deserialization.
///
/// # Example
///
/// ```
/// use sessions::core::lifecyclehook::{HookScriptBody, LifecycleHook};
///
/// let src = r#"
/// on_activate = { type = "inline", value = "echo hello" }
/// on_detach   = { type = "external", value = "./cleanup.sh", timeout = 120 }
/// "#;
/// let hook: LifecycleHook = toml::from_str(src).unwrap();
/// assert!(matches!(
///     hook.on_activate().map(|s| s.body()),
///     Some(HookScriptBody::Inline(_)),
/// ));
/// assert_eq!(hook.on_detach().unwrap().timeout().as_secs(), 120);
/// assert!(toml::from_str::<LifecycleHook>("").is_err());
/// ```
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "LifecycleHookBuilder", into = "LifecycleHookBuilder")]
pub struct LifecycleHook {
    description: Option<String>,
    on_activate: Option<HookScript>,
    on_destroy: Option<HookScript>,
    on_attach: Option<HookScript>,
    on_detach: Option<HookScript>,
}

impl LifecycleHook {
    /// Returns a fresh [`LifecycleHookBuilder`].
    #[must_use]
    pub fn builder() -> LifecycleHookBuilder {
        LifecycleHookBuilder::default()
    }

    /// The hook's free-form description, if any.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// The script to run on session activation, if any.
    #[must_use]
    pub fn on_activate(&self) -> Option<&HookScript> {
        self.on_activate.as_ref()
    }

    /// The script to run on session destruction, if any.
    #[must_use]
    pub fn on_destroy(&self) -> Option<&HookScript> {
        self.on_destroy.as_ref()
    }

    /// The script to run when a client attaches, if any.
    #[must_use]
    pub fn on_attach(&self) -> Option<&HookScript> {
        self.on_attach.as_ref()
    }

    /// The script to run when a client detaches, if any.
    #[must_use]
    pub fn on_detach(&self) -> Option<&HookScript> {
        self.on_detach.as_ref()
    }

    /// Consume the [`LifecycleHook`] and return
    /// `(description, on_activate, on_destroy, on_attach, on_detach)`.
    #[must_use]
    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> (
        Option<String>,
        Option<HookScript>,
        Option<HookScript>,
        Option<HookScript>,
        Option<HookScript>,
    ) {
        (
            self.description,
            self.on_activate,
            self.on_destroy,
            self.on_attach,
            self.on_detach,
        )
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
/// Doubles as the on-the-wire deserialization shape for `LifecycleHook` —
/// every field is optional, and validation runs at [`build`](Self::build)
/// time.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleHookBuilder {
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    on_activate: Option<HookScript>,
    #[serde(skip_serializing_if = "Option::is_none")]
    on_destroy: Option<HookScript>,
    #[serde(skip_serializing_if = "Option::is_none")]
    on_attach: Option<HookScript>,
    #[serde(skip_serializing_if = "Option::is_none")]
    on_detach: Option<HookScript>,
    /// Accepts the removed `on_failure` key purely so [`build`](Self::build)
    /// can reject it by name. Never serialized; `deny_unknown_fields` would
    /// otherwise produce a generic unknown-field error that doesn't say what
    /// to migrate to.
    #[serde(default, skip_serializing)]
    on_failure: Option<HookScript>,
}

impl LifecycleHookBuilder {
    /// Sets the free-form description.
    #[must_use]
    pub fn with_description(self, description: impl Into<String>) -> Self {
        Self {
            description: Some(description.into()),
            ..self
        }
    }

    /// Sets the script to run on activation.
    #[must_use]
    pub fn with_on_activate(self, on_activate: HookScript) -> Self {
        Self {
            on_activate: Some(on_activate),
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

    /// Sets the script to run on attach.
    #[must_use]
    pub fn with_on_attach(self, on_attach: HookScript) -> Self {
        Self {
            on_attach: Some(on_attach),
            ..self
        }
    }

    /// Sets the script to run on detach.
    #[must_use]
    pub fn with_on_detach(self, on_detach: HookScript) -> Self {
        Self {
            on_detach: Some(on_detach),
            ..self
        }
    }

    /// Consumes the builder and produces a [`LifecycleHook`].
    ///
    /// # Errors
    ///
    /// - [`Error::OnFailureRemoved`] if the removed `on_failure` key was set.
    /// - [`Error::EmptyLifecycleHook`] if none of the four transitions has
    ///   been set.
    pub fn build(self) -> Result<LifecycleHook, Error> {
        // Checked before the emptiness test: a hook whose only script is an
        // `on_failure` should say that `on_failure` is gone, not that it is
        // empty.
        if self.on_failure.is_some() {
            return Err(Error::OnFailureRemoved);
        }
        if self.on_activate.is_none()
            && self.on_destroy.is_none()
            && self.on_attach.is_none()
            && self.on_detach.is_none()
        {
            return Err(Error::EmptyLifecycleHook);
        }
        Ok(LifecycleHook {
            description: self.description,
            on_activate: self.on_activate,
            on_destroy: self.on_destroy,
            on_attach: self.on_attach,
            on_detach: self.on_detach,
        })
    }
}

impl From<LifecycleHook> for LifecycleHookBuilder {
    fn from(value: LifecycleHook) -> Self {
        Self {
            description: value.description,
            on_activate: value.on_activate,
            on_destroy: value.on_destroy,
            on_attach: value.on_attach,
            on_detach: value.on_detach,
            on_failure: None,
        }
    }
}

// ---------------------------------------------------------------------------
// External script staging
// ---------------------------------------------------------------------------

/// Where an external hook script lands in the session's staged-hooks
/// directory, relative to that directory's root.
///
/// The client uploads scripts under these paths and the daemon resolves
/// them back from the same inputs, so the scheme is the contract
/// between the two and lives here rather than on either side. It is
/// derived purely from `(source, script path)` — there is no manifest
/// to keep in sync, and no id to allocate.
///
/// The layout mirrors where the script was declared, which keeps a
/// staged tree readable when someone goes looking:
///
/// ```text
/// hooks/loadout/dev/activate.sh     ← loadout `dev`, "activate.sh"
/// hooks/project/scripts/setup.sh    ← the project, "scripts/setup.sh"
/// ```
///
/// The script path is a [`ConfigRelPath`], which rejects absolute paths
/// and `..`. There is one project per session, so `project` needs no
/// discriminator.
///
/// The loadout name is validated **here** rather than trusted from the
/// [`Source`](crate::core::source::Source). A `Source` built on this
/// machine carries a name that came from a
/// [`LoadoutName`](crate::core::loadout::LoadoutName), but a `Source`
/// decoded from the wire carries whatever the peer sent — and the
/// daemon derives a path to *read* from exactly this function. A name
/// that is not a single ordinary path component would let that read
/// climb out of the staged-hooks directory, so it is refused rather
/// than interpolated. See [`safe_path_component`].
///
/// Returns `None` for [`Source::Package`](crate::core::source::Source::Package)
/// (packages cannot declare hooks, and the policy gate denies any that
/// appear, so there is nothing to stage) and for a loadout whose name is
/// unusable as a path component.
#[must_use]
pub fn staged_script_path(
    source: &crate::core::source::Source,
    script: &ConfigRelPath,
) -> Option<Utf8PathBuf> {
    use crate::core::source::Source;
    let prefix = match source {
        Source::UserLoadout { name } => {
            if !safe_path_component(name) {
                return None;
            }
            Utf8PathBuf::from("loadout").join(name)
        }
        Source::Project { .. } => Utf8PathBuf::from("project"),
        Source::Package { .. } => return None,
    };
    Some(prefix.join(script.as_utf8_path()))
}

/// Whether `s` is usable as a single path component that stays put:
/// non-empty, no separators or NUL, and not a relative-directory name.
///
/// [`LoadoutName`](crate::core::loadout::LoadoutName) enforces all of
/// this except the `.`/`..` cases — a name is a display string first and
/// a path fragment second, and neither dot form contains a separator.
/// Both are excluded here because this fragment is joined into a path
/// the daemon then reads from.
#[must_use]
pub fn safe_path_component(s: &str) -> bool {
    !s.is_empty() && s != "." && s != ".." && !s.contains(['/', '\\', '\0'])
}

// ---------------------------------------------------------------------------
// Wire → domain conversions
// ---------------------------------------------------------------------------

impl From<crate::wire::primitives::WireHookScript> for HookScript {
    fn from(s: crate::wire::primitives::WireHookScript) -> Self {
        use crate::wire::primitives::WireHookScript as W;
        // The wire form is produced by a peer, so its timeout is clamped
        // rather than rejected: a skewed or hostile peer must not be able to
        // fault a composition load, but it must not be able to exceed the cap
        // either.
        let (body, timeout_secs) = match s {
            W::Inline {
                body,
                timeout_secs: t,
            } => (HookScriptBody::Inline(body), t),
            W::External {
                path,
                timeout_secs: t,
            } => (HookScriptBody::External(path), t),
        };
        let timeout = Duration::from_secs(t_clamped(timeout_secs));
        Self { body, timeout }
    }
}

/// Clamp a peer-supplied timeout into `[1, MAX_HOOK_TIMEOUT]` seconds.
fn t_clamped(secs: u64) -> u64 {
    secs.clamp(1, MAX_HOOK_TIMEOUT.as_secs())
}

/// Fallible because the wire form may have all four callbacks absent, which
/// the builder rejects.
impl TryFrom<crate::wire::primitives::WireLifecycleHook> for LifecycleHook {
    type Error = Error;
    fn try_from(h: crate::wire::primitives::WireLifecycleHook) -> Result<Self, Self::Error> {
        let mut builder = Self::builder();
        // Read before `description` moves out of `h`.
        let discarded_on_failure = h.on_failure.is_some();
        if let Some(d) = h.description.clone() {
            builder = builder.with_description(d);
        }
        if let Some(s) = h.on_activate {
            builder = builder.with_on_activate(s.into());
        }
        if let Some(s) = h.on_destroy {
            builder = builder.with_on_destroy(s.into());
        }
        if let Some(s) = h.on_attach {
            builder = builder.with_on_attach(s.into());
        }
        if let Some(s) = h.on_detach {
            builder = builder.with_on_detach(s.into());
        }
        // `on_failure` was removed before hooks ever executed, so nothing
        // is losing behaviour here — but a v1 snapshot can still carry
        // one, and dropping a script the author wrote without saying so
        // is the failure mode the config-side `OnFailureRemoved` error
        // exists to prevent. Warn rather than reject: this is a load
        // path, and a session must still come up.
        if discarded_on_failure {
            tracing::warn!(
                description = h.description.as_deref().unwrap_or("<none>"),
                "discarding an `on_failure` script from an older composition \
                 snapshot; it has never executed — use `on_destroy`",
            );
        }
        builder.build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `Source` decoded from the wire carries whatever the peer sent,
    /// so a loadout name that is not a plain path component must not
    /// reach the staged path — the daemon joins that path onto the
    /// session's hooks directory and reads it, so a `..` there reads a
    /// file outside the session.
    #[test]
    fn a_loadout_name_that_is_not_a_path_component_stages_nothing() {
        use crate::core::source::Source;
        let script = ConfigRelPath::try_new("x.sh").unwrap();
        for hostile in [
            "../../../../etc",
            "..",
            ".",
            "",
            "a/b",
            r"a\b",
            "a\0b",
            "loadout/../..",
        ] {
            let source = Source::UserLoadout {
                name: hostile.to_string(),
            };
            assert_eq!(
                staged_script_path(&source, &script),
                None,
                "loadout name {hostile:?} produced a staged path",
            );
        }
    }

    /// The ordinary case still stages where the layout says it does.
    #[test]
    fn a_well_formed_loadout_stages_under_its_own_name() {
        use crate::core::source::Source;
        let script = ConfigRelPath::try_new("scripts/activate.sh").unwrap();
        let source = Source::UserLoadout {
            name: "dev".to_string(),
        };
        assert_eq!(
            staged_script_path(&source, &script),
            Some(Utf8PathBuf::from("loadout/dev/scripts/activate.sh")),
        );
    }

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
            .with_on_activate(HookScript::inline("a"))
            .build()
            .unwrap();
        assert!(hook.on_activate().is_some());
        assert!(hook.on_destroy().is_none());
        assert!(hook.on_attach().is_none());
        assert!(hook.on_detach().is_none());
    }

    /// Each of the four transitions on its own satisfies the
    /// at-least-one invariant.
    #[test]
    fn builder_accepts_any_single_transition() {
        let cases: [fn(LifecycleHookBuilder, HookScript) -> LifecycleHookBuilder; 4] = [
            LifecycleHookBuilder::with_on_activate,
            LifecycleHookBuilder::with_on_destroy,
            LifecycleHookBuilder::with_on_attach,
            LifecycleHookBuilder::with_on_detach,
        ];
        for set in cases {
            assert!(
                set(LifecycleHook::builder(), HookScript::inline("x"))
                    .build()
                    .is_ok()
            );
        }
    }

    #[test]
    fn toml_deserializes_all_four_transitions() {
        let src = r#"
            description = "everything"
            on_activate = { type = "inline",   value = "echo activated" }
            on_destroy  = { type = "external", value = "./teardown.sh" }
            on_attach   = { type = "inline",   value = "echo attached" }
            on_detach   = { type = "external", value = "./detach.sh" }
        "#;
        let hook: LifecycleHook = toml::from_str(src).unwrap();
        assert_eq!(hook.description(), Some("everything"));
        assert!(matches!(
            hook.on_activate().map(HookScript::body),
            Some(HookScriptBody::Inline(s)) if s == "echo activated",
        ));
        assert!(matches!(
            hook.on_destroy().map(HookScript::body),
            Some(HookScriptBody::External(p)) if p.as_str() == "./teardown.sh",
        ));
        assert!(matches!(
            hook.on_attach().map(HookScript::body),
            Some(HookScriptBody::Inline(s)) if s == "echo attached",
        ));
        assert!(matches!(
            hook.on_detach().map(HookScript::body),
            Some(HookScriptBody::External(p)) if p.as_str() == "./detach.sh",
        ));
    }

    #[test]
    fn toml_deserializes_partial_hook() {
        let src = r#"
            on_activate = { type = "inline", value = "echo hi" }
        "#;
        let hook: LifecycleHook = toml::from_str(src).unwrap();
        assert!(hook.on_activate().is_some());
        assert!(hook.on_destroy().is_none());
    }

    #[test]
    fn toml_rejects_empty_hook() {
        let err = toml::from_str::<LifecycleHook>("").unwrap_err();
        assert!(
            err.to_string().contains("on_activate"),
            "expected validation error, got: {err}",
        );
    }

    // -- timeouts ------------------------------------------------------

    /// The regression test for the reason [`HookScript`] is a struct
    /// rather than an adjacently-tagged enum: under adjacent tagging
    /// `timeout` is classified as an unrecognized field and silently
    /// skipped, so this hook would have run with the 60s default while
    /// claiming 120.
    #[test]
    fn timeout_is_not_silently_dropped() {
        let src = r#"on_activate = { type = "inline", value = "x", timeout = 120 }"#;
        let hook: LifecycleHook = toml::from_str(src).unwrap();
        assert_eq!(
            hook.on_activate().unwrap().timeout(),
            Duration::from_mins(2),
        );
    }

    #[test]
    fn timeout_defaults_when_absent() {
        let src = r#"on_activate = { type = "inline", value = "x" }"#;
        let hook: LifecycleHook = toml::from_str(src).unwrap();
        assert_eq!(hook.on_activate().unwrap().timeout(), DEFAULT_HOOK_TIMEOUT);
    }

    #[test]
    fn timeout_above_cap_is_rejected() {
        let over = MAX_HOOK_TIMEOUT.as_secs() + 1;
        let src = format!(r#"on_activate = {{ type = "inline", value = "x", timeout = {over} }}"#);
        let err = toml::from_str::<LifecycleHook>(&src).unwrap_err();
        assert!(
            err.to_string().contains("maximum"),
            "expected cap error, got: {err}",
        );
    }

    #[test]
    fn timeout_at_cap_is_accepted() {
        let at = MAX_HOOK_TIMEOUT.as_secs();
        let src = format!(r#"on_activate = {{ type = "inline", value = "x", timeout = {at} }}"#);
        let hook: LifecycleHook = toml::from_str(&src).unwrap();
        assert_eq!(hook.on_activate().unwrap().timeout(), MAX_HOOK_TIMEOUT);
    }

    #[test]
    fn zero_timeout_is_rejected() {
        let src = r#"on_activate = { type = "inline", value = "x", timeout = 0 }"#;
        let err = toml::from_str::<LifecycleHook>(src).unwrap_err();
        assert!(
            err.to_string().contains("greater than zero"),
            "expected zero-timeout error, got: {err}",
        );
    }

    /// A misspelled key inside a script table is an error rather than a
    /// silently-ignored no-op — the same failure mode that made `timeout`
    /// unusable under adjacent tagging.
    #[test]
    fn unknown_key_in_script_table_is_rejected() {
        let src = r#"on_activate = { type = "inline", value = "x", timout = 120 }"#;
        let err = toml::from_str::<LifecycleHook>(src).unwrap_err();
        assert!(
            err.to_string().contains("timout") || err.to_string().contains("unknown field"),
            "expected unknown-field error, got: {err}",
        );
    }

    #[test]
    fn unknown_key_in_hook_table_is_rejected() {
        let src = r#"
            on_activate = { type = "inline", value = "x" }
            on_activte  = { type = "inline", value = "typo" }
        "#;
        assert!(toml::from_str::<LifecycleHook>(src).is_err());
    }

    // -- on_failure migration ------------------------------------------

    #[test]
    fn on_failure_is_rejected_by_name() {
        let src = r#"
            on_activate = { type = "inline", value = "x" }
            on_failure  = { type = "inline", value = "old" }
        "#;
        let err = toml::from_str::<LifecycleHook>(src).unwrap_err();
        assert!(
            err.to_string().contains("on_destroy"),
            "error should name the replacement, got: {err}",
        );
    }

    /// A hook whose *only* script is the removed `on_failure` reports the
    /// removal, not emptiness — the emptiness error would send the author
    /// looking for a missing script rather than a renamed one.
    #[test]
    fn lone_on_failure_reports_removal_not_emptiness() {
        let src = r#"on_failure = { type = "inline", value = "old" }"#;
        let err = toml::from_str::<LifecycleHook>(src).unwrap_err();
        assert!(
            err.to_string().contains("on_destroy"),
            "expected removal error, got: {err}",
        );
    }

    // -- round trips ---------------------------------------------------

    #[test]
    fn serde_round_trip_through_toml() {
        let original = LifecycleHook::builder()
            .with_description("d")
            .with_on_activate(HookScript::inline("echo hi"))
            .with_on_detach(
                HookScript::try_external("./fail.sh")
                    .unwrap()
                    .with_timeout(Duration::from_mins(2))
                    .unwrap(),
            )
            .build()
            .unwrap();

        let serialized = toml::to_string(&original).unwrap();
        let parsed: LifecycleHook = toml::from_str(&serialized).unwrap();
        assert_eq!(parsed, original);
        assert_eq!(
            parsed.on_detach().unwrap().timeout(),
            Duration::from_mins(2),
        );
    }

    #[test]
    fn hook_script_try_external_helper() {
        let s = HookScript::try_external("./run.sh").unwrap();
        assert!(matches!(s.body(), HookScriptBody::External(p) if p.as_str() == "./run.sh"));
        assert_eq!(s.timeout(), DEFAULT_HOOK_TIMEOUT);
    }

    #[test]
    fn hook_script_try_external_rejects_absolute() {
        let err = HookScript::try_external("/abs").unwrap_err();
        assert!(
            matches!(err, Error::Path(paths::Error::IsAbsolute(_))),
            "got: {err:?}"
        );
    }

    #[test]
    fn hook_script_try_external_rejects_parent_dir() {
        let err = HookScript::try_external("../escape.sh").unwrap_err();
        assert!(
            matches!(err, Error::Path(paths::Error::ContainsParentDir(_))),
            "got: {err:?}",
        );
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
        assert!(
            matches!(parsed.hook.body(), HookScriptBody::External(p) if p.as_str() == "./run.sh"),
        );
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
    fn external_rejects_parent_dir_at_deserialize() {
        let src = r#"
            on_activate = { type = "external", value = "../etc/hook.sh" }
        "#;
        assert!(toml::from_str::<LifecycleHook>(src).is_err());
    }

    #[test]
    fn serde_omits_unset_fields() {
        let hook = LifecycleHook::builder()
            .with_on_activate(HookScript::inline("x"))
            .build()
            .unwrap();
        let serialized = toml::to_string(&hook).unwrap();
        assert!(serialized.contains("on_activate"));
        assert!(!serialized.contains("on_destroy"));
        assert!(!serialized.contains("on_attach"));
        assert!(!serialized.contains("on_detach"));
        assert!(!serialized.contains("on_failure"));
        // A default timeout stays undeclared rather than materializing on
        // round-trip.
        assert!(!serialized.contains("timeout"));
    }

    /// A peer-supplied timeout above the cap is clamped rather than
    /// faulting the conversion: the wire path must not let a skewed or
    /// hostile peer fail a composition load, nor exceed the bound.
    #[test]
    fn wire_timeout_is_clamped_not_rejected() {
        use crate::wire::primitives::WireHookScript;
        let s: HookScript = WireHookScript::Inline {
            body: "x".into(),
            timeout_secs: u64::MAX,
        }
        .into();
        assert_eq!(s.timeout(), MAX_HOOK_TIMEOUT);

        let s: HookScript = WireHookScript::Inline {
            body: "x".into(),
            timeout_secs: 0,
        }
        .into();
        assert_eq!(s.timeout(), Duration::from_secs(1));
    }
}
