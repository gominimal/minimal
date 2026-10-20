//! Wire-form primitives for client/daemon RPC.
//!
//! These are JSON-shaped mirrors of the local domain types. They live
//! in their own module — and have their own `serde` derives — so that
//! the wire schema can evolve independently of the TOML wire forms
//! used at config load. Nothing here uses `#[serde(untagged)]`.

/// Origin of a contributed item. Mirrors [`crate::core::source::Source`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WireSource {
    /// User loadout, identified by name.
    UserLoadout {
        /// Loadout name.
        name: String,
    },
    /// Project (`minimal.toml`) at the given host path.
    Project {
        /// Host path to the project directory.
        path: paths::HostPath,
    },
    /// Package, identified by name.
    Package {
        /// Package name.
        name: String,
    },
}

/// Orientation facts for the attached shell's first-prompt banner.
/// Mirrors [`crate::core::compose::Orientation`].
///
/// Control-plane data, deliberately NOT a session var: it rides the
/// composition as a first-class field so user vars and user policy can
/// never collide with it. The daemon seeds the banner env
/// (`MINIMAL_LOADOUTS`) from it in the launcher baseline. Serde-defaulted
/// end to end so peers that predate the field interop cleanly.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct WireOrientation {
    /// Human-readable display list of the active loadouts (comma-joined
    /// names, `default (built-in)` for the zero-config fallback, `none`
    /// with `--no-loadouts`). Empty means "unknown" — a peer that
    /// predates the field — and seeds nothing, leaving the banner
    /// template's own `${MINIMAL_LOADOUTS:-…}` fallback to render.
    #[serde(default)]
    pub loadouts_display: String,
}

impl From<crate::core::compose::Orientation> for WireOrientation {
    fn from(o: crate::core::compose::Orientation) -> Self {
        Self {
            loadouts_display: o.loadouts_display,
        }
    }
}

impl From<WireOrientation> for crate::core::compose::Orientation {
    fn from(o: WireOrientation) -> Self {
        Self {
            loadouts_display: o.loadouts_display,
        }
    }
}

/// A fully-resolved variable: name and value as plain strings.
///
/// Mirrors [`crate::core::primitives::ResolvedVar`] in a form
/// guaranteed to be JSON-serializable without reaching for any
/// validating newtype.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct WireResolvedVar {
    /// Variable name.
    pub name: String,
    /// Resolved value.
    pub value: String,
    /// Whether the resolved value carries data pulled from the
    /// caller's environment. Preserved across the wire so downstream
    /// consumers (audit logs, telemetry, future secret-scrubbing
    /// heuristics) can distinguish an env-derived value from a
    /// hardcoded literal. Not a gate signal — the policy check ran
    /// on the client before this ever hit the wire — so a peer that
    /// omits the field defaults to `false`, matching the safer
    /// assumption for provenance-tracking consumers (a literal
    /// treated as a literal, rather than a literal spuriously tagged
    /// as env-derived).
    #[serde(default)]
    pub carries_user_data: bool,
}

/// How a variable should resolve. Mirrors
/// [`crate::core::primitives::VarValue`] but uses an explicitly tagged
/// enum so JSON round-trips deterministically.
///
/// `Inherit` and `InheritWithDefault` are only meaningful before
/// resolution — once the client has resolved a value, it ships as
/// `WireResolvedVar`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WireVarSpec {
    /// Literal value, takes effect verbatim.
    Specified {
        /// Variable value.
        value: String,
    },
    /// Inherit from the parent environment; the client resolves.
    Inherit,
    /// Inherit from the parent environment; if unset, use `default`.
    InheritWithDefault {
        /// Fallback when the parent env has no entry.
        default: String,
    },
}

/// A resolved patch: where it lives on the host and where it lands in
/// the sandbox. Mirrors [`crate::core::primitives::ResolvedPatch`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct WireResolvedPatch {
    /// Absolute host path of the source file.
    pub host_path: paths::HostAbsPath,
    /// Destination inside the sandbox, relative to the sandbox user's
    /// home directory. Deserialization rejects absolute paths.
    pub destination: paths::SandboxRelPath,
}

/// A resolved variable + its origin. Mirrors
/// [`crate::core::compose::SessionVar`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct WireSessionVar {
    /// Resolved variable.
    pub var: WireResolvedVar,
    /// Where it came from.
    pub source: WireSource,
}

/// A resolved patch + its origin. Mirrors
/// [`crate::core::compose::SessionPatch`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct WireSessionPatch {
    /// Resolved patch.
    pub patch: WireResolvedPatch,
    /// Where it came from.
    pub source: WireSource,
}

/// Timeout a peer that predates the `timeout_secs` field is assumed to
/// have meant. Matches
/// [`DEFAULT_HOOK_TIMEOUT`](crate::core::lifecyclehook::DEFAULT_HOOK_TIMEOUT).
fn default_hook_timeout_secs() -> u64 {
    crate::core::lifecyclehook::DEFAULT_HOOK_TIMEOUT.as_secs()
}

/// A lifecycle hook script. Mirrors
/// [`crate::core::lifecyclehook::HookScript`].
///
/// `timeout_secs` is serde-defaulted so payloads from peers that predate
/// the field deserialize cleanly. The domain conversion clamps it into
/// range rather than rejecting, so a skewed peer can't fault a load.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WireHookScript {
    /// Script body stored inline.
    Inline {
        /// Script body.
        body: String,
        /// Timeout in whole seconds.
        #[serde(default = "default_hook_timeout_secs")]
        timeout_secs: u64,
    },
    /// Path to a script file, resolved against its anchor at apply time.
    External {
        /// Config-relative path to the script.
        path: paths::ConfigRelPath,
        /// Timeout in whole seconds.
        #[serde(default = "default_hook_timeout_secs")]
        timeout_secs: u64,
    },
}

/// A lifecycle hook. Mirrors
/// [`crate::core::lifecyclehook::LifecycleHook`].
///
/// Every field is serde-defaulted and skipped when unset, so this shape
/// tolerates version skew in both directions: a peer that predates
/// `description` / `on_attach` / `on_detach` simply omits them, and the
/// removed `on_failure` sent by an older peer is ignored rather than
/// faulting the message (unknown fields are not denied here — leniency is
/// deliberate on the wire, unlike the config-file form).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct WireLifecycleHook {
    /// Free-form description, carried so `min session hooks` can label
    /// each hook with what its author called it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Run on session activation, if set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_activate: Option<WireHookScript>,
    /// Run on session destruction, if set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_destroy: Option<WireHookScript>,
    /// Run when a client attaches, if set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_attach: Option<WireHookScript>,
    /// Run when a client detaches, if set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_detach: Option<WireHookScript>,
    /// The removed `on_failure` transition, captured only so a v1
    /// snapshot carrying one can be reported rather than silently
    /// losing a script. Never written (it is skipped when unset, and
    /// nothing sets it) and never converted into a
    /// [`LifecycleHook`](crate::core::lifecyclehook::LifecycleHook) —
    /// see that conversion for where the warning is logged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_failure: Option<WireHookScript>,
}

/// A lifecycle hook + its origin. Mirrors
/// [`crate::core::source::ProvenancedHook`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct WireProvenancedHook {
    /// The hook.
    pub hook: WireLifecycleHook,
    /// Where it came from.
    pub source: WireSource,
}

/// A package the client requested be installed. Mirrors
/// [`crate::core::source::ProvenancedPackage`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct WirePackageRef {
    /// Package name.
    pub name: String,
    /// Where it was requested from.
    pub source: WireSource,
}

/// Daemon-issued correlation token for a single pending item. Scoped
/// to one [`crate::wire::request::ContributionResponse`] — the client
/// echoes each id back in the corresponding verdict.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct PendingId(u32);

impl PendingId {
    /// Construct from a raw id. The daemon is responsible for
    /// uniqueness within a [`crate::wire::request::ContributionResponse`].
    #[must_use]
    pub fn new(id: u32) -> Self {
        Self(id)
    }

    /// Underlying integer.
    #[must_use]
    pub fn get(self) -> u32 {
        self.0
    }
}

/// Daemon → Client: a variable from a package or the project that
/// needs the client to resolve (if inherit-shaped) and run through
/// user policy.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct WirePendingVar {
    /// Correlation id; the client echoes it back on the verdict.
    pub id: PendingId,
    /// Variable name.
    pub name: String,
    /// How to resolve. Inherit-shaped variants require client-side env
    /// lookup.
    pub spec: WireVarSpec,
    /// Where it came from.
    pub source: WireSource,
    /// Whether the value the client will end up with was originally
    /// pulled from a host environment lookup rather than a hardcoded
    /// literal or a fallback default. Set by
    /// `contribution_to_pending` on the daemon side from the
    /// daemon-resolved `ResolvedVar::carries_user_data`; consumed by
    /// the client's `classify_var` to decide whether the policy gate
    /// applies. Defaults to `false` for wire messages emitted before
    /// this field existed (backward-compatible).
    #[serde(default)]
    pub carries_user_data: bool,
}

/// Daemon → Client: a lifecycle hook from the project that the client
/// must run through the user's hooks policy before it may execute.
///
/// Carries the hook itself so the client can show the user what it is
/// being asked to approve — a prompt that named only the project would
/// be asking for consent to code the user cannot see.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct WirePendingHook {
    /// Correlation id; the client echoes it back on the verdict.
    pub id: PendingId,
    /// The hook awaiting a decision.
    pub hook: WireLifecycleHook,
    /// Where it came from — the project root the policy matches.
    pub source: WireSource,
}

/// Daemon → Client: a patch from a package or the project that the
/// client will expand (against its already-gated vars) and run
/// through user policy.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct WirePendingPatch {
    /// Correlation id; the client echoes it back on the verdict.
    pub id: PendingId,
    /// Raw, unexpanded source path expression. Client expands using
    /// its resolved vars + tilde-fallback.
    pub source_pattern: String,
    /// Destination inside the sandbox, relative to the sandbox user's
    /// home directory. Deserialization rejects absolute paths.
    pub destination: paths::SandboxRelPath,
    /// Optional free-form description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Where it came from.
    pub source: WireSource,
}

// ---------------------------------------------------------------------------
// Domain → wire conversions.
//
// The wire schema is structurally separate from the local domain types
// (so it can evolve independently), but the *content* is the same.
// These `From` impls package a domain `Composition` into the wire form
// the client ships to the daemon.

impl From<crate::core::source::Source> for WireSource {
    fn from(s: crate::core::source::Source) -> Self {
        match s {
            crate::core::source::Source::UserLoadout { name } => Self::UserLoadout { name },
            crate::core::source::Source::Project { path } => Self::Project { path },
            crate::core::source::Source::Package { name } => Self::Package { name },
        }
    }
}

impl From<crate::core::primitives::ResolvedVar> for WireResolvedVar {
    fn from(v: crate::core::primitives::ResolvedVar) -> Self {
        let (name, value, carries_user_data) = v.into_parts_with_provenance();
        Self {
            name,
            value,
            carries_user_data,
        }
    }
}

impl From<crate::core::primitives::ResolvedPatch> for WireResolvedPatch {
    fn from(p: crate::core::primitives::ResolvedPatch) -> Self {
        let (host_path, destination) = p.into_parts();
        Self {
            host_path,
            destination,
        }
    }
}

impl From<crate::core::compose::SessionVar> for WireSessionVar {
    fn from(v: crate::core::compose::SessionVar) -> Self {
        let (var, source) = v.into_parts();
        Self {
            var: var.into(),
            source: source.into(),
        }
    }
}

impl From<crate::core::compose::SessionPatch> for WireSessionPatch {
    fn from(p: crate::core::compose::SessionPatch) -> Self {
        let (patch, source) = p.into_parts();
        Self {
            patch: patch.into(),
            source: source.into(),
        }
    }
}

impl From<crate::core::lifecyclehook::HookScript> for WireHookScript {
    fn from(s: crate::core::lifecyclehook::HookScript) -> Self {
        use crate::core::lifecyclehook::HookScriptBody;
        let (body, timeout) = s.into_parts();
        let timeout_secs = timeout.as_secs();
        match body {
            HookScriptBody::Inline(body) => Self::Inline { body, timeout_secs },
            HookScriptBody::External(path) => Self::External { path, timeout_secs },
        }
    }
}

impl From<crate::core::lifecyclehook::LifecycleHook> for WireLifecycleHook {
    fn from(h: crate::core::lifecyclehook::LifecycleHook) -> Self {
        let (description, on_activate, on_destroy, on_attach, on_detach) = h.into_parts();
        Self {
            description,
            on_activate: on_activate.map(Into::into),
            on_destroy: on_destroy.map(Into::into),
            on_attach: on_attach.map(Into::into),
            // Never emitted: the domain type has no such transition.
            on_failure: None,
            on_detach: on_detach.map(Into::into),
        }
    }
}

impl From<crate::core::source::ProvenancedHook> for WireProvenancedHook {
    fn from(h: crate::core::source::ProvenancedHook) -> Self {
        let (hook, source) = h.into_parts();
        Self {
            hook: hook.into(),
            source: source.into(),
        }
    }
}

impl From<crate::core::source::ProvenancedPackage> for WirePackageRef {
    fn from(p: crate::core::source::ProvenancedPackage) -> Self {
        let (name, source) = p.into_parts();
        Self {
            name,
            source: source.into(),
        }
    }
}

// Wire → domain conversions live alongside each domain type — see
// `core::primitives`, `core::source`, `core::lifecyclehook`, and
// `core::compose`.

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip<T>(value: &T) -> T
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let json = serde_json_lenient::to_string(value).expect("serialize");
        serde_json_lenient::from_str(&json).expect("deserialize")
    }

    fn user_source() -> WireSource {
        WireSource::UserLoadout { name: "dev".into() }
    }

    #[test]
    fn source_round_trips_all_variants() {
        let cases = [
            WireSource::UserLoadout { name: "dev".into() },
            WireSource::Project {
                path: paths::HostPath::try_new("/repo").unwrap(),
            },
            WireSource::Package {
                name: "helix".into(),
            },
        ];
        for s in cases {
            assert_eq!(round_trip(&s), s);
        }
    }

    #[test]
    fn source_uses_explicit_kind_tag() {
        let json = serde_json_lenient::to_string(&user_source()).unwrap();
        assert!(
            json.contains(r#""kind":"user_loadout""#),
            "expected `kind` tag, got: {json}"
        );
    }

    #[test]
    fn var_spec_round_trips_all_variants() {
        let cases = [
            WireVarSpec::Specified { value: "hx".into() },
            WireVarSpec::Inherit,
            WireVarSpec::InheritWithDefault {
                default: "C".into(),
            },
        ];
        for s in cases {
            assert_eq!(round_trip(&s), s);
        }
    }

    #[test]
    fn resolved_var_round_trips() {
        let v = WireResolvedVar {
            name: "EDITOR".into(),
            value: "hx".into(),
            carries_user_data: true,
        };
        assert_eq!(round_trip(&v), v);
    }

    /// `carries_user_data` defaults to `false` on deserialization so
    /// an older peer that omits the field doesn't fail to parse; a
    /// value present in the wire round-trips verbatim.
    #[test]
    fn resolved_var_default_carries_user_data_is_false() {
        let raw = serde_json_lenient::json!({
            "name": "EDITOR",
            "value": "hx",
        });
        let v: WireResolvedVar = serde_json_lenient::from_value(raw).expect("deserialize");
        assert!(!v.carries_user_data);
    }

    #[test]
    fn resolved_patch_round_trips() {
        let p = WireResolvedPatch {
            host_path: paths::HostAbsPath::try_new("/home/u/.gitconfig").unwrap(),
            destination: paths::SandboxRelPath::try_new(".gitconfig").unwrap(),
        };
        assert_eq!(round_trip(&p), p);
    }

    #[test]
    fn session_var_round_trips() {
        let v = WireSessionVar {
            var: WireResolvedVar {
                name: "EDITOR".into(),
                value: "hx".into(),
                carries_user_data: true,
            },
            source: user_source(),
        };
        assert_eq!(round_trip(&v), v);
    }

    #[test]
    fn session_patch_round_trips() {
        let p = WireSessionPatch {
            patch: WireResolvedPatch {
                host_path: paths::HostAbsPath::try_new("/home/u/.gitconfig").unwrap(),
                destination: paths::SandboxRelPath::try_new(".gitconfig").unwrap(),
            },
            source: user_source(),
        };
        assert_eq!(round_trip(&p), p);
    }

    #[test]
    fn hook_script_round_trips_both_variants() {
        let cases = [
            WireHookScript::Inline {
                body: "echo hi".into(),
                timeout_secs: 60,
            },
            WireHookScript::External {
                path: paths::ConfigRelPath::try_new("hooks/run.sh").unwrap(),
                timeout_secs: 120,
            },
        ];
        for s in cases {
            assert_eq!(round_trip(&s), s);
        }
    }

    /// A payload from a peer that predates `timeout_secs` deserializes to
    /// the default rather than failing or landing on zero.
    #[test]
    fn hook_script_timeout_defaults_when_absent() {
        let raw = serde_json_lenient::json!({ "kind": "inline", "body": "echo hi" });
        let s: WireHookScript = serde_json_lenient::from_value(raw).expect("deserialize");
        assert_eq!(
            s,
            WireHookScript::Inline {
                body: "echo hi".into(),
                timeout_secs: default_hook_timeout_secs(),
            },
        );
    }

    #[test]
    fn lifecycle_hook_round_trips_with_optional_fields() {
        let h = WireLifecycleHook {
            description: Some("warm caches".into()),
            on_activate: Some(WireHookScript::Inline {
                body: "echo activated".into(),
                timeout_secs: 60,
            }),
            on_destroy: None,
            on_attach: None,
            on_detach: Some(WireHookScript::External {
                path: paths::ConfigRelPath::try_new("detach.sh").unwrap(),
                timeout_secs: 30,
            }),
            on_failure: None,
        };
        assert_eq!(round_trip(&h), h);
    }

    /// A message from a peer that still sends the removed `on_failure`
    /// deserializes cleanly, dropping the field. Wire-level leniency is
    /// deliberate: version skew must not fault a session.
    #[test]
    fn lifecycle_hook_ignores_legacy_on_failure() {
        let raw = serde_json_lenient::json!({
            "on_activate": { "kind": "inline", "body": "x" },
            "on_failure":  { "kind": "inline", "body": "old" },
        });
        let h: WireLifecycleHook = serde_json_lenient::from_value(raw).expect("deserialize");
        assert!(h.on_activate.is_some());
        assert!(h.description.is_none());
    }

    #[test]
    fn empty_lifecycle_hook_omits_unset_fields() {
        let h = WireLifecycleHook::default();
        let json = serde_json_lenient::to_string(&h).unwrap();
        assert_eq!(json, "{}");
        assert_eq!(round_trip(&h), h);
    }

    #[test]
    fn provenanced_hook_round_trips() {
        let h = WireProvenancedHook {
            hook: WireLifecycleHook {
                on_activate: Some(WireHookScript::Inline {
                    body: "echo hi".into(),
                    timeout_secs: 60,
                }),
                ..Default::default()
            },
            source: user_source(),
        };
        assert_eq!(round_trip(&h), h);
    }

    /// The domain → wire → domain trip preserves a non-default timeout.
    /// Guards the seam that made `timeout` unusable under adjacent
    /// tagging: a value that survives TOML but is dropped on the wire is
    /// equally broken.
    #[test]
    fn timeout_survives_domain_wire_round_trip() {
        use crate::core::lifecyclehook::HookScript;
        let original = HookScript::inline("x")
            .with_timeout(std::time::Duration::from_mins(2))
            .unwrap();
        let wire: WireHookScript = original.clone().into();
        let back: HookScript = round_trip(&wire).into();
        assert_eq!(back, original);
    }

    #[test]
    fn package_ref_round_trips() {
        let p = WirePackageRef {
            name: "helix".into(),
            source: user_source(),
        };
        assert_eq!(round_trip(&p), p);
    }

    #[test]
    fn pending_id_round_trips_transparently() {
        let id = PendingId::new(42);
        let json = serde_json_lenient::to_string(&id).unwrap();
        // `serde(transparent)` produces a bare integer.
        assert_eq!(json, "42");
        assert_eq!(round_trip(&id), id);
    }

    #[test]
    fn pending_var_round_trips() {
        let v = WirePendingVar {
            id: PendingId::new(1),
            name: "RUSTC".into(),
            spec: WireVarSpec::InheritWithDefault {
                default: "rustc".into(),
            },
            source: WireSource::Package {
                name: "rust-toolchain".into(),
            },
            carries_user_data: true,
        };
        assert_eq!(round_trip(&v), v);
    }

    #[test]
    fn pending_patch_round_trips() {
        let p = WirePendingPatch {
            id: PendingId::new(2),
            source_pattern: "$XDG_CONFIG_HOME/helix/**/*.toml".into(),
            destination: paths::SandboxRelPath::try_new(".config/helix/").unwrap(),
            description: Some("helix configs".into()),
            source: WireSource::Package {
                name: "helix".into(),
            },
        };
        assert_eq!(round_trip(&p), p);
    }

    #[test]
    fn pending_patch_omits_description_when_none() {
        let p = WirePendingPatch {
            id: PendingId::new(2),
            source_pattern: "$HOME/.gitconfig".into(),
            destination: paths::SandboxRelPath::try_new(".gitconfig").unwrap(),
            description: None,
            source: WireSource::UserLoadout { name: "dev".into() },
        };
        let json = serde_json_lenient::to_string(&p).unwrap();
        assert!(!json.contains("description"), "got: {json}");
    }
}
