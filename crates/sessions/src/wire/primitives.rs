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

/// A lifecycle hook script. Mirrors
/// [`crate::core::lifecyclehook::HookScript`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WireHookScript {
    /// Script body stored inline.
    Inline {
        /// Script body.
        body: String,
    },
    /// Path to a script file, resolved against the config dir at
    /// apply time.
    External {
        /// Config-relative path to the script.
        path: paths::ConfigRelPath,
    },
}

/// A lifecycle hook. Mirrors
/// [`crate::core::lifecyclehook::LifecycleHook`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct WireLifecycleHook {
    /// Run on session activation, if set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_activate: Option<WireHookScript>,
    /// Run on session destruction, if set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_destroy: Option<WireHookScript>,
    /// Run on session failure, if set.
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
        match s {
            crate::core::lifecyclehook::HookScript::Inline(body) => Self::Inline { body },
            crate::core::lifecyclehook::HookScript::External(path) => Self::External { path },
        }
    }
}

impl From<crate::core::lifecyclehook::LifecycleHook> for WireLifecycleHook {
    fn from(h: crate::core::lifecyclehook::LifecycleHook) -> Self {
        let (_description, on_activate, on_destroy, on_failure) = h.into_parts();
        Self {
            on_activate: on_activate.map(Into::into),
            on_destroy: on_destroy.map(Into::into),
            on_failure: on_failure.map(Into::into),
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
        let json = serde_json::to_string(value).expect("serialize");
        serde_json::from_str(&json).expect("deserialize")
    }

    fn user_source() -> WireSource {
        WireSource::UserLoadout { name: "dev".into() }
    }

    #[test]
    fn source_round_trips_all_variants() {
        let cases = [
            WireSource::UserLoadout { name: "dev".into() },
            WireSource::Project {
                path: paths::HostPath::new("/repo"),
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
        let json = serde_json::to_string(&user_source()).unwrap();
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
        let raw = serde_json::json!({
            "name": "EDITOR",
            "value": "hx",
        });
        let v: WireResolvedVar = serde_json::from_value(raw).expect("deserialize");
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
            },
            WireHookScript::External {
                path: paths::ConfigRelPath::try_new("hooks/run.sh").unwrap(),
            },
        ];
        for s in cases {
            assert_eq!(round_trip(&s), s);
        }
    }

    #[test]
    fn lifecycle_hook_round_trips_with_optional_fields() {
        let h = WireLifecycleHook {
            on_activate: Some(WireHookScript::Inline {
                body: "echo activated".into(),
            }),
            on_destroy: None,
            on_failure: Some(WireHookScript::External {
                path: paths::ConfigRelPath::try_new("fail.sh").unwrap(),
            }),
        };
        assert_eq!(round_trip(&h), h);
    }

    #[test]
    fn empty_lifecycle_hook_omits_unset_fields() {
        let h = WireLifecycleHook::default();
        let json = serde_json::to_string(&h).unwrap();
        assert_eq!(json, "{}");
        assert_eq!(round_trip(&h), h);
    }

    #[test]
    fn provenanced_hook_round_trips() {
        let h = WireProvenancedHook {
            hook: WireLifecycleHook {
                on_activate: Some(WireHookScript::Inline {
                    body: "echo hi".into(),
                }),
                ..Default::default()
            },
            source: user_source(),
        };
        assert_eq!(round_trip(&h), h);
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
        let json = serde_json::to_string(&id).unwrap();
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
        let json = serde_json::to_string(&p).unwrap();
        assert!(!json.contains("description"), "got: {json}");
    }
}
