//! The Box Spec: the settings a box is created from. The client builds it,
//! sends it to the daemon on the create request, and the daemon stores it
//! beside the box's record (BOX-068).
//!
//! This is the first version, `v = 0`. It is built from the project's
//! `[session]` table or a declared `[tasks.<name>]` entry, and from the
//! command-line flags of the creating command. It serializes under the
//! `box.toml` tables: `box.type`, `io.pty_enabled`, `install.packages`,
//! `network.mode` and `network.egress.*`.
//!
//! The v0 bytes also carry keys that `box.toml` does not have. #2410 ends
//! each of these exceptions when it bumps [`BOX_SPEC_VERSION`]:
//!
//! - The top-level keys `v`, `entry` and `hooks_enabled`. #2410 removes them
//!   or maps them to `box.toml` tables.
//! - `network.ingress` keeps the [`boxes::IngressPolicy`] shape
//!   (`port_mappings`, `dynamic_allowed_range`, `dynamic_ingress`), not the
//!   `box.toml` `[{proto, port}]` list.
//! - A declared `credentialed_upstream` writes under `[network]`. In
//!   `box.toml` that set comes from `[secrets]` and is never declared.
//!
//! A reader of a stored spec branches on `v` before it reads anything else.
//!
//! [`BoxSpec::for_session`] and [`BoxSpec::for_task`] are an interim
//! builder. #2410 (T16, BOX-064) replaces them with the expansion over the
//! Box Type, `[defaults]`, `[upstream]` and loadouts. The interim ends when
//! that expander lands, writes this file, and bumps [`BOX_SPEC_VERSION`].

use crate::{Session, Task};

/// The version of the Box Spec shape that [`BoxSpec`] serializes.
pub const BOX_SPEC_VERSION: u32 = 0;

/// The entry name of a session box that names no entry of its own: the
/// implicit `default` session.
pub const DEFAULT_SESSION_ENTRY: &str = "default";

/// A box's spec, as the client sends it on the create request.
///
/// Every list is in a fixed order and every map is ordered, so two builds
/// over the same inputs serialize to the same bytes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(into = "SpecDoc", from = "SpecDoc")]
pub struct BoxSpec {
    /// The spec shape's version, [`BOX_SPEC_VERSION`].
    pub v: u32,
    /// The Box Type's name: `session` or `task`. Serialized as `box.type`.
    pub box_type: String,
    /// The entry the box comes from: a task's name, or
    /// [`DEFAULT_SESSION_ENTRY`] for a session.
    pub entry: String,
    /// The packages the entry asks for, in declaration order, each once.
    /// Serialized as `install.packages`.
    pub packages: Vec<String>,
    /// Whether the box runs with a terminal. Serialized as `io.pty_enabled`.
    pub pty_enabled: bool,
    /// Whether the box runs its lifecycle hooks.
    pub hooks_enabled: bool,
    /// The box's network settings.
    pub network: SpecNetwork,
}

/// The network half of a [`BoxSpec`]. It serializes as the `[network]`
/// table: `mode`, then the policy's `egress` and `ingress` tables, and its
/// `credentialed_upstream` and `quic443` when it sets them.
///
/// This is a v0 exception to `box.toml`, which #2410 ends. `ingress` keeps
/// the [`boxes::IngressPolicy`] shape (`port_mappings`,
/// `dynamic_allowed_range`, `dynamic_ingress`), not the `box.toml` shape.
/// A declared `credentialed_upstream` writes under `[network]`, but
/// `box.toml` derives that set from `[secrets]` and never declares it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecNetwork {
    /// The network isolation mode. Serialized as its spec word: `none`,
    /// `host_ip` or `own_ip`.
    pub mode: boxes::NetworkMode,
    /// The egress and ingress policy the creating command resolved.
    pub policy: boxes::BoxPolicy,
}

/// What the creating command's flags set on the spec. This is the last
/// layer, so each value here replaces the one an entry sets.
///
/// The default has hooks on, as a plain create request does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecFlags {
    /// The network mode, from `--network`.
    pub network: boxes::NetworkMode,
    /// The policy that the egress and ingress flags and the project's
    /// `[session]` table resolve to.
    pub policy: boxes::BoxPolicy,
    /// Cleared by `--no-hooks`.
    pub hooks_enabled: bool,
}

impl Default for SpecFlags {
    fn default() -> Self {
        Self {
            network: boxes::NetworkMode::default(),
            policy: boxes::BoxPolicy::default(),
            hooks_enabled: true,
        }
    }
}

impl BoxSpec {
    /// The spec of a session box, from the project's `[session]` table
    /// (`None` when the project has none) and the flags.
    #[must_use]
    pub fn for_session(session: Option<&Session>, flags: SpecFlags) -> Self {
        let packages = session.map_or(&[][..], |s| s.packages.as_slice());
        Self::build(
            boxes::SESSION_BOX_TYPE,
            DEFAULT_SESSION_ENTRY,
            packages,
            true,
            flags,
        )
    }

    /// The spec of a task box, from the `[tasks.<name>]` entry and the
    /// flags. A task's spec carries the request's box policy, which a task
    /// leaves at the default.
    ///
    /// `None` for an interactive task. The `task` Box Type denies a
    /// terminal, so no `task` spec has `pty_enabled = true`.
    #[must_use]
    pub fn for_task(name: &str, task: &Task, flags: SpecFlags) -> Option<Self> {
        if task.interactive {
            return None;
        }
        Some(Self::build(
            boxes::TASK_BOX_TYPE,
            name,
            &task.packages,
            false,
            flags,
        ))
    }

    fn build(
        box_type: &str,
        entry: &str,
        packages: &[String],
        pty_enabled: bool,
        flags: SpecFlags,
    ) -> Self {
        let mut seen = std::collections::BTreeSet::new();
        let packages = packages
            .iter()
            .filter(|p| seen.insert(p.as_str()))
            .cloned()
            .collect();
        Self {
            v: BOX_SPEC_VERSION,
            box_type: box_type.to_string(),
            entry: entry.to_string(),
            packages,
            pty_enabled,
            hooks_enabled: flags.hooks_enabled,
            network: SpecNetwork {
                mode: flags.network,
                policy: flags.policy,
            },
        }
    }
}

/// The serialized shape of a [`BoxSpec`], under the `box.toml` tables.
/// Plain values come before tables, so the shape also writes as TOML.
///
/// `v`, `entry` and `hooks_enabled` are v0 keys that `box.toml` does not
/// have. #2410 removes or maps them when it bumps [`BOX_SPEC_VERSION`], so
/// a reader of a stored spec branches on `v`.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SpecDoc {
    v: u32,
    entry: String,
    hooks_enabled: bool,
    #[serde(rename = "box")]
    box_table: DocBox,
    io: DocIo,
    install: DocInstall,
    network: DocNetwork,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DocBox {
    #[serde(rename = "type")]
    box_type: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DocIo {
    pty_enabled: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DocInstall {
    packages: Vec<String>,
}

/// The `[network]` table. The policy's own keys are `egress`, `ingress`,
/// and `credentialed_upstream` and `quic443` when it sets them, so it is
/// flattened in beside `mode`. The policy refuses an unknown key.
///
/// The flatten puts every [`boxes::BoxPolicy`] key beside `mode`. This is
/// the same v0 exception as on [`SpecNetwork`]: `ingress` keeps the
/// [`boxes::IngressPolicy`] shape, and `credentialed_upstream` is declared
/// here. #2410 ends the interim.
#[derive(serde::Serialize, serde::Deserialize)]
struct DocNetwork {
    #[serde(with = "mode_word")]
    mode: boxes::NetworkMode,
    #[serde(flatten)]
    policy: boxes::BoxPolicy,
}

/// The `mode` key in its spec word, [`boxes::NetworkMode::word`], not the
/// mode's serde form. `NetworkMode` is `#[non_exhaustive]`, so a match on it
/// here needs a wildcard. Writing through `word`, whose match in `boxes` is
/// exhaustive, stores a new mode under its own word, never as `host_ip`.
mod mode_word {
    const WORDS: &[&str] = &["none", "host_ip", "own_ip"];

    pub(super) fn serialize<S: serde::Serializer>(
        mode: &boxes::NetworkMode,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(mode.word())
    }

    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<boxes::NetworkMode, D::Error> {
        let word = <String as serde::Deserialize>::deserialize(deserializer)?;
        match word.as_str() {
            "none" => Ok(boxes::NetworkMode::NoNet),
            "host_ip" => Ok(boxes::NetworkMode::HostNet),
            "own_ip" => Ok(boxes::NetworkMode::OwnIp),
            other => Err(serde::de::Error::unknown_variant(other, WORDS)),
        }
    }
}

impl From<BoxSpec> for SpecDoc {
    fn from(spec: BoxSpec) -> Self {
        Self {
            v: spec.v,
            entry: spec.entry,
            hooks_enabled: spec.hooks_enabled,
            box_table: DocBox {
                box_type: spec.box_type,
            },
            io: DocIo {
                pty_enabled: spec.pty_enabled,
            },
            install: DocInstall {
                packages: spec.packages,
            },
            network: DocNetwork {
                mode: spec.network.mode,
                policy: spec.network.policy,
            },
        }
    }
}

impl From<SpecDoc> for BoxSpec {
    fn from(doc: SpecDoc) -> Self {
        Self {
            v: doc.v,
            box_type: doc.box_table.box_type,
            entry: doc.entry,
            packages: doc.install.packages,
            pty_enabled: doc.io.pty_enabled,
            hooks_enabled: doc.hooks_enabled,
            network: SpecNetwork {
                mode: doc.network.mode,
                policy: doc.network.policy,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // BOX-068: the first spec comes from the `[session]` table or a task,
    // with the flags as the last layer.
    #[test]
    fn spec_v0_from_session_table_task_and_flags() {
        let file: crate::File = toml::from_str(
            r#"
            [session]
            packages = ["git", "ripgrep", "git"]

            [tasks.lint]
            exec = ["cargo", "clippy"]
            packages = ["rust"]

            [tasks.tui]
            exec = ["htop"]
            interactive = true
            "#,
        )
        .unwrap();
        let policy = boxes::BoxPolicy {
            egress: Some(boxes::EgressPolicy::deny_all()),
            ..Default::default()
        };
        let flags = SpecFlags {
            network: boxes::NetworkMode::OwnIp,
            policy: policy.clone(),
            hooks_enabled: false,
        };

        let session = BoxSpec::for_session(file.session.as_ref(), flags.clone());
        assert_eq!(
            session,
            BoxSpec {
                v: BOX_SPEC_VERSION,
                box_type: "session".to_string(),
                entry: "default".to_string(),
                packages: vec!["git".to_string(), "ripgrep".to_string()],
                pty_enabled: true,
                hooks_enabled: false,
                network: SpecNetwork {
                    mode: boxes::NetworkMode::OwnIp,
                    policy: policy.clone(),
                },
            }
        );

        let empty = BoxSpec::for_session(None, SpecFlags::default());
        assert!(empty.packages.is_empty());
        assert_eq!(empty.network.mode, boxes::NetworkMode::default());
        assert!(empty.hooks_enabled, "the default flags leave hooks on");

        let lint = BoxSpec::for_task("lint", &file.tasks["lint"], flags.clone())
            .expect("a task that is not interactive has a spec");
        assert_eq!(lint.box_type, "task");
        assert_eq!(lint.entry, "lint");
        assert_eq!(lint.packages, vec!["rust".to_string()]);
        assert!(
            !lint.pty_enabled,
            "a task that is not interactive has no terminal"
        );
        assert_eq!(lint.network.policy, policy);

        // The task type denies a terminal, so an interactive task has no spec.
        assert_eq!(BoxSpec::for_task("tui", &file.tasks["tui"], flags), None);

        // The spec writes the `box.toml` tables and the mode's spec word,
        // and round-trips.
        let text = toml::to_string(&session).unwrap();
        let value: toml::Value = toml::from_str(&text).unwrap();
        assert_eq!(value["v"].as_integer(), Some(0), "{text}");
        assert_eq!(value["box"]["type"].as_str(), Some("session"), "{text}");
        assert_eq!(value["io"]["pty_enabled"].as_bool(), Some(true), "{text}");
        assert_eq!(
            value["install"]["packages"],
            toml::Value::Array(vec!["git".into(), "ripgrep".into()]),
            "{text}"
        );
        assert_eq!(value["network"]["mode"].as_str(), Some("own_ip"), "{text}");
        assert_eq!(
            value["network"]["egress"]["allow_subnets"],
            toml::Value::Array(vec![]),
            "{text}"
        );
        assert!(value.get("type").is_none(), "{text}");
        assert!(value.get("packages").is_none(), "{text}");
        assert!(value.get("pty_enabled").is_none(), "{text}");
        assert!(value["network"].get("policy").is_none(), "{text}");
        assert_eq!(toml::from_str::<BoxSpec>(&text).unwrap(), session);

        for (mode, word) in [
            (boxes::NetworkMode::NoNet, "none"),
            (boxes::NetworkMode::HostNet, "host_ip"),
            (boxes::NetworkMode::OwnIp, "own_ip"),
        ] {
            let spec = BoxSpec::for_session(
                None,
                SpecFlags {
                    network: mode,
                    ..SpecFlags::default()
                },
            );
            let text = toml::to_string(&spec).unwrap();
            let value: toml::Value = toml::from_str(&text).unwrap();
            assert_eq!(value["network"]["mode"].as_str(), Some(word), "{text}");
            assert_eq!(toml::from_str::<BoxSpec>(&text).unwrap(), spec);
        }
    }
}
