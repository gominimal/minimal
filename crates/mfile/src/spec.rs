//! The Box Spec: the settings a box is created from. The client builds it,
//! sends it to the daemon on the create request, and the daemon stores it
//! beside the box's record (BOX-068).
//!
//! This is the first version, `v = 0`. It is built from the project's
//! `[session]` table or a declared `[tasks.<name>]` entry, and from the
//! command-line flags of the creating command. The full expansion over
//! `[defaults]`, Box Types and loadouts replaces this builder later, and
//! bumps `v`.

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
#[serde(deny_unknown_fields)]
pub struct BoxSpec {
    /// The spec shape's version, [`BOX_SPEC_VERSION`].
    pub v: u32,
    /// The Box Type's name: `session` or `task`.
    #[serde(rename = "type")]
    pub box_type: String,
    /// The entry the box comes from: a task's name, or
    /// [`DEFAULT_SESSION_ENTRY`] for a session.
    pub entry: String,
    /// The packages the entry asks for, in declaration order, each once.
    pub packages: Vec<String>,
    /// Whether the box runs with a terminal.
    pub pty_enabled: bool,
    /// Whether the box runs its lifecycle hooks.
    pub hooks_enabled: bool,
    /// The box's network settings.
    pub network: SpecNetwork,
}

/// The network half of a [`BoxSpec`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpecNetwork {
    /// The network isolation mode.
    pub mode: boxes::NetworkMode,
    /// The egress and ingress policy the creating command resolved.
    pub policy: boxes::BoxPolicy,
}

/// What the creating command's flags set on the spec. This is the last
/// layer, so each value here replaces the one an entry sets.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SpecFlags {
    /// The network mode, from `--network`.
    pub network: boxes::NetworkMode,
    /// The policy that the egress and ingress flags and the project's
    /// `[session]` table resolve to.
    pub policy: boxes::BoxPolicy,
    /// Cleared by `--no-hooks`.
    pub hooks_enabled: bool,
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
    /// flags. The box has a terminal only for an interactive task.
    #[must_use]
    pub fn for_task(name: &str, task: &Task, flags: SpecFlags) -> Self {
        Self::build(
            boxes::TASK_BOX_TYPE,
            name,
            &task.packages,
            task.interactive,
            flags,
        )
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

        let lint = BoxSpec::for_task("lint", &file.tasks["lint"], flags.clone());
        assert_eq!(lint.box_type, "task");
        assert_eq!(lint.entry, "lint");
        assert_eq!(lint.packages, vec!["rust".to_string()]);
        assert!(
            !lint.pty_enabled,
            "a task that is not interactive has no terminal"
        );
        assert_eq!(lint.network.policy, policy);

        let tui = BoxSpec::for_task("tui", &file.tasks["tui"], flags);
        assert!(tui.pty_enabled, "an interactive task has a terminal");

        // The spec round-trips, and its version and type keep their names.
        let text = toml::to_string(&session).unwrap();
        assert!(text.contains("v = 0"), "{text}");
        assert!(text.contains("type = \"session\""), "{text}");
        assert_eq!(toml::from_str::<BoxSpec>(&text).unwrap(), session);
    }
}
