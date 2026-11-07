//! The Box Spec: the settings a box is created from. The client builds it,
//! sends it to the daemon on the create request, and the daemon stores it
//! beside the box's record (BOX-068).
//!
//! This is the first version, `v = 0`. It is built from the project's
//! `[session]` table or a declared `[tasks.<name>]` entry, and from the
//! command-line flags of the creating command. It serializes under the
//! `box.toml` tables: `box.type`, `box.lifetime`, `io.pty_enabled`,
//! `execution.exec`, `install.packages`, `network.mode` and
//! `network.egress.*`.
//!
//! The v0 bytes also carry keys that `box.toml` does not have. #2410 ends
//! each of these exceptions when it bumps [`BOX_SPEC_VERSION`]:
//!
//! - The top-level keys `v`, `entry` and `hooks_enabled`. #2410 removes them
//!   or maps them to `box.toml` tables.
//! - `execution.exec` is an argv array, not the `box.toml` string. A shell
//!   entrypoint leaves the key out.
//! - `execution.timeout` is a whole number of seconds, not the `box.toml`
//!   duration string, and a spec with no timeout leaves the key out in place
//!   of `"0"`.
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
    /// The box's own name, when the spec sets one. Serialized as
    /// `box.name`, and left out when unset. [`Self::box_name`] reads it.
    pub name: Option<String>,
    /// The entry the box comes from: a task's name, or
    /// [`DEFAULT_SESSION_ENTRY`] for a session.
    pub entry: String,
    /// The packages the entry asks for, in declaration order, each once.
    /// Serialized as `install.packages`.
    pub packages: Vec<String>,
    /// Whether the box runs with a terminal. Serialized as `io.pty_enabled`.
    pub pty_enabled: bool,
    /// What the box runs as its first process. Serialized as
    /// `execution.exec`, and left out for [`Entrypoint::Shell`].
    pub entrypoint: Entrypoint,
    /// When the box's run is over. Serialized as `box.lifetime`.
    ///
    /// The spec stores and round-trips this value, but no launch reads it
    /// yet. A box ends when its entrypoint returns, whatever it says.
    pub lifetime: Lifetime,
    /// Whether the box runs its lifecycle hooks.
    pub hooks_enabled: bool,
    /// Whether a resume of the box runs its `on_activate` hooks again
    /// (BOX-028). Serialized as `execution.hooks_on_resume`, and left out
    /// when `false`.
    ///
    /// The spec stores and round-trips this value, but the daemon does not
    /// read this key yet. See <https://github.com/gominimal/minimal/issues/3111>,
    /// the task that makes the daemon read it (BOX-028).
    pub hooks_on_resume: bool,
    /// How long the box may run, in whole seconds, when its entry sets a
    /// `timeout` other than zero (BOX-049). Serialized as
    /// `execution.timeout`, and left out when `None`.
    ///
    /// The spec stores and round-trips this value, but the daemon does not
    /// read this key yet, so the box runs with no limit. See
    /// <https://github.com/gominimal/minimal/issues/3114>, the task that makes
    /// the daemon end the box at its timeout (BOX-037).
    pub timeout: Option<u64>,
    /// The box's network settings.
    pub network: SpecNetwork,
}

/// What a box runs as its first process: the program its launch starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entrypoint {
    /// The box's login shell: the one its composed `SHELL` names, or the
    /// daemon's fallback shell. A session's entrypoint.
    Shell,
    /// A program and its arguments. The first word is the program, and a
    /// word with no `/` names a program under `/usr/bin` in the box.
    Exec(Vec<String>),
}

impl Entrypoint {
    /// The entrypoint of a task box: the in-box command that runs the task
    /// named `task`, `min task run <task>`.
    #[must_use]
    pub fn for_task(task: &str) -> Self {
        Self::Exec(vec![
            "min".to_string(),
            "task".to_string(),
            "run".to_string(),
            task.to_string(),
        ])
    }

    /// The entrypoint a box of `box_type` from `entry` gets when its spec
    /// names none: a spec stored before `execution.exec` existed.
    fn implied(box_type: &str, entry: &str) -> Self {
        if box_type == boxes::TASK_BOX_TYPE {
            Self::for_task(entry)
        } else {
            Self::Shell
        }
    }
}

/// When a box's run is over. Serialized as its spec word.
///
/// Nothing enforces this yet: the daemon does not read it at launch, so
/// [`Lifetime::UntilStopped`] has no effect today.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifetime {
    /// The run is over when the entrypoint returns.
    UntilComplete,
    /// The run lasts until the box is stopped, whatever the entrypoint does.
    UntilStopped,
}

/// The lifetime a v0 spec stored without `box.lifetime` reads as.
fn until_complete() -> Lifetime {
    Lifetime::UntilComplete
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
            Entrypoint::Shell,
            session.map(|s| &s.extra),
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
            Entrypoint::for_task(name),
            Some(&task.extra),
            flags,
        ))
    }

    fn build(
        box_type: &str,
        entry: &str,
        packages: &[String],
        pty_enabled: bool,
        entrypoint: Entrypoint,
        extra: Option<&std::collections::HashMap<String, toml::Value>>,
        flags: SpecFlags,
    ) -> Self {
        // The entry's own keys that its table keeps among the ones it does
        // not read itself.
        let hooks_on_resume = extra.is_some_and(hooks_on_resume);
        let timeout = extra.and_then(entry_timeout);
        let mut seen = std::collections::BTreeSet::new();
        let packages = packages
            .iter()
            .filter(|p| seen.insert(p.as_str()))
            .cloned()
            .collect();
        Self {
            v: BOX_SPEC_VERSION,
            box_type: box_type.to_string(),
            name: None,
            entry: entry.to_string(),
            packages,
            pty_enabled,
            entrypoint,
            // The shipped `session` and `task` types both end their run
            // when the entrypoint returns.
            lifetime: Lifetime::UntilComplete,
            hooks_enabled: flags.hooks_enabled,
            hooks_on_resume,
            timeout,
            network: SpecNetwork {
                mode: flags.network,
                policy: flags.policy,
            },
        }
    }

    /// The name a box created from this spec takes (BOX-163): the spec's
    /// `[box] name`, else the entry's name.
    #[must_use]
    pub fn box_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.entry)
    }
}

/// Whether an entry's own table sets `hooks_on_resume = true` (BOX-028).
/// The entry tables keep the key among the ones they do not read
/// themselves, so it is read from there.
fn hooks_on_resume(extra: &std::collections::HashMap<String, toml::Value>) -> bool {
    extra
        .get("hooks_on_resume")
        .and_then(toml::Value::as_bool)
        .unwrap_or(false)
}

/// The entry's own `timeout` in whole seconds, read through
/// [`crate::duration::spec_timeout`]: `None` when the entry sets none or
/// sets zero. [`crate::File::validate`] refuses a bad value before a spec
/// is built, so a bad value here reads as `None`.
fn entry_timeout(extra: &std::collections::HashMap<String, toml::Value>) -> Option<u64> {
    extra
        .get("timeout")
        .and_then(|value| crate::duration::spec_timeout(value).ok().flatten())
}

/// Whether a flag is unset: the test that leaves `hooks_on_resume` out of
/// the bytes of a spec that does not set it.
fn is_false(value: &bool) -> bool {
    !*value
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
    /// Absent from a v0 spec stored before the table existed. A read then
    /// takes the entrypoint the box's type implies.
    #[serde(default)]
    execution: Option<DocExecution>,
    install: DocInstall,
    network: DocNetwork,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DocBox {
    #[serde(rename = "type")]
    box_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    /// Absent from a v0 spec stored before the key existed, which reads as
    /// `until_complete`.
    #[serde(default = "until_complete")]
    lifetime: Lifetime,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DocIo {
    pty_enabled: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DocExecution {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exec: Option<Vec<String>>,
    /// Absent from a spec that does not set it, which reads as `false`.
    #[serde(default, skip_serializing_if = "is_false")]
    hooks_on_resume: bool,
    /// Absent from a spec that sets no timeout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    timeout: Option<u64>,
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
                name: spec.name,
                lifetime: spec.lifetime,
            },
            io: DocIo {
                pty_enabled: spec.pty_enabled,
            },
            execution: Some(DocExecution {
                exec: match spec.entrypoint {
                    Entrypoint::Shell => None,
                    Entrypoint::Exec(argv) => Some(argv),
                },
                hooks_on_resume: spec.hooks_on_resume,
                timeout: spec.timeout,
            }),
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
        let hooks_on_resume = doc.execution.as_ref().is_some_and(|e| e.hooks_on_resume);
        let timeout = doc.execution.as_ref().and_then(|e| e.timeout);
        let entrypoint = match doc.execution {
            Some(execution) => execution.exec.map_or(Entrypoint::Shell, Entrypoint::Exec),
            None => Entrypoint::implied(&doc.box_table.box_type, &doc.entry),
        };
        let lifetime = doc.box_table.lifetime;
        Self {
            v: doc.v,
            box_type: doc.box_table.box_type,
            name: doc.box_table.name,
            entry: doc.entry,
            packages: doc.install.packages,
            pty_enabled: doc.io.pty_enabled,
            entrypoint,
            lifetime,
            hooks_enabled: doc.hooks_enabled,
            hooks_on_resume,
            timeout,
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
                name: None,
                entry: "default".to_string(),
                packages: vec!["git".to_string(), "ripgrep".to_string()],
                pty_enabled: true,
                entrypoint: Entrypoint::Shell,
                lifetime: Lifetime::UntilComplete,
                hooks_enabled: false,
                hooks_on_resume: false,
                timeout: None,
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

    // T42: the spec carries what the box runs first, when its run is over,
    // and whether it has a terminal, and a launch reads all three from it.
    #[test]
    fn spec_carries_entrypoint_lifetime_and_terminal_flag() {
        let task: crate::Task = toml::from_str(r#"exec = ["cargo", "test"]"#).unwrap();
        let lint = BoxSpec::for_task("lint", &task, SpecFlags::default())
            .expect("a task that is not interactive has a spec");
        assert_eq!(
            lint.entrypoint,
            Entrypoint::Exec(vec![
                "min".to_string(),
                "task".to_string(),
                "run".to_string(),
                "lint".to_string()
            ])
        );
        assert_eq!(lint.lifetime, Lifetime::UntilComplete);
        assert!(!lint.pty_enabled);

        let session = BoxSpec::for_session(None, SpecFlags::default());
        assert_eq!(session.entrypoint, Entrypoint::Shell);
        assert_eq!(session.lifetime, Lifetime::UntilComplete);
        assert!(session.pty_enabled);

        // The task's entrypoint writes as `execution.exec`, and the lifetime
        // as `box.lifetime`.
        let text = toml::to_string(&lint).unwrap();
        let value: toml::Value = toml::from_str(&text).unwrap();
        assert_eq!(
            value["execution"]["exec"],
            toml::Value::Array(vec![
                "min".into(),
                "task".into(),
                "run".into(),
                "lint".into()
            ]),
            "{text}"
        );
        assert_eq!(
            value["box"]["lifetime"].as_str(),
            Some("until_complete"),
            "{text}"
        );
        assert_eq!(value["io"]["pty_enabled"].as_bool(), Some(false), "{text}");
        assert_eq!(toml::from_str::<BoxSpec>(&text).unwrap(), lint);

        // A shell entrypoint leaves the key out, and reads back as the shell.
        let mut until_stopped = session.clone();
        until_stopped.lifetime = Lifetime::UntilStopped;
        let text = toml::to_string(&until_stopped).unwrap();
        let value: toml::Value = toml::from_str(&text).unwrap();
        assert!(value["execution"].get("exec").is_none(), "{text}");
        assert_eq!(
            value["box"]["lifetime"].as_str(),
            Some("until_stopped"),
            "{text}"
        );
        assert_eq!(toml::from_str::<BoxSpec>(&text).unwrap(), until_stopped);

        // A v0 spec stored before `[execution]` and `box.lifetime` existed
        // reads with the entrypoint its type implies and `until_complete`,
        // so a resume starts the same program.
        for spec in [&session, &lint] {
            let mut value: toml::Value = toml::from_str(&toml::to_string(spec).unwrap()).unwrap();
            value.as_table_mut().unwrap().remove("execution");
            value["box"].as_table_mut().unwrap().remove("lifetime");
            let text = toml::to_string(&value).unwrap();
            assert_eq!(&toml::from_str::<BoxSpec>(&text).unwrap(), spec, "{text}");
        }

        // An unknown `[execution]` key is refused, as in every other table.
        let mut value: toml::Value = toml::from_str(&toml::to_string(&lint).unwrap()).unwrap();
        value["execution"]
            .as_table_mut()
            .unwrap()
            .insert("restart".to_string(), true.into());
        assert!(toml::from_str::<BoxSpec>(&toml::to_string(&value).unwrap()).is_err());
    }

    // BOX-028: an entry that sets `hooks_on_resume = true` carries the key
    // in its spec, as `execution.hooks_on_resume`.
    #[test]
    fn spec_carries_hooks_on_resume() {
        let file: crate::File = toml::from_str(
            r#"
            [session]
            hooks_on_resume = true

            [tasks.lint]
            exec = ["cargo", "clippy"]
            hooks_on_resume = true

            [tasks.plain]
            exec = ["true"]
            "#,
        )
        .unwrap();

        let session = BoxSpec::for_session(file.session.as_ref(), SpecFlags::default());
        assert!(session.hooks_on_resume);
        let lint = BoxSpec::for_task("lint", &file.tasks["lint"], SpecFlags::default()).unwrap();
        assert!(lint.hooks_on_resume);
        let plain = BoxSpec::for_task("plain", &file.tasks["plain"], SpecFlags::default()).unwrap();
        assert!(!plain.hooks_on_resume);
        assert!(!BoxSpec::for_session(None, SpecFlags::default()).hooks_on_resume);

        // The key writes as `execution.hooks_on_resume` and reads back.
        for spec in [&session, &lint] {
            let text = toml::to_string(spec).unwrap();
            let value: toml::Value = toml::from_str(&text).unwrap();
            assert_eq!(
                value["execution"]["hooks_on_resume"].as_bool(),
                Some(true),
                "{text}"
            );
            assert_eq!(&toml::from_str::<BoxSpec>(&text).unwrap(), spec, "{text}");
        }

        // A spec that does not set it leaves the key out, so the bytes of a
        // spec stored before the key existed stay the same and read as unset.
        let text = toml::to_string(&plain).unwrap();
        let value: toml::Value = toml::from_str(&text).unwrap();
        assert!(
            value["execution"].get("hooks_on_resume").is_none(),
            "{text}"
        );
        assert!(value.get("hooks_on_resume").is_none(), "{text}");
        assert_eq!(toml::from_str::<BoxSpec>(&text).unwrap(), plain);
    }

    // BOX-049: an entry's `timeout` reaches its spec in whole seconds, as
    // `execution.timeout`. No timeout, or a zero one, leaves the key out.
    #[test]
    fn spec_carries_timeout_under_execution() {
        let file: crate::File = toml::from_str(
            r#"
            [session]
            timeout = "8h"

            [tasks.lint]
            exec = ["cargo", "clippy"]
            timeout = 90

            [tasks.zero]
            exec = ["true"]
            timeout = "0m"

            [tasks.plain]
            exec = ["true"]
            "#,
        )
        .unwrap();

        let session = BoxSpec::for_session(file.session.as_ref(), SpecFlags::default());
        assert_eq!(session.timeout, Some(8 * 3600));
        let lint = BoxSpec::for_task("lint", &file.tasks["lint"], SpecFlags::default()).unwrap();
        assert_eq!(lint.timeout, Some(90));
        for spec in [&session, &lint] {
            let text = toml::to_string(spec).unwrap();
            let value: toml::Value = toml::from_str(&text).unwrap();
            assert_eq!(
                value["execution"]["timeout"].as_integer(),
                spec.timeout.map(|t| i64::try_from(t).unwrap()),
                "{text}"
            );
            assert!(value.get("timeout").is_none(), "{text}");
            assert_eq!(&toml::from_str::<BoxSpec>(&text).unwrap(), spec, "{text}");
        }

        for name in ["zero", "plain"] {
            let spec = BoxSpec::for_task(name, &file.tasks[name], SpecFlags::default()).unwrap();
            assert_eq!(spec.timeout, None, "{name}");
            let text = toml::to_string(&spec).unwrap();
            let value: toml::Value = toml::from_str(&text).unwrap();
            assert!(value["execution"].get("timeout").is_none(), "{text}");
            assert_eq!(toml::from_str::<BoxSpec>(&text).unwrap(), spec);
        }
        assert_eq!(
            BoxSpec::for_session(None, SpecFlags::default()).timeout,
            None
        );
    }

    // BOX-163: a box takes the spec's `[box] name`, else the entry's name.
    #[test]
    fn spec_names_box_from_box_name_else_entry() {
        let task: crate::Task = toml::from_str(r#"exec = ["cargo", "test"]"#).unwrap();
        let mut spec = BoxSpec::for_task("lint", &task, SpecFlags::default())
            .expect("a task that is not interactive has a spec");
        assert_eq!(spec.name, None, "the interim builder sets no name");
        assert_eq!(spec.box_name(), "lint", "no `[box] name`: the entry's name");

        let session = BoxSpec::for_session(None, SpecFlags::default());
        assert_eq!(session.box_name(), DEFAULT_SESSION_ENTRY);

        // An unset name is left out of the bytes, so a v0 spec stored
        // before the key existed reads back the same.
        let text = toml::to_string(&spec).unwrap();
        let value: toml::Value = toml::from_str(&text).unwrap();
        assert!(value["box"].get("name").is_none(), "{text}");
        assert_eq!(toml::from_str::<BoxSpec>(&text).unwrap(), spec);

        spec.name = Some("dev".to_string());
        assert_eq!(spec.box_name(), "dev", "`[box] name` comes first");
        let text = toml::to_string(&spec).unwrap();
        let value: toml::Value = toml::from_str(&text).unwrap();
        assert_eq!(value["box"]["name"].as_str(), Some("dev"), "{text}");
        assert_eq!(value["entry"].as_str(), Some("lint"), "{text}");
        assert_eq!(toml::from_str::<BoxSpec>(&text).unwrap(), spec);
    }
}
