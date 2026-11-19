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

use crate::expand::{ExpansionReport, Layer, Origin, ValueOrigin};
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
    /// `minimald` reads this key at resume (`BoxActor::resume_ended`), and
    /// when it is `true` it runs the box's `on_activate` hooks again.
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
    /// The expanded spec's `lifecycle_hooks`, each with the `declared_by`
    /// table that names its declarer (BOX-068, BOX-179). Serialized as the
    /// top-level `lifecycle_hooks` list, and left out when `None`.
    ///
    /// `None` when the client sent no hook list: a task create, a create
    /// with no `minimal.toml`, or a spec stored before the key existed. The
    /// daemon then composes the project's hooks as before.
    pub lifecycle_hooks: Option<Vec<SpecHook>>,
    /// The expanded spec's `[[file_exports]]` items, as the client stored
    /// them (BOX-203, BOX-204). Serialized as the top-level `file_exports`
    /// list, and left out when `None`.
    ///
    /// The client reads these items and copies the exports when the box
    /// ends. The daemon only keeps them, so a box that declares exports
    /// can resume from its stored spec.
    pub file_exports: Option<Vec<StoredExport>>,
    /// The keys of a stored spec that the schema of a spec names, but that
    /// no field above types, such as `io.exec_enabled` or
    /// `network.dynamic_ingress`. Each value is kept as it was written,
    /// by its dotted path, and a section with no typed keys, such as
    /// `nesting`, is kept whole. A newer client can store such a key, and
    /// the box still resumes from its stored spec.
    pub kept_keys: std::collections::BTreeMap<String, StoredExport>,
}

/// One `[[file_exports]]` item of a stored spec, kept as it was written:
/// a path string, or a table with a `path` key.
///
/// Equality is total: two floats are equal when their bits are equal. A
/// hand-edited stored spec can hold a TOML `nan`, and such an item is
/// still equal to itself.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct StoredExport(pub toml::Value);

impl PartialEq for StoredExport {
    fn eq(&self, other: &Self) -> bool {
        toml_value_eq(&self.0, &other.0)
    }
}

impl Eq for StoredExport {}

/// Equality on two TOML values that compares floats by their bits, so it
/// is reflexive for NaN.
fn toml_value_eq(a: &toml::Value, b: &toml::Value) -> bool {
    use toml::Value;
    match (a, b) {
        (Value::Float(a), Value::Float(b)) => a.to_bits() == b.to_bits(),
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| toml_value_eq(a, b))
        }
        (Value::Table(a), Value::Table(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(key, a)| b.get(key).is_some_and(|b| toml_value_eq(a, b)))
        }
        _ => a == b,
    }
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

impl Lifetime {
    /// The values `lifetime` accepts, as a project writes them.
    pub const ACCEPTED: &'static [&'static str] = &["until_complete", "until_stopped"];
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
    /// The entry's `network.vpn_network_names`, in the order it lists
    /// them, then each name a `--vpn-network-names` flag adds (BCLI-024).
    /// Serialized as `vpn_network_names`, and left out when empty. The
    /// daemon keeps the list and does not enforce it (BOX-076).
    pub vpn_network_names: Vec<String>,
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
        let extra = session.map(|s| settings_of(&s.extra));
        Self::build(
            boxes::SESSION_BOX_TYPE,
            DEFAULT_SESSION_ENTRY,
            packages,
            true,
            Entrypoint::Shell,
            extra.as_ref().map(|t| (t, None)),
            flags,
        )
    }

    /// The spec of a session box from the session entry `entry`, expanded
    /// over its layers into `expanded` (BOX-064). The spec takes the
    /// entry's packages, lifetime, timeout and `hooks_on_resume` from the
    /// expansion, and each value the flags set from `flags`.
    ///
    /// `report` is the expansion's record of the layer that set each key.
    /// `type_chain` names the types of the entry's type chain, the root
    /// first, as [`crate::expand::Layers::type_defaults`] orders them.
    /// A setting that the expansion keeps both flat and under its section
    /// takes the form that the later layer set. Within the type chain's
    /// defaults, the more derived type is the later layer. The packages
    /// take both lists, in that order, without duplicates.
    #[must_use]
    pub fn for_session_entry(
        entry: &str,
        expanded: &toml::Table,
        report: &ExpansionReport,
        type_chain: &[String],
        flags: SpecFlags,
    ) -> Self {
        let ranking = Ranking { report, type_chain };
        let packages = layered_packages(expanded, ranking);
        Self::build(
            boxes::SESSION_BOX_TYPE,
            entry,
            &packages,
            true,
            Entrypoint::Shell,
            Some((expanded, Some(ranking))),
            flags,
        )
    }

    /// The spec of a task box, from the `[tasks.<name>]` entry and the
    /// flags. A task's spec carries the request's box policy.
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
            Some((&settings_of(&task.extra), None)),
            flags,
        ))
    }

    fn build(
        box_type: &str,
        entry: &str,
        packages: &[String],
        pty_enabled: bool,
        entrypoint: Entrypoint,
        // The entry's settings table, and the ranking of the expansion's
        // origins for an expanded one.
        extra: Option<(&toml::Table, Option<Ranking<'_>>)>,
        flags: SpecFlags,
    ) -> Self {
        // The entry's own keys that its table keeps among the ones it does
        // not read itself.
        let hooks_on_resume = extra.is_some_and(|(t, ranking)| hooks_on_resume(t, ranking));
        let timeout = extra.and_then(|(t, ranking)| entry_timeout(t, ranking));
        // Only an expanded entry carries a ranking, and only the expansion
        // refuses a bad lifetime. A task or a `[session]` table keeps the
        // `until_complete` that the shipped `session` and `task` types
        // declare, as does a spec that sets no lifetime.
        let lifetime = extra
            .and_then(|(t, ranking)| ranking.map(|r| (t, r)))
            .and_then(|(t, ranking)| entry_lifetime(t, ranking))
            .unwrap_or(Lifetime::UntilComplete);
        // BOX-203: the entry's exports, for the command that waits for the
        // box to copy them when it ends.
        let file_exports = extra.and_then(|(t, _)| crate::expand::stored_file_exports(t));
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
            lifetime,
            hooks_enabled: flags.hooks_enabled,
            hooks_on_resume,
            timeout,
            network: SpecNetwork {
                mode: flags.network,
                policy: flags.policy,
                vpn_network_names: extra
                    .map(|(t, _)| entry_vpn_network_names(t))
                    .unwrap_or_default(),
            },
            lifecycle_hooks: None,
            file_exports,
            kept_keys: std::collections::BTreeMap::new(),
        }
    }

    /// The name a box created from this spec takes (BOX-163): the spec's
    /// `[box] name`, else the entry's name.
    #[must_use]
    pub fn box_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.entry)
    }
}

/// The names an entry's `[network]` table lists in `vpn_network_names`
/// (BCLI-024), each once, in the order the entry lists them. Empty when the
/// entry sets none. The expansion refuses a value that is not a list of
/// strings (see [`check_section`]), and a value that is not a string is
/// left out here.
#[must_use]
pub fn entry_vpn_network_names(extra: &toml::Table) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let listed = extra
        .get("network")
        .and_then(|network| network.get("vpn_network_names"))
        .and_then(toml::Value::as_array);
    for name in listed.into_iter().flatten().filter_map(toml::Value::as_str) {
        if !names.iter().any(|kept| kept == name) {
            names.push(name.to_owned());
        }
    }
    names
}

/// Whether an entry's own table sets `hooks_on_resume = true` (BOX-028).
/// The entry tables keep the key among the ones they do not read
/// themselves, so it is read from there.
fn hooks_on_resume(extra: &toml::Table, ranking: Option<Ranking<'_>>) -> bool {
    later_value(extra, ranking, "hooks_on_resume", "execution")
        .and_then(toml::Value::as_bool)
        .unwrap_or(false)
}

/// An expanded entry's own `lifetime`, from `lifetime` or `box.lifetime`.
/// `None` when the entry sets none. The expansion refuses a value that is
/// not one of [`Lifetime::ACCEPTED`] (see [`check_section`]), so only an
/// expanded entry reaches here. [`BoxSpec::build`] never reads the lifetime
/// of a task or a `[session]` table, which no check refuses.
fn entry_lifetime(extra: &toml::Table, ranking: Ranking<'_>) -> Option<Lifetime> {
    later_value(extra, Some(ranking), "lifetime", "box")
        .and_then(|value| value.clone().try_into().ok())
}

/// The value of the setting `key`, written flat or under `section` with
/// the same name. The expansion keeps the two forms as two top-level keys.
/// The form that the later origin in `ranking` set wins, as for
/// `loadout_mode` in [`crate::expand`]. Without a ranking, or when one
/// layer sets both, the flat key wins.
fn later_value<'a>(
    table: &'a toml::Table,
    ranking: Option<Ranking<'_>>,
    key: &str,
    section: &str,
) -> Option<&'a toml::Value> {
    let flat = table.get(key);
    let nested = table
        .get(section)
        .and_then(toml::Value::as_table)
        .and_then(|t| t.get(key));
    match (flat, nested) {
        (Some(f), Some(n)) => {
            let rank = |k: &str| ranking.and_then(|r| r.key(k));
            match (rank(key), rank(section)) {
                (Some(f_at), Some(n_at)) if n_at > f_at => Some(n),
                _ => Some(f),
            }
        }
        (f, n) => f.or(n),
    }
}

/// How the stored spec orders the origins of an expansion's values: by
/// layer, and within [`Layer::TypeDefaults`] by the type's position in
/// the type chain, the root first. So a derived type's setting comes
/// after its parent's, as the expansion's `loadout_mode` orders them.
#[derive(Debug, Clone, Copy)]
struct Ranking<'a> {
    /// The expansion's record of the origin of each top-level key.
    report: &'a ExpansionReport,
    /// The entry's type chain, the root first.
    type_chain: &'a [String],
}

impl Ranking<'_> {
    /// The rank of `origin`. A later origin has a greater rank. An origin
    /// outside the type chain's defaults, or of a type the chain does not
    /// name, takes position 0 in its layer.
    fn of(self, origin: &Origin) -> (Layer, usize) {
        let at = origin
            .box_type
            .as_deref()
            .and_then(|t| self.type_chain.iter().position(|c| c == t))
            .unwrap_or(0);
        (origin.layer, at)
    }

    /// The rank of the origin of the top-level key `key`, or of a list's
    /// first item. `None` when the report does not name the key.
    fn key(self, key: &str) -> Option<(Layer, usize)> {
        Some(self.of(self.report.values.get(key)?.first()?))
    }
}

/// The expanded spec's packages: the flat `packages` and the
/// `install.packages` of its `[install]` section, merged in the order of
/// the origins that set them, without duplicates. The fold already unions
/// each form across its layers, and the report keeps the origin of each
/// flat item and of the `install` table.
fn layered_packages(expanded: &toml::Table, ranking: Ranking<'_>) -> Vec<String> {
    let strings = |value: Option<&toml::Value>| -> Vec<String> {
        value
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(toml::Value::as_str)
            .map(str::to_owned)
            .collect()
    };
    let flat = strings(expanded.get("packages"));
    let flat_layers: Vec<Option<(Layer, usize)>> = match ranking.report.values.get("packages") {
        Some(ValueOrigin::List(origins)) => origins.iter().map(|o| Some(ranking.of(o))).collect(),
        Some(ValueOrigin::Value(o)) => vec![Some(ranking.of(o)); flat.len()],
        None => Vec::new(),
    };
    let nested = strings(
        expanded
            .get("install")
            .and_then(toml::Value::as_table)
            .and_then(|t| t.get("packages")),
    );
    let nested_layer = ranking.key("install");
    let mut items: Vec<(Option<(Layer, usize)>, String)> = flat
        .into_iter()
        .enumerate()
        .map(|(i, p)| (flat_layers.get(i).copied().flatten(), p))
        .chain(nested.into_iter().map(|p| (nested_layer, p)))
        .collect();
    // A stable sort keeps each form's own order, and the flat items first
    // within one layer.
    items.sort_by_key(|(layer, _)| *layer);
    let mut seen = std::collections::BTreeSet::new();
    items
        .into_iter()
        .map(|(_, p)| p)
        .filter(|p| seen.insert(p.clone()))
        .collect()
}

/// The keys an entry table keeps among the ones it does not read itself,
/// as one table.
fn settings_of(extra: &std::collections::HashMap<String, toml::Value>) -> toml::Table {
    extra
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

/// The entry's own `timeout` in whole seconds, read through
/// [`crate::duration::spec_timeout`]: `None` when the entry sets none or
/// sets zero. [`crate::File::validate`] refuses a bad value before a spec
/// is built, so a bad value here reads as `None`.
fn entry_timeout(extra: &toml::Table, ranking: Option<Ranking<'_>>) -> Option<u64> {
    later_value(extra, ranking, "timeout", "execution")
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
    /// Absent from a spec that carries no hook list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lifecycle_hooks: Option<Vec<SpecHook>>,
    /// Absent from a spec that declares no exports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    file_exports: Option<Vec<StoredExport>>,
    /// The `[nesting]` section, kept whole. Absent when the spec sets none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nesting: Option<StoredExport>,
}

/// Declares the fields of a `Doc*` table that keep a schema key as it was
/// written ([`BoxSpec::kept_keys`]), and the two functions that move them
/// to and from the kept map, by the dotted path `<section>.<key>`.
macro_rules! kept_fields {
    ($doc:ident, $section:literal, [$($key:ident),* $(,)?]) => {
        impl $doc {
            /// Moves each kept key of this table into `kept`.
            fn put_kept(
                &mut self,
                kept: &mut std::collections::BTreeMap<String, StoredExport>,
            ) {
                $(
                    if let Some(value) = self.$key.take() {
                        kept.insert(concat!($section, ".", stringify!($key)).to_owned(), value);
                    }
                )*
            }

            /// Takes each kept key of this table out of `kept`.
            fn take_kept(
                &mut self,
                kept: &mut std::collections::BTreeMap<String, StoredExport>,
            ) {
                $(
                    self.$key = kept.remove(concat!($section, ".", stringify!($key)));
                )*
            }
        }
    };
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    loadout_mode: Option<StoredExport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    volumes: Option<StoredExport>,
}

kept_fields!(DocBox, "box", [loadout_mode, volumes]);

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DocIo {
    pty_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exec_enabled: Option<StoredExport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stderr_mimetype: Option<StoredExport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stdin_mimetype: Option<StoredExport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stdout_mimetype: Option<StoredExport>,
}

kept_fields!(
    DocIo,
    "io",
    [
        exec_enabled,
        stderr_mimetype,
        stdin_mimetype,
        stdout_mimetype
    ]
);

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DocExecution {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exec: Option<Vec<String>>,
    /// Absent from a spec that does not set it, which reads as `false`.
    #[serde(default, skip_serializing_if = "is_false")]
    hooks_on_resume: bool,
    /// Absent from a spec that sets no timeout. A read also takes a
    /// duration string, as the schema of a spec allows.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "stored_timeout"
    )]
    timeout: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    on_oom: Option<StoredExport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    restart: Option<StoredExport>,
}

kept_fields!(DocExecution, "execution", [on_oom, restart]);

/// A stored `execution.timeout`: whole seconds, or a duration string that
/// [`crate::duration::spec_timeout`] reads.
fn stored_timeout<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<u64>, D::Error> {
    let value = <toml::Value as serde::Deserialize>::deserialize(deserializer)?;
    crate::duration::spec_timeout(&value).map_err(serde::de::Error::custom)
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DocInstall {
    packages: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    raw_packages: Option<StoredExport>,
}

kept_fields!(DocInstall, "install", [raw_packages]);

/// The `[network]` table. The policy's own keys are `egress`, `ingress`,
/// and `credentialed_upstream` and `quic443` when it sets them, so it is
/// flattened in beside `mode`. The policy refuses an unknown key.
///
/// The flatten puts every [`boxes::BoxPolicy`] key beside `mode`. This is
/// the same v0 exception as on [`SpecNetwork`]: `ingress` keeps the
/// [`boxes::IngressPolicy`] shape, and `credentialed_upstream` is declared
/// here. #2410 ends the interim.
///
/// The other keys of [`NETWORK_KEYS`] are kept as they were written,
/// except the flat egress keys. Canonicalisation moves each one to its
/// nested `egress.*` key before a spec is stored, and a resume reads only
/// the policy. So a stored flat key is refused, never kept: a kept deny
/// that no resume applies is a deny the box runs without.
#[derive(serde::Serialize, serde::Deserialize)]
struct DocNetwork {
    #[serde(with = "mode_word")]
    mode: boxes::NetworkMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dynamic_ingress: Option<StoredExport>,
    #[serde(default, skip_serializing, deserialize_with = "refuse_flat_allow_dns")]
    #[expect(dead_code, reason = "present only to refuse the key on a read")]
    egress_allow_dns: Option<()>,
    #[serde(
        default,
        skip_serializing,
        deserialize_with = "refuse_flat_allow_subnets"
    )]
    #[expect(dead_code, reason = "present only to refuse the key on a read")]
    egress_allow_subnets: Option<()>,
    #[serde(
        default,
        skip_serializing,
        deserialize_with = "refuse_flat_deny_subnets"
    )]
    #[expect(dead_code, reason = "present only to refuse the key on a read")]
    egress_deny_subnets: Option<()>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "lenient_names"
    )]
    vpn_network_names: Vec<String>,
    #[serde(flatten)]
    policy: boxes::BoxPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bep: Option<StoredExport>,
}

kept_fields!(DocNetwork, "network", [dynamic_ingress, bep,]);

/// Reads a stored spec's `network.vpn_network_names` leniently: the string
/// items of a list, in order. A hand-edited stored spec can hold another
/// shape. That value reads as no names, and the box still resumes from its
/// stored spec.
fn lenient_names<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = <toml::Value as serde::Deserialize>::deserialize(deserializer)?;
    let names = match value {
        toml::Value::Array(items) => items
            .into_iter()
            .filter_map(|item| match item {
                toml::Value::String(name) => Some(name),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };
    Ok(names)
}

/// Refuses the flat `[network]` egress key `flat` in a stored spec, and
/// names the nested `egress.*` key that a stored spec carries in its place.
fn refuse_flat_egress<E: serde::de::Error>(flat: &str) -> E {
    let nested = crate::network::FLAT_EGRESS_KEYS
        .iter()
        .find(|(key, _)| *key == flat)
        .map_or(flat, |(_, nested)| nested);
    E::custom(format!(
        "a stored spec does not carry `network.{flat}`. \
         Write it as `network.egress.{nested}`."
    ))
}

fn refuse_flat_allow_dns<'de, D: serde::Deserializer<'de>>(_: D) -> Result<Option<()>, D::Error> {
    Err(refuse_flat_egress("egress_allow_dns"))
}

fn refuse_flat_allow_subnets<'de, D: serde::Deserializer<'de>>(
    _: D,
) -> Result<Option<()>, D::Error> {
    Err(refuse_flat_egress("egress_allow_subnets"))
}

fn refuse_flat_deny_subnets<'de, D: serde::Deserializer<'de>>(
    _: D,
) -> Result<Option<()>, D::Error> {
    Err(refuse_flat_egress("egress_deny_subnets"))
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
        let mut kept = spec.kept_keys;
        let mut box_table = DocBox {
            box_type: spec.box_type,
            name: spec.name,
            lifetime: spec.lifetime,
            loadout_mode: None,
            volumes: None,
        };
        box_table.take_kept(&mut kept);
        let mut io = DocIo {
            pty_enabled: spec.pty_enabled,
            exec_enabled: None,
            stderr_mimetype: None,
            stdin_mimetype: None,
            stdout_mimetype: None,
        };
        io.take_kept(&mut kept);
        let mut execution = DocExecution {
            exec: match spec.entrypoint {
                Entrypoint::Shell => None,
                Entrypoint::Exec(argv) => Some(argv),
            },
            hooks_on_resume: spec.hooks_on_resume,
            timeout: spec.timeout,
            on_oom: None,
            restart: None,
        };
        execution.take_kept(&mut kept);
        let mut install = DocInstall {
            packages: spec.packages,
            raw_packages: None,
        };
        install.take_kept(&mut kept);
        let mut network = DocNetwork {
            mode: spec.network.mode,
            dynamic_ingress: None,
            egress_allow_dns: None,
            egress_allow_subnets: None,
            egress_deny_subnets: None,
            vpn_network_names: spec.network.vpn_network_names,
            policy: spec.network.policy,
            bep: None,
        };
        network.take_kept(&mut kept);
        Self {
            v: spec.v,
            entry: spec.entry,
            hooks_enabled: spec.hooks_enabled,
            box_table,
            io,
            execution: Some(execution),
            install,
            network,
            lifecycle_hooks: spec.lifecycle_hooks,
            file_exports: spec.file_exports,
            nesting: kept.remove("nesting"),
        }
    }
}

impl From<SpecDoc> for BoxSpec {
    fn from(mut doc: SpecDoc) -> Self {
        let mut kept = std::collections::BTreeMap::new();
        doc.box_table.put_kept(&mut kept);
        doc.io.put_kept(&mut kept);
        if let Some(execution) = doc.execution.as_mut() {
            execution.put_kept(&mut kept);
        }
        doc.install.put_kept(&mut kept);
        doc.network.put_kept(&mut kept);
        if let Some(nesting) = doc.nesting {
            kept.insert("nesting".to_owned(), nesting);
        }
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
                vpn_network_names: doc.network.vpn_network_names,
            },
            lifecycle_hooks: doc.lifecycle_hooks,
            file_exports: doc.file_exports,
            kept_keys: kept,
        }
    }
}

// ---------------------------------------------------------------------------
// The Box Spec sections of an expanded spec (BOX-076).
// ---------------------------------------------------------------------------

/// The shape of a value inside a Box Spec section.
#[derive(Debug, Clone, Copy)]
enum KeyShape {
    Str,
    Bool,
    Int,
    StrOrInt,
    StrList,
    StrOrStrList,
    /// A string that is one of the listed values.
    Word(&'static [&'static str]),
    /// A table whose keys are the ones listed.
    Keys(&'static [SectionKey]),
    /// Any value. Another check owns the value's shape, so this schema
    /// checks only the key's name, and the names of the listed keys
    /// inside it when it is a table.
    Owned(&'static [SectionKey]),
}

/// One key of a Box Spec section and the shape its value takes.
type SectionKey = (&'static str, KeyShape);

impl KeyShape {
    /// The shape as the error message names it, in the words of
    /// [`crate::expand`]'s top-level check.
    const fn words(self) -> &'static str {
        match self {
            KeyShape::Str | KeyShape::Word(_) => "a string",
            KeyShape::Bool => "true or false",
            KeyShape::Int => "a whole number",
            KeyShape::StrOrInt => "a string or a whole number",
            KeyShape::StrList => "a list of strings",
            KeyShape::StrOrStrList => "a string or a list of strings",
            KeyShape::Keys(_) => "a table",
            KeyShape::Owned(_) => "any value",
        }
    }

    /// `None` when `value` has this shape, else what the value is, as the
    /// error message names it. Only the outer shape: the keys of a
    /// [`KeyShape::Keys`] table are checked by [`check_table`].
    fn mismatch(self, value: &toml::Value) -> Option<&'static str> {
        use toml::Value as V;
        let fits = match (self, value) {
            (KeyShape::Str | KeyShape::Word(_) | KeyShape::StrOrInt, V::String(_))
            | (KeyShape::Bool, V::Boolean(_))
            | (KeyShape::Int | KeyShape::StrOrInt, V::Integer(_))
            | (KeyShape::StrOrStrList, V::String(_))
            | (KeyShape::Keys(_), V::Table(_))
            | (KeyShape::Owned(_), _) => true,
            (KeyShape::StrList | KeyShape::StrOrStrList, V::Array(items)) => {
                if !items.iter().all(V::is_str) {
                    return Some("a list with an item that is not a string");
                }
                true
            }
            _ => false,
        };
        (!fits).then(|| value_words(value))
    }
}

/// What a value is, as the error message names it.
const fn value_words(value: &toml::Value) -> &'static str {
    match value {
        toml::Value::String(_) => "a string",
        toml::Value::Integer(_) => "a whole number",
        toml::Value::Float(_) => "a decimal number",
        toml::Value::Boolean(_) => "a true or false value",
        toml::Value::Datetime(_) => "a date or time",
        toml::Value::Array(_) => "a list",
        toml::Value::Table(_) => "a table",
    }
}

/// `[box]`: the box's type, name, lifetime, loadout mode and volumes.
const BOX_KEYS: &[SectionKey] = &[
    ("lifetime", KeyShape::Word(Lifetime::ACCEPTED)),
    ("loadout_mode", KeyShape::Str),
    ("name", KeyShape::Str),
    ("type", KeyShape::Str),
    ("volumes", KeyShape::StrList),
];

/// `[io]`: the terminal, the standard streams and `exec` into the box.
const IO_KEYS: &[SectionKey] = &[
    ("exec_enabled", KeyShape::Bool),
    ("pty_enabled", KeyShape::Bool),
    ("stderr_mimetype", KeyShape::Str),
    ("stdin_mimetype", KeyShape::Str),
    ("stdout_mimetype", KeyShape::Str),
];

/// `[execution]`: what the box runs and how its run ends. `on_oom` is as
/// the resources spec (BRES) defines it, a string.
const EXECUTION_KEYS: &[SectionKey] = &[
    ("exec", KeyShape::StrOrStrList),
    ("hooks_on_resume", KeyShape::Bool),
    ("on_oom", KeyShape::Str),
    ("restart", KeyShape::Str),
    ("timeout", KeyShape::StrOrInt),
];

/// `[install]`: what the box gets installed.
const INSTALL_KEYS: &[SectionKey] = &[
    ("packages", KeyShape::StrList),
    ("raw_packages", KeyShape::StrList),
];

/// `[network.egress]`: the nested egress keys that the networking and
/// egress-proxy specs bind.
const EGRESS_KEYS: &[SectionKey] = &[
    ("allow_dns_hosts", KeyShape::StrList),
    ("allow_protocols", KeyShape::StrList),
    ("allow_subnets", KeyShape::StrList),
    ("deny_subnets", KeyShape::StrList),
];

/// `[network.bep]`: the egress proxy's settings, the fields of
/// [`boxes::core::bep::BepSettings`].
const BEP_KEYS: &[SectionKey] = &[
    ("no_proxy", KeyShape::StrList),
    ("proxy_env", KeyShape::Bool),
    ("steering", KeyShape::Str),
];

/// No keys inside it are named here.
const ANY: KeyShape = KeyShape::Owned(&[]);

/// `[network]`. The flat egress keys of BOX-157 are accepted here for one
/// release. [`crate::network::canonicalize`] then moves each one to its
/// nested `egress.*` key, and it checks the shape of `mode`, `egress`,
/// `ingress`, `bep` and the flat keys, so this schema checks only their
/// names, and the names and shapes of the keys inside `egress` and `bep`.
const NETWORK_KEYS: &[SectionKey] = &[
    ("bep", KeyShape::Owned(BEP_KEYS)),
    ("dynamic_ingress", KeyShape::Str),
    ("egress", KeyShape::Owned(EGRESS_KEYS)),
    ("egress_allow_dns", ANY),
    ("egress_allow_subnets", ANY),
    ("egress_deny_subnets", ANY),
    ("ingress", ANY),
    ("mode", ANY),
    ("quic443", KeyShape::Str),
    ("vpn_network_names", KeyShape::StrList),
];

/// `[nesting]`: whether the box can create boxes, and which ones.
const NESTING_KEYS: &[SectionKey] = &[
    ("allowed", KeyShape::Bool),
    ("dynamic_providers", KeyShape::Str),
    ("max_depth", KeyShape::Int),
    ("providers", KeyShape::StrList),
    ("types", KeyShape::StrList),
];

/// The Box Spec sections whose keys this schema names, by top-level key.
///
/// The other sections are tables whose keys belong to the part of the
/// product that reads them. `[machine]` and `on_oom` belong to the
/// resources spec (BRES). `[params]`, `[vars]`, `[env_vars]` and `[args]`
/// carry the project's own names. `[secrets]` and `[otel]` are read by
/// their own components. No component reads `[nesting]` yet, so this
/// schema is the only check of its keys.
const SECTIONS: &[SectionKey] = &[
    ("box", KeyShape::Keys(BOX_KEYS)),
    ("execution", KeyShape::Keys(EXECUTION_KEYS)),
    ("install", KeyShape::Keys(INSTALL_KEYS)),
    ("io", KeyShape::Keys(IO_KEYS)),
    ("nesting", KeyShape::Keys(NESTING_KEYS)),
    ("network", KeyShape::Keys(NETWORK_KEYS)),
];

/// The section that also carries the flat top-level setting `key`, such
/// as `io` for `pty_enabled` or `install` for `packages`. `None` when
/// `key` is not a flat setting of the spec, or no section carries it.
pub(crate) fn flat_key_section(key: &str) -> Option<&'static str> {
    if !crate::expand::is_spec_key(key) {
        return None;
    }
    SECTIONS.iter().find_map(|(section, shape)| match shape {
        KeyShape::Keys(keys) if keys.iter().any(|(k, _)| *k == key) => Some(*section),
        _ => None,
    })
}

/// A key inside a Box Spec section that the spec cannot carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionProblem {
    /// The key's dotted path from the top of the spec, such as
    /// `network.egress.allow_hosts`.
    pub key: String,
    /// What is wrong with it.
    pub problem: crate::SpecKeyProblem,
}

/// Checks the keys inside the top-level section `key` of an expanded spec
/// (BOX-076), at every depth this schema names, in key order. A key that
/// is not a section, or a section whose keys the schema leaves to another
/// component, passes.
///
/// # Errors
///
/// A [`SectionProblem`] for the first key that is not a key of its
/// section, or whose value has the wrong shape.
pub fn check_section(key: &str, value: &toml::Value) -> Result<(), SectionProblem> {
    // A flat setting that a section also carries, such as `lifetime`,
    // takes the same values as the section's key.
    if let Some(section) = flat_key_section(key) {
        let shape = SECTIONS.iter().find_map(|(k, shape)| match shape {
            KeyShape::Keys(keys) if *k == section => {
                keys.iter().find(|(name, _)| *name == key).map(|(_, s)| *s)
            }
            _ => None,
        });
        if let Some(shape) = shape {
            check_word(key, shape, value)?;
        }
        return Ok(());
    }
    let Some((_, KeyShape::Keys(keys))) = SECTIONS.iter().find(|(k, _)| *k == key) else {
        return Ok(());
    };
    let Some(table) = value.as_table() else {
        return Ok(());
    };
    check_table(key, table, keys)
}

fn check_table(
    path: &str,
    table: &toml::Table,
    keys: &'static [SectionKey],
) -> Result<(), SectionProblem> {
    let mut names: Vec<&String> = table.keys().collect();
    names.sort();
    for name in names {
        let key = format!("{path}.{name}");
        let Some((_, shape)) = keys.iter().find(|(k, _)| k == name) else {
            return Err(SectionProblem {
                key,
                problem: crate::SpecKeyProblem::Unknown,
            });
        };
        let value = &table[name.as_str()];
        if let Some(found) = shape.mismatch(value) {
            return Err(SectionProblem {
                key,
                problem: crate::SpecKeyProblem::WrongShape {
                    expected: shape.words(),
                    found,
                },
            });
        }
        check_word(&key, *shape, value)?;
        match (shape, value) {
            (KeyShape::Keys(inner), toml::Value::Table(inner_table)) => {
                check_table(&key, inner_table, inner)?;
            }
            (KeyShape::Owned(inner), toml::Value::Table(inner_table)) if !inner.is_empty() => {
                check_table(&key, inner_table, inner)?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Refuses a string that a [`KeyShape::Word`] key does not accept, such
/// as `lifetime = "until-stopped"`. Any other shape or value passes.
fn check_word(key: &str, shape: KeyShape, value: &toml::Value) -> Result<(), SectionProblem> {
    match (shape, value) {
        (KeyShape::Word(accepted), toml::Value::String(found))
            if !accepted.contains(&found.as_str()) =>
        {
            Err(SectionProblem {
                key: key.to_owned(),
                problem: crate::SpecKeyProblem::UnknownValue {
                    found: found.clone(),
                    accepted,
                },
            })
        }
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// The declarer of a lifecycle hook (BOX-179).
// ---------------------------------------------------------------------------

/// The key of a lifecycle hook table that names who declared the hook.
/// The expansion writes it into each hook of the spec's `lifecycle_hooks`.
pub const DECLARED_BY: &str = "declared_by";

/// Who declared one lifecycle hook of an expanded spec: the `declared_by`
/// table of the hook (BOX-179).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum HookDeclarer {
    /// The project's `minimal.toml`, in any of its layers. It carries no
    /// host path.
    Project,
    /// The selected loadout `name`.
    Loadout {
        /// The loadout's name.
        name: String,
    },
}

impl HookDeclarer {
    /// The `declared_by` table: `{ kind = "project" }` or
    /// `{ kind = "loadout", name = "<name>" }`.
    #[must_use]
    pub fn to_value(&self) -> toml::Value {
        let mut table = toml::Table::new();
        match self {
            HookDeclarer::Project => {
                table.insert("kind".to_owned(), "project".into());
            }
            HookDeclarer::Loadout { name } => {
                table.insert("kind".to_owned(), "loadout".into());
                table.insert("name".to_owned(), name.as_str().into());
            }
        }
        toml::Value::Table(table)
    }

    /// The declarer of `hook`, a hook table of an expanded spec. `None`
    /// for a hook with no `declared_by`, or one of another shape.
    #[must_use]
    pub fn of(hook: &toml::Value) -> Option<Self> {
        hook.get(DECLARED_BY)?.clone().try_into().ok()
    }
}

/// One lifecycle hook of a stored spec, with its declarer (BOX-179). It
/// serializes as the hook's own table with a `declared_by` table beside
/// its keys, the shape the expansion writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecHook {
    /// The hook as the project or the loadout wrote it.
    pub hook: boxes::core::lifecyclehook::LifecycleHook,
    /// Who declared the hook.
    pub declared_by: HookDeclarer,
}

impl SpecHook {
    /// The stored hook of `value`, a hook table of an expanded spec.
    ///
    /// # Errors
    ///
    /// Fails when the table has no `declared_by` table of a known shape,
    /// or when the rest of it is not a valid lifecycle hook.
    pub fn from_value(value: &toml::Value) -> Result<Self, String> {
        let declared_by = HookDeclarer::of(value)
            .ok_or_else(|| format!("the hook has no valid `{DECLARED_BY}` table"))?;
        let hook = hook_without_declarer(value)
            .try_into()
            .map_err(|e: toml::de::Error| e.message().to_owned())?;
        Ok(Self { hook, declared_by })
    }

    /// The hook's table with its `declared_by` table.
    fn to_table<E: serde::ser::Error>(&self) -> Result<toml::Table, E> {
        let mut table = toml::Table::try_from(&self.hook).map_err(E::custom)?;
        table.insert(DECLARED_BY.to_owned(), self.declared_by.to_value());
        Ok(table)
    }
}

impl serde::Serialize for SpecHook {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_table::<S::Error>()?.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for SpecHook {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = toml::Value::deserialize(deserializer)?;
        Self::from_value(&value).map_err(serde::de::Error::custom)
    }
}

/// `hook`, a hook table of an expanded spec, without its `declared_by`:
/// the hook as the project or the loadout wrote it.
#[must_use]
pub fn hook_without_declarer(hook: &toml::Value) -> toml::Value {
    match hook {
        toml::Value::Table(table) => {
            let mut table = table.clone();
            table.remove(DECLARED_BY);
            toml::Value::Table(table)
        }
        other => other.clone(),
    }
}

/// The warning for a project section that the expansion leaves out of the
/// spec ([`crate::expand::IGNORED_SECTIONS`]). Each of these sections is
/// client configuration, which only the user's own `config.toml` sets.
/// The `[secret-store-rules]` warning is the one BEP-037 gives.
#[must_use]
pub fn ignored_section_warning(section: &str) -> String {
    if section == boxes::core::bep::STORE_RULES_TABLE {
        return boxes::core::bep::PROJECT_STORE_RULES_IGNORED.to_owned();
    }
    format!(
        "minimal.toml has a [{section}] table. A project cannot set {section}, \
         so the table is ignored. Put the rules in your own config.toml instead. \
         Run `min dirs` to find that file."
    )
}

/// One warning for each project section that `expansion` left out of the
/// spec, in the order the expansion found them, each section once.
#[must_use]
pub fn ignored_section_warnings(expansion: &crate::expand::Expansion) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    expansion
        .ignored_sections
        .iter()
        .filter(|(section, _)| seen.insert(section.as_str()))
        .map(|(section, _)| ignored_section_warning(section))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // BOX-068, BOX-179: the stored spec keeps each hook with its declarer,
    // and a spec with no hook list writes no key.
    #[test]
    fn spec_lifecycle_hooks_round_trip_with_declared_by() {
        let mut spec = BoxSpec::for_session(None, SpecFlags::default());
        let table = toml::Table::try_from(&spec).unwrap();
        assert!(!table.contains_key("lifecycle_hooks"));

        let hook: toml::Value = toml::from_str(
            r#"
            on_activate = { type = "inline", value = "echo hi" }
            declared_by = { kind = "loadout", name = "dev" }
            "#,
        )
        .unwrap();
        spec.lifecycle_hooks = Some(vec![SpecHook::from_value(&hook).unwrap()]);
        let table = toml::Table::try_from(&spec).unwrap();
        let stored = &table["lifecycle_hooks"][0];
        assert_eq!(
            HookDeclarer::of(stored),
            Some(HookDeclarer::Loadout { name: "dev".into() })
        );
        let back: BoxSpec = table.try_into().unwrap();
        assert_eq!(back, spec);

        // A hook with no declarer is refused.
        let bare: toml::Value =
            toml::from_str(r#"on_activate = { type = "inline", value = "echo hi" }"#).unwrap();
        assert!(SpecHook::from_value(&bare).is_err());
    }

    // BOX-203, BOX-204: a stored spec that declares exports reads back,
    // so a box with exports can resume. Its items stay as they were
    // written, and every other unknown key is still refused.
    #[test]
    fn stored_spec_with_file_exports_round_trips() {
        let spec = BoxSpec::for_session(None, SpecFlags::default());
        let table = toml::Table::try_from(&spec).unwrap();
        assert!(!table.contains_key("file_exports"));

        let mut stored = table.clone();
        let items: toml::Value = toml::from_str::<toml::Table>(
            r#"
            items = ["dist/a.txt", { path = "out/b.txt" }, { path = "./reports", note = "kept" }]
            "#,
        )
        .unwrap()["items"]
            .clone();
        stored.insert("file_exports".to_owned(), items.clone());

        let read: BoxSpec = stored.clone().try_into().unwrap();
        let kept: Vec<toml::Value> = read
            .file_exports
            .clone()
            .expect("the stored items read back")
            .into_iter()
            .map(|item| item.0)
            .collect();
        assert_eq!(toml::Value::Array(kept), items);

        let written = toml::Table::try_from(&read).unwrap();
        assert_eq!(written, stored, "a read and a write keep the stored spec");
        let again: BoxSpec = written.try_into().unwrap();
        assert_eq!(again, read);

        let nan = StoredExport(toml::Value::Float(f64::NAN));
        assert_eq!(nan, nan.clone(), "an item with a NaN float equals itself");
        assert_ne!(nan, StoredExport(toml::Value::Float(0.0)));

        let mut unknown = stored;
        unknown.insert("file_imports".to_owned(), toml::Value::Array(Vec::new()));
        let refused = unknown.try_into::<BoxSpec>().unwrap_err();
        assert!(refused.to_string().contains("file_imports"), "{refused}");
    }

    /// A value that fits `shape`, for a key the stored spec does not set.
    fn sample(shape: KeyShape) -> toml::Value {
        match shape {
            KeyShape::Str => "corp".into(),
            KeyShape::Bool => false.into(),
            KeyShape::Int | KeyShape::StrOrInt => 3.into(),
            KeyShape::StrList | KeyShape::StrOrStrList => vec![toml::Value::from("corp")].into(),
            KeyShape::Word(words) => words[0].into(),
            KeyShape::Keys(keys) | KeyShape::Owned(keys) => toml::Value::Table(
                keys.iter()
                    .map(|(key, shape)| ((*key).to_owned(), sample(*shape)))
                    .collect(),
            ),
        }
    }

    // A stored spec that carries every key the schema of a spec names reads
    // back, so a box whose spec a newer client wrote can resume. A read and
    // a write keep each key the typed spec does not read.
    #[test]
    fn stored_spec_with_every_expansion_key_reads_back() {
        let spec = BoxSpec::for_session(None, SpecFlags::default());
        let mut stored = toml::Table::try_from(&spec).unwrap();
        for (section, shape) in SECTIONS {
            let KeyShape::Keys(keys) = shape else {
                continue;
            };
            let table = stored
                .entry((*section).to_owned())
                .or_insert_with(|| toml::Value::Table(toml::Table::new()))
                .as_table_mut()
                .unwrap();
            for (key, shape) in *keys {
                // A stored spec never carries a flat egress key. The test
                // below checks that a read refuses one.
                if *section == "network"
                    && crate::network::FLAT_EGRESS_KEYS
                        .iter()
                        .any(|(flat, _)| flat == key)
                {
                    continue;
                }
                // A sample does not replace a key that the typed spec
                // wrote, such as `mode`.
                table
                    .entry((*key).to_owned())
                    .or_insert_with(|| sample(*shape));
            }
        }
        // The typed keys that `for_session` leaves out, in a shape that
        // the typed spec reads.
        stored["execution"]["exec"] = vec![toml::Value::from("make")].into();
        stored["execution"]["timeout"] = 30.into();
        stored["execution"]["hooks_on_resume"] = true.into();
        stored["network"]["egress"] = sample(KeyShape::Keys(EGRESS_KEYS));
        stored["network"]["egress"]["allow_protocols"] = vec![toml::Value::from("tcp")].into();
        stored["network"]["quic443"] = "block".into();
        // The typed policy reads `ingress` in its own shape, and a session
        // spec sets none.
        stored["network"].as_table_mut().unwrap().remove("ingress");

        let read: BoxSpec = stored.clone().try_into().unwrap();
        assert_eq!(read.entrypoint, Entrypoint::Exec(vec!["make".to_owned()]));
        assert_eq!(read.timeout, Some(30));
        assert_eq!(
            read.kept_keys.get("io.exec_enabled"),
            Some(&StoredExport(false.into()))
        );
        assert_eq!(read.network.vpn_network_names, ["corp"]);
        assert!(!read.kept_keys.contains_key("network.vpn_network_names"));
        assert!(read.kept_keys.contains_key("nesting"));

        let written = toml::Table::try_from(&read).unwrap();
        assert_eq!(written, stored, "a read and a write keep the stored spec");
        let again: BoxSpec = written.try_into().unwrap();
        assert_eq!(again, read);

        // The stored spec also reads back from its text.
        let text = toml::to_string(&stored).unwrap();
        assert_eq!(toml::from_str::<BoxSpec>(&text).unwrap(), read);

        // A duration string is a timeout that the schema allows.
        let mut duration = stored.clone();
        duration["execution"]["timeout"] = "2m".into();
        let read: BoxSpec = duration.try_into().unwrap();
        assert_eq!(read.timeout, Some(120));

        // A flat egress key is refused, and the error names its nested key.
        for (flat, nested) in crate::network::FLAT_EGRESS_KEYS {
            let mut legacy = stored.clone();
            legacy["network"].as_table_mut().unwrap().insert(
                flat.to_owned(),
                vec![toml::Value::from("10.0.0.0/8")].into(),
            );
            let refused = legacy.try_into::<BoxSpec>().unwrap_err().to_string();
            assert!(
                refused.contains(&format!("network.egress.{nested}")),
                "{flat}: {refused}"
            );
        }

        // A key that no schema of a spec names is still refused. The
        // `[network]` table flattens the policy in, so it does not refuse
        // a key, as before.
        for section in ["box", "io", "execution", "install"] {
            let mut unknown = stored.clone();
            unknown[section]
                .as_table_mut()
                .unwrap()
                .insert("not_a_key".to_owned(), true.into());
            let refused = unknown.try_into::<BoxSpec>().unwrap_err();
            assert!(
                refused.to_string().contains("not_a_key"),
                "{section}: {refused}"
            );
        }
    }

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
                    vpn_network_names: Vec::new(),
                },
                lifecycle_hooks: None,
                file_exports: None,
                kept_keys: std::collections::BTreeMap::new(),
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

        // An `[execution]` key that no schema of a spec names is refused,
        // as in every other table. `restart` is a schema key, so it is kept.
        let mut value: toml::Value = toml::from_str(&toml::to_string(&lint).unwrap()).unwrap();
        value["execution"]
            .as_table_mut()
            .unwrap()
            .insert("retries".to_string(), true.into());
        let refused = toml::from_str::<BoxSpec>(&toml::to_string(&value).unwrap()).unwrap_err();
        assert!(refused.to_string().contains("retries"), "{refused}");
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

    // BCLI-029: a session entry's spec takes its lifetime from the
    // expansion, so `until_stopped` reaches the stored spec, and an entry
    // BOX-203: a session entry's `[[file_exports]]` items, its own and the
    // ones `[defaults]` declares, reach the stored spec as written.
    #[test]
    fn for_session_entry_stores_file_exports() {
        let file = r#"
            [defaults]
            file_exports = [{ path = "shared.txt" }]

            [sessions.dev]
            packages = ["git"]

            [[sessions.dev.file_exports]]
            path = "notes.md"

            [sessions.plain]
        "#;
        let dev = expand_in(file, "dev").expect("dev expands");
        let spec =
            BoxSpec::for_session_entry("dev", &dev.spec, &dev.report, &[], SpecFlags::default());
        let paths: Vec<_> = spec
            .file_exports
            .as_ref()
            .expect("the spec stores the exports")
            .iter()
            .filter_map(|item| crate::expand::file_export_path(&item.0))
            .collect();
        assert_eq!(paths.len(), 2, "{paths:?}");
        assert!(paths.contains(&"notes.md"), "{paths:?}");
        assert!(paths.contains(&"shared.txt"), "{paths:?}");

        // The stored bytes carry the list as the top-level `file_exports`.
        let stored = toml::Table::try_from(&spec).unwrap();
        assert_eq!(
            stored["file_exports"].as_array().map(Vec::len),
            Some(2),
            "{stored:?}"
        );

        // An entry with no exports stores no list.
        let plain = expand_in(file, "plain").expect("plain expands");
        let mut plain_spec = plain.spec.clone();
        plain_spec.remove("file_exports");
        let spec = BoxSpec::for_session_entry(
            "plain",
            &plain_spec,
            &plain.report,
            &[],
            SpecFlags::default(),
        );
        assert_eq!(spec.file_exports, None);
    }

    // BOX-203: a task's `[[file_exports]]` items reach its stored spec, and
    // a task with none stores no list.
    #[test]
    fn for_task_stores_file_exports() {
        let file: crate::File = toml::from_str(
            r#"
            [tasks.build]
            exec = ["make"]

            [[tasks.build.file_exports]]
            path = "dist/out.txt"

            [tasks.plain]
            exec = ["true"]
            "#,
        )
        .unwrap();
        let build = BoxSpec::for_task("build", &file.tasks["build"], SpecFlags::default()).unwrap();
        let exports = build.file_exports.as_ref().expect("the spec stores them");
        assert_eq!(exports.len(), 1, "{exports:?}");
        assert_eq!(
            crate::expand::file_export_path(&exports[0].0),
            Some("dist/out.txt")
        );
        let plain = BoxSpec::for_task("plain", &file.tasks["plain"], SpecFlags::default()).unwrap();
        assert_eq!(plain.file_exports, None);
    }

    // that sets none keeps `until_complete`.
    #[test]
    fn box_spec_takes_lifetime_from_expansion() {
        let file = r#"
            [sessions.dev]
            packages = ["git"]

            [sessions.dev.box]
            lifetime = "until_stopped"

            [sessions.plain]
            packages = ["ripgrep"]
        "#;
        let dev = expand_in(file, "dev").expect("dev expands");
        let spec =
            BoxSpec::for_session_entry("dev", &dev.spec, &dev.report, &[], SpecFlags::default());
        assert_eq!(spec.lifetime, Lifetime::UntilStopped, "{:?}", dev.spec);
        assert_eq!(spec.entry, "dev");
        assert_eq!(spec.packages, vec!["git".to_string()]);
        assert_eq!(spec.box_type, boxes::SESSION_BOX_TYPE);
        assert!(spec.pty_enabled);
        let text = toml::to_string(&spec).unwrap();
        let value: toml::Value = toml::from_str(&text).unwrap();
        assert_eq!(
            value["box"]["lifetime"].as_str(),
            Some("until_stopped"),
            "{text}"
        );

        let plain = expand_in(file, "plain").expect("plain expands");
        let spec = BoxSpec::for_session_entry(
            "plain",
            &plain.spec,
            &plain.report,
            &[],
            SpecFlags::default(),
        );
        assert_eq!(spec.lifetime, Lifetime::UntilComplete, "{:?}", plain.spec);
        assert_eq!(spec.packages, vec!["ripgrep".to_string()]);

        // The flat key reads the same as the `box` table's.
        let flat: toml::Table = toml::from_str(r#"lifetime = "until_stopped""#).unwrap();
        let spec = BoxSpec::for_session_entry(
            "dev",
            &flat,
            &ExpansionReport::default(),
            &[],
            SpecFlags::default(),
        );
        assert_eq!(spec.lifetime, Lifetime::UntilStopped);

        // A task and a `[session]` table are not expanded, so no check
        // refuses their lifetime. Their spec keeps `until_complete`.
        let file: crate::File = toml::from_str(
            r#"
            [session]
            lifetime = "until_stopped"

            [tasks.lint]
            exec = ["true"]
            lifetime = "until_stopped"
            "#,
        )
        .unwrap();
        let session = BoxSpec::for_session(file.session.as_ref(), SpecFlags::default());
        assert_eq!(session.lifetime, Lifetime::UntilComplete);
        let lint = BoxSpec::for_task("lint", &file.tasks["lint"], SpecFlags::default()).unwrap();
        assert_eq!(lint.lifetime, Lifetime::UntilComplete);
    }

    // BCLI-029: within one type chain, a derived type's `[box] lifetime`
    // beats the flat `lifetime` of the type it extends. Both are type
    // defaults, so the type's position in the chain breaks the tie.
    #[test]
    fn box_spec_takes_lifetime_from_expansion_derived_type_wins() {
        let file = r#"
            [box_types.a]
            extends = "session"
            defaults = { lifetime = "until_complete" }

            [box_types.b]
            extends = "a"
            defaults = { box = { lifetime = "until_stopped" } }

            [boxes.dev]
            type = "b"
        "#;
        let (dev, chain) = expand_typed(file, "dev");
        assert_eq!(chain, ["session", "a", "b"]);
        let spec =
            BoxSpec::for_session_entry("dev", &dev.spec, &dev.report, &chain, SpecFlags::default());
        assert_eq!(spec.lifetime, Lifetime::UntilStopped, "{:?}", dev.spec);
    }

    // BCLI-029: the entry's `[box] lifetime` beats a flat `lifetime` that
    // a default sets. The later layer wins, whichever form each one uses.
    #[test]
    fn box_spec_takes_lifetime_from_expansion_later_layer_wins() {
        let file = r#"
            [defaults.session]
            lifetime = "until_complete"

            [sessions.dev.box]
            lifetime = "until_stopped"
        "#;
        let dev = expand_in(file, "dev").expect("dev expands");
        let spec =
            BoxSpec::for_session_entry("dev", &dev.spec, &dev.report, &[], SpecFlags::default());
        assert_eq!(spec.lifetime, Lifetime::UntilStopped, "{:?}", dev.spec);

        // The other way round: the entry's flat key beats a default's
        // `[box]` key.
        let file = r#"
            [defaults.session.box]
            lifetime = "until_stopped"

            [sessions.dev]
            lifetime = "until_complete"
        "#;
        let dev = expand_in(file, "dev").expect("dev expands");
        let spec =
            BoxSpec::for_session_entry("dev", &dev.spec, &dev.report, &[], SpecFlags::default());
        assert_eq!(spec.lifetime, Lifetime::UntilComplete, "{:?}", dev.spec);
    }

    // BCLI-029: the stored packages union the flat `packages` and the
    // `[install] packages` of every layer, in layer order, once each.
    #[test]
    fn box_spec_takes_lifetime_from_expansion_unions_packages() {
        let file = r#"
            [defaults]
            packages = ["a", "c"]

            [sessions.dev.install]
            packages = ["b", "a"]
        "#;
        let dev = expand_in(file, "dev").expect("dev expands");
        let spec =
            BoxSpec::for_session_entry("dev", &dev.spec, &dev.report, &[], SpecFlags::default());
        assert_eq!(spec.packages, ["a", "c", "b"], "{:?}", dev.spec);
    }

    // BCLI-029: the expansion refuses a lifetime that is not one of the
    // accepted values, flat or under `[box]`, so no box silently stores
    // `until_complete` for a typo.
    #[test]
    fn box_spec_takes_lifetime_from_expansion_refuses_unknown_value() {
        for (file, key) in [
            ("[sessions.dev]\nlifetime = \"until-stopped\"\n", "lifetime"),
            (
                "[sessions.dev.box]\nlifetime = \"forever\"\n",
                "box.lifetime",
            ),
        ] {
            let err = expand_in(file, "dev").expect_err("a bad lifetime is refused");
            match &err {
                crate::Error::InvalidSpecKey {
                    key: got,
                    problem: crate::SpecKeyProblem::UnknownValue { accepted, .. },
                    ..
                } => {
                    assert_eq!(got, key, "{err}");
                    assert_eq!(*accepted, Lifetime::ACCEPTED);
                }
                other => panic!("unexpected error: {other:?}"),
            }
            let text = err.to_string();
            assert!(
                text.contains("`until_complete` or `until_stopped`"),
                "{text}"
            );
        }
    }

    /// Expands the entry `name` of `file` over its type chain and the
    /// file's `[defaults]`. Returns the expansion and the chain's type
    /// names, the root first.
    fn expand_typed(file: &str, name: &str) -> (crate::expand::Expansion, Vec<String>) {
        let entries = crate::entry::read_entries(file.as_bytes()).expect("entries read");
        let entry = entries
            .iter()
            .find(|e| e.name == name)
            .unwrap_or_else(|| panic!("entry {name} read"));
        let doc: toml::Table = toml::from_str(file).expect("test TOML parses");
        let types = crate::box_types::BoxTypes::from_file(&doc).expect("the types resolve");
        let resolved = types
            .resolve_entry(entry)
            .expect("the entry's type resolves");
        let defaults = doc
            .get("defaults")
            .and_then(toml::Value::as_table)
            .cloned()
            .unwrap_or_default();
        let project_types = types.project().keys().cloned().collect();
        let layers = crate::expand::Layers {
            type_defaults: resolved.defaults.clone(),
            type_constraints: resolved.constraints.clone(),
            ..crate::expand::Layers::default()
        }
        .with_file_defaults(&defaults, entry.box_type.as_deref(), &project_types);
        let expansion = crate::expand::expand(entry, &layers).expect("the entry expands");
        let chain = resolved.defaults.iter().map(|(t, _)| t.clone()).collect();
        (expansion, chain)
    }

    /// Expands the entry `name` of `file`, with the file's `[defaults]`.
    fn expand_in(file: &str, name: &str) -> Result<crate::expand::Expansion, crate::Error> {
        let entries = crate::entry::read_entries(file.as_bytes()).expect("entries read");
        let entry = entries
            .iter()
            .find(|e| e.name == name)
            .unwrap_or_else(|| panic!("entry {name} read"));
        let doc: toml::Table = toml::from_str(file).expect("test TOML parses");
        let defaults = doc
            .get("defaults")
            .and_then(toml::Value::as_table)
            .cloned()
            .unwrap_or_default();
        let layers = crate::expand::Layers::default().with_file_defaults(
            &defaults,
            entry.box_type.as_deref(),
            &std::collections::BTreeSet::new(),
        );
        crate::expand::expand(entry, &layers)
    }

    // BCLI-024: an entry's `network.vpn_network_names` reach the typed spec
    // and its stored bytes, on a session entry and on a task. A stored spec
    // reads the list back into the typed field, and an entry that sets none
    // stores no key.
    #[test]
    fn spec_keeps_vpn_network_names() {
        let file = r#"
            [sessions.dev.network]
            vpn_network_names = ["corp", "lab", "corp"]

            [sessions.plain]
        "#;
        let dev = expand_in(file, "dev").expect("dev expands");
        let spec =
            BoxSpec::for_session_entry("dev", &dev.spec, &dev.report, &[], SpecFlags::default());
        assert_eq!(spec.network.vpn_network_names, ["corp", "lab"]);

        let stored = toml::Table::try_from(&spec).unwrap();
        assert_eq!(
            stored["network"]["vpn_network_names"],
            toml::Value::from(vec!["corp", "lab"]),
            "{stored:?}"
        );
        let read: BoxSpec = stored.try_into().unwrap();
        assert_eq!(read, spec, "a stored spec reads the list back");
        assert!(read.kept_keys.is_empty(), "{:?}", read.kept_keys);

        let plain = expand_in(file, "plain").expect("plain expands");
        let spec = BoxSpec::for_session_entry(
            "plain",
            &plain.spec,
            &plain.report,
            &[],
            SpecFlags::default(),
        );
        assert!(spec.network.vpn_network_names.is_empty());
        let stored = toml::Table::try_from(&spec).unwrap();
        assert!(
            stored["network"].get("vpn_network_names").is_none(),
            "{stored:?}"
        );

        // A hand-edited stored spec with another shape still reads: the
        // string items of a list are kept, and any other value is no names.
        let mut odd = toml::Table::try_from(&spec).unwrap();
        odd["network"].as_table_mut().unwrap().insert(
            "vpn_network_names".to_owned(),
            vec![toml::Value::from("corp"), toml::Value::from(7)].into(),
        );
        let read: BoxSpec = odd.clone().try_into().unwrap();
        assert_eq!(read.network.vpn_network_names, ["corp"]);
        odd["network"]["vpn_network_names"] = "corp".into();
        let read: BoxSpec = odd.try_into().unwrap();
        assert!(read.network.vpn_network_names.is_empty());

        let task_file: crate::File = toml::from_str(
            r#"
            [tasks.build]
            exec = ["make"]

            [tasks.build.network]
            vpn_network_names = ["corp"]
            "#,
        )
        .unwrap();
        let build =
            BoxSpec::for_task("build", &task_file.tasks["build"], SpecFlags::default()).unwrap();
        assert_eq!(build.network.vpn_network_names, ["corp"]);
    }

    // BOX-076: every Box Spec section expands with its keys, and
    // `[network]` takes the nested `egress.*` shape. The flat egress keys
    // of BOX-157 are accepted, and canonicalisation nests them.
    #[test]
    fn sections_follow_box_toml_with_nested_egress() {
        let file = r#"
            [sessions.dev]
            hooks_on_resume = true
            volumes = ["cache"]

            [sessions.dev.box]
            type = "session"
            name = "dev"
            lifetime = "until_stopped"
            loadout_mode = "open"
            volumes = ["cache"]

            [sessions.dev.io]
            pty_enabled = true
            exec_enabled = false
            stdin_mimetype = "text/plain"
            stdout_mimetype = "text/plain"
            stderr_mimetype = "text/plain"

            [sessions.dev.execution]
            exec = ["bash", "-l"]
            timeout = "30m"
            on_oom = "kill"
            hooks_on_resume = true

            [sessions.dev.install]
            packages = ["git"]
            raw_packages = ["ripgrep"]

            [sessions.dev.machine]
            cpus = 2
            memory = "4G"

            [sessions.dev.network]
            mode = "own_ip"
            quic443 = "auto"
            vpn_network_names = ["corp"]
            ingress = [{ proto = "tcp", port = 8080 }]
            dynamic_ingress = "allow"

            [sessions.dev.network.egress]
            allow_dns_hosts = ["example.com"]
            allow_subnets = ["10.0.0.0/8"]
            deny_subnets = ["10.1.0.0/16"]
            allow_protocols = ["https"]

            [sessions.dev.network.bep]
            steering = "dns"
            proxy_env = true
            no_proxy = ["localhost"]

            [sessions.dev.nesting]
            allowed = true
            max_depth = 2
            providers = ["local"]
            types = ["task"]
            dynamic_providers = "deny"

            [sessions.dev.secrets.gh]
            source = "store"

            [sessions.dev.otel]
            endpoint = "http://localhost:4317"

            [[sessions.dev.file_imports]]
            src = "a"
            dst = "/a"

            [[sessions.dev.file_exports]]
            src = "/b"
            dst = "b"

            [[sessions.dev.github_imports]]
            repo = "gominimal/minimal"

            [tasks.lint]
            args = { fix = "false" }
            exec = "cargo clippy"
            [tasks.lint.network]
            mode = "host_ip"
            egress_allow_dns = ["crates.io"]
        "#;
        let dev = expand_in(file, "dev").expect("every section is accepted");
        let net = &dev.spec["network"];
        assert_eq!(
            net["egress"]["allow_dns_hosts"].as_array().map(Vec::len),
            Some(1)
        );
        for section in [
            "box",
            "io",
            "execution",
            "install",
            "machine",
            "network",
            "nesting",
            "secrets",
            "otel",
            "file_imports",
            "file_exports",
            "github_imports",
        ] {
            assert!(dev.spec.contains_key(section), "{section} is carried");
        }

        let mut lint = expand_in(file, "lint").expect("a flat egress key is accepted");
        crate::network::canonicalize(&mut lint.spec).expect("canonicalises");
        let net = lint.spec["network"].as_table().expect("a table");
        assert!(!net.contains_key("egress_allow_dns"), "{net:?}");
        assert_eq!(
            net["egress"]["allow_dns_hosts"][0].as_str(),
            Some("crates.io")
        );
    }

    // BOX-076: an unknown key or a value of the wrong shape, at any depth
    // of a section, fails with exit 3 and names the key.
    #[test]
    fn unknown_key_or_shape_exit3() {
        let cases = [
            (
                "[sessions.dev.network.egress]\nallow_hosts = [\"x\"]\n",
                "`[sessions.dev]` in minimal.toml sets `network.egress.allow_hosts`, \
                 which is not a box setting. Remove the key or correct its name.",
            ),
            (
                "[sessions.dev.io]\npty = true\n",
                "`[sessions.dev]` in minimal.toml sets `io.pty`, \
                 which is not a box setting. Remove the key or correct its name.",
            ),
            (
                "[sessions.dev.box]\ntipe = \"session\"\n",
                "`[sessions.dev]` in minimal.toml sets `box.tipe`, \
                 which is not a box setting. Remove the key or correct its name.",
            ),
            (
                "[sessions.dev.execution]\ntimeout = true\n",
                "`[sessions.dev]` in minimal.toml sets `execution.timeout` to a \
                 true or false value, but `execution.timeout` takes a string or a \
                 whole number. Fix the value.",
            ),
            (
                "[sessions.dev.network]\nvpn_network_names = \"corp\"\n",
                "`[sessions.dev]` in minimal.toml sets `network.vpn_network_names` \
                 to a string, but `network.vpn_network_names` takes a list of \
                 strings. Fix the value.",
            ),
            (
                "[sessions.dev.io]\nstdin_mimetype = 0\n",
                "`[sessions.dev]` in minimal.toml sets `io.stdin_mimetype` to a whole \
                 number, but `io.stdin_mimetype` takes a string. Fix the value.",
            ),
            (
                "[sessions.dev.io]\nstdin = \"null\"\n",
                "`[sessions.dev]` in minimal.toml sets `io.stdin`, \
                 which is not a box setting. Remove the key or correct its name.",
            ),
            (
                "[sessions.dev.nesting]\nalowed = true\n",
                "`[sessions.dev]` in minimal.toml sets `nesting.alowed`, \
                 which is not a box setting. Remove the key or correct its name.",
            ),
            (
                "[sessions.dev.nesting]\nmax_depth = \"2\"\n",
                "`[sessions.dev]` in minimal.toml sets `nesting.max_depth` to a \
                 string, but `nesting.max_depth` takes a whole number. Fix the value.",
            ),
            (
                "[sessions.dev.network.bep]\nstering = \"dns\"\n",
                "`[sessions.dev]` in minimal.toml sets `network.bep.stering`, \
                 which is not a box setting. Remove the key or correct its name.",
            ),
            (
                "[sessions.dev.box]\ndescription = \"dev box\"\n",
                "`[sessions.dev]` in minimal.toml sets `box.description`, \
                 which is not a box setting. Remove the key or correct its name.",
            ),
            (
                "[sessions.dev.network]\nmode = \"own_ip\"\nvpn = [\"corp\"]\n",
                "`[sessions.dev]` in minimal.toml sets `network.vpn`, \
                 which is not a box setting. Remove the key or correct its name.",
            ),
            (
                "[sessions.dev.network]\nquic443 = true\n",
                "`[sessions.dev]` in minimal.toml sets `network.quic443` to a true \
                 or false value, but `network.quic443` takes a string. Fix the value.",
            ),
            (
                "[sessions.dev.install]\npackages = [\"git\", 3]\n",
                "`[sessions.dev]` in minimal.toml sets `install.packages` to a list \
                 with an item that is not a string, but `install.packages` takes a \
                 list of strings. Fix the value.",
            ),
            (
                "[defaults.session.network.egress]\ndeny = [\"x\"]\n[sessions.dev]\n",
                "`[defaults.session]` in minimal.toml sets `network.egress.deny`, \
                 which is not a box setting. Remove the key or correct its name.",
            ),
            (
                "[sessions.dev]\nstray = 1\n",
                "`[sessions.dev]` in minimal.toml sets `stray`, \
                 which is not a box setting. Remove the key or correct its name.",
            ),
        ];
        for (file, message) in cases {
            let err = expand_in(file, "dev").expect_err(file);
            assert_eq!(err.exit_code(), Some(3), "{file}");
            assert_eq!(err.to_string(), message, "{file}");
        }
    }

    // BOX-076, BEP-037: a project's client sections stay out of the
    // expanded spec, and each one gets one warning that names it.
    #[test]
    fn project_secret_store_and_file_rules_left_out_of_spec_with_warning() {
        let file = r#"
            [defaults.package-file-rules]
            keep = ["a"]
            [sessions.dev]
            packages = ["git"]
            [sessions.dev.secret-store-rules.gh]
            upstream = ["github.com"]
            [sessions.dev.loadout-file-rules]
            keep = ["b"]
            [sessions.dev.package-file-rules]
            keep = ["c"]
        "#;
        let e = expand_in(file, "dev").expect("client sections are left out, not refused");
        let bytes = e.spec_bytes().expect("writes");
        for section in crate::expand::IGNORED_SECTIONS {
            assert!(!e.spec.contains_key(section), "{section}");
            assert!(!bytes.contains(section), "{section} in {bytes}");
        }
        let warnings = ignored_section_warnings(&e);
        assert_eq!(
            warnings,
            vec![
                "minimal.toml has a [package-file-rules] table. A project cannot set \
                 package-file-rules, so the table is ignored. Put the rules in your own \
                 config.toml instead. Run `min dirs` to find that file."
                    .to_owned(),
                "minimal.toml has a [loadout-file-rules] table. A project cannot set \
                 loadout-file-rules, so the table is ignored. Put the rules in your own \
                 config.toml instead. Run `min dirs` to find that file."
                    .to_owned(),
                boxes::core::bep::PROJECT_STORE_RULES_IGNORED.to_owned(),
            ],
            "one warning per section, each naming it"
        );
    }

    // BOX-085: `[params]` on an entry is accepted and carried in the
    // expanded spec's bytes.
    #[test]
    fn params_accepted_and_rendered() {
        let file = r#"
            [defaults.session.params]
            region = "eu"
            [sessions.dev]
            [sessions.dev.params]
            model = "large"
            retries = 3
        "#;
        let e = expand_in(file, "dev").expect("params are accepted");
        let params = e.spec["params"].as_table().expect("a table");
        assert_eq!(params["model"].as_str(), Some("large"));
        assert_eq!(params["retries"].as_integer(), Some(3));
        assert!(
            !params.contains_key("region"),
            "the entry's table replaces the defaults' table: {params:?}"
        );
        let bytes = e.spec_bytes().expect("writes");
        assert!(bytes.contains("[params]"), "{bytes}");
        assert!(bytes.contains("model = \"large\""), "{bytes}");
        assert!(bytes.contains("retries = 3"), "{bytes}");

        let err = expand_in("[sessions.dev]\nparams = \"x\"\n", "dev").expect_err("not a table");
        assert_eq!(err.exit_code(), Some(3));
        assert!(err.to_string().contains("`params` takes a table"), "{err}");
    }
}
