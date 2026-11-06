//! The legacy tables of `minimal.toml`, read for one release with a hint.
//!
//! Before Box Specs, a file wrote three things in places that the Box Spec
//! layout moves:
//!
//! - a top-level `[session]` table, now `[defaults.session]` (BOX-050);
//! - `state_key` and `profile` under top-level `[defaults]`, now under
//!   `[defaults.task]` (BOX-051);
//! - a top-level `[params]` parameter schema, now `[args]` (BOX-052).
//!
//! Releases before [`REFUSING_RELEASE`] read each one as its new location and
//! give one hint each time they read it. From [`REFUSING_RELEASE`] on, each one
//! fails with [`Error::LegacyTable`], which exits 3 and carries the same
//! hint.
//!
//! Two readers use this module. [`canonicalize`] rewrites a raw document to
//! the Box Spec layout, for the entry expansion. [`settle`] does the same
//! for a loaded [`File`], whose fields keep the old layout, so the new
//! spellings that the hints name work on this release too.

use std::fmt;
use std::path::Path;

use crate::{Error, File, Session};

/// The first release that refuses the legacy tables. The release before
/// it, 0.8, is the one release that reads them, with a hint. Its
/// development builds report `0.8.0-dev.<n>.g<commit>`.
pub const REFUSING_RELEASE: (u64, u64, u64) = (0, 9, 0);

/// The release this build reports.
#[must_use]
pub fn this_release() -> &'static str {
    version::VERSION
}

/// One legacy table or key set that a file carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegacyTable {
    /// A top-level `[session]` table (BOX-050).
    Session,
    /// `state_key` or `profile`, or both, under top-level `[defaults]`
    /// (BOX-051).
    DefaultsTaskKeys { state_key: bool, profile: bool },
    /// A top-level `[params]` parameter schema (BOX-052).
    Params,
}

impl LegacyTable {
    /// What the file carries, as a refusal names it.
    #[must_use]
    pub fn what(&self) -> String {
        match self {
            LegacyTable::Session => "the `[session]` table".to_owned(),
            LegacyTable::DefaultsTaskKeys { .. } => {
                format!("{} under `[defaults]`", self.keys())
            }
            LegacyTable::Params => "the `[params]` table".to_owned(),
        }
    }

    /// The keys of [`LegacyTable::DefaultsTaskKeys`], as the text names them.
    fn keys(&self) -> &'static str {
        match self {
            LegacyTable::DefaultsTaskKeys {
                state_key: true,
                profile: true,
            } => "`state_key` and `profile`",
            LegacyTable::DefaultsTaskKeys { profile: true, .. } => "`profile`",
            _ => "`state_key`",
        }
    }

    /// The hint: the change to make, and the release that stops reading
    /// the old spelling. The same text goes to stderr during the grace
    /// window and into the exit-3 refusal after it.
    #[must_use]
    pub fn hint(&self) -> String {
        let (major, minor, patch) = REFUSING_RELEASE;
        let refusing = format!("{major}.{minor}.{patch}");
        match self {
            LegacyTable::Session => format!(
                "Rename `[session]` to `[defaults.session]` in minimal.toml. \
                 Release {refusing} and later refuse `[session]`."
            ),
            LegacyTable::DefaultsTaskKeys { state_key, profile } => {
                let keys = self.keys();
                let them = if *state_key && *profile {
                    "these keys"
                } else {
                    "it"
                };
                let deprecated = if *profile {
                    " `profile` is deprecated."
                } else {
                    ""
                };
                format!(
                    "Move {keys} from `[defaults]` to `[defaults.task]` in \
                     minimal.toml.{deprecated} Release {refusing} and later refuse \
                     {them} under `[defaults]`."
                )
            }
            LegacyTable::Params => format!(
                "Rename `[params]` to `[args]` in minimal.toml. \
                 Release {refusing} and later refuse `[params]`."
            ),
        }
    }
}

impl fmt::Display for LegacyTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "hint: {}", self.hint())
    }
}

/// Whether `release` is [`REFUSING_RELEASE`] or later. The numbers before any
/// `-` or `+` decide, so a pre-release of [`REFUSING_RELEASE`] refuses too and
/// its builds show the break before the release does. A release that does
/// not start with three numbers is inside the grace window.
#[must_use]
pub fn past_grace(release: &str) -> bool {
    let core = release
        .trim_start_matches('v')
        .split(['-', '+'])
        .next()
        .unwrap_or_default();
    let mut parts = core.split('.').map(str::parse::<u64>);
    match (parts.next(), parts.next(), parts.next()) {
        (Some(Ok(major)), Some(Ok(minor)), Some(Ok(patch))) => {
            (major, minor, patch) >= REFUSING_RELEASE
        }
        _ => false,
    }
}

/// Fails on the first of `found` when `release` is past the grace window.
fn admit(found: &[LegacyTable], release: &str, path: Option<&Path>) -> Result<(), Error> {
    match found.first() {
        Some(legacy) if past_grace(release) => Err(Error::LegacyTable {
            path: path.map(Path::to_path_buf),
            legacy: legacy.clone(),
        }),
        _ => Ok(()),
    }
}

/// Moves `key` of `table` under `table[into]`, creating that table. A key
/// that `table[into]` already sets keeps that value: the new location is
/// the more specific one.
fn move_under(table: &mut toml::Table, key: &str, into: &str) {
    let Some(value) = table.remove(key) else {
        return;
    };
    let target = table
        .entry(into)
        .or_insert_with(|| toml::Value::Table(toml::Table::new()));
    if let toml::Value::Table(target) = target {
        target.entry(key).or_insert(value);
    }
}

/// Merges `old` under `new`: each key of `new` keeps its value, and `old`
/// supplies the keys `new` does not set.
fn merge_under(old: toml::Table, new: &mut toml::Table) {
    for (key, value) in old {
        new.entry(key).or_insert(value);
    }
}

/// Rewrites a raw `minimal.toml` document to the Box Spec layout, for the
/// entry expansion: `[session]` becomes `[defaults.session]`, `state_key`
/// and `profile` under `[defaults]` move to `[defaults.task]`, and
/// `[params]` becomes `[args]`. A task entry's own `args` is not touched.
///
/// Returns one [`LegacyTable`] for each legacy table it read. The caller
/// prints each one, on every read.
///
/// # Errors
///
/// [`Error::LegacyTable`] when the document carries a legacy table and
/// `release` is [`REFUSING_RELEASE`] or later.
pub fn canonicalize(doc: &mut toml::Table, release: &str) -> Result<Vec<LegacyTable>, Error> {
    let mut found = Vec::new();
    let session = matches!(doc.get("session"), Some(toml::Value::Table(_)));
    if session {
        found.push(LegacyTable::Session);
    }
    let defaults = doc.get("defaults").and_then(toml::Value::as_table);
    let is_key = |k: &str| {
        defaults
            .and_then(|d| d.get(k))
            .is_some_and(|v| !v.is_table())
    };
    let (state_key, profile) = (is_key("state_key"), is_key("profile"));
    if state_key || profile {
        found.push(LegacyTable::DefaultsTaskKeys { state_key, profile });
    }
    let params = matches!(doc.get("params"), Some(toml::Value::Table(_)));
    if params {
        found.push(LegacyTable::Params);
    }
    admit(&found, release, None)?;

    if session && let Some(toml::Value::Table(old)) = doc.remove("session") {
        let defaults = doc
            .entry("defaults")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        if let toml::Value::Table(defaults) = defaults {
            let new = defaults
                .entry("session")
                .or_insert_with(|| toml::Value::Table(toml::Table::new()));
            if let toml::Value::Table(new) = new {
                merge_under(old, new);
            }
        }
    }
    if let Some(toml::Value::Table(defaults)) = doc.get_mut("defaults") {
        if state_key {
            move_under(defaults, "state_key", "task");
        }
        if profile {
            move_under(defaults, "profile", "task");
        }
    }
    if params && let Some(toml::Value::Table(old)) = doc.remove("params") {
        let new = doc
            .entry("args")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        if let toml::Value::Table(new) = new {
            merge_under(old, new);
        }
    }
    Ok(found)
}

/// Reads the legacy tables of a loaded [`File`], whose fields keep the old
/// layout, and reads the new spellings into those fields: `[defaults.session]`
/// into [`File::session`], `state_key` and `profile` under `[defaults.task]`
/// into [`File::defaults`], and `[args]` into [`File::params`]. Where a file
/// writes both spellings, the new one wins key by key.
///
/// Returns one [`LegacyTable`] for each legacy table the file carries. The
/// caller prints each one, on every read.
///
/// # Errors
///
/// [`Error::LegacyTable`] when the file carries a legacy table and `release`
/// is [`REFUSING_RELEASE`] or later. [`Error::Format`] when a new spelling does
/// not have the shape of the table it replaces.
pub(crate) fn settle(
    file: &mut File,
    release: &str,
    path: Option<&Path>,
) -> Result<Vec<LegacyTable>, Error> {
    let mut found = Vec::new();
    if file.session.is_some() {
        found.push(LegacyTable::Session);
    }
    let state_key = file.defaults.state_key.is_some();
    let profile = file.defaults.profile.is_some();
    if state_key || profile {
        found.push(LegacyTable::DefaultsTaskKeys { state_key, profile });
    }
    if file.params.is_some() {
        found.push(LegacyTable::Params);
    }
    admit(&found, release, path)?;

    if let Some(toml::Value::Table(mut new)) = file.defaults.extra.remove("session") {
        if let Some(old) = file.session.take() {
            let old = toml::Table::try_from(&old)
                .map_err(|e| Error::Format(<toml::de::Error as serde::de::Error>::custom(e)))?;
            merge_under(old, &mut new);
        }
        file.session = Some(Session::deserialize_table(new)?);
    }
    if let Some(toml::Value::Table(mut task)) = file.defaults.extra.remove("task") {
        for (key, slot) in [
            ("state_key", &mut file.defaults.state_key),
            ("profile", &mut file.defaults.profile),
        ] {
            if let Some(toml::Value::String(s)) = task.get(key) {
                *slot = Some(s.clone());
                task.remove(key);
            }
        }
        if !task.is_empty() {
            file.defaults
                .extra
                .insert("task".to_owned(), toml::Value::Table(task));
        }
    }
    if let Some(args) = file.extra.remove("args") {
        let args: args::ArgsSpec = args.try_into().map_err(Error::Format)?;
        match &mut file.params {
            Some(params) => params.0.extend(args.0),
            None => file.params = Some(args),
        }
    }
    Ok(found)
}

impl Session {
    /// Reads a `[defaults.session]` table as a [`Session`].
    fn deserialize_table(table: toml::Table) -> Result<Self, Error> {
        toml::Value::Table(table).try_into().map_err(Error::Format)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::entry::read_entries;
    use crate::expand::{Layers, expand};

    /// A release inside the grace window.
    const IN_GRACE: &str = "0.8.0-dev.412.gd9915d40";

    fn doc(src: &str) -> toml::Table {
        toml::from_str(src).expect("test TOML parses")
    }

    /// Canonicalizes `src`, then expands its entry `name`.
    fn expand_canonical(src: &str, name: &str) -> (toml::Table, Vec<LegacyTable>) {
        let mut doc = doc(src);
        let hints = canonicalize(&mut doc, IN_GRACE).expect("inside the grace window");
        let bytes = toml::to_string(&doc).expect("writes");
        let entries = read_entries(bytes.as_bytes()).expect("entries read");
        let entry = entries
            .iter()
            .find(|e| e.name == name)
            .unwrap_or_else(|| panic!("entry {name} read"));
        let defaults = doc
            .get("defaults")
            .and_then(toml::Value::as_table)
            .cloned()
            .unwrap_or_default();
        let layers = Layers::default().with_file_defaults(
            &defaults,
            entry.box_type.as_deref(),
            &BTreeSet::new(),
        );
        (expand(entry, &layers).expect("expands").spec, hints)
    }

    /// Settles a loaded file at `release`.
    fn settled(src: &str, release: &str) -> Result<(File, Vec<LegacyTable>), Error> {
        let mut file: File = toml::from_str(src).expect("test TOML parses");
        let hints = settle(&mut file, release, None)?;
        Ok((file, hints))
    }

    // BOX-049: the per-entry keys are accepted written flat, and `packages`,
    // `patches`, `vars` and `lifecycle_hooks` keep their meaning, whether a
    // file writes them in an entry, in `[defaults.session]`, or in the
    // legacy `[session]`.
    #[test]
    fn flat_per_entry_keys_and_legacy_keys_keep_meaning() {
        let (spec, hints) = expand_canonical(
            r#"
            [sessions.dev]
            timeout = "2h"
            pty_enabled = true
            on_oom = "kill"
            machine = { cpus = 4, memory = "8GiB" }
            packages = ["git"]
            patches = { "/etc/motd" = { inline = "hi" } }
            vars = { EDITOR = "hx" }
            lifecycle_hooks = [{ on_activate = { type = "inline", value = "true" } }]
            "#,
            "dev",
        );
        assert!(hints.is_empty(), "{hints:?}");
        assert_eq!(spec["timeout"].as_str(), Some("2h"));
        assert_eq!(spec["pty_enabled"].as_bool(), Some(true));
        assert_eq!(spec["on_oom"].as_str(), Some("kill"));
        assert_eq!(spec["machine"]["cpus"].as_integer(), Some(4));
        assert_eq!(spec["packages"].as_array().map(Vec::len), Some(1));
        assert_eq!(spec["patches"]["/etc/motd"]["inline"].as_str(), Some("hi"));
        assert_eq!(spec["vars"]["EDITOR"].as_str(), Some("hx"));
        assert_eq!(
            spec["lifecycle_hooks"][0]["on_activate"]["value"].as_str(),
            Some("true")
        );

        // The four legacy keys mean the same in `[session]` and in
        // `[defaults.session]`: both load to one session contribution.
        let body = r#"
            packages = ["git", "ripgrep"]
            vars = { EDITOR = "hx" }
            lifecycle_hooks = [{ on_activate = { type = "inline", value = "true" } }]
            patches = [{ dest = ".psqlrc", source = "config/psqlrc" }]
        "#;
        let (legacy, hints) =
            settled(&format!("[session]\n{body}"), IN_GRACE).expect("inside the grace window");
        assert_eq!(hints, [LegacyTable::Session]);
        let (new, hints) = settled(&format!("[defaults.session]\n{body}"), IN_GRACE)
            .expect("the new spelling reads");
        assert!(hints.is_empty(), "{hints:?}");
        let legacy = legacy.session.expect("[session] reads");
        assert_eq!(legacy.packages, ["git", "ripgrep"]);
        assert_eq!(legacy.lifecycle_hooks.len(), 1);
        assert_eq!(Some(legacy), new.session);
        assert!(new.defaults.extra.is_empty(), "{:?}", new.defaults.extra);
    }

    // BOX-050: a top-level `[session]` reads as `[defaults.session]` and
    // gives one hint on every read.
    #[test]
    fn legacy_session_table_reads_as_defaults_session_with_hint() {
        let src = r#"
            [session]
            packages = ["git"]
            vars = { EDITOR = "hx" }

            [sessions.dev]
            packages = ["helix"]
        "#;
        for _ in 0..2 {
            let (spec, hints) = expand_canonical(src, "dev");
            assert_eq!(hints, [LegacyTable::Session]);
            let packages: Vec<_> = spec["packages"]
                .as_array()
                .expect("a list")
                .iter()
                .filter_map(toml::Value::as_str)
                .collect();
            assert_eq!(packages, ["git", "helix"]);
            assert_eq!(spec["vars"]["EDITOR"].as_str(), Some("hx"));
        }

        let mut d = doc(src);
        canonicalize(&mut d, IN_GRACE).expect("inside the grace window");
        assert!(!d.contains_key("session"), "{d:?}");
        assert_eq!(
            d["defaults"]["session"]["packages"]
                .as_array()
                .map(Vec::len),
            Some(1)
        );

        // A `[session]`-only project still loads, with one hint on each load.
        for _ in 0..2 {
            let (file, hints) = settled("[session]\npackages = [\"git\"]\n", IN_GRACE)
                .expect("inside the grace window");
            assert_eq!(hints.len(), 1);
            assert_eq!(file.session.expect("reads").packages, ["git"]);
        }
        let file = File::from_toml_bytes(b"[session]\npackages = [\"git\"]\n")
            .expect("this release reads [session]");
        assert_eq!(file.session.expect("reads").packages, ["git"]);

        // The new spelling wins key by key over the legacy table.
        let (file, _) = settled(
            "[session]\npackages = [\"git\"]\nvars = { A = \"1\" }\n\
             [defaults.session]\npackages = [\"helix\"]\n",
            IN_GRACE,
        )
        .expect("inside the grace window");
        let session = file.session.expect("reads");
        assert_eq!(session.packages, ["helix"]);
        assert_eq!(session.vars.len(), 1);

        let hint = LegacyTable::Session.to_string();
        assert_eq!(
            hint,
            "hint: Rename `[session]` to `[defaults.session]` in minimal.toml. \
             Release 0.9.0 and later refuse `[session]`."
        );
    }

    // BOX-050: from the grace release on, each legacy table fails with exit
    // 3, carrying the same hint.
    #[test]
    fn legacy_tables_exit3_after_grace_release() {
        let cases = [
            ("[session]\npackages = [\"git\"]\n", LegacyTable::Session),
            (
                "[defaults]\nstate_key = \"dev\"\n",
                LegacyTable::DefaultsTaskKeys {
                    state_key: true,
                    profile: false,
                },
            ),
            (
                "[params.mode]\ntype = \"string\"\ndefault = \"x\"\n",
                LegacyTable::Params,
            ),
        ];
        for release in ["0.9.0", "0.9.0-dev.1.gabc", "0.10.3", "1.0.0"] {
            assert!(past_grace(release), "{release}");
            for (src, legacy) in &cases {
                let err = canonicalize(&mut doc(src), release).expect_err("past grace");
                assert_eq!(err.exit_code(), Some(3), "{err}");
                assert!(err.to_string().contains(&legacy.to_string()), "{err}");
                let err = settled(src, release).expect_err("past grace");
                assert_eq!(err.exit_code(), Some(3), "{err}");
                assert!(err.to_string().contains(&legacy.to_string()), "{err}");
                assert!(err.to_string().contains(&legacy.what()), "{err}");
            }
        }
        for release in [
            "0.8.0",
            "0.8.0-dev.3.gabc",
            "0.8.4",
            "0.7.2",
            "0.0.1",
            "unknown",
        ] {
            assert!(!past_grace(release), "{release}");
            for (src, _) in &cases {
                canonicalize(&mut doc(src), release).expect("inside grace");
                settled(src, release).expect("inside grace");
            }
        }

        let err = settled("[session]\n", "0.9.0").expect_err("past grace");
        assert_eq!(
            err.to_string(),
            "minimal.toml: this release no longer reads the `[session]` table.\n\
             hint: Rename `[session]` to `[defaults.session]` in minimal.toml. \
             Release 0.9.0 and later refuse `[session]`."
        );
        // The new spellings never fail.
        let new = "[defaults.session]\npackages = [\"git\"]\n\
                   [defaults.task]\nstate_key = \"dev\"\n\
                   [args.mode]\ntype = \"string\"\ndefault = \"x\"\n";
        assert!(
            canonicalize(&mut doc(new), "9.0.0")
                .expect("reads")
                .is_empty()
        );
        assert!(settled(new, "9.0.0").expect("reads").1.is_empty());
    }

    // BOX-051: `state_key` and `profile` under `[defaults]` read as
    // `[defaults.task]`, with one hint that names `profile` as deprecated.
    #[test]
    fn legacy_defaults_task_keys_with_hint() {
        let src = r#"
            [defaults]
            state_key = "dev"
            profile = "old"
            packages = ["git"]

            [tasks.lint]
            exec = "cargo clippy"
        "#;
        let (spec, hints) = expand_canonical(src, "lint");
        let legacy = LegacyTable::DefaultsTaskKeys {
            state_key: true,
            profile: true,
        };
        assert_eq!(hints, std::slice::from_ref(&legacy));
        assert_eq!(spec["state_key"].as_str(), Some("dev"));
        assert_eq!(spec["profile"].as_str(), Some("old"));
        // A session entry no longer takes the task keys.
        let (spec, _) = expand_canonical(&format!("{src}\n[sessions.dev]\n"), "dev");
        assert!(!spec.contains_key("state_key"), "{spec:?}");
        assert_eq!(spec["packages"].as_array().map(Vec::len), Some(1));

        assert_eq!(
            legacy.to_string(),
            "hint: Move `state_key` and `profile` from `[defaults]` to \
             `[defaults.task]` in minimal.toml. `profile` is deprecated. \
             Release 0.9.0 and later refuse these keys under `[defaults]`."
        );
        let only = LegacyTable::DefaultsTaskKeys {
            state_key: true,
            profile: false,
        };
        assert!(!only.hint().contains("deprecated"), "{only}");

        // The loaded file gives the task its state key from either spelling.
        let (file, hints) = settled(src, IN_GRACE).expect("inside grace");
        assert_eq!(hints, [legacy]);
        assert_eq!(file.defaults.state_key.as_deref(), Some("dev"));
        let (file, hints) = settled(
            "[defaults.task]\nstate_key = \"dev\"\n[tasks.lint]\nexec = \"x\"\n",
            IN_GRACE,
        )
        .expect("the new spelling reads");
        assert!(hints.is_empty(), "{hints:?}");
        assert_eq!(file.defaults.state_key.as_deref(), Some("dev"));
        assert!(file.defaults.extra.is_empty(), "{:?}", file.defaults.extra);
        let task = file.task("lint").expect("the task reads");
        assert_eq!(task.state_key.as_deref(), Some("dev"));
    }

    // BOX-052: a top-level `[params]` reads as `[args]`, with one hint, and
    // a task's own `args` is unchanged.
    #[test]
    fn legacy_params_reads_as_args_with_hint() {
        let src = r#"
            [params.mode]
            type = "string"
            default = "fast"

            [tasks.build]
            exec = "make %{target}"
            args.target = "string"
        "#;
        let mut d = doc(src);
        let hints = canonicalize(&mut d, IN_GRACE).expect("inside grace");
        assert_eq!(hints, [LegacyTable::Params]);
        assert!(!d.contains_key("params"), "{d:?}");
        assert_eq!(d["args"]["mode"]["default"].as_str(), Some("fast"));
        assert_eq!(
            d["tasks"]["build"]["args"]["target"].as_str(),
            Some("string")
        );
        let (spec, _) = expand_canonical(src, "build");
        assert_eq!(spec["args"]["target"].as_str(), Some("string"));
        assert_eq!(
            LegacyTable::Params.to_string(),
            "hint: Rename `[params]` to `[args]` in minimal.toml. \
             Release 0.9.0 and later refuse `[params]`."
        );

        let (legacy, hints) = settled(src, IN_GRACE).expect("inside grace");
        assert_eq!(hints, [LegacyTable::Params]);
        let (new, hints) = settled(&src.replace("[params.mode]", "[args.mode]"), IN_GRACE)
            .expect("the new spelling reads");
        assert!(hints.is_empty(), "{hints:?}");
        assert_eq!(legacy.params, new.params);
        assert_eq!(legacy.tasks, new.tasks);
        new.validate().expect("[args] validates as [params] did");
        assert!(new.params.expect("reads").0.contains_key("mode"));
    }
}
