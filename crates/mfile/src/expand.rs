//! Expansion: the fold of a box entry's layers into one expanded spec.
//!
//! An entry expands in the order of [`Layer::ORDER`] (BOX-064): the
//! `[upstream]` layer of minimal.toml, the defaults of the entry's Box Type
//! chain (root first), `[defaults]`, `[defaults.<type>]`, the entry, the
//! selected loadouts, then the command-line overrides. The merge rule is
//! the same between every pair of layers (BOX-048): a list unions with the
//! list before it in layer order, each value once, and any other value
//! (a scalar or a table) replaces the earlier one wholesale.
//!
//! The fold is a pure function. Its spec is a `toml::Table`, and
//! [`Expansion::spec_bytes`] writes it with every table in key order, so
//! one set of layers gives the same bytes on every run (BOX-065).
//!
//! The [`ExpansionReport`] says, for every value of the spec, the layer
//! that set it, and for a type's defaults the type (BOX-161). It is kept
//! beside the spec and is never part of the spec's bytes.
//!
//! After the fold, every key of the spec is checked against the box
//! settings and the shape each one takes. A bad key fails with
//! [`Error::InvalidSpecKey`], which exits 3 and names the key and the
//! layer that set it (BOX-066).

use std::collections::{BTreeMap, BTreeSet};

use crate::Error;
use crate::entry::BoxEntry;
use crate::error::{EntryHeader, SpecKeyProblem};

/// The built-in Box Types. A `[defaults.<name>]` table for one of these,
/// or for a project type, is that type's defaults, not a `[defaults]` key.
pub const BUILTIN_BOX_TYPES: [&str; 6] = [
    "session",
    "task",
    "agent",
    "service",
    "build",
    "container-build",
];

/// One layer of an entry's expansion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Layer {
    /// The `[upstream]` table of minimal.toml: the registry pin.
    Upstream,
    /// The `defaults` of a Box Type in the entry's type chain.
    TypeDefaults,
    /// The project's `[defaults]` table, without its type tables.
    Defaults,
    /// The project's `[defaults.<type>]` table for the entry's type.
    DefaultsType,
    /// The entry's own table.
    Entry,
    /// The loadouts that the creating command selected.
    Loadouts,
    /// The creating command's command-line overrides.
    Overrides,
}

impl Layer {
    /// Every layer, in the order the fold applies them (BOX-064).
    pub const ORDER: [Layer; 7] = [
        Layer::Upstream,
        Layer::TypeDefaults,
        Layer::Defaults,
        Layer::DefaultsType,
        Layer::Entry,
        Layer::Loadouts,
        Layer::Overrides,
    ];
}

/// Where one value of an expanded spec came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    /// The layer that set the value.
    pub layer: Layer,
    /// For [`Layer::TypeDefaults`], the type whose defaults set the value.
    /// `None` for every other layer.
    pub box_type: Option<String>,
}

impl Origin {
    /// The origin of a value set by `layer`, which is not a type's defaults.
    #[must_use]
    pub fn of(layer: Layer) -> Self {
        Self {
            layer,
            box_type: None,
        }
    }

    /// The origin of a value set by the defaults of `box_type`.
    #[must_use]
    pub fn type_defaults(box_type: &str) -> Self {
        Self {
            layer: Layer::TypeDefaults,
            box_type: Some(box_type.to_owned()),
        }
    }
}

/// Where the value of one top-level key came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueOrigin {
    /// A scalar or a table: the one layer that set it.
    Value(Origin),
    /// A list: the layer that set each item, in the list's order.
    List(Vec<Origin>),
}

impl ValueOrigin {
    /// The origin of the whole value, or of a list's first item. `None`
    /// only for an empty list.
    #[must_use]
    pub fn first(&self) -> Option<&Origin> {
        match self {
            ValueOrigin::Value(o) => Some(o),
            ValueOrigin::List(items) => items.first(),
        }
    }
}

/// The sources of an expanded spec's values, kept beside the spec
/// (BOX-161). It has one item for each top-level key of the spec.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExpansionReport {
    /// The origin of each top-level key's value, by key.
    pub values: BTreeMap<String, ValueOrigin>,
}

/// The layers of one entry that are not in the entry's own table. Each
/// layer is a table of spec keys. An empty table is a layer that sets
/// nothing.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Layers {
    /// The `[upstream]` table of minimal.toml, as the file writes it: the
    /// registry pin (`repo_url`, `branch`, `commit`, `build_cache_url`).
    /// [`expand`] folds it as the one spec key `upstream`. It holds no
    /// box settings.
    pub upstream: toml::Table,
    /// The defaults of each type in the entry's type chain, the built-in
    /// root first and the entry's own type last, each with its type name.
    pub type_defaults: Vec<(String, toml::Table)>,
    /// `[defaults]`, without its type tables.
    pub defaults: toml::Table,
    /// `[defaults.<type>]` for the entry's type.
    pub defaults_type: toml::Table,
    /// The selected loadouts' layer.
    pub loadouts: toml::Table,
    /// The command-line overrides.
    pub overrides: toml::Table,
}

impl Layers {
    /// Sets [`Layers::defaults`] and [`Layers::defaults_type`] from the
    /// file's top-level `[defaults]` table (BOX-048).
    ///
    /// A key of `[defaults]` whose name is a built-in type or one of
    /// `project_types`, and whose value is a table, is that type's
    /// defaults. Only the one for `box_type` goes into
    /// [`Layers::defaults_type`]. Every other key is in
    /// [`Layers::defaults`], which applies to every entry.
    #[must_use]
    pub fn with_file_defaults(
        mut self,
        defaults: &toml::Table,
        box_type: Option<&str>,
        project_types: &BTreeSet<String>,
    ) -> Self {
        let is_type = |k: &str| BUILTIN_BOX_TYPES.contains(&k) || project_types.contains(k);
        self.defaults = toml::Table::new();
        self.defaults_type = toml::Table::new();
        for (key, value) in defaults {
            match value {
                toml::Value::Table(t) if is_type(key) => {
                    if box_type == Some(key.as_str()) {
                        self.defaults_type = t.clone();
                    }
                }
                _ => {
                    self.defaults.insert(key.clone(), value.clone());
                }
            }
        }
        self
    }
}

/// An expanded spec and its report.
#[derive(Debug, Clone, PartialEq)]
pub struct Expansion {
    /// The expanded spec.
    pub spec: toml::Table,
    /// Where each of the spec's values came from. Never in the spec bytes.
    pub report: ExpansionReport,
    /// Each project section that the fold left out ([`IGNORED_SECTIONS`]),
    /// with the layer that carried it, in layer order. The caller warns
    /// about each one. Never in the spec bytes or the report.
    pub ignored_sections: Vec<(String, Origin)>,
}

impl Expansion {
    /// The spec's bytes: TOML with every table, at every depth, in key
    /// order. The report is not in them.
    ///
    /// # Errors
    ///
    /// The TOML writer's error. A spec of TOML values does not cause one.
    pub fn spec_bytes(&self) -> Result<String, toml::ser::Error> {
        toml::to_string(&canonical_table(&self.spec))
    }
}

/// Expands `entry` over `layers` in the order of [`Layer::ORDER`], then
/// checks every key of the result.
///
/// # Errors
///
/// [`Error::InvalidSpecKey`] for the first key, in key order, that is not
/// a box setting or has a value of the wrong shape. It names the layer
/// that set the bad value.
pub fn expand(entry: &BoxEntry, layers: &Layers) -> Result<Expansion, Error> {
    // The `[upstream]` table is the registry pin, so it sets the one spec
    // key `upstream` and nothing else. An empty table sets nothing.
    let mut upstream = toml::Table::new();
    if !layers.upstream.is_empty() {
        upstream.insert(
            "upstream".to_owned(),
            toml::Value::Table(layers.upstream.clone()),
        );
    }
    let mut ordered: Vec<(Origin, &toml::Table)> = vec![(Origin::of(Layer::Upstream), &upstream)];
    for (box_type, table) in &layers.type_defaults {
        ordered.push((Origin::type_defaults(box_type), table));
    }
    ordered.push((Origin::of(Layer::Defaults), &layers.defaults));
    ordered.push((Origin::of(Layer::DefaultsType), &layers.defaults_type));
    ordered.push((Origin::of(Layer::Entry), &entry.body));
    ordered.push((Origin::of(Layer::Loadouts), &layers.loadouts));
    ordered.push((Origin::of(Layer::Overrides), &layers.overrides));
    let expansion = fold(&ordered);
    check_keys(entry, &expansion)?;
    Ok(expansion)
}

/// The client sections that a project file can carry but never sets. The
/// fold leaves each one out of the spec and lists it in
/// [`Expansion::ignored_sections`], so the caller can warn (BOX-065).
pub const IGNORED_SECTIONS: [&str; 3] = [
    "loadout-file-rules",
    "package-file-rules",
    "secret-store-rules",
];

/// Folds the layers, in the order given, under the merge rule.
fn fold(ordered: &[(Origin, &toml::Table)]) -> Expansion {
    let mut spec = toml::Table::new();
    let mut report = ExpansionReport::default();
    let mut ignored_sections = Vec::new();
    for (origin, layer) in ordered {
        for (key, value) in layer.iter() {
            if IGNORED_SECTIONS.contains(&key.as_str()) {
                ignored_sections.push((key.clone(), origin.clone()));
                continue;
            }
            merge_value(&mut spec, &mut report, key, value, origin);
        }
    }
    Expansion {
        spec,
        report,
        ignored_sections,
    }
}

/// The keys whose list is an argument vector. Order and repeats are part of
/// the command, so a layer replaces such a list whole and keeps every item.
const ARGV_KEYS: &[&str] = &["cmdcmd", "exec"];

/// Merges one key of a layer into the spec: a list onto a list unions,
/// each item once, and any other value replaces the spec's. An argument
/// vector (`ARGV_KEYS`) always replaces, item for item.
fn merge_value(
    spec: &mut toml::Table,
    report: &mut ExpansionReport,
    key: &str,
    value: &toml::Value,
    origin: &Origin,
) {
    if ARGV_KEYS.contains(&key) {
        let value_origin = match value {
            toml::Value::Array(items) => ValueOrigin::List(vec![origin.clone(); items.len()]),
            _ => ValueOrigin::Value(origin.clone()),
        };
        spec.insert(key.to_owned(), value.clone());
        report.values.insert(key.to_owned(), value_origin);
        return;
    }
    if let (Some(toml::Value::Array(have)), toml::Value::Array(add)) = (spec.get_mut(key), value) {
        let origins = match report.values.get_mut(key) {
            Some(ValueOrigin::List(origins)) => origins,
            _ => unreachable!("a list in the spec has a list origin"),
        };
        for item in add {
            if !have.contains(item) {
                have.push(item.clone());
                origins.push(origin.clone());
            }
        }
        return;
    }
    let (value, value_origin) = match value {
        toml::Value::Array(items) => {
            let mut unique: Vec<toml::Value> = Vec::with_capacity(items.len());
            for item in items {
                if !unique.contains(item) {
                    unique.push(item.clone());
                }
            }
            let origins = vec![origin.clone(); unique.len()];
            (toml::Value::Array(unique), ValueOrigin::List(origins))
        }
        other => (other.clone(), ValueOrigin::Value(origin.clone())),
    };
    spec.insert(key.to_owned(), value);
    report.values.insert(key.to_owned(), value_origin);
}

/// A copy of `table` with every table, at every depth, in key order.
fn canonical_table(table: &toml::Table) -> toml::Table {
    let sorted: BTreeMap<&String, &toml::Value> = table.iter().collect();
    sorted
        .into_iter()
        .map(|(k, v)| (k.clone(), canonical_value(v)))
        .collect()
}

fn canonical_value(value: &toml::Value) -> toml::Value {
    match value {
        toml::Value::Table(t) => toml::Value::Table(canonical_table(t)),
        toml::Value::Array(items) => {
            toml::Value::Array(items.iter().map(canonical_value).collect())
        }
        other => other.clone(),
    }
}

/// The shape of value a box setting takes.
#[derive(Debug, Clone, Copy)]
enum Shape {
    Str,
    Bool,
    StrOrInt,
    StrList,
    StrOrStrList,
    Table,
    List,
    TableOrList,
}

impl Shape {
    /// The shape as the error message names it.
    const fn words(self) -> &'static str {
        match self {
            Shape::Str => "a string",
            Shape::Bool => "true or false",
            Shape::StrOrInt => "a string or a whole number",
            Shape::StrList => "a list of strings",
            Shape::StrOrStrList => "a string or a list of strings",
            Shape::Table => "a table",
            Shape::List => "a list",
            Shape::TableOrList => "a table or a list",
        }
    }

    /// `None` when `value` has this shape, else what the value is, as the
    /// error message names it.
    fn mismatch(self, value: &toml::Value) -> Option<&'static str> {
        let all_strings = |items: &[toml::Value]| items.iter().all(toml::Value::is_str);
        let fits = match (self, value) {
            (Shape::Str, toml::Value::String(_))
            | (Shape::Bool, toml::Value::Boolean(_))
            | (Shape::StrOrInt, toml::Value::String(_) | toml::Value::Integer(_))
            | (Shape::StrOrStrList, toml::Value::String(_))
            | (Shape::Table | Shape::TableOrList, toml::Value::Table(_))
            | (Shape::List | Shape::TableOrList, toml::Value::Array(_)) => true,
            (Shape::StrList | Shape::StrOrStrList, toml::Value::Array(items)) => {
                if !all_strings(items) {
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

/// The top-level box settings an expanded spec can carry, and the shape of
/// each: the entry keys this crate reads today, the flat per-entry keys of
/// BOX-049, the top-level sections of a Box Spec, and the keys a type's
/// defaults set.
///
/// This table is an interim. The interim table goes when
/// <https://github.com/gominimal/minimal/issues/3096> lands: BOX-076
/// replaces it with the full Box Spec schema. Two more residuals of this
/// fold are filed:
/// - <https://github.com/gominimal/minimal/issues/3097>: `expand` takes the
///   client `[secret-store-rules]` input of BOX-065.
/// - <https://github.com/gominimal/minimal/issues/3098>: [`Expansion`]
///   marks an implicit `default` entry (BOX-161 with BOX-165).
const SPEC_KEYS: &[(&str, Shape)] = &[
    ("args", Shape::Table),
    ("bash", Shape::Str),
    ("box", Shape::Table),
    ("cmdcmd", Shape::StrList),
    ("description", Shape::Str),
    ("echo", Shape::Str),
    ("env_vars", Shape::Table),
    ("exec", Shape::StrOrStrList),
    ("exec_enabled", Shape::Bool),
    ("execution", Shape::Table),
    ("file_exports", Shape::List),
    ("file_imports", Shape::List),
    ("github_imports", Shape::List),
    ("github_token_mode", Shape::Str),
    ("hooks_on_resume", Shape::Bool),
    ("inherit_cwd", Shape::Bool),
    ("install", Shape::Table),
    ("interactive", Shape::Bool),
    ("io", Shape::Table),
    ("lifecycle_hooks", Shape::List),
    ("lifetime", Shape::Str),
    ("loadout_mode", Shape::Str),
    ("loadouts", Shape::List),
    ("machine", Shape::Table),
    ("name", Shape::Str),
    ("nesting", Shape::Table),
    ("network", Shape::Table),
    ("on_oom", Shape::Str),
    ("otel", Shape::Table),
    ("packages", Shape::StrList),
    ("params", Shape::Table),
    ("patch", Shape::Table),
    ("patches", Shape::TableOrList),
    ("profile", Shape::Str),
    ("pty_enabled", Shape::Bool),
    ("restart", Shape::Str),
    ("secrets", Shape::Table),
    ("state_key", Shape::Str),
    ("timeout", Shape::StrOrInt),
    ("type", Shape::Str),
    ("upstream", Shape::Table),
    ("vars", Shape::Table),
    ("volumes", Shape::StrList),
];

/// Checks every key of the expanded spec, in key order.
fn check_keys(entry: &BoxEntry, expansion: &Expansion) -> Result<(), Error> {
    let keys: BTreeSet<&String> = expansion.spec.keys().collect();
    for key in keys {
        let value = &expansion.spec[key.as_str()];
        let origin = expansion.report.values.get(key.as_str());
        let problem = match SPEC_KEYS.iter().find(|(k, _)| k == key) {
            None => SpecKeyProblem::Unknown,
            Some((_, shape)) => match shape.mismatch(value) {
                None if key.as_str() == "upstream" => {
                    check_upstream(entry, value, origin)?;
                    continue;
                }
                None => continue,
                Some(found) => SpecKeyProblem::WrongShape {
                    expected: shape.words(),
                    found,
                },
            },
        };
        let origin = bad_value_origin(origin, value);
        return Err(Error::InvalidSpecKey {
            key: key.clone(),
            layer: layer_words(entry, origin),
            problem,
        });
    }
    Ok(())
}

/// The keys of an `[upstream]` table, the registry pin. Each takes a
/// string.
const UPSTREAM_KEYS: &[&str] = &["branch", "build_cache_url", "commit", "repo_url"];

/// Checks every key inside the spec's `upstream` table, in key order. The
/// error names a key of minimal.toml's `[upstream]` by its own name, and
/// the same key from any other layer as `upstream.<key>`.
fn check_upstream(
    entry: &BoxEntry,
    value: &toml::Value,
    origin: Option<&ValueOrigin>,
) -> Result<(), Error> {
    let Some(pin) = value.as_table() else {
        return Ok(());
    };
    let origin = origin.and_then(ValueOrigin::first);
    let keys: BTreeSet<&String> = pin.keys().collect();
    for key in keys {
        let problem = if !UPSTREAM_KEYS.contains(&key.as_str()) {
            SpecKeyProblem::UnknownUpstream
        } else if let Some(found) = Shape::Str.mismatch(&pin[key.as_str()]) {
            SpecKeyProblem::WrongShape {
                expected: Shape::Str.words(),
                found,
            }
        } else {
            continue;
        };
        let key = match origin {
            Some(o) if o.layer == Layer::Upstream => key.clone(),
            _ => format!("upstream.{key}"),
        };
        return Err(Error::InvalidSpecKey {
            key,
            layer: layer_words(entry, origin),
            problem,
        });
    }
    Ok(())
}

/// The origin of the bad part of a value: a list's first item that is not
/// a string, else the value's own origin.
fn bad_value_origin<'a>(
    origin: Option<&'a ValueOrigin>,
    value: &toml::Value,
) -> Option<&'a Origin> {
    if let (Some(ValueOrigin::List(origins)), toml::Value::Array(items)) = (origin, value)
        && let Some(i) = items.iter().position(|item| !item.is_str())
    {
        return origins.get(i);
    }
    origin.and_then(ValueOrigin::first)
}

/// A layer as the error message names it.
fn layer_words(entry: &BoxEntry, origin: Option<&Origin>) -> String {
    let Some(origin) = origin else {
        return format!(
            "`{}` in minimal.toml",
            EntryHeader(entry.table.key(), &entry.name)
        );
    };
    match origin.layer {
        Layer::Upstream => "`[upstream]` in minimal.toml".to_owned(),
        Layer::TypeDefaults => {
            let name = origin.box_type.as_deref().unwrap_or_default();
            if BUILTIN_BOX_TYPES.contains(&name) {
                format!("the built-in `{name}` box type")
            } else {
                format!("the `defaults` table of `[box_types.{name}]`")
            }
        }
        Layer::Defaults => "`[defaults]` in minimal.toml".to_owned(),
        Layer::DefaultsType => format!(
            "`[defaults.{}]` in minimal.toml",
            entry.box_type.as_deref().unwrap_or_default()
        ),
        Layer::Entry => format!(
            "`{}` in minimal.toml",
            EntryHeader(entry.table.key(), &entry.name)
        ),
        Layer::Loadouts => "a selected loadout".to_owned(),
        Layer::Overrides => "a command-line flag".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::read_entries;
    use proptest::prelude::*;

    fn table(src: &str) -> toml::Table {
        toml::from_str(src).expect("test TOML parses")
    }

    /// Expands the entry `name` of `file`, with the file's `[defaults]` and
    /// the other layers that `layers` sets.
    fn expand_in(file: &str, name: &str, layers: Layers) -> Result<Expansion, Error> {
        let entries = read_entries(file.as_bytes()).expect("entries read");
        let entry = entries
            .iter()
            .find(|e| e.name == name)
            .unwrap_or_else(|| panic!("entry {name} read"));
        let doc = table(file);
        let defaults = doc
            .get("defaults")
            .and_then(toml::Value::as_table)
            .cloned()
            .unwrap_or_default();
        let layers =
            layers.with_file_defaults(&defaults, entry.box_type.as_deref(), &BTreeSet::new());
        expand(entry, &layers)
    }

    fn strings(value: Option<&toml::Value>) -> Vec<&str> {
        value
            .and_then(toml::Value::as_array)
            .expect("a list")
            .iter()
            .map(|v| v.as_str().expect("a string"))
            .collect()
    }

    // BOX-048: `[defaults]` merges into every entry, `[defaults.<type>]`
    // into entries of that type. Lists union, scalars and tables replace.
    #[test]
    fn defaults_merge_lists_union_scalars_replace() {
        let file = r#"
            [defaults]
            packages = ["git", "ripgrep"]
            timeout = "2h"
            machine = { cpus = 2, memory = "4G" }

            [defaults.session]
            packages = ["helix", "git"]
            timeout = "8h"
            machine = { cpus = 4 }

            [sessions.dev]
            packages = ["fish"]

            [tasks.lint]
            exec = ["cargo", "clippy"]
        "#;

        let dev = expand_in(file, "dev", Layers::default()).expect("dev expands");
        assert_eq!(
            strings(dev.spec.get("packages")),
            ["git", "ripgrep", "helix", "fish"]
        );
        assert_eq!(dev.spec["timeout"].as_str(), Some("8h"));
        // The more specific table replaces the whole table: no `memory`.
        assert_eq!(dev.spec["machine"], toml::Value::Table(table("cpus = 4")));
        assert_eq!(dev.spec["type"].as_str(), Some("session"));

        // A task gets `[defaults]` but not `[defaults.session]`.
        let lint = expand_in(file, "lint", Layers::default()).expect("lint expands");
        assert_eq!(strings(lint.spec.get("packages")), ["git", "ripgrep"]);
        assert_eq!(lint.spec["timeout"].as_str(), Some("2h"));
        assert_eq!(
            lint.spec["machine"],
            toml::Value::Table(table("cpus = 2\nmemory = \"4G\""))
        );
        assert!(!lint.spec.contains_key("session"), "{:?}", lint.spec);
        assert_eq!(strings(lint.spec.get("exec")), ["cargo", "clippy"]);

        // An argument vector replaces whole and keeps its repeats.
        let argv = r#"
            [defaults.task]
            exec = ["cargo", "clippy"]
            cmdcmd = ["sh", "-c", "x"]

            [tasks.test]
            exec = ["cargo", "test", "test"]
            cmdcmd = ["cp", "a", "a"]
        "#;
        let test = expand_in(argv, "test", Layers::default()).expect("test expands");
        assert_eq!(strings(test.spec.get("exec")), ["cargo", "test", "test"]);
        assert_eq!(strings(test.spec.get("cmdcmd")), ["cp", "a", "a"]);

        // `[defaults.<project type>]` is a type table too.
        let types: BTreeSet<String> = ["rust-dev".to_owned()].into();
        let defaults = table("timeout = \"1h\"\n[rust-dev]\ntimeout = \"3h\"\n");
        let rust = Layers::default().with_file_defaults(&defaults, Some("rust-dev"), &types);
        assert_eq!(rust.defaults, table("timeout = \"1h\""));
        assert_eq!(rust.defaults_type, table("timeout = \"3h\""));
        let other = Layers::default().with_file_defaults(&defaults, Some("task"), &types);
        assert_eq!(other.defaults, table("timeout = \"1h\""));
        assert!(other.defaults_type.is_empty());
    }

    proptest! {
        // BOX-048 property: for every pair of layers, merging unions list
        // values in layer order and replaces scalars and tables with the
        // more specific layer's.
        #[test]
        fn defaults_merge_lists_union_scalars_replace_property(
            general in layer_strategy(),
            specific in layer_strategy(),
        ) {
            let merged = fold(&[
                (Origin::of(Layer::Defaults), &general),
                (Origin::of(Layer::DefaultsType), &specific),
            ]);
            let keys: BTreeSet<&String> = general.keys().chain(specific.keys()).collect();
            prop_assert_eq!(merged.spec.len(), keys.len());
            for key in keys {
                let got = &merged.spec[key.as_str()];
                match (general.get(key), specific.get(key)) {
                    (Some(toml::Value::Array(a)), Some(toml::Value::Array(b))) => {
                        let mut want: Vec<toml::Value> = Vec::new();
                        for item in a.iter().chain(b) {
                            if !want.contains(item) {
                                want.push(item.clone());
                            }
                        }
                        prop_assert_eq!(got, &toml::Value::Array(want));
                    }
                    (_, Some(toml::Value::Array(b))) => {
                        let mut want: Vec<toml::Value> = Vec::new();
                        for item in b {
                            if !want.contains(item) {
                                want.push(item.clone());
                            }
                        }
                        prop_assert_eq!(got, &toml::Value::Array(want));
                    }
                    (_, Some(v)) => prop_assert_eq!(got, v),
                    (Some(toml::Value::Array(a)), None) => {
                        let unique: BTreeSet<String> = a.iter().map(ToString::to_string).collect();
                        prop_assert_eq!(got.as_array().map(Vec::len), Some(unique.len()));
                    }
                    (Some(v), None) => prop_assert_eq!(got, v),
                    (None, None) => unreachable!("the key is in one layer"),
                }
            }
        }
    }

    /// A layer of a few keys, each a scalar, a list of strings or a table.
    fn layer_strategy() -> impl Strategy<Value = toml::Table> {
        let value = prop_oneof![
            any::<i64>().prop_map(toml::Value::Integer),
            "[a-c]{1,2}".prop_map(toml::Value::String),
            proptest::collection::vec("[a-d]".prop_map(toml::Value::String), 0..4)
                .prop_map(toml::Value::Array),
            (any::<bool>(), "[a-c]").prop_map(|(b, k)| {
                let mut t = toml::Table::new();
                t.insert(k, toml::Value::Boolean(b));
                toml::Value::Table(t)
            }),
        ];
        proptest::collection::btree_map("[k-n]", value, 0..4).prop_map(|m| m.into_iter().collect())
    }

    /// The expected value of `key` over `layers`, worked out per key and
    /// not by a fold: the last layer that sets the key decides, and when
    /// it sets a list, the list unions every list of the unbroken run of
    /// list-setting layers that ends there.
    fn expected_value(layers: &[toml::Table], key: &str) -> Option<toml::Value> {
        let setting: Vec<&toml::Value> = layers.iter().filter_map(|l| l.get(key)).collect();
        let last = *setting.last()?;
        if !last.is_array() {
            return Some(last.clone());
        }
        let run_start = setting
            .iter()
            .rposition(|v| !v.is_array())
            .map_or(0, |i| i + 1);
        let mut items: Vec<toml::Value> = Vec::new();
        for v in &setting[run_start..] {
            for item in v.as_array().into_iter().flatten() {
                if !items.contains(item) {
                    items.push(item.clone());
                }
            }
        }
        Some(toml::Value::Array(items))
    }

    // BOX-064: the layers apply in the stated order, lists union in that
    // order, and scalars and tables replace wholesale.
    #[test]
    fn expansion_order_and_merge_rules() {
        assert_eq!(
            Layer::ORDER,
            [
                Layer::Upstream,
                Layer::TypeDefaults,
                Layer::Defaults,
                Layer::DefaultsType,
                Layer::Entry,
                Layer::Loadouts,
                Layer::Overrides,
            ]
        );
        let file = r#"
            [defaults]
            packages = ["d"]
            timeout = "defaults"
            machine = { cpus = 3 }

            [defaults.session]
            packages = ["ds"]
            timeout = "defaults.session"

            [sessions.dev]
            packages = ["e"]
            timeout = "entry"
        "#;
        let layers = || Layers {
            upstream: table(
                "repo_url = \"https://github.com/gominimal/pkgs\"\ncommit = \"abc123\"",
            ),
            type_defaults: vec![
                (
                    "session".to_owned(),
                    table("packages = [\"u\"]\ntimeout = \"upstream\"\npty_enabled = false"),
                ),
                (
                    "rust-dev".to_owned(),
                    table("packages = [\"t1\"]\ntimeout = \"t1\""),
                ),
                (
                    "rust-dev-plus".to_owned(),
                    table("packages = [\"t2\"]\ntimeout = \"t2\""),
                ),
            ],
            loadouts: table("packages = [\"l\", \"u\"]\ntimeout = \"loadouts\""),
            overrides: table("timeout = \"overrides\"\nmachine = { memory = \"1G\" }"),
            ..Layers::default()
        };
        let all = expand_in(file, "dev", layers()).expect("expands");
        assert_eq!(
            strings(all.spec.get("packages")),
            ["u", "t1", "t2", "d", "ds", "e", "l"]
        );
        assert_eq!(all.spec["timeout"].as_str(), Some("overrides"));
        assert_eq!(
            all.spec["machine"],
            toml::Value::Table(table("memory = \"1G\""))
        );
        assert_eq!(all.spec["pty_enabled"].as_bool(), Some(false));
        // The `[upstream]` layer is the registry pin: the spec's one
        // `upstream` table, as minimal.toml writes it.
        assert_eq!(
            all.spec["upstream"],
            toml::Value::Table(table(
                "repo_url = \"https://github.com/gominimal/pkgs\"\ncommit = \"abc123\""
            ))
        );
        assert_eq!(
            all.report.values["upstream"],
            ValueOrigin::Value(Origin::of(Layer::Upstream))
        );

        // Take the layers away from the top: the next one down decides.
        let mut l = layers();
        l.overrides = toml::Table::new();
        let e = expand_in(file, "dev", l.clone()).expect("expands");
        assert_eq!(e.spec["timeout"].as_str(), Some("loadouts"));
        assert_eq!(e.spec["machine"], toml::Value::Table(table("cpus = 3")));
        l.loadouts = toml::Table::new();
        let e = expand_in(file, "dev", l.clone()).expect("expands");
        assert_eq!(e.spec["timeout"].as_str(), Some("entry"));
        let file_no_entry_timeout = file.replace("timeout = \"entry\"", "");
        let e = expand_in(&file_no_entry_timeout, "dev", l.clone()).expect("expands");
        assert_eq!(e.spec["timeout"].as_str(), Some("defaults.session"));
        let only_upstream_and_types = "[sessions.dev]\n";
        let e = expand_in(only_upstream_and_types, "dev", l.clone()).expect("expands");
        assert_eq!(e.spec["timeout"].as_str(), Some("t2"));
        l.type_defaults.pop();
        let e = expand_in(only_upstream_and_types, "dev", l.clone()).expect("expands");
        assert_eq!(e.spec["timeout"].as_str(), Some("t1"));
        l.type_defaults.pop();
        let e = expand_in(only_upstream_and_types, "dev", l.clone()).expect("expands");
        assert_eq!(e.spec["timeout"].as_str(), Some("upstream"));
        l.type_defaults.clear();
        let e = expand_in(only_upstream_and_types, "dev", l).expect("expands");
        assert_eq!(e.spec.get("timeout"), None);
        assert!(e.spec.contains_key("upstream"));

        // A scalar in a later layer replaces an earlier list, and a list
        // after it starts the union again.
        let mixed = fold(&[
            (Origin::of(Layer::Upstream), &table("packages = [\"a\"]")),
            (Origin::of(Layer::Defaults), &table("packages = \"x\"")),
            (
                Origin::of(Layer::Entry),
                &table("packages = [\"b\", \"b\"]"),
            ),
            (
                Origin::of(Layer::Overrides),
                &table("packages = [\"c\", \"b\"]"),
            ),
        ]);
        assert_eq!(strings(mixed.spec.get("packages")), ["b", "c"]);
    }

    proptest! {
        // BOX-064 property: for every set of layers, expansion equals the
        // fold of the merge rule over the layers in the stated order.
        #[test]
        fn expansion_order_and_merge_rules_property(
            layers in proptest::collection::vec(layer_strategy(), Layer::ORDER.len()),
        ) {
            let ordered: Vec<(Origin, &toml::Table)> = Layer::ORDER
                .iter()
                .zip(&layers)
                .map(|(layer, t)| (Origin::of(*layer), t))
                .collect();
            let got = fold(&ordered);
            let keys: BTreeSet<&String> = layers.iter().flat_map(toml::Table::keys).collect();
            prop_assert_eq!(got.spec.len(), keys.len());
            for key in keys {
                prop_assert_eq!(got.spec.get(key.as_str()).cloned(), expected_value(&layers, key));
            }
        }
    }

    const EXAMPLE: &str = r#"
        [defaults]
        packages = ["git", "ripgrep"]
        timeout = "2h"

        [defaults.session]
        packages = ["helix"]
        machine = { memory = "4G", cpus = 2 }

        [sessions.dev]
        packages = ["fish", "git"]
        pty_enabled = true
        network = { mode = "own_ip", egress = { allow_dns_hosts = ["b.example", "a.example"] } }
    "#;

    fn example_layers() -> Layers {
        Layers {
            loadouts: table("packages = [\"zellij\"]"),
            overrides: table("timeout = \"30m\""),
            ..Layers::default()
        }
    }

    // BOX-065: one file and one set of overrides expand to the same bytes
    // on every run.
    #[test]
    fn expansion_is_byte_identical_across_runs() {
        let first = expand_in(EXAMPLE, "dev", example_layers()).expect("expands");
        let second = expand_in(EXAMPLE, "dev", example_layers()).expect("expands");
        let bytes = first.spec_bytes().expect("writes");
        assert_eq!(bytes, second.spec_bytes().expect("writes"));
        assert_eq!(
            bytes,
            indoc::indoc! {r#"
                packages = ["git", "ripgrep", "helix", "fish", "zellij"]
                pty_enabled = true
                timeout = "30m"
                type = "session"

                [machine]
                cpus = 2
                memory = "4G"

                [network]
                mode = "own_ip"

                [network.egress]
                allow_dns_hosts = ["b.example", "a.example"]
            "#}
        );

        // The same spec built with its keys in another order writes the
        // same bytes.
        let mut reversed = toml::Table::new();
        for (k, v) in first.spec.iter().rev() {
            reversed.insert(k.clone(), v.clone());
        }
        let reversed = Expansion {
            spec: reversed,
            report: first.report.clone(),
            ignored_sections: Vec::new(),
        };
        assert_eq!(reversed.spec_bytes().expect("writes"), bytes);
    }

    /// A `minimal.toml` of one session entry and a `[defaults]` table, from
    /// a few valid keys.
    fn file_strategy() -> impl Strategy<Value = String> {
        let packages = proptest::collection::vec("[a-e]{1,3}", 0..5);
        (
            packages.clone(),
            packages.clone(),
            proptest::option::of("[0-9]{1,2}h"),
            proptest::option::of(any::<bool>()),
            proptest::option::of(1u8..16),
        )
            .prop_map(|(defaults, entry, timeout, pty, cpus)| {
                let list = |p: &[String]| format!("{p:?}");
                let mut file = format!("[defaults]\npackages = {}\n", list(&defaults));
                if let Some(cpus) = cpus {
                    file.push_str(&format!("machine = {{ cpus = {cpus}, memory = \"2G\" }}\n"));
                }
                file.push_str(&format!("[sessions.dev]\npackages = {}\n", list(&entry)));
                if let Some(t) = timeout {
                    file.push_str(&format!("timeout = \"{t}\"\n"));
                }
                if let Some(pty) = pty {
                    file.push_str(&format!("pty_enabled = {pty}\n"));
                }
                file
            })
    }

    proptest! {
        // BOX-065 property: for every minimal.toml and every set of
        // command-line overrides, expanding twice yields identical bytes.
        #[test]
        fn expansion_is_byte_identical_across_runs_property(
            file in file_strategy(),
            overrides in proptest::option::of("[0-9]{1,2}m"),
        ) {
            let layers = || Layers {
                overrides: overrides
                    .as_ref()
                    .map(|t| table(&format!("timeout = \"{t}\"")))
                    .unwrap_or_default(),
                ..Layers::default()
            };
            let a = expand_in(&file, "dev", layers()).expect("expands");
            let b = expand_in(&file, "dev", layers()).expect("expands");
            prop_assert_eq!(a.spec_bytes().expect("writes"), b.spec_bytes().expect("writes"));
        }
    }

    // BOX-066: a key that is not a box setting, or a value of the wrong
    // shape, exits 3 and names the key and the layer that set it.
    #[test]
    fn invalid_key_exit3_names_key_and_layer() {
        let cases: [(&str, Layers, &str); 9] = [
            (
                "[defaults]\ntimeot = \"2h\"\n[sessions.dev]\n",
                Layers::default(),
                "`[defaults]` in minimal.toml sets `timeot`, which is not a box \
                 setting. Remove the key or correct its name.",
            ),
            (
                "[defaults.session]\npty_enabled = \"yes\"\n[sessions.dev]\n",
                Layers::default(),
                "`[defaults.session]` in minimal.toml sets `pty_enabled` to a \
                 string, but `pty_enabled` takes true or false. Fix the value.",
            ),
            (
                "[sessions.dev]\npackages = [\"git\", 5]\n",
                Layers::default(),
                "`[sessions.dev]` in minimal.toml sets `packages` to a list with \
                 an item that is not a string, but `packages` takes a list of \
                 strings. Fix the value.",
            ),
            (
                "[defaults]\npackages = [\"git\"]\n[sessions.dev]\npackages = [true]\n",
                Layers::default(),
                "`[sessions.dev]` in minimal.toml sets `packages` to a list with \
                 an item that is not a string, but `packages` takes a list of \
                 strings. Fix the value.",
            ),
            (
                "[sessions.dev]\n",
                Layers {
                    type_defaults: vec![("rust-dev".to_owned(), table("timeout = 1.5"))],
                    ..Layers::default()
                },
                "the `defaults` table of `[box_types.rust-dev]` sets `timeout` to a \
                 decimal number, but `timeout` takes a string or a whole number. \
                 Fix the value.",
            ),
            (
                "[sessions.dev]\n",
                Layers {
                    upstream: table("colour = \"red\""),
                    ..Layers::default()
                },
                "`[upstream]` in minimal.toml sets `colour`, which is not an \
                 `[upstream]` setting. The `[upstream]` settings are `repo_url`, \
                 `branch`, `commit` and `build_cache_url`. Remove the key or \
                 correct its name.",
            ),
            (
                "[sessions.dev]\n",
                Layers {
                    upstream: table("commit = 5"),
                    ..Layers::default()
                },
                "`[upstream]` in minimal.toml sets `commit` to a whole number, but \
                 `commit` takes a string. Fix the value.",
            ),
            (
                "[sessions.dev]\nupstream = { colour = \"red\" }\n",
                Layers::default(),
                "`[sessions.dev]` in minimal.toml sets `upstream.colour`, which is \
                 not an `[upstream]` setting. The `[upstream]` settings are \
                 `repo_url`, `branch`, `commit` and `build_cache_url`. Remove the \
                 key or correct its name.",
            ),
            (
                "[tasks.lint]\nexec = \"cargo clippy\"\n",
                Layers {
                    overrides: table("machine = 4"),
                    ..Layers::default()
                },
                "a command-line flag sets `machine` to a whole number, but \
                 `machine` takes a table. Fix the value.",
            ),
        ];
        for (file, layers, message) in cases {
            let name = if file.contains("lint") { "lint" } else { "dev" };
            let err = expand_in(file, name, layers).expect_err("the spec is invalid");
            assert_eq!(err.exit_code(), Some(3), "{err}");
            assert!(matches!(&err, Error::InvalidSpecKey { .. }), "{err:?}");
            assert_eq!(err.to_string(), message);
        }

        // A bad value that a later layer replaces is not in the expanded
        // spec, so the spec is valid.
        let ok = expand_in(
            "[defaults]\npty_enabled = \"yes\"\n[sessions.dev]\npty_enabled = true\n",
            "dev",
            Layers::default(),
        )
        .expect("the expanded spec is valid");
        assert_eq!(ok.spec["pty_enabled"].as_bool(), Some(true));

        // The registry pin's keys expand without error.
        let ok = expand_in(
            "[sessions.dev]\n",
            "dev",
            Layers {
                upstream: table(
                    "repo_url = \"https://github.com/gominimal/pkgs\"\n\
                     commit = \"abc123\"",
                ),
                ..Layers::default()
            },
        )
        .expect("the registry pin is valid");
        assert_eq!(ok.spec["upstream"]["commit"].as_str(), Some("abc123"));

        // Every key a built-in type's defaults set, and the Box Spec
        // sections an entry can set, are box settings.
        let ok = expand_in(
            "[sessions.dev]\nio = { stdin = \"null\" }\n\
             [[sessions.dev.file_imports]]\nsrc = \"a\"\ndst = \"/a\"\n",
            "dev",
            Layers {
                type_defaults: vec![(
                    "session".to_owned(),
                    table(
                        "loadout_mode = \"merge\"\nexec_enabled = true\n\
                         restart = \"never\"\ngithub_token_mode = \"none\"\n\
                         nesting = { allowed = true }",
                    ),
                )],
                ..Layers::default()
            },
        );
        assert!(ok.is_ok(), "{ok:?}");
    }

    // BOX-065: a project's client sections are left out of the spec and
    // listed for the caller to warn, never refused.
    #[test]
    fn invalid_key_exit3_names_key_and_layer_ignores_client_sections() {
        let e = expand_in(
            "[sessions.dev]\npackages = [\"git\"]\n\
             [sessions.dev.secret-store-rules]\ngithub = { upstream = \"x\" }\n",
            "dev",
            Layers::default(),
        )
        .expect("a client section is ignored, not refused");
        let bytes = e.spec_bytes().expect("writes");
        assert!(!bytes.contains("secret-store-rules"), "{bytes}");
        assert!(!e.report.values.contains_key("secret-store-rules"));
        assert_eq!(
            e.ignored_sections,
            vec![("secret-store-rules".to_owned(), Origin::of(Layer::Entry))]
        );
    }

    // BOX-161: the report names the layer of every value, and the type for
    // a type's defaults. The spec bytes carry none of it.
    #[test]
    fn expansion_reports_layer_and_type_per_value_outside_spec_bytes() {
        let layers = Layers {
            upstream: table("commit = \"abc123\""),
            type_defaults: vec![
                ("session".to_owned(), table("lifetime = \"until_complete\"")),
                (
                    "rust-dev".to_owned(),
                    table("packages = [\"rust\"]\ntimeout = \"9h\""),
                ),
            ],
            ..example_layers()
        };
        let e = expand_in(EXAMPLE, "dev", layers).expect("expands");
        let report = &e.report.values;

        let spec_keys: BTreeSet<&String> = e.spec.keys().collect();
        let report_keys: BTreeSet<&String> = report.keys().collect();
        assert_eq!(spec_keys, report_keys);

        let value = |k: &str| match &report[k] {
            ValueOrigin::Value(o) => o.clone(),
            other => panic!("{k} is a list: {other:?}"),
        };
        assert_eq!(value("upstream"), Origin::of(Layer::Upstream));
        assert_eq!(value("lifetime"), Origin::type_defaults("session"));
        assert_eq!(value("machine"), Origin::of(Layer::DefaultsType));
        assert_eq!(value("network"), Origin::of(Layer::Entry));
        assert_eq!(value("pty_enabled"), Origin::of(Layer::Entry));
        assert_eq!(value("timeout"), Origin::of(Layer::Overrides));
        assert_eq!(value("type"), Origin::of(Layer::Entry));

        // A list has one origin per item, in the list's order.
        assert_eq!(
            strings(e.spec.get("packages")),
            ["rust", "git", "ripgrep", "helix", "fish", "zellij"]
        );
        assert_eq!(
            report["packages"],
            ValueOrigin::List(vec![
                Origin::type_defaults("rust-dev"),
                Origin::of(Layer::Defaults),
                Origin::of(Layer::Defaults),
                Origin::of(Layer::DefaultsType),
                Origin::of(Layer::Entry),
                Origin::of(Layer::Loadouts),
            ])
        );

        // The bytes are the spec alone: nothing of the report is in them.
        let bytes = e.spec_bytes().expect("writes");
        let only_spec = Expansion {
            spec: e.spec.clone(),
            report: ExpansionReport::default(),
            ignored_sections: Vec::new(),
        };
        assert_eq!(bytes, only_spec.spec_bytes().expect("writes"));
        for word in [
            "rust-dev",
            "Upstream",
            "TypeDefaults",
            "Loadouts",
            "Overrides",
            "layer",
        ] {
            assert!(!bytes.contains(word), "{word} in {bytes}");
        }
    }
}
