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
//! `vars` and `vars_lenient` are the exception (BOX-180). They merge by
//! variable name, keyed across both tables: a name keeps the value, and
//! the table, of the most specific layer that sets it. A selected loadout
//! only adds names. A loadout that gives a set name another resolved value
//! fails the expansion (BOX-183), and so does one layer that sets a name
//! twice to different values (BOX-184). An `inherit` value resolves
//! against [`Layers::host_vars`].
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
//!
//! The type's constraints come last. [`check_constraints`] reads the
//! finished expansion, after the command-line override layer, and fails
//! with [`BoxTypeError::ConstraintBroken`] when a value of the spec is one
//! the type's constraints exclude (BOX-061). It names the type, the key
//! and the layer that set the value. It reads the spec and never changes
//! it, so a constraint never adds a package, a port or an egress entry
//! (BOX-062).

use std::collections::{BTreeMap, BTreeSet};

use crate::Error;
use crate::box_types::{
    BoxTypeError, BoxTypes, ResolvedType, allowed_words, canonical_constraints, excluded, inline,
};
use crate::entry::{BoxEntry, EntryTable};
use crate::error::{EntryHeader, SpecKeyProblem};

/// The built-in Box Types. A `[defaults.<name>]` table for one of these,
/// or for a project type, is that type's defaults, not a `[defaults]` key.
pub use crate::box_types::BUILTIN_BOX_TYPES;

/// The built-in roots whose entries this release expands (BOX-063).
pub const EXPANDABLE_ROOTS: [&str; 2] = ["session", "task"];

/// Resolves the type of `entry` and checks that this release expands it:
/// its type, or its type's built-in root, is `session` or `task`, and it
/// does not come from `[agents.*]` or `[services.*]` (BOX-063).
///
/// The check is per entry, so a refused entry leaves the file's other
/// entries usable. The resolved type's
/// [`defaults`](crate::box_types::ResolvedType::defaults) are the entry's
/// [`Layers::type_defaults`].
///
/// # Errors
///
/// [`BoxTypeError::Unsupported`] for an entry of another root, and the
/// errors of [`BoxTypes::resolve_entry`] for an entry whose type does not
/// resolve. Each exits 3.
pub fn expandable_type(entry: &BoxEntry, types: &BoxTypes) -> Result<ResolvedType, BoxTypeError> {
    let refuse = |box_type: &str, root: &'static str| BoxTypeError::Unsupported {
        table: entry.table.key(),
        entry: entry.name.clone(),
        box_type: box_type.to_owned(),
        root,
    };
    // A sugar table for a refused type is refused whatever its `type`.
    match entry.table {
        EntryTable::Agents => return Err(refuse("agent", "agent")),
        EntryTable::Services => return Err(refuse("service", "service")),
        EntryTable::Boxes | EntryTable::Sessions | EntryTable::Tasks => {}
    }
    let resolved = types.resolve_entry(entry)?;
    if !EXPANDABLE_ROOTS.contains(&resolved.root) {
        return Err(refuse(&resolved.name, resolved.root));
    }
    Ok(resolved)
}

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
    /// The layer that set each variable of `vars` and `vars_lenient`, by
    /// variable name (BOX-180).
    pub vars: BTreeMap<String, Origin>,
    /// Whether the expanded entry is the implicit default session entry,
    /// which the file does not declare (BOX-165).
    pub implicit: bool,
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
    /// The host's value for each variable that a layer sets to
    /// `{ inherit = true }`, by name. A name the host does not set is not
    /// here. The merge of `vars` compares resolved values (BOX-183,
    /// BOX-184), so the client fills this from its environment, for the
    /// names [`inherited_var_names`] gives.
    pub host_vars: BTreeMap<String, String>,
    /// The client's `[secret-store-rules]`, by item identifier. Expansion
    /// writes a rule's `upstream` and `inject` into each `source =
    /// "store"` reference to its item (BOX-071). The client fills this
    /// from its own configuration, never from the project file.
    pub store_rules: BTreeMap<String, StoreRule>,
}

/// One rule of the client's `[secret-store-rules]`, as expansion writes
/// it into a store reference.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct StoreRule {
    /// The upstream authorities the item's value is sent to, each `host`
    /// or `host:port`. Written as the reference's `upstream.hosts`.
    pub upstream: Vec<String>,
    /// How the value is injected: the rule's `header`, `prefix` and
    /// `basic_auth`, as the rule sets them. Written as the reference's
    /// `inject`.
    pub inject: toml::Table,
}

/// Writes each store reference's authorities into the spec (BOX-071). A
/// `[secrets]` entry with `source = "store"` takes the `upstream` and
/// `inject` of the rule for its `id`. Any `upstream` or `inject` that a
/// layer wrote into the reference is dropped first, so only the client's
/// rules set them. A reference with no rule for its item keeps neither.
fn write_store_authorities(spec: &mut toml::Table, rules: &BTreeMap<String, StoreRule>) {
    let Some(secrets) = spec.get_mut("secrets").and_then(toml::Value::as_table_mut) else {
        return;
    };
    for grant in secrets.iter_mut().filter_map(|(_, v)| v.as_table_mut()) {
        if grant.get("source").and_then(toml::Value::as_str) != Some("store") {
            continue;
        }
        grant.remove("upstream");
        grant.remove("inject");
        let rule = grant
            .get("id")
            .and_then(toml::Value::as_str)
            .and_then(|id| rules.get(id.trim()));
        let Some(rule) = rule else {
            continue;
        };
        let hosts = rule
            .upstream
            .iter()
            .cloned()
            .map(toml::Value::String)
            .collect();
        grant.insert(
            "upstream".to_owned(),
            toml::Value::Table(toml::Table::from_iter([(
                "hosts".to_owned(),
                toml::Value::Array(hosts),
            )])),
        );
        grant.insert("inject".to_owned(), toml::Value::Table(rule.inject.clone()));
    }
}

/// The built-in root of the entry's type: the first type of its chain,
/// else the entry's own type when it is a built-in, else the root that
/// its table implies.
fn entry_root(entry: &BoxEntry, layers: &Layers) -> &'static str {
    layers
        .type_defaults
        .first()
        .and_then(|(name, _)| crate::box_types::builtin(name))
        .or_else(|| {
            entry
                .box_type
                .as_deref()
                .and_then(crate::box_types::builtin)
        })
        .unwrap_or(match entry.table {
            EntryTable::Tasks => "task",
            _ => "session",
        })
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

    /// The Gatehouse §6.3.2 projection of the spec, for a box of the type
    /// `box_type` (BOX-071). Its [`digest`](crate::projection::Projection::digest)
    /// is the one the client sends with the spec.
    #[must_use]
    pub fn projection(&self, box_type: &ResolvedType) -> crate::projection::Projection {
        crate::projection::project(
            &self.spec,
            &crate::projection::TypeFacts::of_resolved(box_type),
        )
    }
}

/// Expands `entry` over `layers` in the order of [`Layer::ORDER`], then
/// checks every key of the result.
///
/// # Errors
///
/// [`Error::InvalidSpecKey`] for the first key, in key order, that is not
/// a box setting or has a value of the wrong shape. It names the layer
/// that set the bad value. The same error, before any loadout applies,
/// when `loadout_mode` is a string other than `sealed` or `open`.
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
    // BOX-166, BOX-167, BOX-170: the layers up to and including the entry
    // set `loadout_mode`, and the mode alone decides whether the selected
    // loadouts apply. A loadout cannot open the gate that admits it.
    let sealed = toml::Table::new();
    let loadouts = match loadout_mode(entry, &ordered)? {
        Some(LoadoutMode::Open) => &layers.loadouts,
        Some(LoadoutMode::Sealed) | None => &sealed,
    };
    ordered.push((Origin::of(Layer::Loadouts), loadouts));
    ordered.push((Origin::of(Layer::Overrides), &layers.overrides));
    let mut expansion = fold(&ordered);
    merge_vars(entry, &ordered, &layers.host_vars, &mut expansion)?;
    // BOX-071: the store references carry the client's authorities, and
    // the omitted values the digest binds are filled, before the spec is
    // checked or projected.
    write_store_authorities(&mut expansion.spec, &layers.store_rules);
    let root = entry_root(entry, layers);
    let had_network = expansion.spec.contains_key("network");
    crate::projection::fill_effective(&mut expansion.spec, root);
    if !had_network {
        expansion.report.values.insert(
            "network".to_owned(),
            ValueOrigin::Value(Origin::type_defaults(root)),
        );
    }
    expansion.report.implicit = entry.implicit;
    check_keys(entry, &expansion)?;
    Ok(expansion)
}

/// Checks a finished expansion of `entry` against the constraints of its
/// type, `box_type`: the final step of expansion, after the command-line
/// override layer (BOX-061). Every type of the chain is checked, the
/// entry's own type first, each key in key order. A type only narrows the
/// type it extends (BOX-156), so the first failing constraint is the
/// tightest one that holds the key.
///
/// The check reads the expansion and never changes it (BOX-062).
///
/// No product path calls this function yet. gominimal/minimal#3295 adds
/// the call after each `expand` in `crates/minimal/src/cmd/boxes/create.rs`.
///
/// # Errors
///
/// [`BoxTypeError::ConstraintBroken`] for the first value that a
/// constraint excludes. It names the type of the chain whose
/// `constraints` table holds that constraint, the key and the layer that
/// set the value, and exits 3.
pub fn check_constraints(
    entry: &BoxEntry,
    expansion: &Expansion,
    box_type: &ResolvedType,
) -> Result<(), BoxTypeError> {
    for (type_name, constraints) in box_type.constraints.iter().rev() {
        for (key, constraint) in canonical_constraints(constraints) {
            // A flat setting is checked where the spec carries it: at its
            // flat key and at the same key under its section.
            let mut places = vec![(key.clone(), key.clone(), expansion.spec.get(&key))];
            if let Some(section) = crate::spec::flat_key_section(&key) {
                let nested = expansion
                    .spec
                    .get(section)
                    .and_then(toml::Value::as_table)
                    .and_then(|t| t.get(&key));
                places.push((format!("{section}.{key}"), section.to_owned(), nested));
            }
            for (path, top, value) in places {
                let Some(value) = value else {
                    continue;
                };
                let Some(bad) = excluded(&path, &constraint, value) else {
                    continue;
                };
                let origin = expansion.report.values.get(&top);
                let origin = match (origin, bad.item) {
                    // Only a top-level list has an origin for each item.
                    (Some(ValueOrigin::List(origins)), Some(i)) if bad.key == top => origins.get(i),
                    (origin, _) => origin.and_then(ValueOrigin::first),
                };
                return Err(BoxTypeError::ConstraintBroken {
                    box_type: type_name.clone(),
                    key: bad.key,
                    value: inline(&bad.value),
                    allowed: allowed_words(&bad.constraint),
                    layer: layer_words(entry, origin),
                    item: bad.item.is_some(),
                });
            }
        }
    }
    Ok(())
}

/// Whether an entry takes its selected loadouts: the `loadout_mode` box
/// setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadoutMode {
    /// The entry takes no loadout (BOX-166).
    Sealed,
    /// The entry takes each selected loadout whole (BOX-167).
    Open,
}

impl LoadoutMode {
    /// The values `loadout_mode` accepts, as the file writes them.
    pub const ACCEPTED: &'static [&'static str] = &["sealed", "open"];

    /// The mode a file writes as `value`, or `None` for any other value.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "sealed" => Some(Self::Sealed),
            "open" => Some(Self::Open),
            _ => None,
        }
    }
}

/// The `loadout_mode` that `ordered`, the layers up to and including the
/// entry, set. It is the flat key or the `[box]` section's key, whichever
/// a later layer set. `None` when no layer sets it, and the gate treats
/// `None` as sealed, so the entry takes no loadout.
///
/// A value that is not a string reads as [`LoadoutMode::Sealed`], so no
/// loadout applies, and [`check_keys`] then refuses its shape.
///
/// # Errors
///
/// [`Error::InvalidSpecKey`] with [`SpecKeyProblem::UnknownValue`] for a
/// string other than `sealed` or `open`, naming the layer that set it
/// (BOX-174).
fn loadout_mode(
    entry: &BoxEntry,
    ordered: &[(Origin, &toml::Table)],
) -> Result<Option<LoadoutMode>, Error> {
    let before = fold(ordered);
    let rank = |key: &str| -> Option<(usize, &Origin)> {
        let origin = before.report.values.get(key)?.first()?;
        let at = ordered.iter().position(|(o, _)| o == origin)?;
        Some((at, origin))
    };
    let flat = before
        .spec
        .get("loadout_mode")
        .and_then(|v| Some((v, rank("loadout_mode")?)));
    let nested = before
        .spec
        .get("box")
        .and_then(toml::Value::as_table)
        .and_then(|b| b.get("loadout_mode"))
        .and_then(|v| Some((v, rank("box")?)));
    let (key, value, origin) = match (flat, nested) {
        (Some((_, (f, _))), Some((v, (n, o)))) if n > f => ("box.loadout_mode", v, o),
        (Some((v, (_, o))), _) => ("loadout_mode", v, o),
        (None, Some((v, (_, o)))) => ("box.loadout_mode", v, o),
        (None, None) => return Ok(None),
    };
    let Some(found) = value.as_str() else {
        return Ok(Some(LoadoutMode::Sealed));
    };
    match LoadoutMode::parse(found) {
        Some(mode) => Ok(Some(mode)),
        None => Err(Error::InvalidSpecKey {
            key: key.to_owned(),
            layer: layer_words(entry, Some(origin)),
            problem: SpecKeyProblem::UnknownValue {
                found: found.to_owned(),
                accepted: LoadoutMode::ACCEPTED,
            },
        }),
    }
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
            if VAR_KEYS.contains(&key.as_str()) {
                continue;
            }
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

/// The keys that hold variables. [`fold`] leaves them out, and
/// [`merge_vars`] merges them by variable name (BOX-180).
const VAR_KEYS: [&str; 2] = ["vars", "vars_lenient"];

/// Which table of the spec holds a variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VarTable {
    /// `vars`, a table of name to value.
    Vars,
    /// `vars_lenient`, a list of `{ name, value }` tables.
    Lenient,
}

/// One variable as the merge holds it.
#[derive(Debug, Clone)]
struct MergedVar {
    table: VarTable,
    /// For [`VarTable::Vars`], the value. For [`VarTable::Lenient`], the
    /// whole list item.
    item: toml::Value,
    /// The value, resolved against the host. `None` for an `inherit` that
    /// the host does not set.
    resolved: Option<String>,
    origin: Origin,
}

/// The names that some layer sets to `{ inherit = true }`, in `vars` or
/// `vars_lenient`. The client looks each one up in its environment and
/// puts the values it finds in [`Layers::host_vars`].
#[must_use]
pub fn inherited_var_names(entry: &BoxEntry, layers: &Layers) -> BTreeSet<String> {
    let tables = layers.type_defaults.iter().map(|(_, t)| t).chain([
        &layers.defaults,
        &layers.defaults_type,
        &entry.body,
        &layers.loadouts,
        &layers.overrides,
    ]);
    let mut names = BTreeSet::new();
    for table in tables {
        for (name, kind, item) in layer_vars(table) {
            if var_value(kind, item)
                .and_then(|v| v.get("inherit"))
                .and_then(toml::Value::as_bool)
                == Some(true)
            {
                names.insert(name.to_owned());
            }
        }
    }
    names
}

/// The variables one layer sets, in the order the layer writes them:
/// `vars` first, then `vars_lenient`. Each is the name, the table and, for
/// `vars`, the value, for `vars_lenient` the whole list item. A part of
/// the wrong shape is not here: [`merge_vars`] keeps it whole, so
/// [`check_keys`] refuses it. A `vars_lenient` item with no string `name`
/// is not here either: [`nameless_lenient`] gives those to [`merge_vars`].
fn layer_vars(layer: &toml::Table) -> Vec<(&str, VarTable, &toml::Value)> {
    let mut out = Vec::new();
    if let Some(toml::Value::Table(vars)) = layer.get("vars") {
        for (name, value) in vars {
            out.push((name.as_str(), VarTable::Vars, value));
        }
    }
    if let Some(toml::Value::Array(items)) = layer.get("vars_lenient") {
        for item in items {
            if let Some(name) = item.get("name").and_then(toml::Value::as_str) {
                out.push((name, VarTable::Lenient, item));
            }
        }
    }
    out
}

/// The `vars_lenient` items of one layer that have no string `name`.
/// [`merge_vars`] keeps each one in the spec's list, so the client's
/// reading of the list refuses it, as it did before the merge by name.
fn nameless_lenient(layer: &toml::Table) -> impl Iterator<Item = &toml::Value> {
    let items = match layer.get("vars_lenient") {
        Some(toml::Value::Array(items)) => items.as_slice(),
        _ => &[],
    };
    items
        .iter()
        .filter(|item| item.get("name").and_then(toml::Value::as_str).is_none())
}

/// The value part of a variable: the value itself for `vars`, and the
/// `value` key of a `vars_lenient` item.
fn var_value(table: VarTable, item: &toml::Value) -> Option<&toml::Value> {
    match table {
        VarTable::Vars => Some(item),
        VarTable::Lenient => item.get("value"),
    }
}

/// The value of a variable after the host resolves it: a string as it is,
/// an `inherit` as the host's value or else its `default`. `None` for an
/// `inherit` with no host value and no default. Any other shape resolves
/// to its TOML text, so two such values compare as they are written.
fn resolve_var(
    name: &str,
    table: VarTable,
    item: &toml::Value,
    host: &BTreeMap<String, String>,
) -> Option<String> {
    match var_value(table, item) {
        Some(toml::Value::String(s)) => Some(s.clone()),
        Some(toml::Value::Table(t))
            if t.get("inherit").and_then(toml::Value::as_bool) == Some(true) =>
        {
            host.get(name).cloned().or_else(|| {
                t.get("default")
                    .and_then(toml::Value::as_str)
                    .map(str::to_owned)
            })
        }
        Some(other) => Some(other.to_string()),
        None => None,
    }
}

/// Merges `vars` and `vars_lenient` of `ordered` by variable name, into
/// `expansion` (BOX-180).
///
/// A name keeps the value and the table of the latest layer that sets it.
/// The selected loadouts' layer is the exception: it only adds names. A
/// loadout value that resolves to the value already set adds nothing, and
/// a loadout `inherit` that the host does not set is not compared.
///
/// A layer's `vars` that is not a table, or `vars_lenient` that is not a
/// list, replaces the spec's value whole, so [`check_keys`] refuses it and
/// names the layer.
///
/// # Errors
///
/// [`Error::LoadoutVarConflict`] when a loadout gives a set name another
/// resolved value (BOX-183). [`Error::DuplicateVar`] when one layer, other
/// than the loadouts, sets a name twice to different resolved values
/// (BOX-184). In the loadouts' layer, that is two loadouts that disagree,
/// so it is [`Error::LoadoutVarConflict`].
fn merge_vars(
    entry: &BoxEntry,
    ordered: &[(Origin, &toml::Table)],
    host: &BTreeMap<String, String>,
    expansion: &mut Expansion,
) -> Result<(), Error> {
    let mut merged: Vec<(String, MergedVar)> = Vec::new();
    // `vars_lenient` items with no name. The merge has no name to key
    // them by, so the spec keeps each one, and the client refuses it.
    let mut nameless: Vec<(toml::Value, Origin)> = Vec::new();
    // The layer that last set each key, and a key whose value has the
    // wrong shape, which the spec then carries whole.
    let mut key_origin: BTreeMap<&str, Origin> = BTreeMap::new();
    let mut bad_shape: BTreeMap<&str, (toml::Value, Origin)> = BTreeMap::new();
    for (origin, layer) in ordered {
        let loadouts = origin.layer == Layer::Loadouts;
        for key in VAR_KEYS {
            let Some(value) = layer.get(key) else {
                continue;
            };
            let shaped = match key {
                "vars" => value.is_table(),
                _ => value.is_array(),
            };
            if shaped {
                bad_shape.remove(key);
            } else {
                bad_shape.insert(key, (value.clone(), origin.clone()));
            }
            key_origin.insert(key, origin.clone());
        }
        nameless.extend(nameless_lenient(layer).map(|item| (item.clone(), origin.clone())));
        // BOX-184: one layer has no later layer to settle a name it sets
        // twice, so two different values for it are refused.
        let mut this_layer: BTreeMap<&str, Option<String>> = BTreeMap::new();
        for (name, table, item) in layer_vars(layer) {
            let resolved = resolve_var(name, table, item, host);
            if let Some(seen) = this_layer.get(name) {
                if *seen == resolved {
                    continue;
                }
                let words = layer_words(entry, Some(origin));
                tracing::debug!(
                    rule = "BOX-184",
                    variable = name,
                    layer = %words,
                    "one layer sets a variable twice to different values"
                );
                return Err(if loadouts {
                    Error::LoadoutVarConflict {
                        name: name.to_owned(),
                        first: words,
                        second: "another selected loadout".to_owned(),
                    }
                } else {
                    Error::DuplicateVar {
                        name: name.to_owned(),
                        layer: words,
                    }
                });
            }
            this_layer.insert(name, resolved.clone());
            let new = MergedVar {
                table,
                item: item.clone(),
                resolved,
                origin: origin.clone(),
            };
            let Some(at) = merged.iter().position(|(n, _)| n == name) else {
                merged.push((name.to_owned(), new));
                continue;
            };
            if !loadouts {
                merged[at].1 = new;
                continue;
            }
            // BOX-183: a loadout adds names, and never changes one.
            let have = &merged[at].1;
            match (&have.resolved, &new.resolved) {
                (Some(a), Some(b)) if a != b => {
                    let first = layer_words(entry, Some(&have.origin));
                    tracing::debug!(
                        rule = "BOX-183",
                        variable = name,
                        set_by = %first,
                        "a selected loadout sets a variable to another value"
                    );
                    return Err(Error::LoadoutVarConflict {
                        name: name.to_owned(),
                        first,
                        second: layer_words(entry, Some(origin)),
                    });
                }
                _ => {}
            }
        }
    }
    let mut vars = toml::Table::new();
    let mut lenient = Vec::new();
    let mut lenient_origins = Vec::new();
    let report = &mut expansion.report;
    for (name, var) in merged {
        match var.table {
            VarTable::Vars => {
                vars.insert(name.clone(), var.item);
            }
            VarTable::Lenient => {
                lenient.push(var.item);
                lenient_origins.push(var.origin.clone());
            }
        }
        report.vars.insert(name, var.origin);
    }
    for (item, origin) in nameless {
        lenient.push(item);
        lenient_origins.push(origin);
    }
    // The names of one key come from several layers, so the key's origin
    // is the layer of each name: in key order for `vars`, and in item
    // order for `vars_lenient`.
    let vars_origins: Vec<Origin> = vars
        .keys()
        .filter_map(|name| report.vars.get(name).cloned())
        .collect();
    for key in VAR_KEYS {
        let Some(origin) = key_origin.remove(key) else {
            continue;
        };
        let (value, origin, origins) = match bad_shape.remove(key) {
            Some((bad, origin)) => (bad, origin, Vec::new()),
            None if key == "vars" => (
                toml::Value::Table(std::mem::take(&mut vars)),
                origin,
                vars_origins.clone(),
            ),
            None => (
                toml::Value::Array(std::mem::take(&mut lenient)),
                origin,
                std::mem::take(&mut lenient_origins),
            ),
        };
        expansion.spec.insert(key.to_owned(), value);
        // A value of the wrong shape, or an empty one, has no names to
        // give a layer, so it keeps the layer that set the key.
        let value_origin = if origins.is_empty() {
            ValueOrigin::Value(origin)
        } else {
            ValueOrigin::List(origins)
        };
        report.values.insert(key.to_owned(), value_origin);
    }
    Ok(())
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
    Duration,
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
            Shape::Duration => crate::duration::TIMEOUT_TAKES,
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
        if let Shape::Duration = self {
            return crate::duration::spec_timeout(value).err();
        }
        let all_strings = |items: &[toml::Value]| items.iter().all(toml::Value::is_str);
        let fits = match (self, value) {
            (Shape::Str, toml::Value::String(_))
            | (Shape::Bool, toml::Value::Boolean(_))
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
pub(crate) const fn value_words(value: &toml::Value) -> &'static str {
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
/// - <https://github.com/gominimal/minimal/issues/3097>: the client passes
///   its `[secret-store-rules]` as [`Layers::store_rules`] (BOX-065).
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
    ("timeout", Shape::Duration),
    ("type", Shape::Str),
    ("upstream", Shape::Table),
    ("vars", Shape::Table),
    ("vars_lenient", Shape::List),
    ("volumes", Shape::StrList),
];

/// Whether `key` is a box setting an expanded spec can carry, so a
/// `[defaults]` table that sets it is read by expansion (BOX-048).
pub(crate) fn is_spec_key(key: &str) -> bool {
    SPEC_KEYS.iter().any(|(k, _)| *k == key)
}

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
                // BOX-076: a section's own keys follow the Box Spec schema.
                None => match crate::spec::check_section(key, value) {
                    Ok(()) => continue,
                    Err(bad) => {
                        return Err(Error::InvalidSpecKey {
                            key: bad.key,
                            layer: layer_words(entry, origin.and_then(ValueOrigin::first)),
                            problem: bad.problem,
                        });
                    }
                },
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
    use crate::entry::{DEFAULT_ENTRY_NAME, EntryTable, implicit_default_entry, read_entries};
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
            timeout = "1s"
            machine = { cpus = 3 }

            [defaults.session]
            packages = ["ds"]
            timeout = "2s"

            [sessions.dev]
            packages = ["e"]
            timeout = "3s"
        "#;
        let layers = || Layers {
            upstream: table(
                "repo_url = \"https://github.com/gominimal/pkgs\"\ncommit = \"abc123\"",
            ),
            type_defaults: vec![
                (
                    "session".to_owned(),
                    crate::box_types::builtin_defaults("session"),
                ),
                (
                    "session".to_owned(),
                    table("packages = [\"u\"]\ntimeout = \"4s\"\npty_enabled = false"),
                ),
                (
                    "rust-dev".to_owned(),
                    table("packages = [\"t1\"]\ntimeout = \"5s\""),
                ),
                (
                    "rust-dev-plus".to_owned(),
                    table("packages = [\"t2\"]\ntimeout = \"6s\""),
                ),
            ],
            loadouts: table("packages = [\"l\", \"u\"]\ntimeout = \"7s\""),
            overrides: table("timeout = \"8s\"\nmachine = { memory = \"1G\" }"),
            ..Layers::default()
        };
        let all = expand_in(file, "dev", layers()).expect("expands");
        assert_eq!(
            strings(all.spec.get("packages")),
            ["u", "t1", "t2", "d", "ds", "e", "l"]
        );
        assert_eq!(all.spec["timeout"].as_str(), Some("8s"));
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
        assert_eq!(e.spec["timeout"].as_str(), Some("7s"));
        assert_eq!(e.spec["machine"], toml::Value::Table(table("cpus = 3")));
        l.loadouts = toml::Table::new();
        let e = expand_in(file, "dev", l.clone()).expect("expands");
        assert_eq!(e.spec["timeout"].as_str(), Some("3s"));
        let file_no_entry_timeout = file.replace("timeout = \"3s\"", "");
        let e = expand_in(&file_no_entry_timeout, "dev", l.clone()).expect("expands");
        assert_eq!(e.spec["timeout"].as_str(), Some("2s"));
        let only_upstream_and_types = "[sessions.dev]\n";
        let e = expand_in(only_upstream_and_types, "dev", l.clone()).expect("expands");
        assert_eq!(e.spec["timeout"].as_str(), Some("6s"));
        l.type_defaults.pop();
        let e = expand_in(only_upstream_and_types, "dev", l.clone()).expect("expands");
        assert_eq!(e.spec["timeout"].as_str(), Some("5s"));
        l.type_defaults.pop();
        let e = expand_in(only_upstream_and_types, "dev", l.clone()).expect("expands");
        assert_eq!(e.spec["timeout"].as_str(), Some("4s"));
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
            type_defaults: vec![(
                "session".to_owned(),
                crate::box_types::builtin_defaults("session"),
            )],
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
                loadout_mode = "open"
                packages = ["git", "ripgrep", "helix", "fish", "zellij"]
                pty_enabled = true
                timeout = "30m"
                type = "session"

                [machine]
                cpus = 2
                memory = "4G"

                [network]
                mode = "own_ip"
                quic443 = "auto"

                [network.bep]
                steering = "dns"

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
        let cases: [(&str, Layers, &str); 10] = [
            (
                "[sessions.dev]\ntimeout = \"2 days\"\n",
                Layers::default(),
                "`[sessions.dev]` in minimal.toml sets `timeout` to a string that is \
                 not a duration, but `timeout` takes a whole number of seconds, or a \
                 string of a whole number followed by s, m or h, such as \"30s\", \
                 \"5m\" or \"1h\". Fix the value.",
            ),
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
                 decimal number, but `timeout` takes a whole number of seconds, or a \
                 string of a whole number followed by s, m or h, such as \"30s\", \
                 \"5m\" or \"1h\". Fix the value.",
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
            "[sessions.dev]\nio = { stdin_mimetype = \"text/plain\" }\n\
             [[sessions.dev.file_imports]]\nsrc = \"a\"\ndst = \"/a\"\n\
             [[sessions.dev.vars_lenient]]\nname = \"my.var\"\nvalue = \"1\"\n",
            "dev",
            Layers {
                type_defaults: vec![(
                    "session".to_owned(),
                    table(
                        "loadout_mode = \"open\"\nexec_enabled = true\n\
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
                (
                    "session".to_owned(),
                    crate::box_types::builtin_defaults("session"),
                ),
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

    /// The built-in root of a type, for the implicit default tests: each
    /// built-in type is its own root, and `rust-dev` has the root `session`.
    fn test_root(t: &str) -> Option<&'static str> {
        BUILTIN_BOX_TYPES
            .into_iter()
            .find(|b| *b == t)
            .or((t == "rust-dev").then_some("session"))
    }

    /// The implicit default entry of `file`, if the file needs one.
    fn implicit_in(file: &str) -> Option<BoxEntry> {
        let entries = read_entries(file.as_bytes()).expect("entries read");
        implicit_default_entry(&entries, test_root)
    }

    // BOX-165: a project with no session entry expands an implicit
    // `[sessions.default]` from its other layers, with no entry layer.
    #[test]
    fn no_session_entry_expands_implicit_default_session() {
        let file = r#"
            [defaults]
            packages = ["git"]
            timeout = "2h"

            [defaults.session]
            packages = ["fish"]
            pty_enabled = true

            [defaults.task]
            timeout = "5m"

            [tasks.test]
            exec = ["cargo", "test"]

            [boxes.ci]
            type = "build"
        "#;
        let entry = implicit_in(file).expect("an implicit default entry");
        assert_eq!(entry.name, DEFAULT_ENTRY_NAME);
        assert_eq!(entry.table, EntryTable::Sessions);
        assert_eq!(entry.box_type.as_deref(), Some("session"));
        assert!(entry.body.is_empty(), "{:?}", entry.body);
        assert!(entry.implicit);

        let doc = table(file);
        let defaults = doc["defaults"].as_table().expect("a table");
        let layers = Layers {
            upstream: table("commit = \"abc123\""),
            type_defaults: vec![("session".to_owned(), table("lifetime = \"until_complete\""))],
            ..Layers::default()
        }
        .with_file_defaults(defaults, entry.box_type.as_deref(), &BTreeSet::new());
        let e = expand(&entry, &layers).expect("expands");

        assert_eq!(strings(e.spec.get("packages")), ["git", "fish"]);
        assert_eq!(e.spec["timeout"].as_str(), Some("2h"));
        assert_eq!(e.spec["pty_enabled"].as_bool(), Some(true));
        assert_eq!(e.spec["lifetime"].as_str(), Some("until_complete"));
        assert!(e.spec.contains_key("upstream"));
        assert!(!e.spec.contains_key("exec"), "{:?}", e.spec);
        // No value comes from an entry layer.
        for (key, origin) in &e.report.values {
            let origins = match origin {
                ValueOrigin::Value(o) => vec![o],
                ValueOrigin::List(items) => items.iter().collect(),
            };
            assert!(
                origins.iter().all(|o| o.layer != Layer::Entry),
                "{key}: {origin:?}"
            );
        }

        // A project with no minimal.toml has no entries, and gets one too.
        let none = implicit_default_entry(&[], test_root).expect("an implicit entry");
        assert_eq!(none, entry);
        let e = expand(&none, &Layers::default()).expect("expands");
        // BOX-071: expansion fills only the values the digest binds.
        let filled = table("[network]\nquic443 = \"auto\"\n[network.bep]\nsteering = \"dns\"\n");
        assert_eq!(e.spec, filled, "{:?}", e.spec);
        assert!(e.report.implicit);

        // A session entry, direct or through a type rooted at `session`,
        // means no implicit entry.
        for file in [
            "[sessions.dev]\n",
            "[boxes.dev]\ntype = \"session\"\n",
            "[boxes.dev]\ntype = \"rust-dev\"\n",
            "[sessions.default]\n",
        ] {
            assert_eq!(implicit_in(file), None, "{file}");
        }
    }

    // BOX-165: an entry named `default` whose type is not rooted at
    // `session` blocks the implicit default.
    #[test]
    fn non_session_default_entry_blocks_implicit_default() {
        for file in [
            "[tasks.default]\nexec = [\"true\"]\n",
            "[boxes.default]\ntype = \"build\"\n",
            "[boxes.default]\ntype = \"unknown-type\"\n",
            "[boxes.default]\n",
            "[agents.default]\n",
        ] {
            assert_eq!(implicit_in(file), None, "{file}");
        }
        // Another name with the same type does not block it.
        assert!(implicit_in("[tasks.other]\n").is_some());
    }

    // BOX-161: the report of the implicit default entry marks it implicit,
    // and the report of a declared entry does not.
    #[test]
    fn implicit_default_entry_reported_as_implicit() {
        let file = "[defaults.session]\npty_enabled = true\n";
        let entry = implicit_in(file).expect("an implicit default entry");
        let layers = Layers::default().with_file_defaults(
            table(file)["defaults"].as_table().expect("a table"),
            Some("session"),
            &BTreeSet::new(),
        );
        let implicit = expand(&entry, &layers).expect("expands");
        assert!(implicit.report.implicit);
        assert_eq!(
            implicit.report.values["pty_enabled"],
            ValueOrigin::Value(Origin::of(Layer::DefaultsType))
        );

        // The mark is beside the spec, never in its bytes.
        let bytes = implicit.spec_bytes().expect("writes");
        assert!(!bytes.contains("implicit"), "{bytes}");

        let declared = expand_in(
            "[sessions.default]\n[defaults.session]\npty_enabled = true\n",
            "default",
            Layers::default(),
        )
        .expect("expands");
        assert!(!declared.report.implicit);
    }

    /// Expands entry `name` of `file` as a client does: resolves its type
    /// against the file's `[box_types]`, then folds the type chain's
    /// defaults and the file's `[defaults]` under the entry.
    fn expand_typed(file: &str, name: &str) -> Result<Result<Expansion, Error>, BoxTypeError> {
        expand_typed_with(file, name, toml::Table::new())
    }

    /// [`expand_typed`], with `loadouts` as the selected loadouts' layer.
    fn expand_typed_with(
        file: &str,
        name: &str,
        loadouts: toml::Table,
    ) -> Result<Result<Expansion, Error>, BoxTypeError> {
        let doc = table(file);
        let types = BoxTypes::from_file(&doc)?;
        let entries = read_entries(file.as_bytes()).expect("entries read");
        let entry = entries
            .iter()
            .find(|e| e.name == name)
            .unwrap_or_else(|| panic!("entry {name} read"));
        let resolved = expandable_type(entry, &types)?;
        let project_types = types.project().keys().cloned().collect();
        let defaults = doc
            .get("defaults")
            .and_then(toml::Value::as_table)
            .cloned()
            .unwrap_or_default();
        let layers = Layers {
            type_defaults: resolved.defaults,
            loadouts,
            ..Layers::default()
        }
        .with_file_defaults(&defaults, entry.box_type.as_deref(), &project_types);
        Ok(expand(entry, &layers))
    }

    const TYPED_FILE: &str = r#"
        [defaults]
        packages = ["git"]

        [box_types.ci]
        extends = "task"
        defaults = { timeout = "10m", packages = ["make"] }

        [box_types.ci-rust]
        extends = "ci"
        defaults = { packages = ["rust"] }

        [box_types.helper]
        extends = "agent"

        [box_types.web]
        extends = "service"

        [defaults.ci-rust]
        pty_enabled = false

        [sessions.dev]
        pty_enabled = true

        [tasks.lint]
        timeout = "1m"

        [boxes.check]
        type = "ci-rust"

        [boxes.bad]
        type = "ci"
        not_a_setting = 1

        [agents.bot]

        [services.api]

        [boxes.builder]
        type = "build"

        [boxes.image]
        type = "container-build"

        [boxes.assistant]
        type = "helper"

        [boxes.frontend]
        type = "web"

        [boxes.plain-agent]
        type = "agent"
    "#;

    // BOX-063: entries whose type, or whose type's built-in root, is
    // `session` or `task` expand, and their keys are validated.
    #[test]
    fn session_and_task_entries_expand_and_validate() {
        let dev = expand_typed(TYPED_FILE, "dev")
            .expect("resolves")
            .expect("expands");
        assert_eq!(dev.spec["type"].as_str(), Some("session"));
        assert_eq!(dev.spec["pty_enabled"].as_bool(), Some(true));
        assert_eq!(strings(dev.spec.get("packages")), ["git"]);

        let lint = expand_typed(TYPED_FILE, "lint")
            .expect("resolves")
            .expect("expands");
        assert_eq!(lint.spec["timeout"].as_str(), Some("1m"));

        // A type that extends `task` through `ci`: the chain's defaults,
        // root first, then `[defaults]`, `[defaults.ci-rust]` and the entry.
        let check = expand_typed(TYPED_FILE, "check")
            .expect("resolves")
            .expect("expands");
        assert_eq!(check.spec["type"].as_str(), Some("ci-rust"));
        assert_eq!(check.spec["timeout"].as_str(), Some("10m"));
        assert_eq!(check.spec["pty_enabled"].as_bool(), Some(false));
        assert_eq!(strings(check.spec.get("packages")), ["make", "rust", "git"]);
        assert_eq!(
            check.report.values["timeout"],
            ValueOrigin::Value(Origin::type_defaults("ci"))
        );

        // Validation still runs on an entry of a type rooted at `task`.
        let err = expand_typed(TYPED_FILE, "bad")
            .expect("resolves")
            .expect_err("an unknown key fails");
        assert_eq!(err.exit_code(), Some(3), "{err}");
        assert!(err.to_string().contains("not_a_setting"), "{err}");

        // An entry type that no table defines fails with exit 3.
        let err = expand_typed("[boxes.x]\ntype = \"nope\"\n", "x").expect_err("fails");
        assert_eq!(err.exit_code(), 3);
        assert_eq!(
            err.to_string(),
            "`[boxes.x]` has the type `nope`, which is not a built-in type and not in `[box_types]`."
        );
        let err = expand_typed("[boxes.x]\n", "x").expect_err("fails");
        assert_eq!(err.exit_code(), 3);
        assert_eq!(
            err.to_string(),
            "`[boxes.x]` sets no `type`. Set `type` to `session`, `task` or a type in `[box_types]`."
        );
    }

    // BOX-063: an entry of `agent`, `service`, `build` or `container-build`,
    // directly or as the built-in root of its type, or from `[agents.*]` or
    // `[services.*]`, is refused with exit 3 naming the type and the epic.
    // The file's other entries stay usable.
    #[test]
    fn other_builtin_type_entry_refused_exit3_other_entries_usable() {
        for (name, header, box_type, root) in [
            ("bot", "[agents.bot]", "agent", "agent"),
            ("api", "[services.api]", "service", "service"),
            ("builder", "[boxes.builder]", "build", "build"),
            (
                "image",
                "[boxes.image]",
                "container-build",
                "container-build",
            ),
            ("assistant", "[boxes.assistant]", "helper", "agent"),
            ("frontend", "[boxes.frontend]", "web", "service"),
            ("plain-agent", "[boxes.plain-agent]", "agent", "agent"),
        ] {
            let err = expand_typed(TYPED_FILE, name).expect_err(name);
            assert_eq!(err.exit_code(), 3, "{name}");
            assert!(
                matches!(&err, BoxTypeError::Unsupported { root: r, .. } if *r == root),
                "{name}: {err:?}"
            );
            let msg = err.to_string();
            assert!(
                msg.starts_with(&format!("`{header}` has the type `{box_type}`")),
                "{msg}"
            );
            assert!(msg.contains("gominimal/inbox#678"), "{msg}");
            assert!(msg.contains(&format!("a box of type `{root}`")), "{msg}");
        }
        assert_eq!(
            expand_typed(TYPED_FILE, "assistant")
                .expect_err("refused")
                .to_string(),
            "`[boxes.assistant]` has the type `helper`, which extends `agent`. \
             This release cannot create a box of type `agent`. \
             gominimal/inbox#678 tracks it. \
             The other entries of minimal.toml are not affected."
        );

        // The refused entries leave the session and task entries usable.
        for name in ["dev", "lint", "check"] {
            expand_typed(TYPED_FILE, name)
                .unwrap_or_else(|e| panic!("{name}: {e}"))
                .unwrap_or_else(|e| panic!("{name}: {e}"));
        }
    }

    /// Expands entry `name` of `file` as a client does, with `overrides` and
    /// `loadouts` as the last two layers, then checks the type's
    /// constraints last (BOX-061). Returns the expansion with and without
    /// the check.
    fn expand_checked(
        file: &str,
        name: &str,
        loadouts: &str,
        overrides: &str,
    ) -> (Expansion, Result<(), BoxTypeError>) {
        let doc = table(file);
        let types = BoxTypes::from_file(&doc).expect("the types resolve");
        let entries = read_entries(file.as_bytes()).expect("entries read");
        let entry = entries
            .iter()
            .find(|e| e.name == name)
            .unwrap_or_else(|| panic!("entry {name} read"));
        let resolved = expandable_type(entry, &types).expect("expandable");
        let project_types = types.project().keys().cloned().collect();
        let defaults = doc
            .get("defaults")
            .and_then(toml::Value::as_table)
            .cloned()
            .unwrap_or_default();
        let layers = Layers {
            type_defaults: resolved.defaults.clone(),
            loadouts: table(loadouts),
            overrides: table(overrides),
            ..Layers::default()
        }
        .with_file_defaults(&defaults, entry.box_type.as_deref(), &project_types);
        let expansion = expand(entry, &layers).expect("expands");
        let checked = check_constraints(entry, &expansion, &resolved);
        (expansion, checked)
    }

    const CONSTRAINED_FILE: &str = r#"
        [box_types.ci]
        extends = "task"
        defaults = { packages = ["git"] }
        constraints = { pty_enabled = false, restart = ["never", "on-failure"], network = { mode = "none" } }

        [box_types.ci-small]
        extends = "ci"
        constraints = { packages = ["git", "make"], restart = "never" }

        [defaults.ci]
        restart = "always"

        [boxes.ok]
        type = "ci-small"
        packages = ["make"]
        restart = "never"
        network = { mode = "none" }

        [boxes.pty]
        type = "ci"
        pty_enabled = true

        [boxes.from-defaults]
        type = "ci"

        [boxes.extra]
        type = "ci-small"
        restart = "never"
        packages = ["curl"]

        [boxes.small-always]
        type = "ci-small"
        restart = "always"
    "#;

    // BOX-061: the expanded spec is checked against the type's constraints
    // after the override layer. A value outside them fails with exit 3
    // naming the type, the key and the layer that set it.
    #[test]
    fn expanded_spec_violating_constraint_exit3_names_type_and_layer() {
        let (_, checked) = expand_checked(CONSTRAINED_FILE, "ok", "", "");
        checked.expect("a spec inside every constraint is accepted");

        // The entry's own table.
        let (_, checked) = expand_checked(CONSTRAINED_FILE, "pty", "", "");
        let err = checked.expect_err("pty_enabled = true is outside the type");
        assert_eq!(err.exit_code(), 3);
        assert_eq!(
            err.to_string(),
            "`[boxes.pty]` in minimal.toml sets `pty_enabled` to `true`. \
             `[box_types.ci]` allows only `false` for `pty_enabled`. Change the value."
        );

        // `[defaults.<type>]`.
        let (_, checked) = expand_checked(CONSTRAINED_FILE, "from-defaults", "", "");
        assert_eq!(
            checked.expect_err("restart = always").to_string(),
            "`[defaults.ci]` in minimal.toml sets `restart` to `\"always\"`. \
             `[box_types.ci]` allows only `\"never\"` or `\"on-failure\"` for `restart`. \
             Change the value."
        );

        // A list item: the layer that added it, here the entry.
        let (_, checked) = expand_checked(CONSTRAINED_FILE, "extra", "", "");
        assert_eq!(
            checked.expect_err("curl is outside the list").to_string(),
            "`[boxes.extra]` in minimal.toml adds `\"curl\"` to `packages`. \
             `[box_types.ci-small]` allows only `\"git\"` or `\"make\"` in `packages`. \
             Change the value."
        );

        // The error names the type whose table holds the failing
        // constraint. A derived type narrows its parent, so its own
        // constraint is checked first.
        let (_, checked) = expand_checked(CONSTRAINED_FILE, "small-always", "", "");
        assert_eq!(
            checked.expect_err("restart = always").to_string(),
            "`[boxes.small-always]` in minimal.toml sets `restart` to `\"always\"`. \
             `[box_types.ci-small]` allows only `\"never\"` for `restart`. \
             Change the value."
        );

        // A nested key names its path, and the parent type that constrains it.
        let (_, checked) =
            expand_checked(CONSTRAINED_FILE, "ok", "", "network = { mode = \"open\" }");
        let err = checked.expect_err("network.mode = open");
        assert_eq!(
            err.to_string(),
            "a command-line flag sets `network.mode` to `\"open\"`. \
             `[box_types.ci]` allows only `\"none\"` for `network.mode`. \
             Change the value."
        );

        // The check runs after the override layer: an override can break a
        // constraint, and an override can repair a value an earlier layer
        // set.
        let (_, checked) = expand_checked(CONSTRAINED_FILE, "ok", "", "pty_enabled = true");
        let msg = checked.expect_err("override breaks").to_string();
        assert!(
            msg.starts_with("a command-line flag sets `pty_enabled`"),
            "{msg}"
        );
        let (_, checked) =
            expand_checked(CONSTRAINED_FILE, "from-defaults", "", "restart = \"never\"");
        checked.expect("the override sets an allowed value last");

        // A selected loadout is named as its layer. A `task`-rooted entry
        // is sealed, so this one opens itself to its loadouts.
        let open = format!(
            "{CONSTRAINED_FILE}\n[boxes.ok-open]\ntype = \"ci-small\"\nloadout_mode = \"open\"\n"
        );
        let (_, checked) = expand_checked(&open, "ok-open", "packages = [\"jq\"]", "");
        let msg = checked.expect_err("loadout adds jq").to_string();
        assert!(
            msg.starts_with("a selected loadout adds `\"jq\"` to `packages`"),
            "{msg}"
        );

        // A setting under its section is checked as the flat key is.
        for (setting, key, value, allowed) in [
            (
                "execution = { restart = \"always\" }",
                "execution.restart",
                "\"always\"",
                "`[box_types.ci-small]` allows only `\"never\"`",
            ),
            (
                "io = { pty_enabled = true }",
                "io.pty_enabled",
                "true",
                "`[box_types.ci]` allows only `false`",
            ),
        ] {
            let file = format!("{CONSTRAINED_FILE}\n[boxes.x]\ntype = \"ci-small\"\n{setting}\n");
            let (_, checked) = expand_checked(&file, "x", "", "");
            let err = checked.expect_err(setting);
            assert!(
                matches!(err, BoxTypeError::ConstraintBroken { .. }),
                "{err:?}"
            );
            assert_eq!(
                err.to_string(),
                format!(
                    "`[boxes.x]` in minimal.toml sets `{key}` to `{value}`. \
                     {allowed} for `{key}`. Change the value."
                )
            );
        }

        // A constraint written under its section checks the flat key too.
        let file = r#"
            [box_types.ci-io]
            extends = "task"
            constraints = { io = { pty_enabled = false }, install = { packages = ["git"] } }

            [boxes.x]
            type = "ci-io"
            pty_enabled = true
        "#;
        let (_, checked) = expand_checked(file, "x", "", "");
        assert_eq!(
            checked.expect_err("flat pty_enabled").to_string(),
            "`[boxes.x]` in minimal.toml sets `pty_enabled` to `true`. \
             `[box_types.ci-io]` allows only `false` for `pty_enabled`. Change the value."
        );
        let (_, checked) =
            expand_checked(file, "x", "", "pty_enabled = false\npackages = [\"jq\"]");
        assert_eq!(
            checked.expect_err("flat packages").to_string(),
            "a command-line flag adds `\"jq\"` to `packages`. \
             `[box_types.ci-io]` allows only `\"git\"` in `packages`. Change the value."
        );

        // A built-in type ships its own constraints: a task has no PTY.
        let file = "[tasks.x]\npty_enabled = true\n";
        let (_, checked) = expand_checked(file, "x", "", "");
        let err = checked.expect_err("a task with a PTY");
        assert_eq!(err.exit_code(), 3);
        assert_eq!(
            err.to_string(),
            "`[tasks.x]` in minimal.toml sets `pty_enabled` to `true`. \
             The built-in type `task` allows only `false` for `pty_enabled`. Change the value."
        );
    }

    /// A value for one constrained key, from a small domain.
    fn small_value() -> impl Strategy<Value = toml::Value> {
        prop::sample::select(vec!["a", "b", "c"]).prop_map(|s| toml::Value::String(s.to_owned()))
    }

    /// A constraint: one value, or a list of values.
    fn small_constraint() -> impl Strategy<Value = toml::Value> {
        prop_oneof![
            small_value(),
            prop::collection::vec(small_value(), 0..3).prop_map(toml::Value::Array),
        ]
    }

    proptest! {
        // BOX-061 property: whichever layer sets the value, an expanded
        // spec outside the type's constraint is rejected, and one inside
        // every constraint is accepted.
        #[test]
        fn expanded_spec_violating_constraint_exit3_names_type_and_layer_property(
            constraint in small_constraint(),
            outer in small_constraint(),
            layer_values in prop::collection::vec(prop::option::of(small_value()), 4),
        ) {
            let mut file = format!(
                "[box_types.outer]\nextends = \"session\"\nconstraints = {{ restart = {outer} }}\n\
                 [box_types.inner]\nextends = \"outer\"\nconstraints = {{ restart = {constraint} }}\n"
            );
            let set = |v: &Option<toml::Value>| {
                v.as_ref().map(|v| format!("restart = {v}\n")).unwrap_or_default()
            };
            file.push_str(&format!("[defaults.inner]\n{}", set(&layer_values[0])));
            file.push_str(&format!("[boxes.dev]\ntype = \"inner\"\n{}", set(&layer_values[1])));
            // A derived type that loosens fails to resolve; that is BOX-156.
            let doc = table(&file);
            prop_assume!(BoxTypes::from_file(&doc).is_ok());
            let (expansion, checked) =
                expand_checked(&file, "dev", &set(&layer_values[2]), &set(&layer_values[3]));
            let inside = expansion.spec.get("restart").is_none_or(|v| {
                crate::box_types::admitted(&constraint).contains(v)
                    && crate::box_types::admitted(&outer).contains(v)
            });
            prop_assert_eq!(checked.is_ok(), inside);
            if let Err(err) = checked {
                prop_assert_eq!(err.exit_code(), 3);
                let msg = err.to_string();
                let layer = layer_values.iter().rposition(Option::is_some).expect("set");
                let words = [
                    "`[defaults.inner]` in minimal.toml",
                    "`[boxes.dev]` in minimal.toml",
                    "a selected loadout",
                    "a command-line flag",
                ][layer];
                prop_assert!(msg.starts_with(&format!("{words} sets `restart`")), "{}", msg);
                prop_assert!(msg.contains("`[box_types.inner]`"), "{}", msg);
            }
        }
    }

    // BOX-062: a type constraint never adds a package, a port or an egress
    // entry. The check reads the spec and leaves it as the layers set it.
    #[test]
    fn constraint_never_adds_package_port_or_egress() {
        let file = r#"
            [box_types.ci]
            extends = "task"
            constraints = { packages = ["git", "make", "rust"], network = { ingress = [{ proto = "tcp", port = 8080 }, { proto = "tcp", port = 9090 }], egress = { allow_dns_hosts = ["example.com", "example.org"] } } }

            [boxes.dev]
            type = "ci"
            packages = ["git"]
            network = { ingress = [{ proto = "tcp", port = 8080 }], egress = { allow_dns_hosts = ["example.com"] } }

            [boxes.bare]
            type = "ci"
        "#;
        let unconstrained = file.replace("constraints = ", "#");
        for name in ["dev", "bare"] {
            let (constrained, checked) = expand_checked(file, name, "", "");
            checked.expect("the spec is inside the constraint");
            let (plain, checked) = expand_checked(&unconstrained, name, "", "");
            checked.expect("no constraint");
            assert_eq!(constrained.spec, plain.spec, "{name}");
            assert_eq!(constrained.report, plain.report, "{name}");
        }
        let (bare, _) = expand_checked(file, "bare", "", "");
        assert!(bare.spec.get("packages").is_none());
        let bare_network = bare.spec["network"].as_table().expect("network");
        assert!(bare_network.get("ingress").is_none());
        assert!(bare_network.get("egress").is_none());
        let (dev, _) = expand_checked(file, "dev", "", "");
        assert_eq!(strings(dev.spec.get("packages")), ["git"]);
        let network = dev.spec["network"].as_table().expect("network");
        assert_eq!(network["ingress"].as_array().map(Vec::len), Some(1));
        assert_eq!(
            strings(network["egress"].get("allow_dns_hosts")),
            ["example.com"]
        );
    }

    proptest! {
        // BOX-062 property: for every constraint and spec, the constrained
        // spec's package, port and egress lists are subsets of the
        // unconstrained spec's.
        #[test]
        fn constraint_never_adds_package_port_or_egress_property(
            allowed in prop::collection::vec(small_value(), 0..4),
            set in prop::collection::vec(small_value(), 0..3),
        ) {
            let list = |v: &[toml::Value]| toml::Value::Array(v.to_vec()).to_string();
            let entry = format!(
                "[boxes.dev]\ntype = \"ci\"\npackages = {}\n\
                 network = {{ egress = {{ allow_dns_hosts = {} }} }}\n",
                list(&set),
                list(&set)
            );
            let file = format!(
                "[box_types.ci]\nextends = \"task\"\n\
                 constraints = {{ packages = {a}, network = {{ ingress = {a}, egress = {{ allow_dns_hosts = {a} }} }} }}\n{entry}",
                a = list(&allowed)
            );
            let plain = format!("[box_types.ci]\nextends = \"task\"\n{entry}");
            let (constrained, checked) = expand_checked(&file, "dev", "", "");
            let (unconstrained, _) = expand_checked(&plain, "dev", "", "");
            prop_assert_eq!(&constrained.spec, &unconstrained.spec);
            prop_assert_eq!(
                checked.is_ok(),
                set.iter().all(|v| allowed.contains(v))
            );
        }
    }

    /// A selected-loadouts layer that sets each part a loadout carries.
    fn whole_loadout() -> toml::Table {
        table(
            "packages = [\"zellij\"]\n\
             patches = { \"~/.bashrc\" = \"alias l=ls\" }\n\
             vars = { EDITOR = \"hx\" }\n\
             vars_lenient = [{ name = \"my.var\", value = \"1\" }]\n\
             lifecycle_hooks = [{ on = \"start\", run = \"echo hi\" }]\n",
        )
    }

    /// The keys of [`whole_loadout`].
    const LOADOUT_KEYS: [&str; 5] = [
        "packages",
        "patches",
        "vars",
        "vars_lenient",
        "lifecycle_hooks",
    ];

    /// Asserts that `expansion` carries no part of [`whole_loadout`].
    fn assert_no_loadout(expansion: &Expansion, what: &str) {
        for key in LOADOUT_KEYS {
            let from_loadout = match expansion.report.values.get(key) {
                Some(ValueOrigin::Value(o)) => o.layer == Layer::Loadouts,
                Some(ValueOrigin::List(items)) => items.iter().any(|o| o.layer == Layer::Loadouts),
                None => false,
            };
            assert!(!from_loadout, "{what}: {key} came from a loadout");
        }
        let packages = expansion.spec.get("packages");
        assert!(
            packages.is_none_or(|p| !strings(Some(p)).contains(&"zellij")),
            "{what}: {:?}",
            expansion.spec.get("packages")
        );
    }

    /// Asserts that `expansion` carries every part of [`whole_loadout`].
    fn assert_whole_loadout(expansion: &Expansion, what: &str) {
        assert!(
            strings(expansion.spec.get("packages")).contains(&"zellij"),
            "{what}: {:?}",
            expansion.spec.get("packages")
        );
        assert_eq!(
            expansion.spec["vars"]["EDITOR"].as_str(),
            Some("hx"),
            "{what}"
        );
        for key in LOADOUT_KEYS {
            assert!(expansion.spec.contains_key(key), "{what}: {key} is missing");
        }
    }

    // BOX-166: a sealed entry takes no loadout at the selected-loadouts
    // layer, whatever that layer carries.
    #[test]
    fn sealed_spec_applies_no_loadout() {
        let file = "[tasks.lint]\n\n[sessions.locked]\nloadout_mode = \"sealed\"\n";
        for name in ["lint", "locked"] {
            let e = expand_typed_with(file, name, whole_loadout())
                .expect("the type resolves")
                .expect("expands");
            assert_eq!(e.spec["loadout_mode"].as_str(), Some("sealed"), "{name}");
            assert_no_loadout(&e, name);
        }
    }

    // BOX-167: an open entry takes the selected loadout whole: packages,
    // config-file patches, vars, vars_lenient and lifecycle hooks.
    #[test]
    fn open_spec_applies_whole_loadout() {
        let file = "[sessions.dev]\n\n[tasks.lint]\nloadout_mode = \"open\"\n";
        for name in ["dev", "lint"] {
            let e = expand_typed_with(file, name, whole_loadout())
                .expect("the type resolves")
                .expect("expands");
            assert_eq!(e.spec["loadout_mode"].as_str(), Some("open"), "{name}");
            assert_whole_loadout(&e, name);
        }
    }

    // BOX-170: the gate reads `loadout_mode` from the layers up to and
    // including the entry, never the type name. A session set to sealed
    // takes nothing, a type that extends task and sets open takes the
    // loadout, and each layer before the entry can set the mode.
    #[test]
    fn loadout_gate_follows_setting_not_type_name() {
        let file = r#"
            [box_types.ci-open]
            extends = "task"
            defaults = { loadout_mode = "open" }

            [box_types.dev-sealed]
            extends = "session"
            defaults = { loadout_mode = "sealed" }

            [defaults.task]
            loadout_mode = "open"

            [sessions.locked]
            loadout_mode = "sealed"

            [sessions.boxed]
            box = { loadout_mode = "sealed" }

            [boxes.ci]
            type = "ci-open"

            [boxes.dev]
            type = "dev-sealed"

            [boxes.reopened]
            type = "dev-sealed"
            loadout_mode = "open"

            [tasks.lint]

            [agents.helper]
        "#;
        for name in ["locked", "boxed", "dev"] {
            let e = expand_typed_with(file, name, whole_loadout())
                .expect("the type resolves")
                .expect("expands");
            assert_no_loadout(&e, name);
        }
        // The agent root supplies no `loadout_mode`, and the gate seals an
        // entry whose layers set none. This release refuses `[agents.*]`
        // before expansion, so expand the entry past that check.
        let helper = Layers {
            type_defaults: vec![(
                "agent".to_owned(),
                crate::box_types::builtin_defaults("agent"),
            )],
            loadouts: whole_loadout(),
            ..Layers::default()
        };
        let e = expand_in(file, "helper", helper).expect("expands");
        assert_eq!(e.spec.get("loadout_mode"), None);
        assert_no_loadout(&e, "helper");
        for name in ["ci", "reopened", "lint"] {
            let e = expand_typed_with(file, name, whole_loadout())
                .expect("the type resolves")
                .expect("expands");
            assert_whole_loadout(&e, name);
        }

        // A loadout that sets `loadout_mode` cannot open a sealed entry.
        let mut opening = whole_loadout();
        opening.insert("loadout_mode".to_owned(), "open".into());
        let e = expand_typed_with(file, "locked", opening)
            .expect("the type resolves")
            .expect("expands");
        assert_no_loadout(&e, "locked, with a loadout that sets open");

        // The report carries the mode and the layer that set it.
        let e = expand_typed_with(file, "dev", toml::Table::new())
            .expect("the type resolves")
            .expect("expands");
        assert_eq!(
            e.report.values["loadout_mode"],
            ValueOrigin::Value(Origin::type_defaults("dev-sealed"))
        );
    }

    // BOX-174: a `loadout_mode` other than `sealed` or `open` fails the
    // expansion with exit 3 before any loadout applies. The error names
    // the key, the value, the layer that set it and the accepted values.
    #[test]
    fn unknown_loadout_mode_refused_exit3() {
        let file = r#"
            [box_types.ci]
            extends = "task"
            defaults = { loadout_mode = "merge" }

            [defaults.session]
            loadout_mode = "Open"

            [sessions.dev]

            [sessions.mine]
            loadout_mode = "everything"

            [sessions.boxed]
            box = { loadout_mode = "merge" }

            [boxes.ci]
            type = "ci"
        "#;
        let cases = [
            (
                "dev",
                "`[defaults.session]` in minimal.toml sets `loadout_mode` to \"Open\". \
                 `loadout_mode` accepts only `sealed` or `open`. Fix the value.",
            ),
            (
                "mine",
                "`[sessions.mine]` in minimal.toml sets `loadout_mode` to \"everything\". \
                 `loadout_mode` accepts only `sealed` or `open`. Fix the value.",
            ),
            (
                "boxed",
                "`[sessions.boxed]` in minimal.toml sets `box.loadout_mode` to \"merge\". \
                 `box.loadout_mode` accepts only `sealed` or `open`. Fix the value.",
            ),
            (
                "ci",
                "the `defaults` table of `[box_types.ci]` sets `loadout_mode` to \"merge\". \
                 `loadout_mode` accepts only `sealed` or `open`. Fix the value.",
            ),
        ];
        for (name, msg) in cases {
            let err = expand_typed_with(file, name, whole_loadout())
                .expect("the type resolves")
                .expect_err("an unknown mode is refused");
            assert!(
                matches!(
                    &err,
                    Error::InvalidSpecKey {
                        problem: SpecKeyProblem::UnknownValue { .. },
                        ..
                    }
                ),
                "{name}: {err:?}"
            );
            assert_eq!(err.exit_code(), Some(3), "{name}");
            assert_eq!(err.to_string(), msg, "{name}");
        }
    }

    /// Layers whose selected loadouts' layer is `loadouts` and whose host
    /// sets `host`.
    fn vars_layers(loadouts: &str, host: &[(&str, &str)]) -> Layers {
        Layers {
            loadouts: table(loadouts),
            host_vars: host
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            ..Layers::default()
        }
    }

    /// The `vars_lenient` items of `spec`, as `(name, value)` pairs.
    fn lenient(spec: &toml::Table) -> Vec<(String, toml::Value)> {
        spec["vars_lenient"]
            .as_array()
            .expect("a list")
            .iter()
            .map(|item| {
                (
                    item["name"].as_str().unwrap().to_owned(),
                    item["value"].clone(),
                )
            })
            .collect()
    }

    // BOX-180: `vars` and `vars_lenient` merge by name across both tables.
    // A name keeps the value, and the table, of the most specific layer up
    // to the entry, and a loadout adds the names it sets.
    #[test]
    fn vars_merge_by_name_across_layers() {
        let file = r#"
            [defaults]
            vars = { A = "defaults", B = "defaults", KEEP = "defaults" }
            [defaults.session]
            vars_lenient = [{ name = "my.var", value = "1" }]
            [sessions.dev]
            loadout_mode = "open"
            vars = { A = "entry" }
            vars_lenient = [{ name = "B", value = "entry" }]
        "#;
        let loadouts = r#"
            vars = { A = "entry", C = "loadout", H = { inherit = true }, GONE = { inherit = true } }
            vars_lenient = [{ name = "KEEP", value = "defaults" }]
        "#;
        let e = expand_in(file, "dev", vars_layers(loadouts, &[("H", "host")]))
            .expect("the entry expands");
        let vars = e.spec["vars"].as_table().expect("a table");
        let names: Vec<&str> = vars.keys().map(String::as_str).collect();
        assert_eq!(names, ["A", "C", "GONE", "H", "KEEP"]);
        assert_eq!(vars["A"].as_str(), Some("entry"), "the entry wins");
        assert_eq!(vars["KEEP"].as_str(), Some("defaults"), "defaults kept");
        assert_eq!(vars["C"].as_str(), Some("loadout"), "a loadout adds");
        assert_eq!(
            lenient(&e.spec),
            [
                ("B".to_owned(), toml::Value::from("entry")),
                ("my.var".to_owned(), toml::Value::from("1")),
            ],
            "B moves to the entry's table, and keeps its first place"
        );
        // The report keeps the layer of each name.
        let at = |name: &str| e.report.vars[name].layer;
        assert_eq!(
            at("A"),
            Layer::Entry,
            "a loadout's equal value adds nothing"
        );
        assert_eq!(at("B"), Layer::Entry);
        assert_eq!(at("KEEP"), Layer::Defaults);
        assert_eq!(at("my.var"), Layer::DefaultsType);
        assert_eq!(at("C"), Layer::Loadouts);
        assert_eq!(at("H"), Layer::Loadouts);
        // The key's origin names the layer of each name, so a render can
        // label every layer that the names came from.
        let layers_of = |key: &str| match &e.report.values[key] {
            ValueOrigin::List(origins) => origins.iter().map(|o| o.layer).collect::<Vec<_>>(),
            other => panic!("{key}: {other:?}"),
        };
        assert_eq!(
            layers_of("vars"),
            [
                Layer::Entry,
                Layer::Loadouts,
                Layer::Loadouts,
                Layer::Loadouts,
                Layer::Defaults
            ]
        );
        assert_eq!(
            layers_of("vars_lenient"),
            [Layer::Entry, Layer::DefaultsType]
        );
        // The merge is the same on every run.
        let again = expand_in(file, "dev", vars_layers(loadouts, &[("H", "host")])).unwrap();
        assert_eq!(e.spec_bytes().unwrap(), again.spec_bytes().unwrap());
        // A sealed entry takes no loadout name.
        let sealed = file.replace("\"open\"", "\"sealed\"");
        let e = expand_in(&sealed, "dev", vars_layers(loadouts, &[])).unwrap();
        let names: Vec<&String> = e.spec["vars"].as_table().unwrap().keys().collect();
        assert_eq!(names, ["A", "KEEP"]);
        // A loadout's `inherit` that matches the set value, or that the host
        // does not set, is not a conflict.
        let loadouts = "vars = { A = { inherit = true }, KEEP = { inherit = true } }";
        let e = expand_in(file, "dev", vars_layers(loadouts, &[("A", "entry")])).unwrap();
        assert_eq!(e.spec["vars"]["A"].as_str(), Some("entry"));
        assert_eq!(e.spec["vars"]["KEEP"].as_str(), Some("defaults"));
        // A name that the entry has only from a type's defaults: the entry
        // still wins over the built-in layer.
        let layers = Layers {
            type_defaults: vec![(
                "session".to_owned(),
                table("vars = { T = \"type\", A = \"type\" }"),
            )],
            ..Layers::default()
        };
        let e = expand_in(file, "dev", layers).unwrap();
        assert_eq!(e.spec["vars"]["T"].as_str(), Some("type"));
        assert_eq!(e.spec["vars"]["A"].as_str(), Some("entry"));
        assert_eq!(e.report.vars["T"], Origin::type_defaults("session"));
        // A `vars_lenient` item with no name stays in the list, so the
        // client refuses it, and the merge does not drop it silently.
        let nameless = file.replace(
            "[{ name = \"B\", value = \"entry\" }]",
            "[{ name = \"B\", value = \"entry\" }, { value = \"x\" }]",
        );
        let e = expand_in(&nameless, "dev", Layers::default()).unwrap();
        let items = e.spec["vars_lenient"].as_array().unwrap();
        assert_eq!(items.len(), 3, "{items:?}");
        assert!(items.iter().any(|item| item.get("name").is_none()));
        match &e.report.values["vars_lenient"] {
            ValueOrigin::List(origins) => assert_eq!(origins.len(), items.len()),
            other => panic!("{other:?}"),
        }
    }

    // BOX-183: a loadout that gives a set name another resolved value fails
    // the expansion with exit 3, naming the variable, both sources and the
    // policy remedy.
    #[test]
    fn conflicting_loadout_var_refused_exit3() {
        let file = r#"
            [defaults]
            vars = { D = "defaults" }
            [sessions.dev]
            loadout_mode = "open"
            vars = { A = "entry", I = { inherit = true } }
        "#;
        let conflict = |name: &str, first: &str, second: &str| {
            format!(
                "The variable `{name}` has two different values. {first} sets one \
                 value, and {second} sets the other. A loadout cannot change a \
                 variable that is already set. Remove `{name}` from one of them, \
                 or add `{name}` to the `ignore` list under `[vars]` in \
                 user_policy.toml to drop every value of `{name}`."
            )
        };
        let cases = [
            (
                "a literal against the entry",
                "vars = { A = \"loadout\" }",
                vec![],
                conflict(
                    "A",
                    "`[sessions.dev]` in minimal.toml",
                    "a selected loadout",
                ),
            ),
            (
                "a lenient item against [defaults]",
                "vars_lenient = [{ name = \"D\", value = \"loadout\" }]",
                vec![],
                conflict("D", "`[defaults]` in minimal.toml", "a selected loadout"),
            ),
            (
                "a literal against the entry's resolved inherit",
                "vars = { I = \"loadout\" }",
                vec![("I", "host")],
                conflict(
                    "I",
                    "`[sessions.dev]` in minimal.toml",
                    "a selected loadout",
                ),
            ),
            (
                "an inherit that resolves to another value",
                "vars = { A = { inherit = true } }",
                vec![("A", "host")],
                conflict(
                    "A",
                    "`[sessions.dev]` in minimal.toml",
                    "a selected loadout",
                ),
            ),
            (
                "two loadouts",
                "vars = { N = \"one\" }\nvars_lenient = [{ name = \"N\", value = \"two\" }]",
                vec![],
                conflict("N", "a selected loadout", "another selected loadout"),
            ),
        ];
        for (what, loadouts, host, msg) in cases {
            let err = expand_in(file, "dev", vars_layers(loadouts, &host)).expect_err(what);
            assert!(
                matches!(err, Error::LoadoutVarConflict { .. }),
                "{what}: {err:?}"
            );
            assert_eq!(err.exit_code(), Some(3), "{what}");
            assert_eq!(err.to_string(), msg, "{what}");
        }
        // The same values pass, and a sealed entry checks nothing.
        expand_in(
            file,
            "dev",
            vars_layers("vars = { I = \"host\" }", &[("I", "host")]),
        )
        .expect("the same resolved value is one variable");
        let sealed = file.replace("\"open\"", "\"sealed\"");
        expand_in(
            &sealed,
            "dev",
            vars_layers("vars = { A = \"loadout\" }", &[]),
        )
        .expect("a sealed entry takes no loadout");
    }

    // BOX-184: one layer that sets a name twice, in `vars_lenient` or in
    // both tables, to different values fails with exit 3, naming the
    // variable and the layer. The same value twice is one variable.
    #[test]
    fn duplicate_var_in_one_layer_refused_exit3() {
        let cases = [
            (
                "both tables of the entry",
                "[sessions.dev]\nvars = { A = \"1\" }\nvars_lenient = [{ name = \"A\", value = \"2\" }]\n",
                "A",
                "`[sessions.dev]` in minimal.toml",
            ),
            (
                "vars_lenient of [defaults]",
                "[defaults]\nvars_lenient = [{ name = \"my.var\", value = \"1\" }, { name = \"my.var\", value = \"2\" }]\n[sessions.dev]\n",
                "my.var",
                "`[defaults]` in minimal.toml",
            ),
            (
                "an inherit and a literal in [defaults.session]",
                "[defaults.session]\nvars = { H = { inherit = true } }\nvars_lenient = [{ name = \"H\", value = \"literal\" }]\n[sessions.dev]\n",
                "H",
                "`[defaults.session]` in minimal.toml",
            ),
        ];
        for (what, file, name, layer) in cases {
            let err = expand_in(file, "dev", vars_layers("", &[("H", "host")])).expect_err(what);
            assert!(matches!(err, Error::DuplicateVar { .. }), "{what}: {err:?}");
            assert_eq!(err.exit_code(), Some(3), "{what}");
            assert_eq!(
                err.to_string(),
                format!(
                    "{layer} sets the variable `{name}` twice, to different values. \
                     Remove one of the two settings."
                ),
                "{what}"
            );
        }
        // The same resolved value twice is one variable, kept once.
        let file = "[sessions.dev]\nvars = { A = \"1\", H = { inherit = true } }\n\
                    vars_lenient = [{ name = \"A\", value = \"1\" }, { name = \"H\", value = \"host\" }]\n";
        let e = expand_in(file, "dev", vars_layers("", &[("H", "host")])).expect("one variable");
        assert_eq!(e.spec["vars"]["A"].as_str(), Some("1"));
        assert!(lenient(&e.spec).is_empty(), "{:?}", e.spec);
    }

    /// Expands the entry `name` of `file` over its type chain, with the
    /// client's `store_rules` and the command-line `overrides`, and gives
    /// the expansion and its projection digest.
    fn expand_projected(
        file: &str,
        name: &str,
        overrides: &str,
        store_rules: BTreeMap<String, StoreRule>,
    ) -> (Expansion, String) {
        let doc = table(file);
        let types = BoxTypes::from_file(&doc).expect("the types resolve");
        let entries = read_entries(file.as_bytes()).expect("entries read");
        let entry = entries
            .iter()
            .find(|e| e.name == name)
            .unwrap_or_else(|| panic!("entry {name} read"));
        let resolved = expandable_type(entry, &types).expect("expandable");
        let project_types = types.project().keys().cloned().collect();
        let defaults = doc
            .get("defaults")
            .and_then(toml::Value::as_table)
            .cloned()
            .unwrap_or_default();
        let layers = Layers {
            type_defaults: resolved.defaults.clone(),
            overrides: table(overrides),
            store_rules,
            ..Layers::default()
        }
        .with_file_defaults(&defaults, entry.box_type.as_deref(), &project_types);
        let expansion = expand(entry, &layers).expect("expands");
        let digest = expansion.projection(&resolved).digest();
        (expansion, digest)
    }

    fn npm_rule(hosts: &[&str]) -> BTreeMap<String, StoreRule> {
        BTreeMap::from([(
            "npm-token".to_owned(),
            StoreRule {
                upstream: hosts.iter().map(|h| (*h).to_owned()).collect(),
                inject: table("header = \"Authorization\"\nprefix = \"Bearer \"\n"),
            },
        )])
    }

    const STORE_FILE: &str = r#"
        [sessions.dev.secrets.NPM]
        source = "store"
        store = "keychain"
        id = "npm-token"
        upstream = { hosts = ["project.example"] }

        [sessions.dev.secrets.OTHER]
        source = "store"
        store = "keychain"
        id = "no-rule"
        inject = { header = "X-Project" }

        [sessions.dev.secret-store-rules.npm-token]
        upstream = ["project.example"]
    "#;

    // BOX-071: expansion writes each store reference's `upstream` and
    // `inject` from the client's `[secret-store-rules]`, never from the
    // project file, so the projection's `secret_grants` carry them.
    #[test]
    fn store_reference_upstream_and_inject_written_into_spec() {
        let (e, digest) =
            expand_projected(STORE_FILE, "dev", "", npm_rule(&["registry.npmjs.org"]));
        let npm = e.spec["secrets"]["NPM"].as_table().expect("the reference");
        assert_eq!(
            npm["upstream"],
            toml::Value::Table(table("hosts = [\"registry.npmjs.org\"]")),
            "the client's rule, not the project's value"
        );
        assert_eq!(
            npm["inject"],
            toml::Value::Table(table("header = \"Authorization\"\nprefix = \"Bearer \"\n"))
        );
        assert_eq!(npm["id"].as_str(), Some("npm-token"));
        let other = e.spec["secrets"]["OTHER"]
            .as_table()
            .expect("the reference");
        assert!(other.get("upstream").is_none(), "{other:?}");
        assert!(
            other.get("inject").is_none(),
            "the project never sets it: {other:?}"
        );
        assert!(e.spec.get("secret-store-rules").is_none());

        // The digest binds where the secret is sent.
        let (_, moved) = expand_projected(STORE_FILE, "dev", "", npm_rule(&["evil.example"]));
        assert_ne!(digest, moved);
        let (_, again) = expand_projected(STORE_FILE, "dev", "", npm_rule(&["registry.npmjs.org"]));
        assert_eq!(digest, again);
    }

    const GRANTS_FILE: &str = r#"
        [box_types.release]
        extends = "task"
        defaults = { github_token_mode = "installation" }

        [sessions.dev.secrets.GH]
        source = "broker"
        scopes = ["github:repo:read"]

        [sessions.dev.secrets.API]
        source = "client_env"

        [tasks.lint.secrets.GH]
        source = "broker"
        scopes = ["github:repo:read"]

        [boxes.ship]
        type = "release"
        [boxes.ship.secrets.GH]
        source = "broker"
        scopes = ["github:repo:write"]

        [sessions.set]
        [sessions.set.network]
        quic443 = "block"
        [sessions.set.network.bep]
        steering = "proxy_env"
        [sessions.set.secrets.GH]
        source = "broker"
        scopes = ["github:repo:read"]
        mode = "installation"
    "#;

    // BOX-071: expansion fills each `github:*` grant's omitted `mode` from
    // the type's `github_token_mode`, an omitted `network.quic443` with
    // `auto` and an omitted `bep.steering` with `dns`, so the digest binds
    // the effective values. A value the spec sets is kept.
    #[test]
    fn expansion_fills_token_mode_quic443_steering_before_digest() {
        let mode = |e: &Expansion, name: &str| {
            e.spec["secrets"][name]
                .get("mode")
                .and_then(toml::Value::as_str)
                .map(str::to_owned)
        };
        let (dev, dev_digest) = expand_projected(GRANTS_FILE, "dev", "", BTreeMap::new());
        assert_eq!(mode(&dev, "GH").as_deref(), Some("user"));
        assert_eq!(mode(&dev, "API"), None, "not a GitHub grant");
        assert_eq!(dev.spec["network"]["quic443"].as_str(), Some("auto"));
        assert_eq!(dev.spec["network"]["bep"]["steering"].as_str(), Some("dns"));
        let (lint, _) = expand_projected(GRANTS_FILE, "lint", "", BTreeMap::new());
        assert_eq!(mode(&lint, "GH").as_deref(), Some("user"));
        let (ship, _) = expand_projected(GRANTS_FILE, "ship", "", BTreeMap::new());
        assert_eq!(mode(&ship, "GH").as_deref(), Some("installation"));
        let (set, _) = expand_projected(GRANTS_FILE, "set", "", BTreeMap::new());
        assert_eq!(mode(&set, "GH").as_deref(), Some("installation"));
        assert_eq!(set.spec["network"]["quic443"].as_str(), Some("block"));
        assert_eq!(
            set.spec["network"]["bep"]["steering"].as_str(),
            Some("proxy_env")
        );

        // Writing the filled values out projects the same digest, and
        // another value projects another one.
        let explicit = GRANTS_FILE.replace(
            "[sessions.dev.secrets.API]",
            "[sessions.dev.network]\nquic443 = \"auto\"\nbep = { steering = \"dns\" }\n\
             [sessions.dev.secrets.API]",
        );
        let explicit = explicit.replacen(
            "scopes = [\"github:repo:read\"]\n",
            "scopes = [\"github:repo:read\"]\nmode = \"user\"\n",
            1,
        );
        let (_, explicit_digest) = expand_projected(&explicit, "dev", "", BTreeMap::new());
        assert_eq!(dev_digest, explicit_digest);
        let (_, other) = expand_projected(
            GRANTS_FILE,
            "dev",
            "network = { quic443 = \"allow\" }",
            BTreeMap::new(),
        );
        assert_ne!(dev_digest, other);
    }

    /// The host facts a client can create a box under.
    #[derive(Debug, Clone, Copy)]
    enum HostFacts {
        Unenrolled,
        Enrolled,
    }

    /// The layers a client builds for the entry `dev` of `file`. Every
    /// input of expansion is named here, with no `..Layers::default()`, so
    /// an input that varies with `facts` cannot be added unseen: none
    /// does (BOX-142).
    fn client_layers(
        facts: HostFacts,
        file: &str,
        overrides: &str,
        store_rules: &BTreeMap<String, StoreRule>,
    ) -> Layers {
        let _ = facts;
        let doc = table(file);
        let defaults = doc
            .get("defaults")
            .and_then(toml::Value::as_table)
            .cloned()
            .unwrap_or_default();
        Layers {
            upstream: doc
                .get("upstream")
                .and_then(toml::Value::as_table)
                .cloned()
                .unwrap_or_default(),
            type_defaults: vec![(
                "session".to_owned(),
                crate::box_types::builtin_defaults("session"),
            )],
            defaults: toml::Table::new(),
            defaults_type: toml::Table::new(),
            loadouts: toml::Table::new(),
            overrides: table(overrides),
            host_vars: BTreeMap::new(),
            store_rules: store_rules.clone(),
        }
        .with_file_defaults(&defaults, Some("session"), &BTreeSet::new())
    }

    proptest! {
        // BOX-142 (property): one minimal.toml, one set of overrides and
        // one set of client store rules expand to the same spec bytes and
        // projection digest whether the host is enrolled or not.
        #[test]
        fn enrolled_and_unenrolled_expansion_identical(
            packages in proptest::collection::vec("[a-z]{1,6}", 0..4),
            quic in proptest::option::of(prop_oneof!["auto", "block", "allow"]),
            mode in proptest::option::of(prop_oneof!["none", "host_ip", "own_ip"]),
            hosts in proptest::collection::vec("[a-z]{1,6}\\.example", 0..3),
            pinned in any::<bool>(),
        ) {
            let quoted: Vec<String> = packages.iter().map(|p| format!("\"{p}\"")).collect();
            let mut file = String::new();
            if pinned {
                file.push_str("[upstream]\nrepo_url = \"https://r.example\"\ncommit = \"abc\"\n");
            }
            file.push_str(&format!(
                "[sessions.dev]\ntype = \"session\"\npackages = [{}]\n\
                 [sessions.dev.secrets.NPM]\nsource = \"store\"\nstore = \"keychain\"\n\
                 id = \"npm-token\"\n\
                 [sessions.dev.secrets.GH]\nsource = \"broker\"\nscopes = [\"github:repo\"]\n",
                quoted.join(", ")
            ));
            let mut overrides = String::new();
            if mode.is_some() || quic.is_some() {
                overrides.push_str("[network]\n");
            }
            if let Some(mode) = &mode {
                overrides.push_str(&format!("mode = \"{mode}\"\n"));
            }
            if let Some(quic) = &quic {
                overrides.push_str(&format!("quic443 = \"{quic}\"\n"));
            }
            let host_refs: Vec<&str> = hosts.iter().map(String::as_str).collect();
            let rules = npm_rule(&host_refs);
            let entries = read_entries(file.as_bytes()).expect("entries read");
            let entry = entries.iter().find(|e| e.name == "dev").expect("dev");
            let resolved = expandable_type(entry, &BoxTypes::from_file(&table(&file)).unwrap())
                .expect("a session expands");
            let run = |facts| {
                let layers = client_layers(facts, &file, &overrides, &rules);
                let e = expand(entry, &layers).expect("expands");
                (e.spec_bytes().expect("writes"), e.projection(&resolved).digest())
            };
            prop_assert_eq!(run(HostFacts::Unenrolled), run(HostFacts::Enrolled));
        }
    }
}
