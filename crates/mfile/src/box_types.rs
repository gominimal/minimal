//! Box Types: the built-in types and the project's `[box_types.<name>]`.
//!
//! A project type names its parent with `extends`, and can carry
//! `defaults` and `constraints` tables. Every project type resolves,
//! through its chain of `extends`, to one built-in type: its built-in root
//! (BOX-059). [`BoxTypes::from_file`] resolves every project type of a file
//! at once, so a file with a broken type fails as a whole.
//!
//! A project type fails with [`BoxTypeError`], which exits 3 and names the
//! type, when it has no `extends`, when its chain forms a cycle, when its
//! chain names a type that does not exist, or when it takes a built-in
//! name. A redefinition names both definitions.
//!
//! A type's `constraints` only narrow. Each key of the table holds a value
//! the spec's key must take: a list admits each of its items, a table
//! constrains each of its own keys, and any other value admits itself. A
//! derived type whose constraint admits a value that its parent type's
//! constraint excludes fails with exit 3 (BOX-156). A constraint is a
//! check, never a layer: it sets nothing in a spec, so it never adds a
//! package, a port or an egress entry (BOX-062).

use std::collections::BTreeMap;
use std::fmt;

use crate::entry::BoxEntry;
use crate::error::EntryHeader;

/// The top-level table that declares the project's Box Types.
pub const BOX_TYPES_TABLE: &str = "box_types";

/// The built-in Box Types. Each one is its own built-in root.
pub const BUILTIN_BOX_TYPES: [&str; 6] = [
    "session",
    "task",
    "agent",
    "service",
    "build",
    "container-build",
];

/// The built-in type named `name`, as a static string.
#[must_use]
pub fn builtin(name: &str) -> Option<&'static str> {
    BUILTIN_BOX_TYPES.into_iter().find(|b| *b == name)
}

/// One `[box_types.<name>]` of the project file.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProjectType {
    /// The type this one extends: a built-in or another project type.
    pub extends: String,
    /// The type's `defaults` table. Empty when the file sets none.
    pub defaults: toml::Table,
    /// The type's `constraints` table. Empty when the file sets none.
    pub constraints: toml::Table,
}

/// A Box Type resolved to its built-in root.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedType {
    /// The type's name.
    pub name: String,
    /// The built-in type at the end of the type's `extends` chain.
    pub root: &'static str,
    /// Every type of the chain, the built-in root first and the type last,
    /// each with its `defaults`. A built-in type sets no defaults here.
    /// This is the order of [`crate::expand::Layers::type_defaults`].
    pub defaults: Vec<(String, toml::Table)>,
    /// Every type of the chain, the built-in root first and the type last,
    /// each with its `constraints`.
    pub constraints: Vec<(String, toml::Table)>,
}

/// The Box Types of one project file, each checked to resolve to a
/// built-in root.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BoxTypes {
    project: BTreeMap<String, ProjectType>,
}

/// Why a Box Type does not resolve, or why an entry's type cannot be used.
/// Every case exits 3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoxTypeError {
    /// `[box_types]` or `[box_types.<name>]` is not a table. Carries the
    /// type name, or `None` for `[box_types]` itself.
    NotATable(Option<String>),
    /// A key of `[box_types.<name>]` has the wrong shape. Carries the type,
    /// the key, and what the key takes.
    WrongShape {
        name: String,
        key: &'static str,
        expected: &'static str,
    },
    /// A project type has no `extends`.
    MissingExtends(String),
    /// A project type takes the name of a built-in type.
    Redefinition(String),
    /// A project type's chain reaches a type that is neither built in nor
    /// in `[box_types]`. Carries the type that names it, and the name.
    UnknownExtends { name: String, extends: String },
    /// A chain of `extends` returns to a type. Carries the types of the
    /// cycle, in chain order, the first one repeated at the end.
    Cycle(Vec<String>),
    /// An entry's `type` is neither built in nor in `[box_types]`.
    UnknownType {
        table: &'static str,
        entry: String,
        box_type: String,
    },
    /// A `[boxes.<name>]` entry sets no `type`.
    NoType { table: &'static str, entry: String },
    /// An entry's type, or its type's built-in root, is one this release
    /// does not create (BOX-063). Carries the entry, its type and the root.
    Unsupported {
        table: &'static str,
        entry: String,
        box_type: String,
        root: &'static str,
    },
    /// A derived type's constraint admits a value that its parent type's
    /// constraint on the same key excludes (BOX-156). Carries the type,
    /// the key path, the parent, and the value when one value shows it.
    Loosening {
        name: String,
        key: String,
        parent: String,
        value: Option<String>,
    },
    /// An expanded spec carries a value that its type's constraints
    /// exclude (BOX-061). Carries the type, the key path, the value, the
    /// values the type allows and the layer that set the value, each as
    /// the message names it, and whether the value is a list item.
    ConstraintBroken {
        box_type: String,
        key: String,
        value: String,
        allowed: String,
        layer: String,
        item: bool,
    },
}

/// A Box Type as a message names it: its table for a project type.
struct TypeWords<'a>(&'a str);

impl fmt::Display for TypeWords<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if builtin(self.0).is_some() {
            write!(f, "the built-in type `{}`", self.0)
        } else {
            write!(f, "`[{BOX_TYPES_TABLE}.{}]`", self.0)
        }
    }
}

impl BoxTypeError {
    /// The exit code a command ends with on this error: 3, a configuration
    /// error.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        3
    }
}

/// The issue that tracks the box types this release does not create.
pub const UNSUPPORTED_TYPES_ISSUE: &str = "gominimal/inbox#678";

impl fmt::Display for BoxTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BoxTypeError::NotATable(None) => {
                write!(f, "`[{BOX_TYPES_TABLE}]` in minimal.toml is not a table.")
            }
            BoxTypeError::NotATable(Some(name)) => write!(
                f,
                "`{BOX_TYPES_TABLE}.{name}` in minimal.toml is not a table. \
                 Write it as `[{BOX_TYPES_TABLE}.{name}]` with an `extends` key."
            ),
            BoxTypeError::WrongShape {
                name,
                key,
                expected,
            } => write!(
                f,
                "`{key}` in `[{BOX_TYPES_TABLE}.{name}]` is not {expected}."
            ),
            BoxTypeError::MissingExtends(name) => write!(
                f,
                "`[{BOX_TYPES_TABLE}.{name}]` has no `extends`. \
                 Set `extends` to `session`, `task` or another type in `[{BOX_TYPES_TABLE}]`."
            ),
            BoxTypeError::Redefinition(name) => write!(
                f,
                "`[{BOX_TYPES_TABLE}.{name}]` has the name of the built-in type `{name}`. \
                 A project type cannot replace a built-in type. \
                 Rename `[{BOX_TYPES_TABLE}.{name}]` and set `extends = \"{name}\"` in it."
            ),
            BoxTypeError::UnknownExtends { name, extends } => write!(
                f,
                "`[{BOX_TYPES_TABLE}.{name}]` extends `{extends}`, \
                 which is not a built-in type and not in `[{BOX_TYPES_TABLE}]`."
            ),
            BoxTypeError::Cycle(cycle) => {
                let first = cycle.first().map(String::as_str).unwrap_or_default();
                write!(
                    f,
                    "`[{BOX_TYPES_TABLE}.{first}]` extends itself through {}. \
                     Change one `extends` so that the chain ends at a built-in type.",
                    cycle
                        .iter()
                        .map(|t| format!("`{t}`"))
                        .collect::<Vec<_>>()
                        .join(" -> ")
                )
            }
            BoxTypeError::UnknownType {
                table,
                entry,
                box_type,
            } => write!(
                f,
                "`{}` has the type `{box_type}`, \
                 which is not a built-in type and not in `[{BOX_TYPES_TABLE}]`.",
                EntryHeader(table, entry)
            ),
            BoxTypeError::NoType { table, entry } => write!(
                f,
                "`{}` sets no `type`. \
                 Set `type` to `session`, `task` or a type in `[{BOX_TYPES_TABLE}]`.",
                EntryHeader(table, entry)
            ),
            BoxTypeError::Unsupported {
                table,
                entry,
                box_type,
                root,
            } => {
                write!(
                    f,
                    "`{}` has the type `{box_type}`",
                    EntryHeader(table, entry)
                )?;
                if box_type != root {
                    write!(f, ", which extends `{root}`")?;
                }
                write!(
                    f,
                    ". This release cannot create a box of type `{root}`. \
                     {UNSUPPORTED_TYPES_ISSUE} tracks it. \
                     The other entries of minimal.toml are not affected."
                )
            }
            BoxTypeError::Loosening {
                name,
                key,
                parent,
                value,
            } => {
                match value {
                    Some(value) => write!(
                        f,
                        "`[{BOX_TYPES_TABLE}.{name}]` allows `{value}` for `{key}` \
                         in `constraints`, but its parent type {} does not.",
                        TypeWords(parent)
                    )?,
                    None => write!(
                        f,
                        "`[{BOX_TYPES_TABLE}.{name}]` allows values for `{key}` \
                         in `constraints` that its parent type {} does not allow.",
                        TypeWords(parent)
                    )?,
                }
                write!(
                    f,
                    " A type can only narrow the constraints of the type it extends. \
                     Change `{key}` in the `constraints` of `[{BOX_TYPES_TABLE}.{name}]`."
                )
            }
            BoxTypeError::ConstraintBroken {
                box_type,
                key,
                value,
                allowed,
                layer,
                item,
            } => {
                let verb = if *item { "adds" } else { "sets" };
                let (first, second) = if *item {
                    (format!("`{value}`"), format!("`{key}`"))
                } else {
                    (format!("`{key}`"), format!("`{value}`"))
                };
                let mut words = TypeWords(box_type).to_string();
                if let Some(first) = words.get_mut(..1) {
                    first.make_ascii_uppercase();
                }
                write!(
                    f,
                    "{layer} {verb} {first} to {second}. \
                     {words} allows {allowed} {} `{key}`. Change the value.",
                    if *item { "in" } else { "for" }
                )
            }
        }
    }
}

impl std::error::Error for BoxTypeError {}

impl BoxTypes {
    /// Reads the `[box_types]` table of a parsed `minimal.toml`, and
    /// resolves every project type to its built-in root. A file without
    /// `[box_types]` has only the built-in types.
    ///
    /// # Errors
    ///
    /// A [`BoxTypeError`] for the first project type, in name order, that
    /// has the wrong shape, takes a built-in name, has no `extends`, or
    /// does not reach a built-in root.
    pub fn from_file(doc: &toml::Table) -> Result<Self, BoxTypeError> {
        let Some(value) = doc.get(BOX_TYPES_TABLE) else {
            return Ok(Self::default());
        };
        let table = value.as_table().ok_or(BoxTypeError::NotATable(None))?;
        let mut project = BTreeMap::new();
        for (name, value) in table {
            project.insert(name.clone(), read_type(name, value)?);
        }
        let types = Self { project };
        for name in types.project.keys() {
            types.resolve(name)?;
        }
        Ok(types)
    }

    /// The project types, by name.
    #[must_use]
    pub fn project(&self) -> &BTreeMap<String, ProjectType> {
        &self.project
    }

    /// Whether `name` is a built-in type or a project type.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        builtin(name).is_some() || self.project.contains_key(name)
    }

    /// The built-in root of `name`, or `None` when no type has that name.
    #[must_use]
    pub fn root(&self, name: &str) -> Option<&'static str> {
        self.resolve(name).ok().map(|r| r.root)
    }

    /// Resolves `name` through its `extends` chain to its built-in root.
    ///
    /// # Errors
    ///
    /// [`BoxTypeError::UnknownExtends`] when the chain names a type that
    /// does not exist, and [`BoxTypeError::Cycle`] when it returns to a
    /// type. A name that is no type fails with
    /// [`BoxTypeError::UnknownExtends`] naming itself.
    pub fn resolve(&self, name: &str) -> Result<ResolvedType, BoxTypeError> {
        let mut chain: Vec<&str> = Vec::new();
        let mut current = name;
        let root = loop {
            if let Some(root) = builtin(current) {
                break root;
            }
            if let Some(at) = chain.iter().position(|t| *t == current) {
                let mut cycle: Vec<String> = chain[at..].iter().map(|t| (*t).to_owned()).collect();
                cycle.push(current.to_owned());
                return Err(BoxTypeError::Cycle(cycle));
            }
            let Some(project) = self.project.get(current) else {
                return Err(BoxTypeError::UnknownExtends {
                    name: chain.last().copied().unwrap_or(name).to_owned(),
                    extends: current.to_owned(),
                });
            };
            chain.push(current);
            current = &project.extends;
        };
        let mut defaults = vec![(root.to_owned(), toml::Table::new())];
        let mut constraints = vec![(root.to_owned(), toml::Table::new())];
        for t in chain.iter().rev() {
            let project = &self.project[*t];
            defaults.push(((*t).to_owned(), project.defaults.clone()));
            constraints.push(((*t).to_owned(), project.constraints.clone()));
        }
        check_narrowing(&constraints)?;
        Ok(ResolvedType {
            name: name.to_owned(),
            root,
            defaults,
            constraints,
        })
    }

    /// Resolves the type of `entry`.
    ///
    /// # Errors
    ///
    /// [`BoxTypeError::NoType`] for an entry with no type, and
    /// [`BoxTypeError::UnknownType`] for a type that is not built in and
    /// not in `[box_types]`.
    pub fn resolve_entry(&self, entry: &BoxEntry) -> Result<ResolvedType, BoxTypeError> {
        let table = entry.table.key();
        let Some(box_type) = entry.box_type.as_deref() else {
            return Err(BoxTypeError::NoType {
                table,
                entry: entry.name.clone(),
            });
        };
        if !self.contains(box_type) {
            return Err(BoxTypeError::UnknownType {
                table,
                entry: entry.name.clone(),
                box_type: box_type.to_owned(),
            });
        }
        self.resolve(box_type)
    }
}

/// Checks that each type of a chain, root first, only narrows the
/// constraints of the type before it (BOX-156).
fn check_narrowing(chain: &[(String, toml::Table)]) -> Result<(), BoxTypeError> {
    // The resolved constraint of each key: the last one the chain set. Each
    // one is checked to admit no more than the one before it, so the last
    // one admits no more than any of them.
    let mut resolved: BTreeMap<&str, &toml::Value> = BTreeMap::new();
    for (i, (name, table)) in chain.iter().enumerate() {
        for (key, derived) in table {
            if let Some(parent) = resolved.get(key.as_str())
                && let Some((key, value)) = loosening(key, derived, parent)
            {
                return Err(BoxTypeError::Loosening {
                    name: name.clone(),
                    key,
                    parent: chain[i.saturating_sub(1)].0.clone(),
                    value: value.map(|v| inline(&v)),
                });
            }
            resolved.insert(key, derived);
        }
    }
    Ok(())
}

/// The values a constraint that is not a table admits: a list's items, or
/// the value itself.
pub(crate) fn admitted(constraint: &toml::Value) -> &[toml::Value] {
    match constraint {
        toml::Value::Array(items) => items,
        other => std::slice::from_ref(other),
    }
}

/// Where `derived` admits a value that `parent` excludes: the key path
/// under `path`, and a value that shows it when one does. `None` when
/// `derived` admits no more than `parent`.
fn loosening(
    path: &str,
    derived: &toml::Value,
    parent: &toml::Value,
) -> Option<(String, Option<toml::Value>)> {
    match (derived, parent) {
        (toml::Value::Table(d), toml::Value::Table(p)) => p.iter().find_map(|(k, pv)| {
            let sub = format!("{path}.{k}");
            match d.get(k) {
                None => Some((sub, None)),
                Some(dv) => loosening(&sub, dv, pv),
            }
        }),
        // A table admits tables without end. A list of values does not hold
        // them all.
        (toml::Value::Table(_), _) => Some((path.to_owned(), None)),
        (_, parent) => admitted(derived)
            .iter()
            .find(|v| excluded(path, parent, v).is_some())
            .map(|v| (path.to_owned(), Some(v.clone()))),
    }
}

/// The part of a spec value that a constraint excludes.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Excluded {
    /// The key path of the excluded value.
    pub key: String,
    /// The excluded value, or the excluded item of a list.
    pub value: toml::Value,
    /// For a list item, its index in the list.
    pub item: Option<usize>,
    /// The constraint that excludes it.
    pub constraint: toml::Value,
}

/// The first part of `value`, at key path `path`, that `constraint` does
/// not admit. A table constrains only the keys it names, and only where
/// the value sets them. A list value is checked item by item.
pub(crate) fn excluded(
    path: &str,
    constraint: &toml::Value,
    value: &toml::Value,
) -> Option<Excluded> {
    let exclude = |value: &toml::Value, item| Excluded {
        key: path.to_owned(),
        value: value.clone(),
        item,
        constraint: constraint.clone(),
    };
    match (constraint, value) {
        (toml::Value::Table(c), toml::Value::Table(v)) => c.iter().find_map(|(k, cv)| {
            v.get(k)
                .and_then(|vv| excluded(&format!("{path}.{k}"), cv, vv))
        }),
        (toml::Value::Table(_), _) => Some(exclude(value, None)),
        (_, toml::Value::Array(items)) => {
            let allowed = admitted(constraint);
            items
                .iter()
                .position(|item| !allowed.contains(item))
                .map(|i| exclude(&items[i], Some(i)))
        }
        (_, _) => (!admitted(constraint).contains(value)).then(|| exclude(value, None)),
    }
}

/// A TOML value as one line, the way minimal.toml writes it inline.
pub(crate) fn inline(value: &toml::Value) -> String {
    value.to_string()
}

/// The values a constraint allows, as a message names them.
pub(crate) fn allowed_words(constraint: &toml::Value) -> String {
    if constraint.is_table() {
        return "only a table".to_owned();
    }
    let values: Vec<String> = admitted(constraint)
        .iter()
        .map(|v| format!("`{}`", inline(v)))
        .collect();
    match values.as_slice() {
        [] => "no value".to_owned(),
        [one] => format!("only {one}"),
        [rest @ .., last] => format!("only {} or {last}", rest.join(", ")),
    }
}

/// Reads one `[box_types.<name>]` table.
fn read_type(name: &str, value: &toml::Value) -> Result<ProjectType, BoxTypeError> {
    if builtin(name).is_some() {
        return Err(BoxTypeError::Redefinition(name.to_owned()));
    }
    let table = value
        .as_table()
        .ok_or_else(|| BoxTypeError::NotATable(Some(name.to_owned())))?;
    let extends = match table.get("extends") {
        None => return Err(BoxTypeError::MissingExtends(name.to_owned())),
        Some(toml::Value::String(s)) => s.clone(),
        Some(_) => {
            return Err(BoxTypeError::WrongShape {
                name: name.to_owned(),
                key: "extends",
                expected: "a string",
            });
        }
    };
    let sub_table = |key: &'static str| match table.get(key) {
        None => Ok(toml::Table::new()),
        Some(toml::Value::Table(t)) => Ok(t.clone()),
        Some(_) => Err(BoxTypeError::WrongShape {
            name: name.to_owned(),
            key,
            expected: "a table",
        }),
    };
    Ok(ProjectType {
        extends,
        defaults: sub_table("defaults")?,
        constraints: sub_table("constraints")?,
    })
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn types(src: &str) -> Result<BoxTypes, BoxTypeError> {
        BoxTypes::from_file(&toml::from_str(src).expect("TOML"))
    }

    // BOX-059: a project type resolves through `extends` to a built-in
    // root, with the defaults and constraints of its chain, root first.
    #[test]
    fn box_type_resolves_to_builtin_root() {
        let t = types(
            r#"
            [box_types.ci]
            extends = "task"
            defaults = { timeout = "10m", packages = ["git"] }
            constraints = { pty_enabled = false }

            [box_types.ci-rust]
            extends = "ci"
            defaults = { packages = ["rust"] }

            [box_types.dev]
            extends = "session"
            "#,
        )
        .expect("the types resolve");

        let r = t.resolve("ci-rust").expect("resolves");
        assert_eq!(r.root, "task");
        assert_eq!(r.name, "ci-rust");
        let names: Vec<&str> = r.defaults.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["task", "ci", "ci-rust"]);
        assert_eq!(r.defaults[1].1["timeout"].as_str(), Some("10m"));
        assert!(r.defaults[0].1.is_empty());
        let names: Vec<&str> = r.constraints.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["task", "ci", "ci-rust"]);
        assert_eq!(r.constraints[1].1["pty_enabled"].as_bool(), Some(false));

        assert_eq!(t.root("ci"), Some("task"));
        assert_eq!(t.root("dev"), Some("session"));
        assert_eq!(t.root("nope"), None);
        // Each built-in type is its own root, with or without a project file.
        for b in BUILTIN_BOX_TYPES {
            assert_eq!(t.root(b), Some(b));
            assert_eq!(BoxTypes::default().root(b), Some(b));
        }
        // A file with no `[box_types]` has only the built-in types.
        assert!(types("").expect("resolves").project().is_empty());
    }

    /// A type graph whose chains all end at a built-in: type `t<i>` extends
    /// either a built-in or a type with a lower index.
    fn acyclic_graph() -> impl Strategy<Value = Vec<(usize, Option<usize>)>> {
        prop::collection::vec(
            (0..BUILTIN_BOX_TYPES.len(), any::<prop::sample::Index>()),
            1..12,
        )
        .prop_map(|raw| {
            raw.into_iter()
                .enumerate()
                .map(|(i, (b, pick))| {
                    // About half the types extend an earlier type.
                    let parent = (i > 0 && pick.index(2) == 0).then(|| pick.index(i));
                    (b, parent)
                })
                .collect()
        })
    }

    fn graph_toml(graph: &[(usize, Option<usize>)]) -> String {
        let mut src = String::new();
        for (i, (b, parent)) in graph.iter().enumerate() {
            let extends = parent.map_or(BUILTIN_BOX_TYPES[*b].to_owned(), |p| format!("t{p}"));
            src.push_str(&format!("[box_types.t{i}]\nextends = \"{extends}\"\n"));
        }
        src
    }

    proptest! {
        // BOX-059 property: for every type graph whose chains end at a
        // built-in, resolution yields that built-in as the root.
        #[test]
        fn box_type_resolves_to_builtin_root_property(graph in acyclic_graph()) {
            let t = types(&graph_toml(&graph)).expect("the types resolve");
            for i in 0..graph.len() {
                let mut at = i;
                while let Some(p) = graph[at].1 {
                    at = p;
                }
                let expected = BUILTIN_BOX_TYPES[graph[at].0];
                let r = t.resolve(&format!("t{i}")).expect("resolves");
                prop_assert_eq!(r.root, expected);
                prop_assert_eq!(r.defaults.first().map(|(n, _)| n.as_str()), Some(expected));
                prop_assert_eq!(r.defaults.last().map(|(n, _)| n.clone()), Some(format!("t{i}")));
            }
        }
    }

    // BOX-059: a type without `extends`, a cycle, or a built-in name fails
    // with exit 3 naming the type, and a redefinition names both
    // definitions.
    #[test]
    fn box_type_missing_extends_cycle_or_redefinition_exit3() {
        let err = types("[box_types.ci]\ndefaults = { timeout = \"1m\" }\n").expect_err("fails");
        assert_eq!(err, BoxTypeError::MissingExtends("ci".to_owned()));
        assert_eq!(err.exit_code(), 3);
        assert_eq!(
            err.to_string(),
            "`[box_types.ci]` has no `extends`. \
             Set `extends` to `session`, `task` or another type in `[box_types]`."
        );

        let err = types(
            "[box_types.a]\nextends = \"b\"\n[box_types.b]\nextends = \"c\"\n\
             [box_types.c]\nextends = \"a\"\n",
        )
        .expect_err("fails");
        assert_eq!(err.exit_code(), 3);
        assert_eq!(
            err.to_string(),
            "`[box_types.a]` extends itself through `a` -> `b` -> `c` -> `a`. \
             Change one `extends` so that the chain ends at a built-in type."
        );
        let err = types("[box_types.me]\nextends = \"me\"\n").expect_err("fails");
        assert_eq!(err, BoxTypeError::Cycle(vec!["me".into(), "me".into()]));

        for b in BUILTIN_BOX_TYPES {
            let err =
                types(&format!("[box_types.{b}]\nextends = \"session\"\n")).expect_err("fails");
            assert_eq!(err.exit_code(), 3);
            let msg = err.to_string();
            // Both definitions: the project's table and the built-in type.
            assert!(msg.contains(&format!("`[box_types.{b}]`")), "{msg}");
            assert!(msg.contains(&format!("the built-in type `{b}`")), "{msg}");
        }
        assert_eq!(
            types("[box_types.task]\nextends = \"session\"\n")
                .expect_err("fails")
                .to_string(),
            "`[box_types.task]` has the name of the built-in type `task`. \
             A project type cannot replace a built-in type. \
             Rename `[box_types.task]` and set `extends = \"task\"` in it."
        );

        let err = types("[box_types.ci]\nextends = \"nothing\"\n").expect_err("fails");
        assert_eq!(
            err.to_string(),
            "`[box_types.ci]` extends `nothing`, \
             which is not a built-in type and not in `[box_types]`."
        );
        assert_eq!(err.exit_code(), 3);

        for (src, msg) in [
            (
                "[box_types.ci]\nextends = 1\n",
                "`extends` in `[box_types.ci]` is not a string.",
            ),
            (
                "[box_types.ci]\nextends = \"task\"\ndefaults = 1\n",
                "`defaults` in `[box_types.ci]` is not a table.",
            ),
            (
                "[box_types.ci]\nextends = \"task\"\nconstraints = []\n",
                "`constraints` in `[box_types.ci]` is not a table.",
            ),
            (
                "box_types = 1\n",
                "`[box_types]` in minimal.toml is not a table.",
            ),
        ] {
            let err = types(src).expect_err(src);
            assert_eq!(err.to_string(), msg);
            assert_eq!(err.exit_code(), 3);
        }
    }

    /// A type graph with one defect, and the type the error must name.
    fn broken_graph() -> impl Strategy<Value = (String, String)> {
        (acyclic_graph(), 0..3usize, any::<prop::sample::Index>()).prop_map(
            |(graph, defect, pick)| {
                let mut src = graph_toml(&graph);
                let n = graph.len();
                match defect {
                    0 => {
                        src.push_str("[box_types.zz-broken]\ndefaults = {}\n");
                        (src, "zz-broken".to_owned())
                    }
                    1 => {
                        // `aa-0` -> `aa-1` -> ... -> `aa-0`, sorted first.
                        let len = pick.index(3) + 1;
                        for i in 0..len {
                            let next = (i + 1) % len;
                            src.push_str(&format!("[box_types.aa-{i}]\nextends = \"aa-{next}\"\n"));
                        }
                        (src, "aa-0".to_owned())
                    }
                    _ => {
                        let b = BUILTIN_BOX_TYPES[pick.index(BUILTIN_BOX_TYPES.len())];
                        src.push_str(&format!(
                            "[box_types.{b}]\nextends = \"t{}\"\n",
                            pick.index(n)
                        ));
                        (src, b.to_owned())
                    }
                }
            },
        )
    }

    proptest! {
        // BOX-059 property: a type graph with a missing extends, a cycle or
        // a built-in name fails, naming the type.
        #[test]
        fn box_type_missing_extends_cycle_or_redefinition_exit3_property(
            (src, name) in broken_graph()
        ) {
            let err = types(&src).expect_err("fails");
            prop_assert_eq!(err.exit_code(), 3);
            let msg = err.to_string();
            prop_assert!(msg.starts_with(&format!("`[box_types.{name}]`")), "{}", msg);
        }
    }

    // BOX-156: a derived type whose constraint admits a value that its
    // parent type's constraint on the same key excludes fails with exit 3
    // naming the type, the key and the parent.
    #[test]
    fn derived_type_loosening_constraint_exit3_names_type_key_parent() {
        let base = r#"
            [box_types.ci]
            extends = "task"
            constraints = { pty_enabled = false, restart = ["never", "on-failure"], network = { mode = "none" } }
        "#;
        // Narrowing, repeating, or constraining a new key resolves.
        types(&format!(
            "{base}[box_types.ci-small]\nextends = \"ci\"\n\
             constraints = {{ pty_enabled = false, restart = \"never\", \
             network = {{ mode = \"none\", egress = {{ allow_dns_hosts = [] }} }}, \
             packages = [\"git\"] }}\n\
             [box_types.ci-tiny]\nextends = \"ci-small\"\nconstraints = {{ restart = [] }}\n"
        ))
        .expect("each type only narrows");

        for (constraints, key, msg) in [
            (
                "pty_enabled = [false, true]",
                "pty_enabled",
                "`[box_types.ci-loose]` allows `true` for `pty_enabled` in `constraints`, \
                 but its parent type `[box_types.ci]` does not.",
            ),
            (
                "restart = \"always\"",
                "restart",
                "`[box_types.ci-loose]` allows `\"always\"` for `restart` in `constraints`, \
                 but its parent type `[box_types.ci]` does not.",
            ),
            (
                "network = { mode = \"open\" }",
                "network.mode",
                "`[box_types.ci-loose]` allows `\"open\"` for `network.mode` in `constraints`, \
                 but its parent type `[box_types.ci]` does not.",
            ),
            (
                "network = { egress = {} }",
                "network.mode",
                "`[box_types.ci-loose]` allows values for `network.mode` in `constraints` \
                 that its parent type `[box_types.ci]` does not allow.",
            ),
        ] {
            let src = format!(
                "{base}[box_types.ci-loose]\nextends = \"ci\"\nconstraints = {{ {constraints} }}\n"
            );
            let err = types(&src).expect_err(constraints);
            assert_eq!(err.exit_code(), 3);
            assert_eq!(
                err.to_string(),
                format!(
                    "{msg} A type can only narrow the constraints of the type it extends. \
                     Change `{key}` in the `constraints` of `[box_types.ci-loose]`."
                )
            );
        }

        // The parent's resolved constraint holds through a type that does
        // not repeat it: the parent named is the type extended.
        let err = types(&format!(
            "{base}[box_types.mid]\nextends = \"ci\"\n\
             [box_types.leaf]\nextends = \"mid\"\nconstraints = {{ pty_enabled = true }}\n"
        ))
        .expect_err("loosens through mid");
        assert_eq!(
            err,
            BoxTypeError::Loosening {
                name: "leaf".into(),
                key: "pty_enabled".into(),
                parent: "mid".into(),
                value: Some("true".into()),
            }
        );
    }

    fn small_constraint() -> impl Strategy<Value = Option<Vec<u8>>> {
        prop::option::of(prop::collection::vec(0u8..3, 0..3))
    }

    proptest! {
        // BOX-156 property: a chain resolves iff no derived type's
        // constraint admits a value its parent's resolved constraint
        // excludes, so every resolved constraint is a subset of its
        // parent's.
        #[test]
        fn derived_type_loosening_constraint_exit3_names_type_key_parent_property(
            chain in prop::collection::vec(small_constraint(), 1..5),
        ) {
            let mut src = String::new();
            for (i, c) in chain.iter().enumerate() {
                let extends = if i == 0 { "task".to_owned() } else { format!("t{}", i - 1) };
                src.push_str(&format!("[box_types.t{i}]\nextends = \"{extends}\"\n"));
                if let Some(c) = c {
                    let items: Vec<String> = c.iter().map(|v| format!("\"v{v}\"")).collect();
                    src.push_str(&format!("constraints = {{ restart = [{}] }}\n", items.join(", ")));
                }
            }
            // Brute force over the domain: the first type whose set is not
            // inside the last set before it.
            let mut resolved: Option<Vec<u8>> = None;
            let mut loose = None;
            for (i, c) in chain.iter().enumerate() {
                if let Some(c) = c {
                    if let Some(p) = &resolved && c.iter().any(|v| !p.contains(v)) {
                        loose = Some(i);
                        break;
                    }
                    resolved = Some(c.clone());
                }
            }
            match (types(&src), loose) {
                (Ok(t), None) => {
                    for i in 0..chain.len() {
                        let name = format!("t{i}");
                        prop_assert!(t.resolve(&name).is_ok());
                    }
                }
                (Err(err), Some(i)) => {
                    prop_assert_eq!(err.exit_code(), 3);
                    prop_assert_eq!(
                        err,
                        BoxTypeError::Loosening {
                            name: format!("t{i}"),
                            key: "restart".into(),
                            parent: format!("t{}", i - 1),
                            value: chain[i].as_ref().and_then(|c| {
                                let p = resolved.as_ref()?;
                                c.iter().find(|v| !p.contains(v)).map(|v| format!("\"v{v}\""))
                            }),
                        }
                    );
                }
                (got, want) => prop_assert!(false, "{:?} vs loosening at {:?}", got, want),
            }
        }
    }
}
