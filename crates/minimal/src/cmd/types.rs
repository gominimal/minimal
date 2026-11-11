//! `min type list` and `min type show <name>`: the box types a project can
//! use, and the defaults and constraints of one of them.
//!
//! BCLI-019: the list holds the six built-in types and each type of the
//! project's `[box_types]`, each with its source. BCLI-020: the show names,
//! for every default and constraint, the type that sets it and that type's
//! source. A type is named as the expansion report names the type that
//! supplies a value (BOX-161): by its plain name.
//!
//! The values come from `mfile::box_types`, the same data the expansion
//! folds. A built-in type carries the defaults and constraints that data
//! gives it, so this command and the expansion cannot disagree.

use std::io::Write;
use std::path::PathBuf;

use anyhow::Context as _;
use mfile::box_types::{BUILTIN_BOX_TYPES, BoxTypes, ResolvedType, builtin};
use serde::Serialize;

use crate::{GlobalArgs, TypeShowArgs};

use super::box_audit::printable;
use super::output::{ObjectType, OutputMode, Rendered, write_object};

/// Where a type comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TypeSource {
    /// One of the built-in types.
    Builtin,
    /// A `[box_types.<name>]` table of the project's `minimal.toml`.
    Project,
    /// An organization's type. Reserved: no type carries it yet.
    Org,
}

impl TypeSource {
    /// The source as the text form and `-o json` spell it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Builtin => "builtin",
            Self::Project => "project",
            Self::Org => "org",
        }
    }
}

impl std::fmt::Display for TypeSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The source of the type named `name`, in `types`.
fn source_of(name: &str) -> TypeSource {
    if builtin(name).is_some() {
        TypeSource::Builtin
    } else {
        TypeSource::Project
    }
}

/// One row of `min type list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TypeRow {
    /// The type's name.
    pub name: String,
    /// Where the type comes from.
    pub source: TypeSource,
    /// The type a project type extends. `None` for a built-in type.
    pub extends: Option<String>,
    /// The built-in type at the end of the type's `extends` chain.
    pub root: String,
}

/// The rows of `min type list`: the built-in types in their fixed order,
/// then the project types by name.
#[must_use]
pub fn type_rows(types: &BoxTypes) -> Vec<TypeRow> {
    let mut rows: Vec<TypeRow> = BUILTIN_BOX_TYPES
        .iter()
        .map(|name| TypeRow {
            name: (*name).to_owned(),
            source: TypeSource::Builtin,
            extends: None,
            root: (*name).to_owned(),
        })
        .collect();
    for (name, project) in types.project() {
        rows.push(TypeRow {
            name: name.clone(),
            source: TypeSource::Project,
            extends: Some(project.extends.clone()),
            // `BoxTypes::from_file` resolved every project type already.
            root: types.root(name).unwrap_or_default().to_owned(),
        });
    }
    rows
}

/// Write the rows of `min type list` as a table.
///
/// # Errors
/// The writer's error.
pub fn write_type_list(out: &mut dyn Write, rows: &[TypeRow]) -> std::io::Result<()> {
    let width = rows
        .iter()
        .map(|r| printable(&r.name).len())
        .chain(["NAME".len()])
        .max()
        .unwrap_or_default();
    let parent_width = rows
        .iter()
        .map(|r| printable(r.extends.as_deref().unwrap_or("-")).len())
        .chain(["EXTENDS".len()])
        .max()
        .unwrap_or_default();
    writeln!(
        out,
        "{:<width$}  {:<7}  {:<parent_width$}  BUILT-IN TYPE",
        "NAME", "SOURCE", "EXTENDS"
    )?;
    for row in rows {
        writeln!(
            out,
            "{:<width$}  {:<7}  {:<parent_width$}  {}",
            printable(&row.name),
            row.source.as_str(),
            printable(row.extends.as_deref().unwrap_or("-")),
            row.root,
        )?;
    }
    Ok(())
}

/// One value of a type's defaults or constraints, with the type that sets
/// it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TypeValue {
    /// The setting, as a dotted key (`io.exec_enabled`).
    pub key: String,
    /// The value, as TOML writes it inline.
    pub value: String,
    /// The type whose table sets the value.
    pub set_by: String,
    /// The source of that type.
    pub source: TypeSource,
}

/// What `min type show <name>` renders.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TypeDetail {
    /// The type's name.
    pub name: String,
    /// Where the type comes from.
    pub source: TypeSource,
    /// The type a project type extends. `None` for a built-in type.
    pub extends: Option<String>,
    /// The built-in type at the end of the type's `extends` chain.
    pub root: String,
    /// The defaults of every type of the chain, the built-in type first and
    /// this type last.
    pub defaults: Vec<TypeValue>,
    /// The constraints of every type of the chain, in the same order.
    pub constraints: Vec<TypeValue>,
}

/// Flatten `table` into dotted keys, each with its value inline.
fn flatten(prefix: &str, table: &toml::Table, into: &mut Vec<(String, String)>) {
    for (key, value) in table {
        let dotted = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        match value {
            toml::Value::Table(inner) if !inner.is_empty() => flatten(&dotted, inner, into),
            other => into.push((dotted, other.to_string())),
        }
    }
}

/// The values of each `(type, table)` of a chain, in chain order.
fn chain_values(chain: &[(String, toml::Table)]) -> Vec<TypeValue> {
    let mut values = Vec::new();
    for (set_by, table) in chain {
        let mut flat = Vec::new();
        flatten("", table, &mut flat);
        values.extend(flat.into_iter().map(|(key, value)| TypeValue {
            key,
            value,
            set_by: set_by.clone(),
            source: source_of(set_by),
        }));
    }
    values
}

/// The detail of a resolved type.
#[must_use]
pub fn type_detail(types: &BoxTypes, resolved: &ResolvedType) -> TypeDetail {
    TypeDetail {
        name: resolved.name.clone(),
        source: source_of(&resolved.name),
        extends: types
            .project()
            .get(&resolved.name)
            .map(|p| p.extends.clone()),
        root: resolved.root.to_owned(),
        defaults: chain_values(&resolved.defaults),
        constraints: chain_values(&resolved.constraints),
    }
}

fn write_values(out: &mut dyn Write, values: &[TypeValue]) -> std::io::Result<()> {
    if values.is_empty() {
        return writeln!(out, "  (none)");
    }
    let width = values
        .iter()
        .map(|v| printable(&v.key).len() + printable(&v.value).len() + 3)
        .max()
        .unwrap_or_default();
    for v in values {
        let setting = format!("{} = {}", printable(&v.key), printable(&v.value));
        writeln!(
            out,
            "  {setting:<width$}  from {} ({})",
            printable(&v.set_by),
            v.source.as_str()
        )?;
    }
    Ok(())
}

impl Rendered for TypeDetail {
    const TYPE: ObjectType = ObjectType::Type;

    fn text(&self, out: &mut dyn Write) -> std::io::Result<()> {
        writeln!(out, "Name:           {}", printable(&self.name))?;
        writeln!(out, "Source:         {}", self.source.as_str())?;
        if let Some(extends) = &self.extends {
            writeln!(out, "Extends:        {}", printable(extends))?;
        }
        writeln!(out, "Built-in type:  {}", self.root)?;
        writeln!(out)?;
        writeln!(out, "Defaults, in the order they apply:")?;
        write_values(out, &self.defaults)?;
        writeln!(out)?;
        writeln!(out, "Constraints:")?;
        write_values(out, &self.constraints)
    }
}

/// The directory the commands look for the project in, and whether the
/// search walks up from it. `--repo-dir` names the project root, as
/// `min init` reads it, so the search stays there. Without it the search
/// walks up from the current directory.
fn project_dir(global: &GlobalArgs) -> (PathBuf, bool) {
    match &global.repo_dir {
        Some(dir) => (dir.clone(), false),
        None => (PathBuf::from("."), true),
    }
}

/// The box types of the project in `dir`, or only the built-in types when
/// no `minimal.toml` is found there, or above it when `search_ancestors`.
///
/// # Errors
/// A `minimal.toml` that does not load, or whose `[box_types]` does not
/// resolve. `doing` names the command in the message.
pub fn load_types(
    dir: &std::path::Path,
    search_ancestors: bool,
    doing: &str,
) -> anyhow::Result<BoxTypes> {
    let loaded = if search_ancestors {
        mfile::File::from_dir_recursive(dir)
    } else {
        mfile::File::from_dir(dir)
    };
    let file = match loaded {
        Ok(file) => file,
        Err(mfile::Error::NotFound) => {
            tracing::debug!(dir = %dir.display(), "no project file: built-in types only");
            return Ok(BoxTypes::default());
        }
        Err(error) => anyhow::bail!(
            "Cannot {doing}: the project's {} does not load: {error}",
            mfile::MFILE_NAME
        ),
    };
    let Some(path) = file.file_path() else {
        return Ok(BoxTypes::default());
    };
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("Cannot {doing}: cannot read {}", path.display()))?;
    let doc: toml::Table = toml::from_str(&text).map_err(|error| {
        anyhow::anyhow!(
            "Cannot {doing}: {} is not valid TOML: {error}",
            path.display()
        )
    })?;
    let types =
        BoxTypes::from_file(&doc).map_err(|error| anyhow::anyhow!("Cannot {doing}: {error}"))?;
    tracing::debug!(
        path = %path.display(),
        project_types = types.project().len(),
        "read the project's box types"
    );
    Ok(types)
}

/// `min type list`.
///
/// # Errors
/// As [`load_types`], or the writer's error.
pub fn cmd_type_list(global: &GlobalArgs, out: &mut dyn Write) -> anyhow::Result<()> {
    let (dir, search_ancestors) = project_dir(global);
    let types = load_types(&dir, search_ancestors, "list the box types")?;
    write_type_list(out, &type_rows(&types)).context("failed to write to stdout")?;
    out.flush().context("failed to write to stdout")
}

/// `min type show <name>`.
///
/// # Errors
/// As [`load_types`], a name that is no type, or the writer's error.
pub fn cmd_type_show(
    global: &GlobalArgs,
    args: &TypeShowArgs,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    let (dir, search_ancestors) = project_dir(global);
    let types = load_types(&dir, search_ancestors, "show the box type")?;
    if !types.contains(&args.name) {
        anyhow::bail!(
            "No box type is named `{}`. Run `min type list` to see the box types.",
            printable(&args.name)
        );
    }
    let resolved = types
        .resolve(&args.name)
        .map_err(|error| anyhow::anyhow!("Cannot show the box type: {error}"))?;
    write_object(out, OutputMode::Text, &type_detail(&types, &resolved))
        .context("failed to write to stdout")?;
    out.flush().context("failed to write to stdout")
}
