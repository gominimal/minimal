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
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use mfile::box_types::{BUILTIN_BOX_TYPES, BoxTypeError, BoxTypes, ResolvedType, builtin};
use serde::Serialize;

use crate::{GlobalArgs, TypeListArgs, TypeOutputFormat, TypeShowArgs};

use super::box_audit::printable;
use super::output::{ObjectType, OutputMode, Rendered, write_object, write_objects};

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

impl Rendered for TypeRow {
    const TYPE: ObjectType = ObjectType::Type;

    fn text(&self, out: &mut dyn Write) -> std::io::Result<()> {
        write_type_list(out, std::slice::from_ref(self))
    }
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
    /// Every type of the `extends` chain, the built-in type first and this
    /// type last. A type that sets no value is in it too.
    pub chain: Vec<String>,
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
        chain: resolved
            .defaults
            .iter()
            .map(|(name, _)| name.clone())
            .collect(),
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
        let chain: Vec<String> = self
            .chain
            .iter()
            .map(|n| printable(n).into_owned())
            .collect();
        writeln!(out, "Type chain:     {}", chain.join(" -> "))?;
        writeln!(out)?;
        writeln!(out, "Defaults, in the order they apply:")?;
        write_values(out, &self.defaults)?;
        writeln!(out)?;
        writeln!(out, "Constraints:")?;
        write_values(out, &self.constraints)
    }
}

/// Why the project's box types do not load.
#[derive(Debug)]
pub enum BoxTypesCause {
    /// The `minimal.toml` does not load.
    Load(mfile::Error),
    /// The `minimal.toml` at `path` is not valid TOML.
    Parse {
        /// The file.
        path: PathBuf,
        /// The parser's error.
        error: toml::de::Error,
    },
    /// A type of `[box_types]` does not resolve.
    Resolve(BoxTypeError),
}

/// `min type list` or `min type show` cannot read the project's box types.
/// The command exits 3, the exit code of an invalid project file.
#[derive(Debug)]
pub struct BoxTypesInvalid {
    /// What the command was doing, as the message says it.
    pub doing: &'static str,
    /// Why the types do not load.
    pub cause: BoxTypesCause,
}

impl BoxTypesInvalid {
    /// The exit code of the refusal.
    pub const EXIT_CODE: u8 = 3;
}

impl std::fmt::Display for BoxTypesInvalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The cause is in this text and `source()` returns none, so the
        // printer's `{:#}` shows it once.
        let doing = self.doing;
        match &self.cause {
            BoxTypesCause::Load(error) => write!(
                f,
                "Cannot {doing}: the project's {} does not load: {error}",
                mfile::MFILE_NAME
            ),
            BoxTypesCause::Parse { path, error } => write!(
                f,
                "Cannot {doing}: {} is not valid TOML: {error}",
                path.display()
            ),
            BoxTypesCause::Resolve(error) => write!(f, "Cannot {doing}: {error}"),
        }
    }
}

impl std::error::Error for BoxTypesInvalid {}

/// `min type show <name>` of a name that is no box type. The command exits
/// 4, the exit code of a thing that is not found.
#[derive(Debug)]
pub struct BoxTypeNotFound {
    /// The name the user gave.
    pub name: String,
}

impl BoxTypeNotFound {
    /// The exit code of the refusal.
    pub const EXIT_CODE: u8 = 4;
    /// The next step, for the `hint` of the machine-mode error object.
    pub const HINT: &'static str = "run `min type list` to see the box types";
}

impl std::fmt::Display for BoxTypeNotFound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "No box type is named `{}`. Run `min type list` to see the box types.",
            printable(&self.name)
        )
    }
}

impl std::error::Error for BoxTypeNotFound {}

/// An object with its `min/v1/type` stamp first, for the TOML and YAML
/// forms. The JSON form takes its stamp from [`write_object`].
#[derive(Serialize)]
struct Stamped<'a, T: Serialize> {
    schema: &'static str,
    #[serde(flatten)]
    body: &'a T,
}

fn stamped<T: Rendered>(body: &T) -> Stamped<'_, T> {
    Stamped {
        schema: T::TYPE.schema(),
        body,
    }
}

/// The TOML form of `min type list`: one `[[types]]` table for each type,
/// because a TOML document cannot be an array.
#[derive(Serialize)]
struct TypeListDoc<'a> {
    types: Vec<Stamped<'a, TypeRow>>,
}

/// A string as a YAML double-quoted scalar. Every control character is
/// escaped, so the text cannot carry a terminal control sequence.
fn yaml_quote(text: &str) -> String {
    let mut quoted = String::with_capacity(text.len() + 2);
    quoted.push('"');
    for c in text.chars() {
        match c {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            '\n' => quoted.push_str("\\n"),
            '\t' => quoted.push_str("\\t"),
            c if c.is_control() || matches!(c, '\u{2028}' | '\u{2029}' | '\u{feff}') => {
                quoted.push_str(&format!("\\u{:04x}", u32::from(c)));
            }
            c => quoted.push(c),
        }
    }
    quoted.push('"');
    quoted
}

/// A mapping key, plain where YAML reads it as the same string, and
/// quoted otherwise.
fn yaml_key(key: &str) -> String {
    let plain = key
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        && !matches!(
            key.to_ascii_lowercase().as_str(),
            "true" | "false" | "null" | "yes" | "no" | "on" | "off" | "y" | "n"
        );
    if plain {
        key.to_owned()
    } else {
        yaml_quote(key)
    }
}

/// A YAML node, built from an ordered TOML document so the keys keep the
/// order of the object's fields.
enum YamlNode {
    /// A value on one line, already written as YAML.
    Scalar(String),
    Map(Vec<(String, YamlNode)>),
    Seq(Vec<YamlNode>),
}

fn yaml_from_value(value: &toml_edit::Value) -> YamlNode {
    use toml_edit::Value;
    match value {
        Value::String(s) => YamlNode::Scalar(yaml_quote(s.value())),
        Value::Integer(i) => YamlNode::Scalar(i.value().to_string()),
        Value::Float(f) => {
            let f = *f.value();
            YamlNode::Scalar(if f.is_nan() {
                ".nan".to_owned()
            } else if f.is_infinite() {
                if f > 0.0 { ".inf" } else { "-.inf" }.to_owned()
            } else {
                format!("{f:?}")
            })
        }
        Value::Boolean(b) => YamlNode::Scalar(b.value().to_string()),
        Value::Datetime(d) => YamlNode::Scalar(yaml_quote(&d.value().to_string())),
        Value::Array(items) => YamlNode::Seq(items.iter().map(yaml_from_value).collect()),
        Value::InlineTable(table) => YamlNode::Map(
            table
                .iter()
                .map(|(k, v)| (k.to_owned(), yaml_from_value(v)))
                .collect(),
        ),
    }
}

fn yaml_from_table(table: &toml_edit::Table) -> YamlNode {
    YamlNode::Map(
        table
            .iter()
            .map(|(k, item)| (k.to_owned(), yaml_from_item(item)))
            .collect(),
    )
}

fn yaml_from_item(item: &toml_edit::Item) -> YamlNode {
    match item {
        toml_edit::Item::None => YamlNode::Scalar("null".to_owned()),
        toml_edit::Item::Value(value) => yaml_from_value(value),
        toml_edit::Item::Table(table) => yaml_from_table(table),
        toml_edit::Item::ArrayOfTables(tables) => {
            YamlNode::Seq(tables.iter().map(yaml_from_table).collect())
        }
    }
}

impl YamlNode {
    /// The node on one line: a scalar, or an empty map or sequence.
    fn inline(&self) -> Option<String> {
        match self {
            Self::Scalar(s) => Some(s.clone()),
            Self::Map(entries) if entries.is_empty() => Some("{}".to_owned()),
            Self::Seq(items) if items.is_empty() => Some("[]".to_owned()),
            Self::Map(_) | Self::Seq(_) => None,
        }
    }

    /// Write the node as a block, each line at `indent`.
    fn block(&self, out: &mut String, indent: usize) {
        if let Some(inline) = self.inline() {
            out.push_str(&" ".repeat(indent));
            out.push_str(&inline);
            out.push('\n');
            return;
        }
        match self {
            Self::Map(entries) => {
                for (key, value) in entries {
                    out.push_str(&" ".repeat(indent));
                    out.push_str(&yaml_key(key));
                    out.push(':');
                    if let Some(inline) = value.inline() {
                        out.push(' ');
                        out.push_str(&inline);
                        out.push('\n');
                    } else {
                        out.push('\n');
                        value.block(out, indent + 2);
                    }
                }
            }
            Self::Seq(items) => {
                for item in items {
                    out.push_str(&" ".repeat(indent));
                    out.push_str("- ");
                    // The item's first line goes on the line of its dash.
                    let mut nested = String::new();
                    item.block(&mut nested, indent + 2);
                    out.push_str(nested.get(indent + 2..).unwrap_or_default());
                }
            }
            Self::Scalar(_) => {}
        }
    }
}

/// `value` as a YAML document, its keys in the order of its fields. With
/// `key`, the document is the value under that key.
fn yaml_document<T: Serialize>(value: &T, key: Option<&str>) -> std::io::Result<String> {
    let text = toml::to_string(value).map_err(std::io::Error::other)?;
    let doc: toml_edit::DocumentMut = text.parse().map_err(std::io::Error::other)?;
    let node = match key {
        Some(key) => doc
            .get(key)
            .map_or(YamlNode::Seq(Vec::new()), yaml_from_item),
        None => yaml_from_table(doc.as_table()),
    };
    let mut out = String::new();
    node.block(&mut out, 0);
    Ok(out)
}

/// Write the rows of `min type list` in `format`: a JSON array, a YAML
/// sequence, or a TOML `[[types]]` table for each row. Each row is a
/// `min/v1/type` object.
///
/// # Errors
/// The writer's error, or a row that does not encode.
pub fn write_type_rows_as(
    out: &mut dyn Write,
    format: TypeOutputFormat,
    rows: &[TypeRow],
) -> std::io::Result<()> {
    match format {
        TypeOutputFormat::Json => write_objects(out, OutputMode::Json, rows),
        TypeOutputFormat::Yaml => {
            let doc = TypeListDoc {
                types: rows.iter().map(stamped).collect(),
            };
            out.write_all(yaml_document(&doc, Some("types"))?.as_bytes())
        }
        TypeOutputFormat::Toml => {
            let doc = TypeListDoc {
                types: rows.iter().map(stamped).collect(),
            };
            let text = toml::to_string(&doc).map_err(std::io::Error::other)?;
            out.write_all(text.as_bytes())
        }
    }
}

/// Write the detail of `min type show` in `format`, as one `min/v1/type`
/// object.
///
/// # Errors
/// The writer's error, or a detail that does not encode.
pub fn write_type_detail_as(
    out: &mut dyn Write,
    format: TypeOutputFormat,
    detail: &TypeDetail,
) -> std::io::Result<()> {
    match format {
        TypeOutputFormat::Json => write_object(out, OutputMode::Json, detail),
        TypeOutputFormat::Yaml => out.write_all(yaml_document(&stamped(detail), None)?.as_bytes()),
        TypeOutputFormat::Toml => {
            let text = toml::to_string(&stamped(detail)).map_err(std::io::Error::other)?;
            out.write_all(text.as_bytes())
        }
    }
}

/// The directory the commands look for the project in, and whether the
/// search walks up from it. `--repo-dir` names the project root, as
/// `min init` reads it, so the search stays there. Without it the search
/// walks up from `cwd`, which must be absolute: `Path::parent` of a
/// relative `.` never reaches the real parent directory.
fn project_dir(global: &GlobalArgs, cwd: &Path) -> (PathBuf, bool) {
    match &global.repo_dir {
        Some(dir) => (dir.clone(), false),
        None => (cwd.to_path_buf(), true),
    }
}

/// The current directory, absolute, for the upward search.
fn current_dir() -> anyhow::Result<PathBuf> {
    std::env::current_dir().context("reading the current directory")
}

/// The box types of the project in `dir`, or only the built-in types when
/// no `minimal.toml` is found there, or above it when `search_ancestors`.
///
/// # Errors
/// [`BoxTypesInvalid`] for a `minimal.toml` that does not load, is not
/// valid TOML, or whose `[box_types]` does not resolve. `doing` names the
/// command in the message.
pub fn load_types(
    dir: &std::path::Path,
    search_ancestors: bool,
    doing: &'static str,
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
        Err(error) => {
            return Err(BoxTypesInvalid {
                doing,
                cause: BoxTypesCause::Load(error),
            }
            .into());
        }
    };
    let Some(path) = file.file_path() else {
        return Ok(BoxTypes::default());
    };
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("Cannot {doing}: cannot read {}", path.display()))?;
    let doc: toml::Table = toml::from_str(&text).map_err(|error| BoxTypesInvalid {
        doing,
        cause: BoxTypesCause::Parse {
            path: path.to_path_buf(),
            error,
        },
    })?;
    let types = BoxTypes::from_file(&doc).map_err(|error| BoxTypesInvalid {
        doing,
        cause: BoxTypesCause::Resolve(error),
    })?;
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
pub fn cmd_type_list(
    global: &GlobalArgs,
    args: &TypeListArgs,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    cmd_type_list_in(global, &current_dir()?, args, out)
}

/// `min type list`, run in the absolute directory `cwd`.
///
/// # Errors
/// As [`cmd_type_list`].
pub fn cmd_type_list_in(
    global: &GlobalArgs,
    cwd: &Path,
    args: &TypeListArgs,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    let (dir, search_ancestors) = project_dir(global, cwd);
    let types = load_types(&dir, search_ancestors, "list the box types")?;
    let rows = type_rows(&types);
    match args.output {
        None => write_type_list(out, &rows),
        Some(format) => write_type_rows_as(out, format, &rows),
    }
    .context("failed to write to stdout")?;
    out.flush().context("failed to write to stdout")
}

/// `min type show <name>`.
///
/// # Errors
/// As [`load_types`], [`BoxTypeNotFound`] for a name that is no type, or
/// the writer's error.
pub fn cmd_type_show(
    global: &GlobalArgs,
    args: &TypeShowArgs,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    cmd_type_show_in(global, &current_dir()?, args, out)
}

/// `min type show <name>`, run in the absolute directory `cwd`.
///
/// # Errors
/// As [`cmd_type_show`].
pub fn cmd_type_show_in(
    global: &GlobalArgs,
    cwd: &Path,
    args: &TypeShowArgs,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    let (dir, search_ancestors) = project_dir(global, cwd);
    let types = load_types(&dir, search_ancestors, "show the box type")?;
    if !types.contains(&args.name) {
        return Err(BoxTypeNotFound {
            name: args.name.clone(),
        }
        .into());
    }
    let resolved = types.resolve(&args.name).map_err(|error| BoxTypesInvalid {
        doing: "show the box type",
        cause: BoxTypesCause::Resolve(error),
    })?;
    let detail = type_detail(&types, &resolved);
    match args.output {
        None => write_object(out, OutputMode::Text, &detail),
        Some(format) => write_type_detail_as(out, format, &detail),
    }
    .context("failed to write to stdout")?;
    out.flush().context("failed to write to stdout")
}
