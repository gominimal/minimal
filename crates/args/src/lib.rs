//! Types for defining the schema of arguments of `mfile::Task` & parameters to sideloads.
//!
//!  * [Arg] / [ScalarArg]: A concrete argument value.
//!  * [ArgSchema]: The type of an argument.
//!  * [ArgSpec]: The type of an argument, combined with metadata such as help text.
//!    [ArgSpec::parse] can be used to parse a string representing the invocation of
//!    these arguments into their concrete values.
//!  * [ArgsSpec]: Newtype around a map of argument names to [ArgSpec] (schema) descriptions.
//!  * [ArgsSet]: A concrete set of arguments, effectively a Newtype of `HashMap<String, Arg>`.

use std::{
    collections::{BTreeSet, HashMap},
    hash::Hash,
};

/// A set of arguments.
#[derive(Debug, Clone, PartialEq)]
pub struct ArgsSet(HashMap<String, Arg>);

impl ArgsSet {
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Arg)> {
        self.0.iter()
    }
}

impl Hash for ArgsSet {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let keys: BTreeSet<_> = self.0.keys().cloned().collect();
        for k in keys.into_iter() {
            k.hash(state);
            self.0.get(&k).unwrap().hash(state);
        }
    }
}

impl From<HashMap<String, Arg>> for ArgsSet {
    fn from(value: HashMap<String, Arg>) -> Self {
        Self(value)
    }
}

impl AsRef<HashMap<String, Arg>> for ArgsSet {
    fn as_ref(&self) -> &HashMap<String, Arg> {
        &self.0
    }
}

/// A scalar argument value.
#[derive(Debug, Clone, PartialEq)]
pub enum ScalarArg {
    String(String),
    Number(f64),
    Boolean(bool),
}

impl Hash for ScalarArg {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            Self::String(s) => s.hash(state),
            Self::Number(n) => n.to_le_bytes().hash(state),
            Self::Boolean(b) => b.hash(state),
        }
    }
}

impl ScalarArg {
    /// Append the nickel literal representation of this value to `buf`.
    pub fn write_nickel(&self, buf: &mut String) {
        match self {
            ScalarArg::String(s) => {
                buf.push('"');
                buf.push_str(s);
                buf.push('"');
            }
            ScalarArg::Number(f) => buf.push_str(&f.to_string()),
            ScalarArg::Boolean(b) => buf.push_str(if *b { "true" } else { "false" }),
        }
    }
}

/// An argument value.
#[derive(Debug, Clone, Hash, PartialEq)]
pub enum Arg {
    Scalar(ScalarArg),
    Array(Vec<ScalarArg>),
    Enum(String),
}

impl Arg {
    /// Append the nickel literal representation of this value to `buf`.
    pub fn write_nickel(&self, buf: &mut String) {
        match self {
            Arg::Scalar(s) => s.write_nickel(buf),
            Arg::Enum(s) => {
                buf.push('"');
                buf.push_str(s);
                buf.push('"');
            }
            Arg::Array(v) => {
                buf.push('[');
                for (i, s) in v.iter().enumerate() {
                    if i > 0 {
                        buf.push_str(", ");
                    }
                    s.write_nickel(buf);
                }
                buf.push(']');
            }
        }
    }

    /// Write a `let <ident> = <value> in\n` binding into `buf`.
    pub fn write_nickel_binding(&self, ident: &str, buf: &mut String) {
        buf.push_str("let ");
        buf.push_str(ident);
        buf.push_str(" = ");
        self.write_nickel(buf);
        buf.push_str(" in\n");
    }
}

/// The leaf scalar types an argument can have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrimitiveSpec {
    String,
    Number,
    Boolean,
}

impl PrimitiveSpec {
    /// Parse a string value into a [ScalarArg] according to the given primitive type.
    pub fn parse(&self, s: &str) -> Result<ScalarArg, String> {
        match self {
            PrimitiveSpec::String => Ok(ScalarArg::String(s.to_string())),
            PrimitiveSpec::Number => {
                let f: f64 = s
                    .parse()
                    .map_err(|_| format!("expected a number, got `{s}`"))?;
                Ok(ScalarArg::Number(f))
            }
            PrimitiveSpec::Boolean => match s {
                "true" => Ok(ScalarArg::Boolean(true)),
                "false" => Ok(ScalarArg::Boolean(false)),
                _ => Err(format!("expected `true` or `false`, got `{s}`")),
            },
        }
    }
}

impl std::fmt::Display for PrimitiveSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrimitiveSpec::String => f.write_str("string"),
            PrimitiveSpec::Number => f.write_str("number"),
            PrimitiveSpec::Boolean => f.write_str("boolean"),
        }
    }
}

impl TryFrom<&str> for PrimitiveSpec {
    type Error = ();
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s.to_ascii_lowercase().as_str() {
            "string" => Ok(PrimitiveSpec::String),
            "number" => Ok(PrimitiveSpec::Number),
            "boolean" | "bool" => Ok(PrimitiveSpec::Boolean),
            _ => Err(()),
        }
    }
}

/// The type an argument can have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgSchema {
    /// A single scalar value: "string", "number", or "boolean".
    Scalar(PrimitiveSpec),
    /// An array whose elements are the given primitive type.
    Array(PrimitiveSpec),
    /// An exhaustive enumeration of mutually-exclusive options.
    Enum(BTreeSet<String>),
}

impl TryFrom<&str> for ArgSchema {
    type Error = String;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        if let Some(rest) = s
            .strip_prefix("Array ")
            .or_else(|| s.strip_prefix("array "))
        {
            return Ok(ArgSchema::Array(
                PrimitiveSpec::try_from(rest)
                    .map_err(|_| format!("invalid array primitive `{rest}`"))?,
            ));
        }
        if let Ok(primitive) = PrimitiveSpec::try_from(s) {
            return Ok(ArgSchema::Scalar(primitive));
        }

        if s.trim().starts_with('[') {
            return Ok(ArgSchema::Enum(parse_enum_schema(s)?));
        }

        Err(format!("unknown spec `{s}`"))
    }
}

impl<'de> serde::Deserialize<'de> for ArgSchema {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::{self, MapAccess, SeqAccess, Visitor};

        struct ArgSpecVisitor;

        impl<'de> Visitor<'de> for ArgSpecVisitor {
            type Value = ArgSchema;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(
                    f,
                    "a type string (\"string\", \"number\", \"boolean\", \"Array string\"), \
                     an array of strings, or {{type = \"...\"}}"
                )
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<ArgSchema, E> {
                ArgSchema::try_from(v).map_err(de::Error::custom)
            }

            fn visit_string<E: de::Error>(self, v: String) -> Result<ArgSchema, E> {
                self.visit_str(&v)
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<ArgSchema, A::Error> {
                let mut opts = BTreeSet::new();
                while let Some(val) = seq.next_element::<String>()? {
                    opts.insert(val);
                }
                if opts.is_empty() {
                    return Err(de::Error::custom(
                        "enum spec must contain at least one option",
                    ));
                }
                Ok(ArgSchema::Enum(opts))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<ArgSchema, A::Error> {
                let mut type_str: Option<String> = None;
                while let Some(key) = map.next_key::<String>()? {
                    if key == "type" {
                        type_str = Some(map.next_value()?);
                    } else {
                        map.next_value::<de::IgnoredAny>()?; // skip unknown
                    }
                }
                let s =
                    type_str.ok_or_else(|| de::Error::custom("expected `type` key in table"))?;
                ArgSchema::try_from(s.as_str()).map_err(de::Error::custom)
            }
        }

        d.deserialize_any(ArgSpecVisitor)
    }
}

impl ArgSchema {
    /// Parses the given value string into a concrete argument.
    pub fn parse(&self, value: &str) -> Result<Arg, String> {
        match &self {
            ArgSchema::Scalar(p) => Ok(Arg::Scalar(p.parse(value)?)),
            ArgSchema::Array(p) => {
                let items = parse_bracketed_list(value)?;
                let arr: Result<Vec<ScalarArg>, String> =
                    items.iter().map(|v| p.parse(v)).collect();
                Ok(Arg::Array(arr?))
            }
            ArgSchema::Enum(permitted) => {
                if permitted.contains(value) {
                    Ok(Arg::Enum(value.to_string()))
                } else {
                    Err(format!("`{value}` is not a valid value"))
                }
            }
        }
    }

    /// Returns the string form of this spec (e.g. `"Array number"`).
    pub fn as_type_string(&self) -> String {
        match self {
            ArgSchema::Scalar(p) => p.to_string(),
            ArgSchema::Array(p) => format!("Array {p}"),
            ArgSchema::Enum(opts) => format!(
                "[{}]",
                opts.iter()
                    .map(|s| format!("\"{s}\""))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
}

/// Parse a bracketed, comma-separated list of the form `[val1, val2, "val 3"]`.
///
/// Whitespace around values is trimmed. Values may optionally be quoted with
/// double quotes, which allows commas and leading/trailing whitespace within a
/// value. Returns an error if the input is not wrapped in `[]` or contains
/// malformed quoting.
fn parse_bracketed_list(s: &str) -> Result<Vec<String>, String> {
    let s = s.trim();
    let inner = s
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or_else(|| format!("expected value wrapped in `[]`, got `{s}`"))?;

    let mut values = Vec::new();
    let mut chars = inner.chars().peekable();

    loop {
        // Skip leading whitespace before the next value.
        while chars.peek() == Some(&' ') || chars.peek() == Some(&'\t') {
            chars.next();
        }

        // End of input — we're done.
        if chars.peek().is_none() {
            break;
        }

        let value = if chars.peek() == Some(&'"') {
            // Quoted value: consume until the closing `"`.
            chars.next(); // opening quote
            let mut buf = String::new();
            loop {
                match chars.next() {
                    Some('"') => break,
                    Some(c) => buf.push(c),
                    None => return Err("unterminated quote in bracketed list".to_string()),
                }
            }
            buf
        } else {
            // Unquoted value: consume until `,` or end.
            let mut buf = String::new();
            while let Some(&c) = chars.peek() {
                if c == ',' {
                    break;
                }
                buf.push(c);
                chars.next();
            }
            let trimmed = buf.trim().to_string();
            if trimmed.is_empty() {
                return Err("empty value in bracketed list".to_string());
            }
            trimmed
        };

        values.push(value);

        // Skip whitespace after the value, then expect `,` or end.
        while chars.peek() == Some(&' ') || chars.peek() == Some(&'\t') {
            chars.next();
        }
        match chars.peek() {
            Some(&',') => {
                chars.next();
            }
            Some(c) => return Err(format!("unexpected character `{c}` in bracketed list")),
            None => break,
        }
    }

    Ok(values)
}

/// Parse an enum spec string of the form `[opt1, opt2, "opt 3"]` into its options.
fn parse_enum_schema(s: &str) -> Result<BTreeSet<String>, String> {
    let values = parse_bracketed_list(s)?;
    if values.is_empty() {
        return Err("enum spec must contain at least one option".to_string());
    }
    Ok(values.into_iter().collect())
}

impl serde::Serialize for ArgSchema {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.as_type_string())
    }
}

/// A single argument definition: the type schema plus optional metadata like `help`.
///
/// Deserializes from either:
/// - A string: `"string"` → `TaskArg { spec: Scalar(String), help: None, default: None }`
/// - A table with `type`: `{type = "string"[, help = ..][, default = ...]}` → `TaskArg { spec: .., .. }`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgSpec {
    pub spec: ArgSchema,
    pub help: Option<String>,
    pub default: Option<String>,
}

impl<'de> serde::Deserialize<'de> for ArgSpec {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::{self, MapAccess, SeqAccess, Visitor};

        struct TaskArgVisitor;

        impl<'de> Visitor<'de> for TaskArgVisitor {
            type Value = ArgSpec;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(
                    f,
                    "a type string, an array of strings, or a table with `type` (and optional `help`)"
                )
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<ArgSpec, E> {
                Ok(ArgSpec {
                    spec: ArgSchema::try_from(v).map_err(de::Error::custom)?,
                    help: None,
                    default: None,
                })
            }

            fn visit_string<E: de::Error>(self, v: String) -> Result<ArgSpec, E> {
                self.visit_str(&v)
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<ArgSpec, A::Error> {
                let mut opts = BTreeSet::new();
                while let Some(val) = seq.next_element::<String>()? {
                    opts.insert(val);
                }
                if opts.is_empty() {
                    return Err(de::Error::custom(
                        "enum spec must contain at least one option",
                    ));
                }
                Ok(ArgSpec {
                    spec: ArgSchema::Enum(opts),
                    help: None,
                    default: None,
                })
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<ArgSpec, A::Error> {
                let mut type_str: Option<String> = None;
                let mut help: Option<String> = None;
                let mut default: Option<String> = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "type" => type_str = Some(map.next_value()?),
                        "help" => help = Some(map.next_value()?),
                        "default" => default = Some(map.next_value()?),
                        _ => {
                            map.next_value::<de::IgnoredAny>()?; // skip unknown
                        }
                    }
                }
                let s =
                    type_str.ok_or_else(|| de::Error::custom("expected `type` key in table"))?;
                let spec = ArgSchema::try_from(s.as_str()).map_err(de::Error::custom)?;
                if let Some(default) = &default {
                    // Validate default
                    spec.parse(default).map_err(de::Error::custom)?;
                }

                Ok(ArgSpec {
                    spec,
                    help,
                    default,
                })
            }
        }

        d.deserialize_any(TaskArgVisitor)
    }
}

impl serde::Serialize for ArgSpec {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if let Some(help) = &self.help {
            use serde::ser::SerializeMap;
            let mut map = s.serialize_map(None)?;
            map.serialize_entry("type", &self.spec.as_type_string())?;
            map.serialize_entry("help", help)?;
            map.end()
        } else {
            self.spec.serialize(s)
        }
    }
}

/// A set of arguments defined together.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ArgsSpec(pub HashMap<String, ArgSpec>);

impl ArgsSpec {
    /// Returns true if no arguments are defined.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Hydrates the table of toml values against the argument schema, returning an [ArgsSet] if valid.
    pub fn from_toml(&self, table: &toml::Table) -> Result<ArgsSet, String> {
        let scalar_from_toml = |v: &toml::Value,
                                p: &PrimitiveSpec,
                                name: &str|
         -> Result<ScalarArg, String> {
            match (v, p) {
                (toml::Value::String(s), PrimitiveSpec::String) => Ok(ScalarArg::String(s.clone())),
                (toml::Value::Integer(i), PrimitiveSpec::Number) => {
                    Ok(ScalarArg::Number(*i as f64))
                }
                (toml::Value::Float(f), PrimitiveSpec::Number) => Ok(ScalarArg::Number(*f)),
                (toml::Value::Boolean(b), PrimitiveSpec::Boolean) => Ok(ScalarArg::Boolean(*b)),
                (toml::Value::Datetime(dt), PrimitiveSpec::String) => {
                    Ok(ScalarArg::String(dt.to_string()))
                }
                _ => Err(format!("argument `{name}`: expected {p}, got `{v}`")),
            }
        };

        let mut out = HashMap::with_capacity(self.0.len());
        for (name, spec) in self.0.iter() {
            let v = match (table.get(name), &spec.default) {
                (None, None) => return Err(format!("missing argument {name}")),
                (None, Some(default)) => {
                    out.insert(name.clone(), spec.spec.parse(default)?);
                    continue;
                }
                (Some(v), _) => v,
            };

            let arg = match &spec.spec {
                ArgSchema::Scalar(p) => Arg::Scalar(scalar_from_toml(v, p, name)?),
                ArgSchema::Array(p) => {
                    let arr = v
                        .as_array()
                        .ok_or_else(|| format!("argument `{name}`: expected array, got `{v}`"))?;
                    let items: Result<Vec<ScalarArg>, String> = arr
                        .iter()
                        .map(|elem| scalar_from_toml(elem, p, name))
                        .collect();
                    Arg::Array(items?)
                }
                ArgSchema::Enum(permitted) => {
                    let s = v.as_str().ok_or_else(|| {
                        format!("argument `{name}`: expected string for enum, got `{v}`")
                    })?;
                    if !permitted.contains(s) {
                        return Err(format!(
                            "argument `{name}`: `{s}` is not a valid enum value"
                        ));
                    }
                    Arg::Enum(s.to_string())
                }
            };
            out.insert(name.clone(), arg);
        }
        Ok(ArgsSet(out))
    }

    /// Parse a CLI argument string (e.g. `"--count 42 --name foo"`) according
    /// to this schema, returning the parsed values as a map of argument names
    /// to [Arg] values.
    ///
    /// Shell quoting is handled via `shlex`.
    pub fn parse(&self, args: &str) -> Result<ArgsSet, clap::Error> {
        let argv = shlex::split(args).ok_or_else(|| {
            clap::Command::new("task").no_binary_name(true).error(
                clap::error::ErrorKind::InvalidValue,
                "invalid shell quoting",
            )
        })?;
        self.parse_argv_named("task", argv)
    }

    /// Parse pre-split CLI arguments according to this schema, returning the
    /// parsed values as a map of argument names to [Arg] values.
    ///
    /// Equivalent to [`parse_argv_named`](Self::parse_argv_named) with a
    /// display name of `"task"`.
    pub fn parse_argv<I, T>(&self, args: I) -> Result<ArgsSet, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        self.parse_argv_named("task", args)
    }

    /// Parse pre-split CLI arguments according to this schema, returning the
    /// parsed values as a map of argument names to [Arg] values.
    ///
    /// `display_name` controls the program name shown in clap's usage/error
    /// output (e.g. `"minimal run smoketest"`).
    ///
    /// Each top-level arg in the schema becomes a single `--name` flag.
    ///
    /// ## CLI mapping
    ///
    /// | Schema | CLI | Result |
    /// |--------|-----|--------|
    /// | `arg = "string"` | `--arg foo` | `Arg::Scalar(ScalarArg::String("foo"))` |
    /// | `arg = "number"` | `--arg 42` | `Arg::Scalar(ScalarArg::Number(42.0))` |
    /// | `arg = "boolean"` | `--arg true` | `Arg::Scalar(ScalarArg::Boolean(true))` |
    /// | `arg = "Array string"` | `--arg a --arg b` | `Arg::Array(vec![..])` |
    /// | `arg = "Array number"` | `--arg 1 --arg 2` | `Arg::Array(vec![..])` |
    /// | `arg = "[a, b]"` | `--arg a` | `Arg::Enum("a")` |
    pub fn parse_argv_named<I, T>(
        &self,
        display_name: &str,
        args: I,
    ) -> Result<ArgsSet, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        use clap::{Arg as ClapArg, ArgAction, Command};

        // Build a clap command. One flag per top-level arg name.
        let mut cmd = Command::new(display_name.to_string()).no_binary_name(true);
        for (n, ta) in self.0.iter() {
            let mut arg = ClapArg::new(n.clone())
                .long(n.clone())
                .required(ta.default.is_none())
                .action(match &ta.spec {
                    ArgSchema::Array(_) => ArgAction::Append,
                    _ => ArgAction::Set,
                });
            if let ArgSchema::Enum(opts) = &ta.spec {
                arg = arg.value_parser(opts.iter().cloned().collect::<Vec<_>>());
            }
            cmd = cmd.arg(arg);
        }

        let matches = cmd.clone().try_get_matches_from(args)?;

        // Helper to produce a clap value-validation error.
        let val_err = |msg: String| cmd.clone().error(clap::error::ErrorKind::InvalidValue, msg);

        let mut result = HashMap::new();
        for (name, ta) in self.0.iter() {
            if !matches.contains_id(name)
                && let Some(default) = &ta.default
            {
                result.insert(name.clone(), ta.spec.parse(default).map_err(&val_err)?);
                continue;
            }

            match &ta.spec {
                ArgSchema::Scalar(p) => {
                    if let Some(raw) = matches.get_one::<String>(name) {
                        result.insert(name.clone(), Arg::Scalar(p.parse(raw).map_err(&val_err)?));
                    }
                }
                ArgSchema::Array(p) => {
                    if let Some(values) = matches.get_many::<String>(name) {
                        let arr: Result<Vec<ScalarArg>, clap::Error> =
                            values.map(|v| p.parse(v).map_err(&val_err)).collect();
                        result.insert(name.clone(), Arg::Array(arr?));
                    }
                }
                ArgSchema::Enum(_) => {
                    if let Some(raw) = matches.get_one::<String>(name) {
                        result.insert(name.clone(), Arg::Enum(raw.clone()));
                    }
                }
            }
        }

        Ok(ArgsSet(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;

    /// Helper: a minimal TOML table with an `args` field, used to deserialize
    /// a [TaskArgs] without depending on the `mfile` crate's `Task` type.
    #[derive(serde::Deserialize)]
    struct ArgsOnly {
        #[serde(default)]
        args: ArgsSpec,
    }

    #[test]
    fn deser_types() {
        // Short-form scalars and arrays
        let t: ArgsOnly = toml::from_str(indoc! {r#"
            args.name = "string"
            args.tags = "Array number"
            args.enum = "[a, b, c-eeee]"
            args.input = {type = "string", help = "something", default = "c"}
        "#})
        .unwrap();
        assert_eq!(
            t.args.0.get("name").unwrap().spec,
            ArgSchema::Scalar(PrimitiveSpec::String)
        );
        assert_eq!(
            t.args.0.get("tags").unwrap().spec,
            ArgSchema::Array(PrimitiveSpec::Number)
        );
        assert_eq!(
            t.args.0.get("input").unwrap(),
            &ArgSpec {
                spec: ArgSchema::Scalar(PrimitiveSpec::String),
                help: Some("something".to_string()),
                default: Some("c".to_string()),
            }
        );
        assert_eq!(
            t.args.0.get("enum").unwrap().spec,
            ArgSchema::Enum(BTreeSet::from_iter(
                vec!["a".to_string(), "b".to_string(), "c-eeee".to_string()].into_iter()
            ))
        );
    }

    #[test]
    fn deser_enum_from_array() {
        let t: ArgsOnly = toml::from_str(indoc! {r#"
            args.mode = ["debug", "release"]
        "#})
        .unwrap();
        assert_eq!(
            t.args.0.get("mode").unwrap().spec,
            ArgSchema::Enum(BTreeSet::from(
                ["debug".to_string(), "release".to_string(),]
            ))
        );
    }

    #[test]
    fn parse_cli_args() {
        let t: ArgsOnly = toml::from_str(indoc! {r#"
            args.name = "string"
            args.count = "number"
            args.verbose = "boolean"
            args.tags = "Array string"
            args.enum = "[a, b]"
            args.default_str = {type = "string", default = ""}
        "#})
        .unwrap();

        let result = t
            .args
            .parse("--name hello --count 42 --verbose true --tags a --tags b --enum a")
            .unwrap();
        assert_eq!(
            result.as_ref().get("name").unwrap(),
            &Arg::Scalar(ScalarArg::String("hello".to_string()))
        );
        assert_eq!(
            result.as_ref().get("count").unwrap(),
            &Arg::Scalar(ScalarArg::Number(42.0))
        );
        assert_eq!(
            result.as_ref().get("enum").unwrap(),
            &Arg::Enum("a".to_string())
        );
        assert_eq!(
            result.as_ref().get("verbose").unwrap(),
            &Arg::Scalar(ScalarArg::Boolean(true))
        );
        assert_eq!(
            result.as_ref().get("tags").unwrap(),
            &Arg::Array(vec![
                ScalarArg::String("a".to_string()),
                ScalarArg::String("b".to_string()),
            ])
        );
        assert_eq!(
            result.as_ref().get("default_str").unwrap(),
            &Arg::Scalar(ScalarArg::String("".to_string()))
        );
    }

    #[test]
    fn parse_errors() {
        let t: ArgsOnly = toml::from_str(indoc! {r#"
            args.name = "string"
            args.flag = "boolean"
            args.enum = "[a, b]"
        "#})
        .unwrap();

        // Missing required arg
        assert!(t.args.parse("--name hello").is_err());
        // Unknown flag
        assert!(t.args.parse("--name hello --flag true --bogus x").is_err());
        // Invalid boolean
        assert!(t.args.parse("--name hello --flag yes").is_err());
        // Invalid enum
        assert!(t.args.parse("--name hello --flag true --enum c").is_err());
    }

    #[test]
    fn parse_enum_spec_basic() {
        let opts = parse_enum_schema("[a, b, c]").unwrap();
        assert_eq!(
            opts,
            BTreeSet::from(["a".to_string(), "b".to_string(), "c".to_string()])
        );
    }

    #[test]
    fn parse_enum_spec_quoted() {
        let opts = parse_enum_schema(r#"["hello world", "foo,] bar", baz]"#).unwrap();
        assert_eq!(
            opts,
            BTreeSet::from([
                "hello world".to_string(),
                "foo,] bar".to_string(),
                "baz".to_string(),
            ])
        );
    }

    #[test]
    fn parse_enum_spec_whitespace() {
        let opts = parse_enum_schema("[  alpha ,  beta  , gamma  ]").unwrap();
        assert_eq!(
            opts,
            BTreeSet::from(["alpha".to_string(), "beta".to_string(), "gamma".to_string(),])
        );
    }

    #[test]
    fn parse_enum_spec_single() {
        let opts = parse_enum_schema("[only]").unwrap();
        assert_eq!(opts, BTreeSet::from(["only".to_string()]));
    }

    #[test]
    fn parse_enum_spec_errors() {
        assert!(parse_enum_schema("not brackets").is_err());
        assert!(parse_enum_schema("[]").is_err());
        assert!(parse_enum_schema("[a, , b]").is_err());
        assert!(parse_enum_schema(r#"["unterminated]"#).is_err());
    }

    #[test]
    fn argschema_parse() {
        assert_eq!(
            ArgSchema::Array(PrimitiveSpec::String)
                .parse("[hello, world]")
                .unwrap(),
            Arg::Array(vec![
                ScalarArg::String("hello".to_string()),
                ScalarArg::String("world".to_string()),
            ])
        );

        assert_eq!(
            ArgSchema::Array(PrimitiveSpec::Number)
                .parse("[1, 2.5, 3]")
                .unwrap(),
            Arg::Array(vec![
                ScalarArg::Number(1.0),
                ScalarArg::Number(2.5),
                ScalarArg::Number(3.0),
            ])
        );
        // Quoted values with commas
        assert_eq!(
            ArgSchema::Array(PrimitiveSpec::String)
                .parse(r#"["hello, world", foo]"#)
                .unwrap(),
            Arg::Array(vec![
                ScalarArg::String("hello, world".to_string()),
                ScalarArg::String("foo".to_string()),
            ])
        );

        // Empty array
        assert_eq!(
            ArgSchema::Array(PrimitiveSpec::Number).parse("[]").unwrap(),
            Arg::Array(vec![])
        );
        // Invalid number in array
        assert!(
            ArgSchema::Array(PrimitiveSpec::Number)
                .parse("[1, abc]")
                .is_err()
        );

        // booleans
        assert_eq!(
            ArgSchema::Scalar(PrimitiveSpec::Boolean)
                .parse("true")
                .unwrap(),
            Arg::Scalar(ScalarArg::Boolean(true)),
        );
        assert_eq!(
            ArgSchema::Scalar(PrimitiveSpec::Boolean)
                .parse("false")
                .unwrap(),
            Arg::Scalar(ScalarArg::Boolean(false)),
        );

        // strings
        assert_eq!(
            ArgSchema::Scalar(PrimitiveSpec::String)
                .parse("true")
                .unwrap(),
            Arg::Scalar(ScalarArg::String("true".to_string())),
        );

        // enums
        assert_eq!(
            ArgSchema::Enum(["a".to_string(), "b".to_string()].into())
                .parse("a")
                .unwrap(),
            Arg::Enum("a".to_string())
        );
        assert_eq!(
            ArgSchema::Enum(["a".to_string(), "b".to_string()].into())
                .parse("b")
                .unwrap(),
            Arg::Enum("b".to_string())
        );
        assert!(
            ArgSchema::Enum(["a".to_string(), "b".to_string()].into())
                .parse("c")
                .is_err()
        );
    }

    #[test]
    fn argsspec_from_toml() {
        let spec: ArgsOnly = toml::from_str(indoc! {r#"
            args.name = "string"
            args.count = "number"
            args.verbose = "boolean"
            args.tags = "Array string"
            args.mode = "[debug, release]"
            args.default_enum = {type = "[x, y]", default = "x"}
            args.default_str = {type = "string", default = "fallback"}
        "#})
        .unwrap();

        // All explicit values provided.
        let values: toml::Value = toml::from_str(indoc! {r#"
            name = "hello"
            count = 42
            verbose = true
            tags = ["a", "b"]
            mode = "release"
        "#})
        .unwrap();
        let result = spec.args.from_toml(values.as_table().unwrap()).unwrap();

        assert_eq!(
            result.as_ref().get("name").unwrap(),
            &Arg::Scalar(ScalarArg::String("hello".to_string()))
        );
        assert_eq!(
            result.as_ref().get("count").unwrap(),
            &Arg::Scalar(ScalarArg::Number(42.0))
        );
        assert_eq!(
            result.as_ref().get("verbose").unwrap(),
            &Arg::Scalar(ScalarArg::Boolean(true))
        );
        assert_eq!(
            result.as_ref().get("tags").unwrap(),
            &Arg::Array(vec![
                ScalarArg::String("a".to_string()),
                ScalarArg::String("b".to_string()),
            ])
        );
        assert_eq!(
            result.as_ref().get("mode").unwrap(),
            &Arg::Enum("release".to_string())
        );
        // Defaults should be filled in.
        assert_eq!(
            result.as_ref().get("default_enum").unwrap(),
            &Arg::Enum("x".to_string())
        );
        assert_eq!(
            result.as_ref().get("default_str").unwrap(),
            &Arg::Scalar(ScalarArg::String("fallback".to_string()))
        );

        // Float number.
        let values: toml::Value = toml::from_str(indoc! {r#"
            name = "hi"
            count = 3.15
            verbose = false
            tags = []
            mode = "debug"
        "#})
        .unwrap();
        let result = spec.args.from_toml(values.as_table().unwrap()).unwrap();
        assert_eq!(
            result.as_ref().get("count").unwrap(),
            &Arg::Scalar(ScalarArg::Number(3.15))
        );
        assert_eq!(
            result.as_ref().get("verbose").unwrap(),
            &Arg::Scalar(ScalarArg::Boolean(false))
        );
        assert_eq!(result.as_ref().get("tags").unwrap(), &Arg::Array(vec![]));

        // Missing required arg is an error.
        let values: toml::Value = toml::from_str("name = \"hi\"\n").unwrap();
        assert!(spec.args.from_toml(values.as_table().unwrap()).is_err());

        // Invalid enum value is an error.
        let values: toml::Value = toml::from_str(indoc! {r#"
            name = "hi"
            count = 1
            verbose = true
            tags = []
            mode = "profile"
        "#})
        .unwrap();
        assert!(spec.args.from_toml(values.as_table().unwrap()).is_err());

        // Type mismatch (string where number expected) is an error.
        let values: toml::Value = toml::from_str(indoc! {r#"
            name = "hi"
            count = "not a number"
            verbose = true
            tags = []
            mode = "debug"
        "#})
        .unwrap();
        assert!(spec.args.from_toml(values.as_table().unwrap()).is_err());
    }

    #[test]
    fn argspec_try_from_enum() {
        let spec = ArgSchema::try_from("[debug, release]").unwrap();
        assert_eq!(
            spec,
            ArgSchema::Enum(BTreeSet::from(
                ["debug".to_string(), "release".to_string(),]
            ))
        );
    }
}
