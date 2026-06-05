//! Types for defining the schema of arguments of `mfile::Task` & parameters to sideloads.
//!
//!  * [Arg] / [ScalarArg]: A concrete argument value.
//!  * [ArgSchema]: The type of an argument.
//!  * [ArgSpec]: The type of an argument, combined with metadata such as help text.
//!    [ArgSpec::parse] can be used to parse a string representing the invocation of
//!    these arguments into their concrete values.
//!  * [ArgsSpec]: Newtype around a map of argument names to [ArgSpec] (schema) descriptions.
//!  * [ArgsSet]: A concrete set of arguments, effectively a Newtype of `HashMap<String, Arg>`.
//!
//! ## Usage
//!
//! ### Loading argument schema
//!
//! The argument schema is typically defined in some config file. Represent the schema of
//! arguments by having a field in your config file of type [ArgsSpec], which implements the
//! serde traits.
//!
//! ```rust
//! # use args::ArgsSpec;
//! let schema: ArgsSpec = toml::from_str("name = \"string\"").unwrap();
//! ```
//!
//! ### Hydrating arguments from a config file
//!
//! Use the [DiskArg] type to capture arguments specified in a config file:
//!
//! ```rust
//! # use std::collections::HashMap;
//! # use args::DiskArg;
//! #[derive(serde::Deserialize)]
//! struct MyConfig {
//!   args: HashMap<String, DiskArg>,
//! }
//! ```
//!
//! You can then hydrate a map of [DiskArg]'s against an [ArgsSpec]:
//!
//! ```rust
//! # use std::collections::HashMap;
//! # use args::{DiskArg, ArgsSpec};
//! # let args = HashMap::from_iter([("name".to_string(), DiskArg::String("a".to_string()))]);
//! let schema: ArgsSpec = toml::from_str("name = \"string\"").unwrap();
//! schema.from_deserialized(&args);
//! ```
//! ### Hydrating arguments from a command-line invocation
//!
//! Use [ArgsSet::parse] to parse the arguments section of a command-line invocartion:
//!
//! ```rust
//! # use std::collections::HashMap;
//! # use args::{DiskArg, ArgsSpec};
//! let schema: ArgsSpec = toml::from_str("name = \"string\"").unwrap();
//! schema.parse("--name hello"); // Ok(ArgsSet)
//! ```

use std::{
    collections::{BTreeSet, HashMap},
    hash::Hash,
};

use clap::builder::StyledStr;

/// A set of arguments, already validated against a corresponding schema.
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

/// A deserialized argument value captured without schema knowledge.
///
/// When deserializing argument values from a configuration file (TOML, JSON, etc.),
/// the schema is not yet available, so the concrete type cannot be validated. `DiskArg`
/// captures the raw value as-is and can later be validated against an [`ArgsSpec`] via
/// [`ArgsSpec::from_deserialized`].
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum DiskArg {
    Boolean(bool),
    Integer(i64),
    Float(f64),
    String(String),
    Array(Vec<DiskArg>),
}

impl Hash for DiskArg {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            DiskArg::Boolean(b) => {
                state.write_u8(0); // Type marker
                b.hash(state);
            }
            DiskArg::Integer(i) => {
                state.write_u8(1); // Type marker
                i.hash(state);
            }
            DiskArg::Float(f) => {
                state.write_u8(2); // Type marker
                f.to_le_bytes().hash(state);
            }
            DiskArg::String(s) => {
                state.write_u8(3); // Type marker
                s.hash(state);
            }
            DiskArg::Array(a) => {
                state.write_u8(4); // Type marker
                state.write_u64(a.len() as u64);
                a.iter().for_each(|e| e.hash(state));
            }
        }
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
    /// Returns this value as a Nickel value, suitable for use in an
    /// initial-env binding.
    pub fn to_nickel(&self) -> nickel_lang_core::eval::value::NickelValue {
        use nickel_lang_core::eval::value::NickelValue;
        match self {
            ScalarArg::String(s) => NickelValue::string_posless(s.as_str()),
            ScalarArg::Number(f) => {
                NickelValue::number_posless(nickel_lang_core::term::Number::try_from(*f).unwrap())
            }
            ScalarArg::Boolean(b) => NickelValue::bool_value_posless(*b),
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
    /// Returns this value as a Nickel value, suitable for use in an
    /// initial-env binding.
    pub fn to_nickel(&self) -> nickel_lang_core::eval::value::NickelValue {
        use nickel_lang_core::eval::value::{Array, NickelValue};
        match self {
            Arg::Scalar(s) => s.to_nickel(),
            Arg::Enum(s) => NickelValue::string_posless(s.as_str()),
            Arg::Array(items) => NickelValue::array_posless(
                Array::from_iter(items.iter().map(ScalarArg::to_nickel)),
                Vec::new(),
            ),
        }
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

/// A set of argument schemas defined together.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ArgsSpec(pub HashMap<String, ArgSpec>);

impl ArgsSpec {
    /// Returns true if no arguments are defined.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Hydrates a map of deserialized [`DiskArg`] values against the argument schema,
    /// returning an [`ArgsSet`] if valid.
    ///
    /// This is the format-agnostic equivalent of [`from_toml`](Self::from_toml):
    /// the caller deserializes a `HashMap<String, DiskArg>` from any serde-supported
    /// format (TOML, JSON, YAML, …) and this method validates and converts the values.
    pub fn from_deserialized(&self, values: &HashMap<String, DiskArg>) -> Result<ArgsSet, String> {
        let scalar_from_disk = |v: &DiskArg,
                                p: &PrimitiveSpec,
                                name: &str|
         -> Result<ScalarArg, String> {
            match (v, p) {
                (DiskArg::String(s), PrimitiveSpec::String) => Ok(ScalarArg::String(s.clone())),
                (DiskArg::Integer(i), PrimitiveSpec::Number) => Ok(ScalarArg::Number(*i as f64)),
                (DiskArg::Float(f), PrimitiveSpec::Number) => Ok(ScalarArg::Number(*f)),
                (DiskArg::Boolean(b), PrimitiveSpec::Boolean) => Ok(ScalarArg::Boolean(*b)),
                _ => Err(format!("argument `{name}`: expected {p}, got {v:?}")),
            }
        };

        let mut out = HashMap::with_capacity(self.0.len());
        for (name, spec) in self.0.iter() {
            let v = match (values.get(name), &spec.default) {
                (None, None) => return Err(format!("missing argument {name}")),
                (None, Some(default)) => {
                    out.insert(name.clone(), spec.spec.parse(default)?);
                    continue;
                }
                (Some(v), _) => v,
            };

            let arg = match &spec.spec {
                ArgSchema::Scalar(p) => Arg::Scalar(scalar_from_disk(v, p, name)?),
                ArgSchema::Array(p) => {
                    let arr = match v {
                        DiskArg::Array(arr) => arr,
                        _ => return Err(format!("argument `{name}`: expected array, got {v:?}")),
                    };
                    let items: Result<Vec<ScalarArg>, String> = arr
                        .iter()
                        .map(|elem| scalar_from_disk(elem, p, name))
                        .collect();
                    Arg::Array(items?)
                }
                ArgSchema::Enum(permitted) => {
                    let s = match v {
                        DiskArg::String(s) => s,
                        _ => {
                            return Err(format!(
                                "argument `{name}`: expected string for enum, got {v:?}"
                            ));
                        }
                    };
                    if !permitted.contains(s.as_str()) {
                        return Err(format!(
                            "argument `{name}`: `{s}` is not a valid enum value"
                        ));
                    }
                    Arg::Enum(s.clone())
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
        let cmd = self.as_clap_cmd(display_name)?;
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

    /// Returns the usage string describing the arguments as a command invocation.
    pub fn cmd_usage(&self, display_name: &str) -> Result<StyledStr, clap::Error> {
        Ok(self.as_clap_cmd(display_name)?.render_usage())
    }

    fn as_clap_cmd(&self, display_name: &str) -> Result<clap::Command, clap::Error> {
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
        Ok(cmd)
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
    fn disk_arg_deserialize() {
        // DiskArg should capture values from TOML without schema knowledge.
        let raw: HashMap<String, DiskArg> = toml::from_str(indoc! {r#"
            name = "hello"
            count = 42
            ratio = 2.72
            verbose = true
            tags = ["a", "b"]
        "#})
        .unwrap();

        assert_eq!(raw.get("name").unwrap(), &DiskArg::String("hello".into()));
        assert_eq!(raw.get("count").unwrap(), &DiskArg::Integer(42));
        assert_eq!(raw.get("ratio").unwrap(), &DiskArg::Float(2.72));
        assert_eq!(raw.get("verbose").unwrap(), &DiskArg::Boolean(true));
        assert_eq!(
            raw.get("tags").unwrap(),
            &DiskArg::Array(vec![
                DiskArg::String("a".into()),
                DiskArg::String("b".into()),
            ])
        );
    }

    #[test]
    fn argsspec_from_deserialized() {
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
        let values: HashMap<String, DiskArg> = toml::from_str(indoc! {r#"
            name = "hello"
            count = 42
            verbose = true
            tags = ["a", "b"]
            mode = "release"
        "#})
        .unwrap();
        let result = spec.args.from_deserialized(&values).unwrap();

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
        // Defaults filled in.
        assert_eq!(
            result.as_ref().get("default_enum").unwrap(),
            &Arg::Enum("x".to_string())
        );
        assert_eq!(
            result.as_ref().get("default_str").unwrap(),
            &Arg::Scalar(ScalarArg::String("fallback".to_string()))
        );

        // Float number.
        let values: HashMap<String, DiskArg> = toml::from_str(indoc! {r#"
            name = "hi"
            count = 3.15
            verbose = false
            tags = []
            mode = "debug"
        "#})
        .unwrap();
        let result = spec.args.from_deserialized(&values).unwrap();
        assert_eq!(
            result.as_ref().get("count").unwrap(),
            &Arg::Scalar(ScalarArg::Number(3.15))
        );

        // Missing required arg is an error.
        let values: HashMap<String, DiskArg> = toml::from_str("name = \"hi\"\n").unwrap();
        assert!(spec.args.from_deserialized(&values).is_err());

        // Invalid enum value is an error.
        let values: HashMap<String, DiskArg> = toml::from_str(indoc! {r#"
            name = "hi"
            count = 1
            verbose = true
            tags = []
            mode = "profile"
        "#})
        .unwrap();
        assert!(spec.args.from_deserialized(&values).is_err());

        // Type mismatch (string where number expected) is an error.
        let values: HashMap<String, DiskArg> = toml::from_str(indoc! {r#"
            name = "hi"
            count = "not a number"
            verbose = true
            tags = []
            mode = "debug"
        "#})
        .unwrap();
        assert!(spec.args.from_deserialized(&values).is_err());
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
