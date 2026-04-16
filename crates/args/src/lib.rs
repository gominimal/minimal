//! Typed arguments support for tasks & sideloads.

use std::collections::{BTreeSet, HashMap};

/// The leaf scalar types an argument can have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgPrimitive {
    String,
    Number,
    Boolean,
}

impl std::fmt::Display for ArgPrimitive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArgPrimitive::String => f.write_str("string"),
            ArgPrimitive::Number => f.write_str("number"),
            ArgPrimitive::Boolean => f.write_str("boolean"),
        }
    }
}

impl TryFrom<&str> for ArgPrimitive {
    type Error = ();
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s.to_ascii_lowercase().as_str() {
            "string" => Ok(ArgPrimitive::String),
            "number" => Ok(ArgPrimitive::Number),
            "boolean" | "bool" => Ok(ArgPrimitive::Boolean),
            _ => Err(()),
        }
    }
}

/// Parse a string value into a [toml::Value] according to the given primitive type.
fn parse_primitive(s: &str, p: &ArgPrimitive) -> Result<toml::Value, String> {
    match p {
        ArgPrimitive::String => Ok(toml::Value::String(s.to_string())),
        ArgPrimitive::Number => {
            if let Ok(i) = s.parse::<i64>() {
                Ok(toml::Value::Integer(i))
            } else if let Ok(f) = s.parse::<f64>() {
                Ok(toml::Value::Float(f))
            } else {
                Err(format!("expected a number, got `{s}`"))
            }
        }
        ArgPrimitive::Boolean => match s {
            "true" => Ok(toml::Value::Boolean(true)),
            "false" => Ok(toml::Value::Boolean(false)),
            _ => Err(format!("expected `true` or `false`, got `{s}`")),
        },
    }
}

/// The type an argument can have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgSchema {
    /// A single scalar value: "string", "number", or "boolean".
    Scalar(ArgPrimitive),
    /// An array whose elements are the given primitive type.
    Array(ArgPrimitive),
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
                ArgPrimitive::try_from(rest)
                    .map_err(|_| format!("invalid array primitive `{rest}`"))?,
            ));
        }
        if let Ok(primitive) = ArgPrimitive::try_from(s) {
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
                        map.next_value::<toml::Value>()?; // skip unknown
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

/// Parse an enum spec string of the form `[opt1, opt2, "opt 3"]` into its options.
///
/// Whitespace around options is trimmed. Options may optionally be quoted with
/// double quotes, which allows commas and leading/trailing whitespace within a
/// value. Returns an error if the input is not wrapped in `[]` or contains
/// malformed quoting.
fn parse_enum_schema(s: &str) -> Result<BTreeSet<String>, String> {
    let s = s.trim();
    let inner = s
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or_else(|| format!("enum spec must be wrapped in `[]`, got `{s}`"))?;

    let mut opts = BTreeSet::new();
    let mut chars = inner.chars().peekable();

    loop {
        // Skip leading whitespace before the next option.
        while chars.peek() == Some(&' ') || chars.peek() == Some(&'\t') {
            chars.next();
        }

        // End of input — we're done.
        if chars.peek().is_none() {
            break;
        }

        let value = if chars.peek() == Some(&'"') {
            // Quoted option: consume until the closing `"`.
            chars.next(); // opening quote
            let mut buf = String::new();
            loop {
                match chars.next() {
                    Some('"') => break,
                    Some(c) => buf.push(c),
                    None => return Err("unterminated quote in enum spec".to_string()),
                }
            }
            buf
        } else {
            // Unquoted option: consume until `,` or end.
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
                return Err("empty option in enum spec".to_string());
            }
            trimmed
        };

        opts.insert(value);

        // Skip whitespace after the value, then expect `,` or end.
        while chars.peek() == Some(&' ') || chars.peek() == Some(&'\t') {
            chars.next();
        }
        match chars.peek() {
            Some(&',') => {
                chars.next();
            }
            Some(c) => return Err(format!("unexpected character `{c}` in enum spec")),
            None => break,
        }
    }

    if opts.is_empty() {
        return Err("enum spec must contain at least one option".to_string());
    }

    Ok(opts)
}

impl serde::Serialize for ArgSchema {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.as_type_string())
    }
}

/// A single argument definition: the type schema plus optional metadata like `help`.
///
/// Deserializes from either:
/// - A string: `"string"` → `TaskArg { spec: Scalar(String), help: None }`
/// - A table with `type`: `{type = "string", help = "something"}` → `TaskArg { spec: .., help: Some(..) }`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgSpec {
    pub spec: ArgSchema,
    pub help: Option<String>,
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
                })
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<ArgSpec, A::Error> {
                let mut type_str: Option<String> = None;
                let mut help: Option<String> = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "type" => type_str = Some(map.next_value()?),
                        "help" => help = Some(map.next_value()?),
                        _ => {
                            map.next_value::<toml::Value>()?; // skip unknown
                        }
                    }
                }
                let s =
                    type_str.ok_or_else(|| de::Error::custom("expected `type` key in table"))?;
                let spec = ArgSchema::try_from(s.as_str()).map_err(de::Error::custom)?;
                Ok(ArgSpec { spec, help })
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
pub struct ArgSet(pub HashMap<String, ArgSpec>);

impl ArgSet {
    /// Returns true if no arguments are defined.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Parse a CLI argument string (e.g. `"--count 42 --name foo"`) according
    /// to this schema, returning the parsed values as a [toml::Value::Table].
    ///
    /// Shell quoting is handled via `shlex`.
    pub fn parse(&self, args: &str) -> Result<toml::Value, clap::Error> {
        let argv = shlex::split(args).ok_or_else(|| {
            clap::Command::new("task").no_binary_name(true).error(
                clap::error::ErrorKind::InvalidValue,
                "invalid shell quoting",
            )
        })?;
        self.parse_argv_named("task", argv)
    }

    /// Parse pre-split CLI arguments according to this schema, returning the
    /// parsed values as a [toml::Value::Table].
    ///
    /// Equivalent to [`parse_argv_named`](Self::parse_argv_named) with a
    /// display name of `"task"`.
    pub fn parse_argv<I, T>(&self, args: I) -> Result<toml::Value, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        self.parse_argv_named("task", args)
    }

    /// Parse pre-split CLI arguments according to this schema, returning the
    /// parsed values as a [toml::Value::Table].
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
    /// | `arg = "string"` | `--arg foo` | `arg = "foo"` |
    /// | `arg = "number"` | `--arg 42` | `arg = 42` |
    /// | `arg = "boolean"` | `--arg true` | `arg = true` |
    /// | `arg = "Array string"` | `--arg a --arg b` | `arg = ["a", "b"]` |
    /// | `arg = "Array number"` | `--arg 1 --arg 2` | `arg = [1, 2]` |
    /// | `arg = "[a, b]"` | `--arg a` | `arg = a` |
    pub fn parse_argv_named<I, T>(
        &self,
        display_name: &str,
        args: I,
    ) -> Result<toml::Value, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        use clap::{Arg, ArgAction, Command};

        // Build a clap command. One flag per top-level arg name.
        let mut cmd = Command::new(display_name.to_string()).no_binary_name(true);
        for (n, ta) in self.0.iter() {
            let mut arg =
                Arg::new(n.clone())
                    .long(n.clone())
                    .required(true)
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

        // Reconstruct a toml table from the matches.
        let mut root = toml::map::Map::new();
        for (name, ta) in self.0.iter() {
            match &ta.spec {
                ArgSchema::Scalar(p) => {
                    if let Some(raw) = matches.get_one::<String>(name) {
                        root.insert(name.clone(), parse_primitive(raw, p).map_err(&val_err)?);
                    }
                }
                ArgSchema::Array(p) => {
                    if let Some(values) = matches.get_many::<String>(name) {
                        let arr: Result<Vec<toml::Value>, clap::Error> = values
                            .map(|v| parse_primitive(v, p).map_err(&val_err))
                            .collect();
                        root.insert(name.clone(), toml::Value::Array(arr?));
                    }
                }
                ArgSchema::Enum(_) => {
                    if let Some(raw) = matches.get_one::<String>(name) {
                        root.insert(
                            name.clone(),
                            parse_primitive(raw, &ArgPrimitive::String).map_err(&val_err)?,
                        );
                    }
                }
            }
        }

        Ok(toml::Value::Table(root))
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
        args: ArgSet,
    }

    #[test]
    fn deser_types() {
        // Short-form scalars and arrays
        let t: ArgsOnly = toml::from_str(indoc! {r#"
            args.name = "string"
            args.tags = "Array number"
            args.enum = "[a, b, c-eeee]"
            args.input = {type = "string", help = "something"}
        "#})
        .unwrap();
        assert_eq!(
            t.args.0.get("name").unwrap().spec,
            ArgSchema::Scalar(ArgPrimitive::String)
        );
        assert_eq!(
            t.args.0.get("tags").unwrap().spec,
            ArgSchema::Array(ArgPrimitive::Number)
        );
        assert_eq!(
            t.args.0.get("input").unwrap(),
            &ArgSpec {
                spec: ArgSchema::Scalar(ArgPrimitive::String),
                help: Some("something".to_string()),
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
        "#})
        .unwrap();

        let result = t
            .args
            .parse("--name hello --count 42 --verbose true --tags a --tags b --enum a")
            .unwrap();
        let table = result.as_table().unwrap();
        assert_eq!(table.get("name").unwrap().as_str().unwrap(), "hello");
        assert_eq!(table.get("count").unwrap().as_integer().unwrap(), 42);
        assert_eq!(table.get("enum").unwrap().as_str().unwrap(), "a");
        assert!(table.get("verbose").unwrap().as_bool().unwrap());
        let arr = table.get("tags").unwrap().as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0].as_str().unwrap(), "a");
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
