use std::collections::HashMap;

/// The leaf scalar types an argument can have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgPrimitive {
    String,
    Number,
    Boolean,
}

/// Argument type schema: a scalar or an array of scalars.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgSpec {
    /// A single scalar value: "string", "number", or "boolean".
    Scalar(ArgPrimitive),
    /// An array whose elements are the given primitive type.
    Array(ArgPrimitive),
}

impl TryFrom<&str> for ArgPrimitive {
    type Error = String;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s.to_ascii_lowercase().as_str() {
            "string" => Ok(ArgPrimitive::String),
            "number" => Ok(ArgPrimitive::Number),
            "boolean" | "bool" => Ok(ArgPrimitive::Boolean),
            other => Err(format!(
                "unknown type `{other}`, expected `string`, `number`, or `boolean`"
            )),
        }
    }
}

impl TryFrom<&str> for ArgSpec {
    type Error = String;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        if let Some(rest) = s
            .strip_prefix("Array ")
            .or_else(|| s.strip_prefix("array "))
        {
            Ok(ArgSpec::Array(ArgPrimitive::try_from(rest)?))
        } else {
            Ok(ArgSpec::Scalar(ArgPrimitive::try_from(s)?))
        }
    }
}

impl<'de> serde::Deserialize<'de> for ArgSpec {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::{self, MapAccess, Visitor};

        struct ArgSpecVisitor;

        impl<'de> Visitor<'de> for ArgSpecVisitor {
            type Value = ArgSpec;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(
                    f,
                    "a type string (\"string\", \"number\", \"boolean\", \"Array string\") or {{type = \"...\"}}"
                )
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<ArgSpec, E> {
                ArgSpec::try_from(v).map_err(de::Error::custom)
            }

            fn visit_string<E: de::Error>(self, v: String) -> Result<ArgSpec, E> {
                self.visit_str(&v)
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<ArgSpec, A::Error> {
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
                ArgSpec::try_from(s.as_str()).map_err(de::Error::custom)
            }
        }

        d.deserialize_any(ArgSpecVisitor)
    }
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

impl ArgSpec {
    /// Returns the string form of this spec (e.g. `"Array number"`).
    pub fn as_type_string(&self) -> String {
        match self {
            ArgSpec::Scalar(p) => p.to_string(),
            ArgSpec::Array(p) => format!("Array {p}"),
        }
    }
}

impl serde::Serialize for ArgSpec {
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
pub struct TaskArg {
    pub spec: ArgSpec,
    pub help: Option<String>,
}

impl<'de> serde::Deserialize<'de> for TaskArg {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::{self, MapAccess, Visitor};

        struct TaskArgVisitor;

        impl<'de> Visitor<'de> for TaskArgVisitor {
            type Value = TaskArg;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(
                    f,
                    "a type string, or a table with `type` (and optional `help`)"
                )
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<TaskArg, E> {
                Ok(TaskArg {
                    spec: ArgSpec::try_from(v).map_err(de::Error::custom)?,
                    help: None,
                })
            }

            fn visit_string<E: de::Error>(self, v: String) -> Result<TaskArg, E> {
                self.visit_str(&v)
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<TaskArg, A::Error> {
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
                let spec = ArgSpec::try_from(s.as_str()).map_err(de::Error::custom)?;
                Ok(TaskArg { spec, help })
            }
        }

        d.deserialize_any(TaskArgVisitor)
    }
}

impl serde::Serialize for TaskArg {
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

/// Arguments defined on a task.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TaskArgs(pub(crate) HashMap<String, TaskArg>);

/// How a particular arg should be collected from the CLI.
enum ArgKind {
    /// A single scalar: `--name foo` or `--count 42` or `--verbose true`.
    Scalar(ArgPrimitive),
    /// Repeated scalar: `--tag a --tag b` → array.
    ScalarArray(ArgPrimitive),
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

impl TaskArgs {
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

        // Classify each top-level arg.
        let arg_kinds: Vec<(String, ArgKind)> = self
            .0
            .iter()
            .map(|(name, ta)| {
                let kind = match &ta.spec {
                    ArgSpec::Scalar(p) => ArgKind::Scalar(p.clone()),
                    ArgSpec::Array(p) => ArgKind::ScalarArray(p.clone()),
                };
                (name.clone(), kind)
            })
            .collect();

        // Build a clap command. One flag per top-level arg name.
        // Clap requires 'static str for arg names; leak is fine for a
        // small, bounded set of names per task schema.
        let leaked_names: Vec<&'static str> = arg_kinds
            .iter()
            .map(|(n, _)| &*Box::leak(n.clone().into_boxed_str()))
            .collect();
        let leaked_display: &'static str = &*Box::leak(display_name.to_string().into_boxed_str());
        let mut cmd = Command::new(leaked_display).no_binary_name(true);
        for (i, (_, kind)) in arg_kinds.iter().enumerate() {
            let action = match kind {
                ArgKind::ScalarArray(_) => ArgAction::Append,
                _ => ArgAction::Set,
            };
            cmd = cmd.arg(
                Arg::new(leaked_names[i])
                    .long(leaked_names[i])
                    .required(true)
                    .action(action),
            );
        }

        let matches = cmd.clone().try_get_matches_from(args)?;

        // Helper to produce a clap value-validation error.
        let val_err = |msg: String| cmd.clone().error(clap::error::ErrorKind::InvalidValue, msg);

        // Reconstruct a toml table from the matches.
        let mut root = toml::map::Map::new();
        for (i, (name, kind)) in arg_kinds.iter().enumerate() {
            let cli_name = leaked_names[i];
            match kind {
                ArgKind::Scalar(p) => {
                    if let Some(raw) = matches.get_one::<String>(cli_name) {
                        root.insert(name.clone(), parse_primitive(raw, p).map_err(&val_err)?);
                    }
                }
                ArgKind::ScalarArray(p) => {
                    if let Some(values) = matches.get_many::<String>(cli_name) {
                        let arr: Result<Vec<toml::Value>, clap::Error> = values
                            .map(|v| parse_primitive(v, p).map_err(&val_err))
                            .collect();
                        root.insert(name.clone(), toml::Value::Array(arr?));
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

    #[test]
    fn deser_types() {
        use crate::Task;

        // Short-form scalars and arrays
        let t: Task = toml::from_str(indoc! {r#"
            exec = "echo"
            args.name = "string"
            args.tags = "Array number"
            args.input = {type = "string", help = "something"}
        "#})
        .unwrap();
        assert_eq!(
            t.args.0.get("name").unwrap().spec,
            ArgSpec::Scalar(ArgPrimitive::String)
        );
        assert_eq!(
            t.args.0.get("tags").unwrap().spec,
            ArgSpec::Array(ArgPrimitive::Number)
        );
        assert_eq!(
            t.args.0.get("input").unwrap(),
            &TaskArg {
                spec: ArgSpec::Scalar(ArgPrimitive::String),
                help: Some("something".to_string()),
            }
        );
    }

    #[test]
    fn parse_cli_args() {
        use crate::Task;

        let t: Task = toml::from_str(indoc! {r#"
            exec = "echo"
            args.name = "string"
            args.count = "number"
            args.verbose = "boolean"
            args.tags = "Array string"
        "#})
        .unwrap();

        let result = t
            .args
            .parse("--name hello --count 42 --verbose true --tags a --tags b")
            .unwrap();
        let table = result.as_table().unwrap();
        assert_eq!(table.get("name").unwrap().as_str().unwrap(), "hello");
        assert_eq!(table.get("count").unwrap().as_integer().unwrap(), 42);
        assert!(table.get("verbose").unwrap().as_bool().unwrap());
        let arr = table.get("tags").unwrap().as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0].as_str().unwrap(), "a");
    }

    #[test]
    fn parse_errors() {
        use crate::Task;

        let t: Task = toml::from_str(indoc! {r#"
            exec = "echo"
            args.name = "string"
            args.flag = "boolean"
        "#})
        .unwrap();

        // Missing required arg
        assert!(t.args.parse("--name hello").is_err());
        // Unknown flag
        assert!(t.args.parse("--name hello --flag true --bogus x").is_err());
        // Invalid boolean
        assert!(t.args.parse("--name hello --flag yes").is_err());
    }
}
