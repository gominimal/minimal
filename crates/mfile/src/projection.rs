//! The Box Spec projection and its digest (BOX-071).
//!
//! The projection is the Gatehouse §6.3.2 record of an expanded spec: the
//! fields a verifier checks a box against, under §6.3.2's field names. The
//! client and the daemon both build it from the spec, and both digest it.
//! The daemon stores its own digest beside the client's in the box's
//! record.
//!
//! The record holds exactly these fields:
//!
//! | field | from the spec |
//! |---|---|
//! | `v` | [`PROJECTION_VERSION`] |
//! | `type.name`, `type.source`, `type.root` | the box's type ([`TypeFacts`]) |
//! | `type.registry` | only when `type.source` is `org` |
//! | `network.mode` | `network.mode` |
//! | `network.egress_dns` | `network.egress.allow_dns_hosts` |
//! | `network.egress_subnets` | `network.egress.allow_subnets` |
//! | `network.egress_deny_subnets` | `network.egress.deny_subnets` |
//! | `network.ingress_ports` | `network.ingress` |
//! | `network.quic443` | `network.quic443`, `auto` when omitted |
//! | `bep.steering` | `network.bep.steering`, `dns` when omitted |
//! | `registry_pinned`, `registry_commit` | `upstream.commit` |
//! | `loadout_mode` | `loadout_mode` or `box.loadout_mode` |
//! | `pty_enabled` | `pty_enabled` or `io.pty_enabled` |
//! | `lifetime` | `lifetime` or `box.lifetime` |
//! | `nesting` | the `[nesting]` bounds |
//! | `secret_grants` | `[secrets]`, each `github:*` grant with its `mode` |
//!
//! `network.egress.allow_protocols` is in no field: the node enforces it
//! unprojected. Every other key of the spec is outside the record, so a
//! change to it leaves the digest as it was.
//!
//! The digest is SHA-256 over the record's RFC 8785 (JCS) bytes, encoded
//! as base64url with no padding.

use std::collections::BTreeMap;

use base64::Engine as _;
use sha2::{Digest as _, Sha256};

use crate::box_types::{ResolvedType, builtin};

/// The version of the projection record, its `v` field.
pub const PROJECTION_VERSION: i64 = 1;

/// Where a Box Type is defined: its `type.source` in the projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeSource {
    /// One of the built-in types.
    Builtin,
    /// A `[box_types.<name>]` of the project file.
    Project,
    /// An organization registry. No resolver gives this source yet.
    Org,
}

impl TypeSource {
    /// The word the projection writes.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            TypeSource::Builtin => "builtin",
            TypeSource::Project => "project",
            TypeSource::Org => "org",
        }
    }
}

/// The type facts the projection carries: the `type` field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeFacts {
    /// The type's name.
    pub name: String,
    /// Where the type is defined.
    pub source: TypeSource,
    /// The built-in type the type is built on. A built-in is its own root.
    pub root: String,
    /// The registry of an `org` type. Projected only for that source.
    pub registry: Option<String>,
}

impl TypeFacts {
    /// The facts of a type that the client resolved.
    #[must_use]
    pub fn of_resolved(resolved: &ResolvedType) -> Self {
        let source = if builtin(&resolved.name).is_some() {
            TypeSource::Builtin
        } else {
            TypeSource::Project
        };
        Self {
            name: resolved.name.clone(),
            source,
            root: resolved.root.to_owned(),
            registry: None,
        }
    }

    /// The facts that `spec` itself states: the type is `box.type`, else
    /// `default_type`. This is the rule that the daemon's admission check
    /// reads, so the digest names the type that admission checked. A built-in
    /// type is its own root. A project type takes its root from
    /// `type.root`.
    ///
    /// `None` when the type is not a built-in and the spec names no
    /// built-in `type.root`, or when a built-in type names another root.
    #[must_use]
    pub fn of_spec(spec: &toml::Table, default_type: &str) -> Option<Self> {
        let name = spec
            .get("box")
            .and_then(toml::Value::as_table)
            .and_then(|b| b.get("type"))
            .and_then(toml::Value::as_str)
            .unwrap_or(default_type)
            .to_owned();
        let stated_root = spec
            .get("type")
            .and_then(toml::Value::as_table)
            .and_then(|t| t.get("root"))
            .and_then(toml::Value::as_str);
        let (source, root) = match builtin(&name) {
            Some(own) => match stated_root {
                Some(root) if root != own => return None,
                _ => (TypeSource::Builtin, own),
            },
            None => (TypeSource::Project, builtin(stated_root?)?),
        };
        Some(Self {
            name,
            source,
            root: root.to_owned(),
            registry: None,
        })
    }
}

/// The `github_token_mode` of the built-in type `root`: `user` for
/// `session`, `agent` and `task`, and `installation` for `service`,
/// `build` and `container-build`. `None` for a name that is not a
/// built-in type.
#[must_use]
pub fn builtin_token_mode(root: &str) -> Option<&'static str> {
    match root {
        "session" | "agent" | "task" => Some("user"),
        "service" | "build" | "container-build" => Some("installation"),
        _ => None,
    }
}

/// The `network.quic443` that an omitted value means.
pub const DEFAULT_QUIC443: &str = "auto";

/// The `network.bep.steering` that an omitted value means.
pub const DEFAULT_STEERING: &str = "dns";

/// Whether a `[secrets]` entry asks for a `github:` scope.
fn is_github_grant(grant: &toml::Table) -> bool {
    grant
        .get("scopes")
        .and_then(toml::Value::as_array)
        .is_some_and(|scopes| {
            scopes
                .iter()
                .filter_map(toml::Value::as_str)
                .any(|scope| scope.starts_with("github:"))
        })
}

/// The token mode that fills a `github:*` grant with no `mode`: the
/// spec's `github_token_mode`, else the built-in default of `root`.
fn token_mode<'a>(spec: &'a toml::Table, root: &str) -> Option<&'a str> {
    spec.get("github_token_mode")
        .and_then(toml::Value::as_str)
        .or_else(|| builtin_token_mode(root))
}

/// Fills the values that an omitted key means, so the digest binds the
/// effective values (BOX-071): each `github:*` grant of `[secrets]` with
/// no `mode` takes the token mode of the type, whose built-in root is
/// `root`, and an omitted `network.quic443` and `network.bep.steering`
/// take [`DEFAULT_QUIC443`] and [`DEFAULT_STEERING`]. A value the spec
/// sets is kept. Filling a filled spec changes nothing.
pub fn fill_effective(spec: &mut toml::Table, root: &str) {
    if let Some(mode) = token_mode(spec, root).map(str::to_owned)
        && let Some(secrets) = spec.get_mut("secrets").and_then(toml::Value::as_table_mut)
    {
        for grant in secrets.iter_mut().filter_map(|(_, v)| v.as_table_mut()) {
            if is_github_grant(grant) && !grant.contains_key("mode") {
                grant.insert("mode".to_owned(), toml::Value::String(mode.clone()));
            }
        }
    }
    let network = spec
        .entry("network")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()));
    let Some(network) = network.as_table_mut() else {
        return;
    };
    network
        .entry("quic443")
        .or_insert_with(|| toml::Value::String(DEFAULT_QUIC443.to_owned()));
    let bep = network
        .entry("bep")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()));
    if let Some(bep) = bep.as_table_mut() {
        bep.entry("steering")
            .or_insert_with(|| toml::Value::String(DEFAULT_STEERING.to_owned()));
    }
}

/// A JSON value of the projection record. It has no decimal numbers: no
/// field of the record takes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Json {
    /// `null`: a field whose source the spec does not set.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A whole number.
    Int(i64),
    /// A string.
    Str(String),
    /// An array, in its order.
    List(Vec<Json>),
    /// An object.
    Object(BTreeMap<String, Json>),
}

impl Json {
    /// The value at `key` of an object, or `None`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(map) => map.get(key),
            _ => None,
        }
    }

    /// The RFC 8785 (JCS) serialization of the value: no whitespace, the
    /// members of each object in the order of their names' UTF-16 code
    /// units, and each string escaped as JCS states.
    #[must_use]
    pub fn jcs(&self) -> String {
        let mut out = String::new();
        self.write_jcs(&mut out);
        out
    }

    fn write_jcs(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Int(n) => out.push_str(&n.to_string()),
            Json::Str(s) => write_jcs_string(s, out),
            Json::List(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write_jcs(out);
                }
                out.push(']');
            }
            Json::Object(map) => {
                let mut members: Vec<(&String, &Json)> = map.iter().collect();
                members.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
                out.push('{');
                for (i, (name, value)) in members.into_iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_jcs_string(name, out);
                    out.push(':');
                    value.write_jcs(out);
                }
                out.push('}');
            }
        }
    }

    /// The value of a TOML value. A date or time becomes its string, and
    /// a decimal number its shortest string, as no projected field takes
    /// either.
    fn of_toml(value: &toml::Value) -> Self {
        match value {
            toml::Value::String(s) => Json::Str(s.clone()),
            toml::Value::Integer(n) => Json::Int(*n),
            toml::Value::Float(f) => Json::Str(f.to_string()),
            toml::Value::Boolean(b) => Json::Bool(*b),
            toml::Value::Datetime(d) => Json::Str(d.to_string()),
            toml::Value::Array(items) => Json::List(items.iter().map(Json::of_toml).collect()),
            toml::Value::Table(t) => Json::Object(
                t.iter()
                    .map(|(k, v)| (k.clone(), Json::of_toml(v)))
                    .collect(),
            ),
        }
    }
}

/// Writes `s` as a JCS string: `"` and `\` escaped, the control
/// characters with a short escape where JSON has one and `\u00xx` in
/// lower-case hex otherwise, and every other character as itself.
fn write_jcs_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// The §6.3.2 projection of one expanded spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Projection {
    /// The record, a JSON object of exactly the §6.3.2 fields.
    pub record: Json,
}

impl Projection {
    /// The record's RFC 8785 (JCS) bytes.
    #[must_use]
    pub fn jcs_bytes(&self) -> Vec<u8> {
        self.record.jcs().into_bytes()
    }

    /// SHA-256 over [`Self::jcs_bytes`], encoded as base64url with no
    /// padding.
    #[must_use]
    pub fn digest(&self) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(self.jcs_bytes()))
    }
}

/// The value at the dotted `path` of `spec`.
fn at<'a>(spec: &'a toml::Table, path: &[&str]) -> Option<&'a toml::Value> {
    let (last, parents) = path.split_last()?;
    let mut table = spec;
    for key in parents {
        table = table.get(*key)?.as_table()?;
    }
    table.get(*last)
}

/// The value of the first of `paths` that `spec` sets, or `null`.
fn first_of(spec: &toml::Table, paths: &[&[&str]]) -> Json {
    paths
        .iter()
        .find_map(|p| at(spec, p))
        .map_or(Json::Null, Json::of_toml)
}

/// The list at `path`, or an empty list when the spec sets none: an
/// absent allow list grants nothing.
fn list_at(spec: &toml::Table, path: &[&str]) -> Json {
    match at(spec, path) {
        Some(value) => Json::of_toml(value),
        None => Json::List(Vec::new()),
    }
}

/// The ports `network.ingress` admits, each its port number in the box,
/// in the spec's order (§6.3.2 `"ingress_ports": [8080]`). It reads the
/// `box.toml` list of `{ proto, port }` and the `port_mappings` of a v0
/// spec, whose port in the box is `internal_port`.
fn ingress_ports(spec: &toml::Table) -> Json {
    let port = |item: &toml::Table, key: &str| item.get(key).map_or(Json::Null, Json::of_toml);
    let ports = match at(spec, &["network", "ingress"]) {
        Some(toml::Value::Array(items)) => items
            .iter()
            .filter_map(toml::Value::as_table)
            .map(|item| port(item, "port"))
            .collect(),
        Some(toml::Value::Table(policy)) => policy
            .get("port_mappings")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(toml::Value::as_table)
            .map(|item| port(item, "internal_port"))
            .collect(),
        _ => Vec::new(),
    };
    Json::List(ports)
}

/// The `[nesting]` bounds that §6.3.2 projects. Any other key of the
/// table is not in the record.
const NESTING_BOUNDS: [&str; 5] = [
    "allowed",
    "max_depth",
    "types",
    "providers",
    "dynamic_providers",
];

/// The five `[nesting]` bounds, each `null` when the spec does not set it.
fn nesting(spec: &toml::Table) -> Json {
    let table = spec.get("nesting").and_then(toml::Value::as_table);
    Json::Object(
        NESTING_BOUNDS
            .iter()
            .map(|key| {
                let value = table
                    .and_then(|t| t.get(*key))
                    .map_or(Json::Null, Json::of_toml);
                ((*key).to_owned(), value)
            })
            .collect(),
    )
}

/// The grants of `[secrets]`, one object for each entry in name order,
/// each built from the §6.3.2 key set of its kind, never from the entry's
/// own keys. The entry's name is `env`. A `source = "store"` reference
/// carries `env`, `source`, `store`, `id`, `upstream` (a list of
/// authorities) and `inject`, as expansion wrote them. Every other grant
/// is brokered and carries `env`, `scopes`, and `mode` when it is set or
/// filled, and no `source`.
fn secret_grants(spec: &toml::Table) -> Json {
    let Some(secrets) = spec.get("secrets").and_then(toml::Value::as_table) else {
        return Json::List(Vec::new());
    };
    let mut names: Vec<&String> = secrets.keys().collect();
    names.sort();
    let empty = toml::Table::new();
    Json::List(
        names
            .into_iter()
            .map(|name| {
                let entry = secrets[name.as_str()].as_table().unwrap_or(&empty);
                let value = |key: &str| entry.get(key).map_or(Json::Null, Json::of_toml);
                let list = |key: &str| entry.get(key).map_or(Json::List(Vec::new()), Json::of_toml);
                let mut grant = BTreeMap::from([("env".to_owned(), Json::Str(name.clone()))]);
                if entry.get("source").and_then(toml::Value::as_str) == Some("store") {
                    grant.insert("source".to_owned(), Json::Str("store".to_owned()));
                    for key in ["store", "id", "inject"] {
                        grant.insert(key.to_owned(), value(key));
                    }
                    grant.insert("upstream".to_owned(), list("upstream"));
                } else {
                    grant.insert("scopes".to_owned(), list("scopes"));
                    if let Some(mode) = entry.get("mode") {
                        grant.insert("mode".to_owned(), Json::of_toml(mode));
                    }
                }
                Json::Object(grant)
            })
            .collect(),
    )
}

/// Why a spec that the daemon received has no projection digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecDigestError {
    /// The spec is not a table of TOML values: it is not an object, or it
    /// holds a value that TOML has no form for. A `null` inside the spec is
    /// not one of these: [`spec_digest`] reads it as an absent key.
    NotATable(String),
    /// The spec does not name its type's built-in root.
    NoRoot,
}

impl std::fmt::Display for SpecDigestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpecDigestError::NotATable(why) => {
                write!(f, "the spec is not a table of TOML values: {why}")
            }
            SpecDigestError::NoRoot => {
                f.write_str("the spec does not name its type's built-in root")
            }
        }
    }
}

impl std::error::Error for SpecDigestError {}

/// The projection digest of a spec as it arrived, read from any serde
/// form, such as the JSON of a create request (BOX-071). A `null` reads
/// as an absent key, as an absent value is what a JSON writer leaves as
/// `null`. The type is the spec's own, as [`TypeFacts::of_spec`] reads
/// it, with `default_type` for a spec that names none.
///
/// # Errors
///
/// [`SpecDigestError`] when the spec is not a table of TOML values, or
/// does not name its type's built-in root.
pub fn spec_digest<'de, D: serde::Deserializer<'de>>(
    spec: D,
    default_type: &str,
) -> Result<String, SpecDigestError> {
    let loose = <Loose as serde::Deserialize>::deserialize(spec)
        .map_err(|e| SpecDigestError::NotATable(e.to_string()))?;
    let Some(toml::Value::Table(table)) = loose.into_toml() else {
        return Err(SpecDigestError::NotATable("it is not an object".to_owned()));
    };
    let facts = TypeFacts::of_spec(&table, default_type).ok_or(SpecDigestError::NoRoot)?;
    Ok(project(&table, &facts).digest())
}

/// A value of any self-describing serde form, `null` included.
enum Loose {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    List(Vec<Loose>),
    Map(Vec<(String, Loose)>),
}

impl Loose {
    /// The TOML value, or `None` for a `null`. A `null` in a list or a
    /// table is left out.
    fn into_toml(self) -> Option<toml::Value> {
        Some(match self {
            Loose::Null => return None,
            Loose::Bool(b) => toml::Value::Boolean(b),
            Loose::Int(n) => toml::Value::Integer(n),
            Loose::Float(f) => toml::Value::Float(f),
            Loose::Str(s) => toml::Value::String(s),
            Loose::List(items) => {
                toml::Value::Array(items.into_iter().filter_map(Loose::into_toml).collect())
            }
            Loose::Map(pairs) => toml::Value::Table(
                pairs
                    .into_iter()
                    .filter_map(|(k, v)| Some((k, v.into_toml()?)))
                    .collect(),
            ),
        })
    }
}

impl<'de> serde::Deserialize<'de> for Loose {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visit;
        impl<'de> serde::de::Visitor<'de> for Visit {
            type Value = Loose;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a spec value")
            }
            fn visit_unit<E>(self) -> Result<Loose, E> {
                Ok(Loose::Null)
            }
            fn visit_none<E>(self) -> Result<Loose, E> {
                Ok(Loose::Null)
            }
            fn visit_some<D: serde::Deserializer<'de>>(self, d: D) -> Result<Loose, D::Error> {
                serde::Deserialize::deserialize(d)
            }
            fn visit_bool<E>(self, v: bool) -> Result<Loose, E> {
                Ok(Loose::Bool(v))
            }
            fn visit_i64<E>(self, v: i64) -> Result<Loose, E> {
                Ok(Loose::Int(v))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Loose, E> {
                i64::try_from(v)
                    .map(Loose::Int)
                    .map_err(|_| E::custom(format!("{v} is too large for a spec number")))
            }
            fn visit_f64<E>(self, v: f64) -> Result<Loose, E> {
                Ok(Loose::Float(v))
            }
            fn visit_str<E>(self, v: &str) -> Result<Loose, E> {
                Ok(Loose::Str(v.to_owned()))
            }
            fn visit_string<E>(self, v: String) -> Result<Loose, E> {
                Ok(Loose::Str(v))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Loose, A::Error> {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element()? {
                    items.push(item);
                }
                Ok(Loose::List(items))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Loose, A::Error> {
                let mut pairs = Vec::new();
                while let Some((k, v)) = map.next_entry::<String, Loose>()? {
                    pairs.push((k, v));
                }
                Ok(Loose::Map(pairs))
            }
        }
        deserializer.deserialize_any(Visit)
    }
}

/// Builds the §6.3.2 projection of `spec`, a box of the type `facts`
/// names (BOX-071).
///
/// The values that an omitted key means are filled first, as
/// [`fill_effective`] does, so a spec that expansion filled and one that
/// it did not project the same record.
#[must_use]
pub fn project(spec: &toml::Table, facts: &TypeFacts) -> Projection {
    let mut spec = spec.clone();
    fill_effective(&mut spec, &facts.root);
    let spec = &spec;
    let obj = |pairs: Vec<(&str, Json)>| {
        Json::Object(pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
    };

    let mut type_fields = vec![
        ("name", Json::Str(facts.name.clone())),
        ("source", Json::Str(facts.source.word().to_owned())),
        ("root", Json::Str(facts.root.clone())),
    ];
    if facts.source == TypeSource::Org {
        let registry = facts.registry.clone().map_or(Json::Null, Json::Str);
        type_fields.push(("registry", registry));
    }

    let network = obj(vec![
        ("mode", first_of(spec, &[&["network", "mode"]])),
        (
            "egress_dns",
            list_at(spec, &["network", "egress", "allow_dns_hosts"]),
        ),
        (
            "egress_subnets",
            list_at(spec, &["network", "egress", "allow_subnets"]),
        ),
        (
            "egress_deny_subnets",
            list_at(spec, &["network", "egress", "deny_subnets"]),
        ),
        ("ingress_ports", ingress_ports(spec)),
        ("quic443", first_of(spec, &[&["network", "quic443"]])),
    ]);
    let bep = obj(vec![(
        "steering",
        first_of(spec, &[&["network", "bep", "steering"]]),
    )]);

    let commit = at(spec, &["upstream", "commit"]).and_then(toml::Value::as_str);

    let record = obj(vec![
        ("v", Json::Int(PROJECTION_VERSION)),
        ("type", obj(type_fields)),
        ("network", network),
        ("bep", bep),
        ("registry_pinned", Json::Bool(commit.is_some())),
        (
            "registry_commit",
            commit.map_or(Json::Null, |c| Json::Str(c.to_owned())),
        ),
        (
            "loadout_mode",
            first_of(spec, &[&["loadout_mode"], &["box", "loadout_mode"]]),
        ),
        (
            "pty_enabled",
            first_of(spec, &[&["pty_enabled"], &["io", "pty_enabled"]]),
        ),
        (
            "lifetime",
            first_of(spec, &[&["lifetime"], &["box", "lifetime"]]),
        ),
        ("nesting", nesting(spec)),
        ("secret_grants", secret_grants(spec)),
    ]);
    Projection { record }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn table(src: &str) -> toml::Table {
        toml::from_str(src).expect("the test spec parses")
    }

    fn session() -> TypeFacts {
        TypeFacts::of_spec(&toml::Table::new(), "session").expect("session is built in")
    }

    /// A spec that sets every source of the record, and keys outside it.
    const FULL: &str = r#"
        type = "session"
        packages = ["git"]
        loadout_mode = "open"
        pty_enabled = true
        lifetime = "until_stopped"

        [upstream]
        repo_url = "https://example.com/registry"
        commit = "0123abcd"

        [network]
        mode = "own_ip"
        quic443 = "block"
        ingress = [{ proto = "tcp", port = 8080 }]

        [network.egress]
        allow_dns_hosts = ["example.com"]
        allow_subnets = ["10.0.0.0/8"]
        deny_subnets = ["10.1.0.0/16"]
        allow_protocols = ["tcp"]

        [network.bep]
        steering = "both"
        proxy_env = true

        [nesting]
        allowed = true
        max_depth = 2

        [secrets.GH]
        source = "broker"
        scopes = ["github:repo:read"]

        [secrets.NPM]
        source = "store"
        store = "keychain"
        id = "npm-token"
        upstream = ["registry.npmjs.org"]
        inject = { header = "Authorization", prefix = "Bearer " }
    "#;

    fn names(value: &Json) -> Vec<&str> {
        match value {
            Json::Object(map) => map.keys().map(String::as_str).collect(),
            _ => Vec::new(),
        }
    }

    // BOX-071: the record is exactly the §6.3.2 field set, under its
    // names, with the nested egress keys mapped onto them, and
    // `allow_protocols` in no field. The digest is base64url SHA-256 over
    // the JCS bytes.
    #[test]
    fn projection_is_the_6_3_2_field_set() {
        let p = project(&table(FULL), &session());
        let r = &p.record;
        let mut top = names(r);
        top.sort_unstable();
        assert_eq!(
            top,
            [
                "bep",
                "lifetime",
                "loadout_mode",
                "nesting",
                "network",
                "pty_enabled",
                "registry_commit",
                "registry_pinned",
                "secret_grants",
                "type",
                "v",
            ]
        );
        let mut net = names(r.get("network").unwrap());
        net.sort_unstable();
        assert_eq!(
            net,
            [
                "egress_deny_subnets",
                "egress_dns",
                "egress_subnets",
                "ingress_ports",
                "mode",
                "quic443",
            ]
        );
        assert_eq!(
            names(r.get("type").unwrap()),
            ["name", "root", "source"],
            "type.registry is only for an org type"
        );
        let n = r.get("network").unwrap();
        let s = |v: &str| Json::Str(v.to_owned());
        assert_eq!(
            n.get("egress_dns"),
            Some(&Json::List(vec![s("example.com")]))
        );
        assert_eq!(
            n.get("egress_subnets"),
            Some(&Json::List(vec![s("10.0.0.0/8")]))
        );
        assert_eq!(
            n.get("egress_deny_subnets"),
            Some(&Json::List(vec![s("10.1.0.0/16")]))
        );
        assert_eq!(n.get("quic443"), Some(&s("block")));
        assert_eq!(r.get("bep").unwrap().get("steering"), Some(&s("both")));
        assert_eq!(r.get("registry_pinned"), Some(&Json::Bool(true)));
        assert_eq!(r.get("registry_commit"), Some(&s("0123abcd")));
        assert_eq!(r.get("v"), Some(&Json::Int(PROJECTION_VERSION)));
        let jcs = p.record.jcs();
        assert!(!jcs.contains("allow_protocols"), "{jcs}");
        assert!(!jcs.contains("proxy_env"), "{jcs}");
        assert!(!jcs.contains("packages"), "{jcs}");
        assert!(
            jcs.starts_with("{\"bep\":{\"steering\":\"both\"},\"lifetime\""),
            "{jcs}"
        );
        assert_eq!(
            p.digest(),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(jcs.as_bytes()))
        );
        assert_eq!(p.digest().len(), 43);

        // Each admitted port is its number.
        assert_eq!(
            n.get("ingress_ports"),
            Some(&Json::List(vec![Json::Int(8080)]))
        );

        // Each grant is the §6.3.2 key set of its kind, its name as `env`.
        let Some(Json::List(grants)) = r.get("secret_grants") else {
            panic!("secret_grants is a list: {r:?}");
        };
        let keys: Vec<Vec<&str>> = grants.iter().map(names).collect();
        assert_eq!(
            keys,
            [
                vec!["env", "mode", "scopes"],
                vec!["env", "id", "inject", "source", "store", "upstream"],
            ]
        );
        assert_eq!(grants[0].get("env"), Some(&s("GH")));
        assert_eq!(grants[0].get("mode"), Some(&s("user")), "filled");
        assert_eq!(grants[1].get("env"), Some(&s("NPM")));
        assert_eq!(
            grants[1].get("upstream"),
            Some(&Json::List(vec![s("registry.npmjs.org")]))
        );
        // A key the entry sets outside its kind's set is not projected.
        let mut extra = table(FULL);
        extra["secrets"]["GH"]
            .as_table_mut()
            .unwrap()
            .insert("note".to_owned(), toml::Value::String("x".to_owned()));
        assert_eq!(project(&extra, &session()).digest(), p.digest());

        // `nesting` is exactly the five bounds. Another key of `[nesting]`
        // leaves the digest unchanged.
        let mut bounds = names(r.get("nesting").unwrap());
        bounds.sort_unstable();
        assert_eq!(
            bounds,
            [
                "allowed",
                "dynamic_providers",
                "max_depth",
                "providers",
                "types"
            ]
        );
        assert_eq!(
            r.get("nesting").unwrap().get("max_depth"),
            Some(&Json::Int(2))
        );
        assert_eq!(r.get("nesting").unwrap().get("types"), Some(&Json::Null));
        let mut extra = table(FULL);
        extra["nesting"]
            .as_table_mut()
            .unwrap()
            .insert("comment".to_owned(), toml::Value::String("x".to_owned()));
        assert_eq!(project(&extra, &session()).digest(), p.digest());

        // A v0 spec states its ingress as the policy's port mappings.
        let v0 = table(
            "[network.ingress]\nport_mappings = [{ external_port = 9000, \
             internal_port = 8080, proto = \"tcp\" }]\n",
        );
        let v0 = project(&v0, &session());
        assert_eq!(
            v0.record.get("network").unwrap().get("ingress_ports"),
            n.get("ingress_ports")
        );

        // An org type carries its registry.
        let org = TypeFacts {
            name: "ci".to_owned(),
            source: TypeSource::Org,
            root: "task".to_owned(),
            registry: Some("acme".to_owned()),
        };
        assert_eq!(
            names(project(&table(FULL), &org).record.get("type").unwrap()),
            ["name", "registry", "root", "source"]
        );
    }

    #[test]
    fn jcs_orders_by_utf16_and_escapes_controls() {
        let mut map = BTreeMap::new();
        map.insert("\u{e000}".to_owned(), Json::Int(1));
        map.insert("\u{1f600}".to_owned(), Json::Int(2));
        map.insert("a\"\\\n\u{1}".to_owned(), Json::Str("é/".to_owned()));
        let jcs = Json::Object(map).jcs();
        assert_eq!(
            jcs,
            "{\"a\\\"\\\\\\n\\u0001\":\"é/\",\"\u{1f600}\":2,\"\u{e000}\":1}"
        );
    }

    #[test]
    fn type_facts_of_spec_reads_box_type_and_root() {
        let t = TypeFacts::of_spec(&table("[box]\ntype = \"task\"\n"), "session").unwrap();
        assert_eq!((t.name.as_str(), t.root.as_str()), ("task", "task"));
        assert_eq!(t.source, TypeSource::Builtin);
        let p = TypeFacts::of_spec(
            &table("[box]\ntype = \"ci\"\n[type]\nroot = \"task\"\n"),
            "session",
        )
        .unwrap();
        assert_eq!((p.source, p.root.as_str()), (TypeSource::Project, "task"));
        assert!(TypeFacts::of_spec(&table("[box]\ntype = \"ci\"\n"), "session").is_none());
        // A flat `type` string is not the box's type: admission reads
        // only `box.type`, so the digest does too.
        let flat = TypeFacts::of_spec(&table("type = \"task\"\n"), "session").unwrap();
        assert_eq!(flat.name, "session");
        assert!(
            TypeFacts::of_spec(
                &table("[box]\ntype = \"task\"\n[type]\nroot = \"session\"\n"),
                "s"
            )
            .is_none()
        );
    }

    /// The keys outside the record that a change can touch, and the keys
    /// inside it, each with a value to set.
    const OUTSIDE: &[(&[&str], &str)] = &[
        (&["network", "egress", "allow_protocols"], "udp"),
        (&["packages"], "ripgrep"),
        (&["network", "bep", "no_proxy"], "localhost"),
        (&["description"], "changed"),
    ];
    const INSIDE: &[(&[&str], &str)] = &[
        (
            &["network", "egress", "allow_dns_hosts"],
            "other-host.example",
        ),
        (&["network", "egress", "deny_subnets"], "10.9.0.0/16"),
        (&["network", "quic443"], "allow"),
        (&["network", "bep", "steering"], "proxy_env"),
        (&["lifetime"], "until_complete"),
        (&["upstream", "commit"], "ffff"),
    ];

    fn set(spec: &mut toml::Table, path: &[&str], word: &str, list: bool) {
        let (last, parents) = path.split_last().unwrap();
        let mut t = spec;
        for key in parents {
            t = t
                .entry(*key)
                .or_insert_with(|| toml::Value::Table(toml::Table::new()))
                .as_table_mut()
                .unwrap();
        }
        let value = toml::Value::String(word.to_owned());
        let value = if list {
            toml::Value::Array(vec![value])
        } else {
            value
        };
        t.insert((*last).to_owned(), value);
    }

    fn is_list(path: &[&str]) -> bool {
        matches!(
            path.last(),
            Some(
                &("allow_protocols" | "packages" | "no_proxy" | "allow_dns_hosts" | "deny_subnets")
            )
        )
    }

    proptest! {
        // BOX-071 (property): a change outside the §6.3.2 set, the
        // `allow_protocols` included, leaves the digest unchanged, and a
        // change inside it changes the digest.
        #[test]
        fn digest_binds_exactly_the_projected_fields(
            outside in 0..OUTSIDE.len(),
            inside in 0..INSIDE.len(),
            hosts in proptest::collection::vec("[a-z]{1,8}\\.example", 0..4),
        ) {
            let mut base = table(FULL);
            let list: Vec<toml::Value> = hosts.iter().cloned().map(toml::Value::String).collect();
            base["network"]["egress"].as_table_mut().unwrap()
                .insert("allow_dns_hosts".to_owned(), toml::Value::Array(list));
            let before = project(&base, &session()).digest();

            let mut out = base.clone();
            let (path, word) = OUTSIDE[outside];
            set(&mut out, path, word, is_list(path));
            prop_assert_eq!(project(&out, &session()).digest(), before.clone());

            let mut inn = base.clone();
            let (path, word) = INSIDE[inside];
            set(&mut inn, path, word, is_list(path));
            prop_assert_ne!(project(&inn, &session()).digest(), before);
        }
    }
}
