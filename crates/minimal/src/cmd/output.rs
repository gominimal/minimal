//! The one writer for what a `min` command renders: the `min/v1/<type>`
//! objects of `-o json` and `-o jsonl`, the text form beside them, the
//! machine-mode error object on stderr, and secrets as references.
//!
//! BCLI-033: every object a machine mode writes carries a `schema` field
//! `min/v1/<type>`. The stamp is added here, by [`write_object`] and
//! [`write_objects`], so a command never spells its own schema string.
//!
//! BCLI-063: a secret-bearing field holds a [`Secret`]. Its value is never
//! reachable from a rendering: serde writes the reference, and so do
//! `Display` and `Debug`. Every output mode goes through those three, so no
//! output mode writes a secret's value.

use std::io::Write;

use serde::{Serialize, Serializer};

/// The output mode a command renders in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    /// Text for a person, the default.
    Text,
    /// `-o json`: one JSON document on stdout.
    Json,
    /// `-o jsonl`: one JSON object on each line.
    Jsonl,
}

impl OutputMode {
    /// Every mode, for the code and tests that must cover each of them.
    pub const ALL: [Self; 3] = [Self::Text, Self::Json, Self::Jsonl];

    /// Whether the mode is a machine mode, whose failure is one error
    /// object on stderr.
    #[must_use]
    pub fn is_machine(self) -> bool {
        !matches!(self, Self::Text)
    }
}

/// The types of object the machine modes write (BCLI-033). Each one is
/// stamped `min/v1/<type>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectType {
    Box,
    Event,
    Error,
    Type,
    Host,
    Provider,
    Spec,
    /// One exec in the exec listing of `min box show`.
    Exec,
}

impl ObjectType {
    /// Every object type.
    pub const ALL: [Self; 8] = [
        Self::Box,
        Self::Event,
        Self::Error,
        Self::Type,
        Self::Host,
        Self::Provider,
        Self::Spec,
        Self::Exec,
    ];

    /// The `schema` field value: `min/v1/<type>`.
    #[must_use]
    pub fn schema(self) -> &'static str {
        match self {
            Self::Box => "min/v1/box",
            Self::Event => "min/v1/event",
            Self::Error => "min/v1/error",
            Self::Type => "min/v1/type",
            Self::Host => "min/v1/host",
            Self::Provider => "min/v1/provider",
            Self::Spec => "min/v1/spec",
            Self::Exec => "min/v1/exec",
        }
    }
}

/// An object a command renders. Its serde form is the body of the machine
/// object (a struct or a map, so the stamp can sit beside its fields), and
/// [`Rendered::text`] is its text form.
pub trait Rendered: Serialize {
    /// The object's type, which names its schema.
    const TYPE: ObjectType;

    /// Write the text form. A secret-bearing field writes its [`Secret`]
    /// through `Display`, which writes the reference.
    ///
    /// # Errors
    /// The writer's error.
    fn text(&self, out: &mut dyn Write) -> std::io::Result<()>;
}

/// An object with its schema stamp first, then its own fields.
#[derive(Serialize)]
struct Stamped<'a, T: Serialize> {
    schema: &'static str,
    #[serde(flatten)]
    body: &'a T,
}

fn stamped<T: Rendered>(object: &T) -> Stamped<'_, T> {
    Stamped {
        schema: T::TYPE.schema(),
        body: object,
    }
}

fn encode_error(e: serde_json_lenient::Error) -> std::io::Error {
    std::io::Error::other(e)
}

/// Write one object in `mode`: its text form, one pretty JSON document, or
/// one JSON line. Both machine forms carry the `schema` stamp.
///
/// # Errors
/// The writer's error, or an object that does not encode as a JSON object.
pub fn write_object<T: Rendered>(
    out: &mut dyn Write,
    mode: OutputMode,
    object: &T,
) -> std::io::Result<()> {
    match mode {
        OutputMode::Text => object.text(out),
        OutputMode::Json => {
            let doc =
                serde_json_lenient::to_string_pretty(&stamped(object)).map_err(encode_error)?;
            writeln!(out, "{doc}")
        }
        OutputMode::Jsonl => {
            let line = serde_json_lenient::to_string(&stamped(object)).map_err(encode_error)?;
            writeln!(out, "{line}")
        }
    }
}

/// Write a listing in `mode`: each object's text form, one JSON array of
/// stamped objects, or one stamped JSON line for each object.
///
/// # Errors
/// The writer's error, or an object that does not encode as a JSON object.
pub fn write_objects<T: Rendered>(
    out: &mut dyn Write,
    mode: OutputMode,
    objects: &[T],
) -> std::io::Result<()> {
    match mode {
        OutputMode::Text | OutputMode::Jsonl => {
            for object in objects {
                write_object(out, mode, object)?;
            }
            Ok(())
        }
        OutputMode::Json => {
            let all: Vec<_> = objects.iter().map(stamped).collect();
            let doc = serde_json_lenient::to_string_pretty(&all).map_err(encode_error)?;
            writeln!(out, "{doc}")
        }
    }
}

/// A secret, as a rendered object holds it: the reference that names it,
/// and the value, which no rendering writes (BCLI-063).
///
/// The serde form is `{"ref": "<reference>"}`, so a reader can tell a
/// reference from a plain string. `Display` writes the reference, and
/// `Debug` writes the reference with the value redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret {
    reference: String,
    value: Option<String>,
}

impl Secret {
    /// A secret known only by its reference.
    #[must_use]
    pub fn reference_only(reference: impl Into<String>) -> Self {
        Self {
            reference: reference.into(),
            value: None,
        }
    }

    /// A secret whose value the command holds. The value stays in memory
    /// for the code that needs it, and never reaches the output.
    #[must_use]
    pub fn with_value(reference: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            reference: reference.into(),
            value: Some(value.into()),
        }
    }

    /// The reference for a `[secrets.<VAR>]` grant: `store:<store>/<id>`
    /// for a store item, `broker:<VAR>` for a broker grant and
    /// `env:<VAR>` for a copy of the client's variable.
    #[must_use]
    pub fn of_grant(name: &str, grant: &boxes::core::bep::SecretGrant) -> Self {
        use boxes::core::bep::GrantSource;
        Self::reference_only(match &grant.source {
            GrantSource::Store { store, id } => format!("store:{store}/{id}"),
            GrantSource::Broker => format!("broker:{name}"),
            GrantSource::ClientEnv => format!("env:{name}"),
        })
    }

    /// The reference that names the secret.
    #[must_use]
    pub fn reference(&self) -> &str {
        &self.reference
    }

    /// The value, for code that uses the secret. Never pass it to a writer.
    #[must_use]
    pub fn expose(&self) -> Option<&str> {
        self.value.as_deref()
    }
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap as _;
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry("ref", &self.reference)?;
        map.end()
    }
}

impl std::fmt::Display for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<secret {}>", self.reference)
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secret")
            .field("reference", &self.reference)
            .field("value", &self.value.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// The body of the `min/v1/error` object: `code`, `message` and `hint`,
/// each one always present. The hint is empty when nothing about the
/// failure names a remedy.
#[derive(Serialize)]
struct ErrorObject<'a> {
    code: &'a str,
    message: &'a str,
    hint: &'a str,
}

impl Rendered for ErrorObject<'_> {
    const TYPE: ObjectType = ObjectType::Error;

    fn text(&self, out: &mut dyn Write) -> std::io::Result<()> {
        writeln!(out, "error: {}", self.message)?;
        if !self.hint.is_empty() {
            writeln!(out, "hint: {}", self.hint)?;
        }
        Ok(())
    }
}

/// The machine-mode error object, as one line: the `min/v1/error` stamp,
/// `code`, `message` and `hint`.
///
/// # Errors
/// An encode failure, which the error object's plain strings cannot cause.
pub fn error_line(failure: &crate::MachineModeFailure) -> std::io::Result<String> {
    let mut line = Vec::new();
    write_error(&mut line, failure)?;
    Ok(String::from_utf8_lossy(&line).trim_end().to_owned())
}

/// Write the one `min/v1/error` object of a failed machine-mode run, as one
/// line on `err`, the run's stderr (BCLI-033). Nothing else goes there, and
/// nothing goes to stdout.
///
/// # Errors
/// The writer's error.
pub fn write_error(
    err: &mut dyn Write,
    failure: &crate::MachineModeFailure,
) -> std::io::Result<()> {
    let object = ErrorObject {
        code: failure.code(),
        message: failure.message(),
        hint: failure.hint(),
    };
    write_object(err, OutputMode::Jsonl, &object)
}

/// The slot for the root `cmd` span of this run, so a command records the
/// box id it resolved there, whatever span is current when it resolves it.
static ROOT_SPAN: std::sync::Mutex<Option<tracing::Span>> = std::sync::Mutex::new(None);

/// Keep `root` as the span that [`record_box_id`] records on, or, with
/// `None`, release it so the span can close.
pub(crate) fn set_root_span(root: Option<&tracing::Span>) {
    if let Ok(mut slot) = ROOT_SPAN.lock() {
        *slot = root.cloned();
    }
}

/// Record the id of the box a command resolved on the run's root `cmd`
/// span, beside its verb and outcome.
pub fn record_box_id(id: &str) {
    if let Ok(slot) = ROOT_SPAN.lock()
        && let Some(root) = slot.as_ref()
    {
        root.record("box_id", id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// A box object as a listing renders it, with one secret-bearing field.
    #[derive(Serialize)]
    struct BoxRow {
        id: String,
        name: String,
        token: Secret,
    }

    impl Rendered for BoxRow {
        const TYPE: ObjectType = ObjectType::Box;
        fn text(&self, out: &mut dyn Write) -> std::io::Result<()> {
            writeln!(out, "{}  {}  {}", self.id, self.name, self.token)
        }
    }

    /// An object of any type, for the stamp test.
    #[derive(Serialize)]
    struct Any {
        #[serde(skip)]
        ty: ObjectType,
        field: u32,
    }

    /// A spec object with a map of secrets, the way a spec's
    /// `[secrets.<VAR>]` table renders.
    #[derive(Serialize)]
    struct SpecDoc {
        name: String,
        secrets: std::collections::BTreeMap<String, Secret>,
    }

    impl Rendered for SpecDoc {
        const TYPE: ObjectType = ObjectType::Spec;
        fn text(&self, out: &mut dyn Write) -> std::io::Result<()> {
            writeln!(out, "{}", self.name)?;
            for (var, secret) in &self.secrets {
                writeln!(out, "  {var}  {secret}")?;
            }
            Ok(())
        }
    }

    /// An event object that carries a secret in a nested record.
    #[derive(Serialize)]
    struct EventDoc {
        kind: String,
        detail: Vec<Secret>,
    }

    impl Rendered for EventDoc {
        const TYPE: ObjectType = ObjectType::Event;
        fn text(&self, out: &mut dyn Write) -> std::io::Result<()> {
            writeln!(out, "{} {:?}", self.kind, self.detail)
        }
    }

    fn render<T: Rendered>(mode: OutputMode, object: &T) -> String {
        let mut out = Vec::new();
        write_object(&mut out, mode, object).unwrap();
        String::from_utf8(out).unwrap()
    }

    /// Every type names its own `min/v1/<type>`, and both machine modes put
    /// the stamp on every object, alone and in a listing.
    #[test]
    fn json_output_schema_per_object() {
        let names = [
            "box", "event", "error", "type", "host", "provider", "spec", "exec",
        ];
        for (ty, name) in ObjectType::ALL.into_iter().zip(names) {
            assert_eq!(ty.schema(), format!("min/v1/{name}"));
        }

        let rows = [
            BoxRow {
                id: "b1".into(),
                name: "web".into(),
                token: Secret::reference_only("store:vault/web"),
            },
            BoxRow {
                id: "b2".into(),
                name: "db".into(),
                token: Secret::reference_only("env:DB"),
            },
        ];

        // -o json, one object: one document, stamped first.
        let doc = render(OutputMode::Json, &rows[0]);
        let value: serde_json_lenient::Value = serde_json_lenient::from_str(&doc).unwrap();
        assert_eq!(value["schema"], "min/v1/box", "{doc}");
        assert_eq!(value["id"], "b1", "{doc}");
        assert!(
            doc.trim_start().starts_with("{\n  \"schema\""),
            "the stamp is the first field: {doc}"
        );

        // -o json, a listing: an array whose every element is stamped.
        let mut out = Vec::new();
        write_objects(&mut out, OutputMode::Json, &rows).unwrap();
        let value: serde_json_lenient::Value = serde_json_lenient::from_slice(&out).unwrap();
        let items = value.as_array().expect("a listing is an array");
        assert_eq!(items.len(), 2);
        for item in items {
            assert_eq!(item["schema"], "min/v1/box", "{item}");
        }

        // -o jsonl: one stamped object on each line.
        let mut out = Vec::new();
        write_objects(&mut out, OutputMode::Jsonl, &rows).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.lines().count(), 2, "{text}");
        for line in text.lines() {
            let value: serde_json_lenient::Value = serde_json_lenient::from_str(line).unwrap();
            assert_eq!(value["schema"], "min/v1/box", "{line}");
        }

        // Text carries no stamp: it is for a person.
        assert!(!render(OutputMode::Text, &rows[0]).contains("min/v1"));

        // The stamp follows the type, for each of the eight.
        for ty in ObjectType::ALL {
            let object = Any { ty, field: 7 };
            let line = serde_json_lenient::to_string(&Stamped {
                schema: object.ty.schema(),
                body: &object,
            })
            .unwrap();
            let value: serde_json_lenient::Value = serde_json_lenient::from_str(&line).unwrap();
            assert_eq!(value["schema"], ty.schema(), "{line}");
            assert_eq!(value["field"], 7, "{line}");
        }
    }

    /// The error object is one `min/v1/error` line with `code`, `message`
    /// and `hint`, the hint present even when it is empty.
    #[test]
    fn error_object_is_one_stamped_line_with_three_fields() {
        for hint in ["run `min ls`", ""] {
            let failure =
                crate::MachineModeFailure::new("not_found", "no box 'x'".into(), hint.into());
            let mut err = Vec::new();
            write_error(&mut err, &failure).unwrap();
            let text = String::from_utf8(err).unwrap();
            assert_eq!(text.lines().count(), 1, "{text}");
            let value: serde_json_lenient::Value = serde_json_lenient::from_str(&text).unwrap();
            assert_eq!(value["schema"], "min/v1/error");
            assert_eq!(value["code"], "not_found");
            assert_eq!(value["message"], "no box 'x'");
            assert_eq!(value["hint"], hint);
            assert_eq!(error_line(&failure).unwrap(), text.trim_end());
        }
    }

    /// A grant renders as its reference, never its source's value.
    #[test]
    fn grant_references_name_the_source() {
        use boxes::core::bep::{GrantSource, SecretGrant};
        let grant = |source| SecretGrant {
            source,
            scopes: Vec::new(),
            mode: None,
        };
        let store = GrantSource::Store {
            store: "keychain".into(),
            id: "claude".into(),
        };
        assert_eq!(
            Secret::of_grant("CLAUDE", &grant(store)).reference(),
            "store:keychain/claude"
        );
        assert_eq!(
            Secret::of_grant("GH", &grant(GrantSource::Broker)).reference(),
            "broker:GH"
        );
        assert_eq!(
            Secret::of_grant("NPM", &grant(GrantSource::ClientEnv)).reference(),
            "env:NPM"
        );
    }

    fn reference() -> impl Strategy<Value = String> {
        "(store|env|broker):[a-z]{1,8}(/[a-z]{1,8})?"
    }

    /// A value no reference or fixed field can contain: references are
    /// lower case, and a value is upper case and digits, at least 12 long.
    fn value() -> impl Strategy<Value = String> {
        "[A-Z0-9]{12,40}"
    }

    proptest! {
        /// BCLI-063: in every output mode, every secret-bearing field of a
        /// box, spec and event object renders its reference and never its
        /// value.
        #[test]
        fn secrets_rendered_as_refs_in_every_output_mode(
            secrets in proptest::collection::vec((reference(), value()), 1..5),
            mode_index in 0usize..3,
        ) {
            let mode = OutputMode::ALL[mode_index];
            let held: Vec<Secret> = secrets
                .iter()
                .map(|(r, v)| Secret::with_value(r.clone(), v.clone()))
                .collect();

            let row = BoxRow {
                id: "b1".into(),
                name: "web".into(),
                token: held[0].clone(),
            };
            let spec = SpecDoc {
                name: "web".into(),
                secrets: held
                    .iter()
                    .enumerate()
                    .map(|(i, s)| (format!("VAR{i}"), s.clone()))
                    .collect(),
            };
            let event = EventDoc { kind: "created".into(), detail: held.clone() };

            let outputs = [
                (vec![0], render(mode, &row)),
                ((0..held.len()).collect(), render(mode, &spec)),
                ((0..held.len()).collect(), render(mode, &event)),
            ];
            for (fields, output) in outputs {
                for (_, value) in &secrets {
                    prop_assert!(!output.contains(value.as_str()), "{mode:?} wrote a value: {output}");
                }
                for i in fields {
                    prop_assert!(
                        output.contains(secrets[i].0.as_str()),
                        "{mode:?} lost the reference {}: {output}",
                        secrets[i].0
                    );
                }
            }
            // The holder keeps the value for the code that uses it.
            prop_assert_eq!(held[0].expose(), Some(secrets[0].1.as_str()));
        }
    }
}
