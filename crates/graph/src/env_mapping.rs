//! Typed decoding of the `env_dir_mappings` / `env_file_mappings` package
//! attributes.
//!
//! Two consumers read these attributes — [`SetupForPackages`] on the
//! task-exec path and `minimald`'s session-composition extractor — and both
//! have to make the same security-relevant decision about each entry: a
//! `class = 'Credential` mapping is dropped, because the secrets strategy is
//! deferred and credentials must not reach a sandbox through package attrs.
//!
//! Doing that against the raw [`AttrValue`] form meant `.unwrap()` chains for
//! the shape and a `== "Credential"` string comparison for the class, once
//! per consumer. The string comparison in particular failed *open*: a bare
//! nickel enum tag renders as [`AttrValue::String`] today, and if that ever
//! changed the comparison would quietly stop matching and credential
//! mappings would flow through unfiltered. Decoding into
//! [`EnvFsMapping`] once, here, closes that: every entry is classified or
//! rejected, so a rendering change is a loud decode error on *every* mapping
//! rather than a silent unfiltering of the credential ones.
//!
//! The schema this mirrors is `env_dir_mappings` / `env_file_mappings` in
//! `crates/stdlib/minimal-ncl/attr_classes.ncl`:
//!
//! ```text
//! Array {
//!     read_only | Bool,
//!     path | String,
//!     class | [| 'Credential, 'State |],
//! }
//! ```
//!
//! [`SetupForPackages`]: crate::SetupForPackages

use crate::BuildSpec;
use decode::AttrValue;

/// Which attribute an entry was declared under, and therefore whether the
/// path names a directory or a single file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EnvMappingKind {
    /// From `env_dir_mappings`: `path` is a directory root.
    Dir,
    /// From `env_file_mappings`: `path` is a single file.
    File,
}

impl EnvMappingKind {
    /// The attribute name entries of this kind are read from.
    #[must_use]
    pub fn attr(self) -> &'static str {
        match self {
            Self::Dir => "env_dir_mappings",
            Self::File => "env_file_mappings",
        }
    }

    /// Both kinds, in the order the attributes are read.
    const ALL: [Self; 2] = [Self::Dir, Self::File];
}

/// What a package says a mapping contains — the nickel enum
/// `[| 'Credential, 'State |]`.
///
/// Exhaustive on purpose: an entry whose class is anything else (a tag this
/// enum does not know, a value of the wrong shape, or no class at all) is a
/// decode error, never a mapping that flows on unclassified. The filter this
/// feeds exists to keep credentials out of sandboxes, so "cannot tell what
/// this is" has to fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EnvMappingClass {
    /// A credential. Dropped by both consumers until the secrets strategy
    /// lands (see the `TODO(secrets)` notes at each drop site).
    Credential,
    /// Ordinary persistent state, e.g. a tool's config directory.
    State,
}

impl EnvMappingClass {
    /// The nickel tag this class is written as.
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            Self::Credential => "Credential",
            Self::State => "State",
        }
    }
}

/// One decoded `env_dir_mappings` / `env_file_mappings` entry.
///
/// `path` is kept exactly as the package declared it — `~/`-rooted paths are
/// not expanded here, and trailing separators are not trimmed. Both are
/// consumer-specific concerns: expansion needs a home the graph doesn't know
/// (see `mfile::EnvPatches::expand_home`), and the session composer's walker
/// has its own normalization rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvFsMapping {
    /// Directory or file, from the attribute it was declared under.
    pub kind: EnvMappingKind,
    /// The path, verbatim as declared.
    pub path: String,
    /// The package author's declared read-only intent. Honoured by the
    /// task-exec path (as a read-only bind mount) and only warned about on
    /// the composition path, which is copy-based.
    pub read_only: bool,
    /// What the mapping contains.
    pub class: EnvMappingClass,
}

/// Why an `env_dir_mappings` / `env_file_mappings` attribute could not be
/// decoded.
///
/// Always names the package and attribute, because the fix is always an edit
/// to some package's nickel declaration and the graph is the only layer that
/// still knows which one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvMappingError {
    /// The package whose attribute failed to decode.
    pub package: String,
    /// The attribute it was declared under.
    pub attr: &'static str,
    /// What was wrong with it.
    pub kind: EnvMappingErrorKind,
}

/// The specific way an entry departed from the schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvMappingErrorKind {
    /// The attribute's value was neither a list of entries nor a single
    /// entry record.
    NotEntries,
    /// An element of the list was not a record.
    EntryNotARecord,
    /// A required field was absent.
    MissingField(&'static str),
    /// A field was present with the wrong type.
    WrongType {
        /// The field name.
        field: &'static str,
        /// The type the schema calls for.
        expected: &'static str,
    },
    /// The `class` field held a tag this build of minimal does not know.
    UnknownClass(String),
}

impl std::fmt::Display for EnvMappingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "package `{}`: `{}`: ", self.package, self.attr)?;
        match &self.kind {
            EnvMappingErrorKind::NotEntries => {
                write!(f, "expected a list of mapping records")
            }
            EnvMappingErrorKind::EntryNotARecord => {
                write!(f, "expected each entry to be a record")
            }
            EnvMappingErrorKind::MissingField(field) => {
                write!(f, "an entry is missing the required `{field}` field")
            }
            EnvMappingErrorKind::WrongType { field, expected } => {
                write!(f, "an entry's `{field}` field is not {expected}")
            }
            EnvMappingErrorKind::UnknownClass(tag) => write!(
                f,
                "an entry's `class` is `{tag}`, which is not one of {}",
                [EnvMappingClass::Credential, EnvMappingClass::State]
                    .map(|c| format!("'{}", c.tag()))
                    .join(", "),
            ),
        }
    }
}

impl std::error::Error for EnvMappingError {}

impl From<EnvMappingError> for std::io::Error {
    fn from(e: EnvMappingError) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
    }
}

impl EnvFsMapping {
    /// Decodes every `env_dir_mappings` and `env_file_mappings` entry a build
    /// spec declares, in attribute order (dirs then files). A spec that
    /// declares neither yields an empty vec.
    pub fn decode_all(spec: &BuildSpec) -> Result<Vec<Self>, EnvMappingError> {
        let mut out = Vec::new();
        for kind in EnvMappingKind::ALL {
            if let Some(v) = spec.attrs.get(kind.attr()) {
                out.extend(Self::decode_attr(&spec.name, kind, v)?);
            }
        }
        Ok(out)
    }

    /// Decodes one attribute's value into its entries.
    ///
    /// Both wire shapes the schema can produce are accepted: a list of
    /// records, and — for a package that declared a single mapping without
    /// wrapping it in a list — a bare record.
    pub fn decode_attr(
        package: &str,
        kind: EnvMappingKind,
        value: &AttrValue,
    ) -> Result<Vec<Self>, EnvMappingError> {
        let err = |k| EnvMappingError {
            package: package.to_string(),
            attr: kind.attr(),
            kind: k,
        };
        let entries: Vec<&AttrValue> = match value {
            AttrValue::List(l) => l.iter().collect(),
            AttrValue::Map(_) => vec![value],
            _ => return Err(err(EnvMappingErrorKind::NotEntries)),
        };
        entries
            .into_iter()
            .map(|entry| Self::decode_entry(kind, entry).map_err(err))
            .collect()
    }

    /// Decodes a single entry record.
    fn decode_entry(kind: EnvMappingKind, entry: &AttrValue) -> Result<Self, EnvMappingErrorKind> {
        let entry = entry.as_map().ok_or(EnvMappingErrorKind::EntryNotARecord)?;
        let field = |name: &'static str| {
            entry
                .get(name)
                .ok_or(EnvMappingErrorKind::MissingField(name))
        };
        let path = field("path")?
            .as_string()
            .ok_or(EnvMappingErrorKind::WrongType {
                field: "path",
                expected: "a string",
            })?
            .clone();
        let read_only = *field("read_only")?
            .as_bool()
            .ok_or(EnvMappingErrorKind::WrongType {
                field: "read_only",
                expected: "a boolean",
            })?;
        Ok(Self {
            kind,
            path,
            read_only,
            class: EnvMappingClass::decode(field("class")?)?,
        })
    }
}

impl EnvMappingClass {
    /// Decodes the `class` field of one entry.
    ///
    /// A bare nickel enum tag arrives as [`AttrValue::String`]; a tag
    /// carrying an argument would arrive as [`AttrValue::EnumVariant`]. Both
    /// are accepted so the decode does not hinge on which of the two
    /// `decode`'s conversion happens to pick, and anything else — including a
    /// tag this build does not know — is an error rather than a mapping that
    /// slips past the credential filter unclassified.
    fn decode(value: &AttrValue) -> Result<Self, EnvMappingErrorKind> {
        let tag = match value {
            AttrValue::String(s, _) => s.as_str(),
            AttrValue::EnumVariant(tag, _) => tag.as_str(),
            _ => {
                return Err(EnvMappingErrorKind::WrongType {
                    field: "class",
                    expected: "an enum tag",
                });
            }
        };
        match tag {
            t if t == Self::Credential.tag() => Ok(Self::Credential),
            t if t == Self::State.tag() => Ok(Self::State),
            other => Err(EnvMappingErrorKind::UnknownClass(other.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nickel_lang_core::term::IndexMap;

    fn entry(fields: &[(&str, AttrValue)]) -> AttrValue {
        AttrValue::Map(IndexMap::from_iter(
            fields.iter().map(|(k, v)| (k.to_string(), v.clone())),
        ))
    }

    fn tag(t: &str) -> AttrValue {
        AttrValue::String(t.to_string(), None)
    }

    fn well_formed(class: &str) -> AttrValue {
        entry(&[
            ("path", tag("~/.claude.json")),
            ("read_only", AttrValue::Bool(false)),
            ("class", tag(class)),
        ])
    }

    /// The happy path: both classes decode, `path` is kept verbatim (no `~/`
    /// expansion, no trailing-slash trimming) and the kind comes from the
    /// attribute the entry was declared under.
    #[test]
    fn decodes_both_classes_keeping_the_path_verbatim() {
        let value = AttrValue::List(vec![well_formed("State"), well_formed("Credential")]);

        let got = EnvFsMapping::decode_attr("claude-code", EnvMappingKind::File, &value).unwrap();

        assert_eq!(
            got,
            vec![
                EnvFsMapping {
                    kind: EnvMappingKind::File,
                    path: "~/.claude.json".to_string(),
                    read_only: false,
                    class: EnvMappingClass::State,
                },
                EnvFsMapping {
                    kind: EnvMappingKind::File,
                    path: "~/.claude.json".to_string(),
                    read_only: false,
                    class: EnvMappingClass::Credential,
                },
            ]
        );
    }

    /// This is the whole point of the type. A class the decoder does not
    /// recognise is an error naming the package, not an entry that sails past
    /// the credential filter because it failed a `== "Credential"` string
    /// test. The same holds if the class is missing entirely, or arrives with
    /// a shape the decoder doesn't expect — which is exactly what a change to
    /// `decode::AttrValue`'s enum-tag rendering would look like from here.
    #[test]
    fn an_unclassifiable_entry_is_an_error_not_a_pass_through() {
        let cases = [
            (
                well_formed("Secret"),
                EnvMappingErrorKind::UnknownClass("Secret".to_string()),
            ),
            (
                entry(&[
                    ("path", tag("~/.claude.json")),
                    ("read_only", AttrValue::Bool(false)),
                ]),
                EnvMappingErrorKind::MissingField("class"),
            ),
            (
                entry(&[
                    ("path", tag("~/.claude.json")),
                    ("read_only", AttrValue::Bool(false)),
                    ("class", AttrValue::Bool(true)),
                ]),
                EnvMappingErrorKind::WrongType {
                    field: "class",
                    expected: "an enum tag",
                },
            ),
        ];

        for (value, want) in cases {
            let err = EnvFsMapping::decode_attr(
                "claude-code",
                EnvMappingKind::File,
                &AttrValue::List(vec![value]),
            )
            .expect_err("an unclassifiable entry must not decode");
            assert_eq!(err.kind, want);
            assert_eq!(err.package, "claude-code");
            assert_eq!(err.attr, "env_file_mappings");
            assert!(
                err.to_string().contains("claude-code"),
                "the error must name the package to go and edit, got {err}"
            );
        }
    }

    /// A tag rendered as an enum *variant* rather than a string decodes the
    /// same way, so the filter does not hinge on which of the two forms
    /// `decode`'s conversion produces.
    #[test]
    fn a_tag_decodes_from_either_attr_value_rendering() {
        let variant = entry(&[
            ("path", tag("~/.claude.json")),
            ("read_only", AttrValue::Bool(true)),
            (
                "class",
                AttrValue::EnumVariant("Credential".to_string(), Box::new(AttrValue::Bool(true))),
            ),
        ]);

        let got = EnvFsMapping::decode_attr(
            "claude-code",
            EnvMappingKind::File,
            &AttrValue::List(vec![variant]),
        )
        .unwrap();

        assert_eq!(got[0].class, EnvMappingClass::Credential);
        assert!(got[0].read_only);
    }

    /// The shape errors the old code met with `.unwrap()` — a panic in the
    /// daemon — are ordinary errors naming the offending field.
    #[test]
    fn malformed_shapes_are_errors_rather_than_panics() {
        let cases = [
            (AttrValue::Bool(true), EnvMappingErrorKind::NotEntries),
            (
                AttrValue::List(vec![AttrValue::Bool(true)]),
                EnvMappingErrorKind::EntryNotARecord,
            ),
            (
                AttrValue::List(vec![entry(&[
                    ("read_only", AttrValue::Bool(false)),
                    ("class", tag("State")),
                ])]),
                EnvMappingErrorKind::MissingField("path"),
            ),
            (
                AttrValue::List(vec![entry(&[
                    ("path", tag("~/.claude")),
                    ("read_only", tag("yes")),
                    ("class", tag("State")),
                ])]),
                EnvMappingErrorKind::WrongType {
                    field: "read_only",
                    expected: "a boolean",
                },
            ),
        ];

        for (value, want) in cases {
            assert_eq!(
                EnvFsMapping::decode_attr("b1", EnvMappingKind::Dir, &value)
                    .expect_err("malformed input must not decode")
                    .kind,
                want
            );
        }
    }

    /// A package that declares one mapping as a bare record, rather than a
    /// one-element list, decodes too — the session-composition extractor
    /// accepted that shape before this type existed and still must.
    #[test]
    fn a_bare_record_decodes_as_a_single_entry() {
        let got =
            EnvFsMapping::decode_attr("b1", EnvMappingKind::Dir, &well_formed("State")).unwrap();

        assert_eq!(got.len(), 1);
        assert_eq!(got[0].kind, EnvMappingKind::Dir);
    }
}
