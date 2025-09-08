use crate::spec_schema::ObjTy;
use nickel_lang_core::files::Files;
use nickel_lang_core::position::TermPos;
use std::collections::HashMap;

use serde::{de, de::Visitor, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// An error during processing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Error {
    SpecError(SpecError),
    UnexpectedObject {
        files: Files,
        got: ObjTy,
        want: ObjTy,
        pos: TermPos,
    },
    MissingField {
        files: Files,
        obj: ObjTy,
        pos: TermPos,
        field: &'static str,
    },
    MissingID(Files, TermPos),
    MissingTy(Files, TermPos),
}

impl Error {
    pub fn report_to_stderr(&self) {
        use nickel_lang_core::error::{report::report, Diagnostic, Label};
        use nickel_lang_core::files::FileId;
        use nickel_lang_core::position::RawSpan;
        use Error::*;

        /// Create a primary label from a span.
        fn primary(span: &RawSpan) -> Label<FileId> {
            Label::primary(span.src_id, span.start.to_usize()..span.end.to_usize())
        }

        /// Create a secondary label from a span.
        #[allow(dead_code)]
        fn secondary(span: &RawSpan) -> Label<FileId> {
            Label::secondary(span.src_id, span.start.to_usize()..span.end.to_usize())
        }

        match self {
            SpecError(se) => se.report_to_stderr(),
            UnexpectedObject {
                files,
                got,
                want,
                pos,
            } => {
                let mut files = files.clone();
                let diagnostic = Diagnostic::error()
                    .with_message(format!(
                        "unexpected record: found {:?} when looking for {:?}",
                        got, want
                    ))
                    .with_label(primary(&pos.into_opt().unwrap()).with_message("at this record"));

                report(
                    &mut files,
                    diagnostic,
                    nickel_lang_core::error::report::ErrorFormat::Text,
                    nickel_lang_core::error::report::ColorOpt::Auto,
                );
            }
            MissingID(files, pos) => {
                let mut files = files.clone();
                let diagnostic = Diagnostic::error()
                    .with_message("record was not declared a build spec")
                    .with_label(primary(&pos.into_opt().unwrap()));

                report(
                    &mut files,
                    diagnostic,
                    nickel_lang_core::error::report::ErrorFormat::Text,
                    nickel_lang_core::error::report::ColorOpt::Auto,
                );
            }
            MissingTy(files, pos) => {
                let mut files = files.clone();
                let diagnostic = Diagnostic::error()
                    .with_message("record was not given a type")
                    .with_label(primary(&pos.into_opt().unwrap()))
                    .with_note("Perhaps you meant to apply ('|' operator) a type such as BuildSpec, OutputLib, Source, etc etc");

                report(
                    &mut files,
                    diagnostic,
                    nickel_lang_core::error::report::ErrorFormat::Text,
                    nickel_lang_core::error::report::ColorOpt::Auto,
                );
            }
            Error::MissingField {
                files,
                obj,
                pos,
                field,
            } => {
                let mut files = files.clone();
                let diagnostic = Diagnostic::error()
                    .with_message(format!(
                        "missing field {} for record of type {:?}",
                        field, obj
                    ))
                    .with_label(primary(&pos.into_opt().unwrap()));

                report(
                    &mut files,
                    diagnostic,
                    nickel_lang_core::error::report::ErrorFormat::Text,
                    nickel_lang_core::error::report::ColorOpt::Auto,
                );
            }
        }
    }
}

impl From<SpecError> for Error {
    fn from(e: SpecError) -> Self {
        Self::SpecError(e)
    }
}

/// A hash describing the object (specification hash), as well as everything it is dependent on.
///
/// This hash should change if any semantics change, but stay the same for anything immaterial (i.e, should
/// not change with comments, line numbers, locations in different files etc).
#[allow(dead_code)]
trait SpecHashable {
    fn spec_hash(&self, _graph: &DepGraph, _seen: &mut HashMap<BuildSpecRef, ()>) -> SpecHash;
}

/// A hash describing the object (specificatino hash), including everything it is dependent on.
///
/// This hash should change if any semantics change, but stay the same for anything immaterial (i.e, should
/// not change with comments, line numbers, locations in different files etc).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SpecHash(pub blake3::Hash);

impl PartialOrd for SpecHash {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SpecHash {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl SpecHash {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// symbolic hash to represent a cycle when computing a SpecHash.
    fn cycle() -> Self {
        Self(blake3::Hash::from_bytes([1u8; 32]))
    }
}

impl PartialEq<blake3::Hash> for SpecHash {
    fn eq(&self, h: &blake3::Hash) -> bool {
        h == &self.0
    }
}

impl Serialize for SpecHash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0.as_bytes())
    }
}

impl<'de> Deserialize<'de> for SpecHash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct HashVisitor;

        impl<'de> Visitor<'de> for HashVisitor {
            type Value = SpecHash;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a 32-byte blake3 hash")
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.bytes_to_hash(value)
            }

            fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.bytes_to_hash(&value)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let mut bytes = Vec::with_capacity(32);
                while let Some(byte) = seq.next_element::<u8>()? {
                    bytes.push(byte);
                }
                self.bytes_to_hash(&bytes)
            }
        }

        impl HashVisitor {
            fn bytes_to_hash<E>(&self, value: &[u8]) -> Result<SpecHash, E>
            where
                E: de::Error,
            {
                if value.len() != 32 {
                    return Err(E::custom(format!(
                        "expected 32 bytes for blake3 hash, got {}",
                        value.len()
                    )));
                }

                let mut hash_bytes = [0u8; 32];
                hash_bytes.copy_from_slice(value);
                let hash = blake3::Hash::from(hash_bytes);
                Ok(SpecHash(hash))
            }
        }

        deserializer.deserialize_bytes(HashVisitor)
    }
}

mod spec_reader;
pub use spec_reader::{SpecError, SpecReader, SpecReaderOptions};

mod spec_schema;

pub mod dep_graph;
pub use dep_graph::{BuildOutput, BuildSpec, BuildSpecInput, BuildSpecRef, DepGraph};

mod planner;
pub use planner::ExecPlan;

mod build_manifest;
pub use build_manifest::BuildManifest;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialized_spec_hash_roundtrip_json() {
        // Create a test hash from some data
        let original_data = b"test data for hashing";
        let hash = blake3::hash(original_data);
        let spec_hash = SpecHash(hash);

        // Serialize to JSON
        let serialized = serde_json::to_string(&spec_hash).expect("Failed to serialize");

        // Deserialize from JSON
        let deserialized: SpecHash =
            serde_json::from_str(&serialized).expect("Failed to deserialize");

        // Verify roundtrip
        assert_eq!(spec_hash, deserialized);
        assert_eq!(spec_hash.0.as_bytes(), deserialized.0.as_bytes());
    }
}
