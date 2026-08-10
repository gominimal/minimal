use serde::{Deserialize, Deserializer, Serialize, Serializer, de, de::Visitor};
use std::fmt;

/// A hash describing the object (specification hash), including everything it is dependent on.
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
    /// Returns the bytes representation of a spec hash.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Decodes a spec hash from a lowercase-hex representation.
    pub fn from_hex(hex: impl AsRef<[u8]>) -> Result<Self, blake3::HexError> {
        Ok(SpecHash(blake3::Hash::from_hex(hex)?))
    }

    /// Decodes a spec hash from a bytes representation.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        SpecHash(blake3::Hash::from_bytes(bytes))
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
        let serialized = serde_json_lenient::to_string(&spec_hash).expect("Failed to serialize");

        // Deserialize from JSON
        let deserialized: SpecHash =
            serde_json_lenient::from_str(&serialized).expect("Failed to deserialize");

        // Verify roundtrip
        assert_eq!(spec_hash, deserialized);
        assert_eq!(spec_hash.0.as_bytes(), deserialized.0.as_bytes());
    }
}
