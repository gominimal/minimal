//! The on-disk/wire format of the remote cache index (`index.shisha`), and the
//! in-memory [`IndexFile`] that reads and writes it.
//!
//! # Format
//!
//! A bare, headerless array of fixed 68-byte records, ordered by ascending
//! `spec_hash` (an [`IndexFile`] is a `BTreeMap`, and [`IndexFile::write_to`]
//! drains it in order). There is no magic, no version, and no entry count:
//!
//! ```text
//! byte  0..32   spec_hash   blake3, the key
//! byte 32..36   flags       reserved; MUST be zero
//! byte 36..68   sha256      content hash of the build output
//! ```
//!
//! Because the record order is a pure function of the keys, the same set of
//! entries always serializes to identical bytes. Callers that sign or otherwise
//! digest an index file depend on that.
//!
//! `flags` is the sole forward-compatibility hook: a reader that sees a
//! non-zero value knows the format moved on and refuses to guess
//! ([`IndexFile::from_reader`] errors rather than misparse).

use common::SpecHash;
use std::collections::BTreeMap;
use std::io::{Read, Write};

/// Size of one wire record (see the format description above).
pub(crate) const WIRE_RECORD_LEN: u64 = 68;

fn read_wire_kv<R: Read>(reader: &mut R) -> std::io::Result<(SpecHash, IndexEntry)> {
    let mut buf = [0u8; 32];
    reader.read_exact(&mut buf[..])?;
    let spec_hash = SpecHash::from_bytes(buf);

    Ok((spec_hash, IndexEntry::read_wire(reader)?))
}

fn write_wire_kv<W: Write>(writer: &mut W, k: &SpecHash, v: &IndexEntry) -> std::io::Result<()> {
    writer.write_all(k.as_bytes())?;

    v.write_wire(writer)
}

/// An iterator over a type implementing [Read] or [AsyncReadExt], yielding parsed index entries till EOF.
struct IndexWireIter<'a, R> {
    r: &'a mut R,
}

impl<'a, R: Read> Iterator for IndexWireIter<'a, R> {
    type Item = std::io::Result<(SpecHash, IndexEntry)>;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        match read_wire_kv(self.r) {
            Ok((k, v)) => Some(Ok((k, v))),
            Err(e) => {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    None
                } else {
                    Some(Err(e))
                }
            }
        }
    }
}

/// The value of a [IndexFile] entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IndexEntry {
    sha256: [u8; 32],
}

impl IndexEntry {
    pub(crate) fn read_wire<R: Read>(reader: &mut R) -> std::io::Result<IndexEntry> {
        let mut flags = [0u8; 4];
        reader.read_exact(&mut flags[..])?;
        if flags != [0u8; 4] {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Unexpected flags value: this index might be in an updated format that requires an update to minimal",
            ));
        }

        let mut sha256 = [0u8; 32];
        reader.read_exact(&mut sha256[..])?;

        Ok(Self { sha256 })
    }

    pub(crate) fn write_wire<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&[0u8; 4])?;
        writer.write_all(&self.sha256[..])
    }
}

/// An in-memory index of build outputs accessible remotely.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IndexFile {
    idx: BTreeMap<SpecHash, IndexEntry>,
}

impl IndexFile {
    /// Loads a remote index that was previously serialized with [Self::write_to].
    pub fn from_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut err = None;
        let idx = BTreeMap::from_iter(IndexWireIter { r: reader }.filter_map(|res| {
            match (res, err.as_ref()) {
                (Ok(e), None) => Some(e),
                (Err(e), None) => {
                    err = Some(e);
                    None
                }
                (Err(_), Some(_)) | (Ok(_), Some(_)) => None,
            }
        }));

        if let Some(err) = err {
            return Err(err);
        }

        Ok(Self { idx })
    }

    /// Returns true if the given spec hash is in the remote index.
    pub fn exists(&self, spec_hash: &SpecHash) -> bool {
        self.idx.contains_key(spec_hash)
    }

    /// Returns the SHA256 of the build represented by the given spec hash, if present.
    pub fn sha256(&self, spec_hash: &SpecHash) -> Option<[u8; 32]> {
        self.idx.get(spec_hash).map(|entry| entry.sha256)
    }

    /// Serialize the index to the given [Write] implementation.
    pub fn write_to<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        for (k, v) in self.idx.iter() {
            write_wire_kv(w, k, v)?;
        }
        Ok(())
    }

    /// Absorbs `other`'s entries into `self` (other wins on overlap).
    /// Returns the number of entries whose value *changed* — overlapping
    /// records should be byte-identical across per-link closures, so a
    /// non-zero count is a divergence signal the caller should surface.
    pub fn merge(&mut self, other: IndexFile) -> usize {
        let mut conflicts = 0;
        for (k, v) in other.idx {
            if let Some(prev) = self.idx.insert(k, v.clone())
                && prev != v
            {
                conflicts += 1;
            }
        }
        conflicts
    }

    /// The number of entries in the index.
    pub fn len(&self) -> usize {
        self.idx.len()
    }

    /// Whether the index has no entries.
    pub fn is_empty(&self) -> bool {
        self.idx.is_empty()
    }
}

impl Extend<(SpecHash, [u8; 32])> for IndexFile {
    #[inline]
    fn extend<T: IntoIterator<Item = (SpecHash, [u8; 32])>>(&mut self, iter: T) {
        self.idx.extend(
            iter.into_iter()
                .map(|(spec_hash, sha256)| (spec_hash, IndexEntry { sha256 })),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn roundtrip_wire() {
        let mut buf: Vec<u8> = Vec::new();
        write_wire_kv(
            &mut buf,
            &SpecHash::from_hex("1234000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
            &IndexEntry { sha256: [1u8; 32] },
        )
        .unwrap();

        let mut curs = Cursor::new(buf);
        let decoded = read_wire_kv(&mut curs).unwrap();
        assert_eq!(curs.position(), 68);
        assert_eq!(
            decoded.0,
            SpecHash::from_hex("1234000000000000000000000000000000000000000000000000000000000000")
                .unwrap()
        );
        assert_eq!(decoded.1, IndexEntry { sha256: [1u8; 32] },);
    }

    #[test]
    fn from_reader() {
        let mut buf: Vec<u8> = Vec::new();
        for n in 0..2 {
            write_wire_kv(
                &mut buf,
                &SpecHash::from_hex(
                    "123400000000000000000000000000000000000000000000000000000000000".to_owned()
                        + if n == 0 { "0" } else { "1" },
                )
                .unwrap(),
                &IndexEntry { sha256: [1u8; 32] },
            )
            .unwrap();
        }

        let mut curs = Cursor::new(buf);
        let ri = IndexFile::from_reader(&mut curs).unwrap();
        assert_eq!(ri.idx.len(), 2);
        assert_eq!(
            ri.idx.first_key_value(),
            Some((
                &SpecHash::from_hex(
                    "1234000000000000000000000000000000000000000000000000000000000000"
                )
                .unwrap(),
                &IndexEntry { sha256: [1u8; 32] },
            ))
        );
    }

    #[test]
    fn merge_unions_and_counts_only_value_changes() {
        let h = |b: u8| common::SpecHash::from_bytes([b; 32]);
        let mut a = IndexFile::default();
        a.extend([(h(1), [0x11; 32]), (h(2), [0x22; 32])]);
        let mut b = IndexFile::default();
        // h(2) identical (no conflict), h(3) new, h(1) DIFFERENT (conflict).
        b.extend([(h(2), [0x22; 32]), (h(3), [0x33; 32]), (h(1), [0xFF; 32])]);

        let conflicts = a.merge(b);
        assert_eq!(conflicts, 1);
        assert_eq!(a.len(), 3);
        // Other wins on overlap.
        assert_eq!(a.sha256(&h(1)), Some([0xFF; 32]));
        assert_eq!(a.sha256(&h(3)), Some([0x33; 32]));
    }
}

/// Kani proof harnesses for the untrusted-bytes record codec
/// (gominimal/minimal#1109, harness set 1).
///
/// `index.shisha` bytes come from storage the signed-index design (#86)
/// exists *because* we don't trust — bucket, CDN, or mirror. These
/// harnesses prove, for **every** input within the stated bounds (not a
/// fuzzer's sample of them), that the 68-byte record codec — the layer
/// that actually touches hostile bytes — is safe and lossless:
///
///   * decoding an arbitrary record, at any truncation, never panics
///     and never reads out of bounds — `read_wire_kv` returns `Ok` or
///     `Err`, only;
///   * a nonzero `flags` field always surfaces as `Err` (the format's
///     sole forward-compat hook actually fires), and it fires *before*
///     the sha256 bytes are consumed;
///   * encode→decode round-trips every record exactly, emitting
///     precisely [`WIRE_RECORD_LEN`] bytes with zero flags — so
///     serialized output can never trip the flags gate.
///
/// **Deliberately record-level, not file-level.** `IndexFile` composes
/// this codec through a `BTreeMap`, and symbolic 32-byte keys inside
/// std collections are a classic bounded-model-checking blow-up (the
/// first cut of these harnesses OOM'd CBMC); std's `BTreeMap` is also
/// not our proof obligation. The division of labor: Kani proves the
/// codec **totally**, the `index_file` fuzz/unit coverage samples the
/// file-level composition (`from_reader`, `merge`, canonical ordering
/// — see the `#[cfg(test)]` module and the rcache fuzz target).
///
/// No `blake3` stubbing is needed: nothing here ever invokes the
/// compression function — `SpecHash`/`blake3::Hash` act purely as an
/// inert `[u8; 32]` wrapper.
///
/// Run: `cargo kani -p rcache` (or `just kani`, or `scripts/kani.sh`).
/// Kani pinned at 0.67.0 in CI — older releases give spurious failures
/// on arrays > 64 elements (kani#2416/#4408), and one wire record is
/// 68 bytes.
#[cfg(kani)]
mod kani_proofs {
    use super::*;
    use std::io::Cursor;

    const RECORD: usize = WIRE_RECORD_LEN as usize;

    /// Decoding an arbitrary record at any truncation never panics,
    /// and succeeds IFF the input is one full record with zero flags —
    /// stated as an iff so neither arm can silently become unreachable
    /// (a one-sided `Ok =>` postcondition still "verifies" when a
    /// changed reader makes `Ok` impossible; mutation-tested). On
    /// success exactly the whole record was consumed — the property
    /// the callers' `len % 68 == 0` arithmetic silently relies on.
    #[kani::proof]
    fn read_record_never_panics() {
        let bytes: [u8; RECORD] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= RECORD);
        let mut cur = Cursor::new(&bytes[..len]);
        let res = read_wire_kv(&mut cur);
        let full_and_zero_flags =
            len == RECORD && bytes[32] == 0 && bytes[33] == 0 && bytes[34] == 0 && bytes[35] == 0;
        assert_eq!(res.is_ok(), full_and_zero_flags);
        if res.is_ok() {
            assert_eq!(cur.position(), WIRE_RECORD_LEN);
        }
    }

    /// The flags forward-compat gate always fires: any record whose 4
    /// flag bytes are not all zero fails to decode — and fails at the
    /// flags field (position 36), before the sha256 bytes are consumed.
    #[kani::proof]
    fn nonzero_flags_always_rejected() {
        let bytes: [u8; RECORD] = kani::any();
        kani::assume(bytes[32] != 0 || bytes[33] != 0 || bytes[34] != 0 || bytes[35] != 0);
        let mut cur = Cursor::new(&bytes[..]);
        assert!(read_wire_kv(&mut cur).is_err());
        assert_eq!(cur.position(), 36);
    }

    /// Encode→decode round-trips every record exactly, and the encoded
    /// form is exactly one 68-byte record with zero flags — so output
    /// this code writes can never trip the flags gate on read-back.
    #[kani::proof]
    fn record_roundtrip_is_exact() {
        let key: [u8; 32] = kani::any();
        let sha256: [u8; 32] = kani::any();
        let k = SpecHash::from_bytes(key);
        let v = IndexEntry { sha256 };

        let mut out = Vec::new();
        write_wire_kv(&mut out, &k, &v).expect("Vec write is infallible");
        // Pin the exact field OFFSETS, not just round-trip equality: a
        // wire-layout permutation both sides agree on (key and sha256
        // swapped, say) round-trips fine but breaks every other reader
        // of index.shisha. Mutation-tested.
        assert_eq!(out.len(), RECORD);
        assert_eq!(&out[0..32], &key[..]);
        assert_eq!(&out[32..36], &[0u8; 4]);
        assert_eq!(&out[36..68], &sha256[..]);

        let (k2, v2) =
            read_wire_kv(&mut Cursor::new(&out[..])).expect("own serialization always decodes");
        // Compare key BYTES, not `SpecHash == SpecHash`: blake3's
        // `PartialEq` is a constant-time comparison whose
        // optimization-barrier internals are opaque to the model
        // checker and yield a spurious counterexample. Byte equality
        // is the property under proof anyway.
        assert_eq!(k2.as_bytes(), k.as_bytes());
        assert_eq!(v2, v);
    }
}
