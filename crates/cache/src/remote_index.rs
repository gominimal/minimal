use graph::SpecHash;
use std::collections::BTreeMap;
use std::io::{Read, Write};

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

/// An iterator over a type implementing [Read], yielding parsed index entries till EOF.
struct IndexWireIter<'a, R: Read> {
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

/// The value of a [RemoteIndex] entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteIndex {
    idx: BTreeMap<SpecHash, IndexEntry>,
}

impl RemoteIndex {
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

    /// Serialize the index to the given [Write] implementation.
    pub fn write_to<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        for (k, v) in self.idx.iter() {
            write_wire_kv(w, k, v)?;
        }
        Ok(())
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
        let ri = RemoteIndex::from_reader(&mut curs).unwrap();
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
}
