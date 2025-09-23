use common::SpecHash;
use futures::{io::AsyncReadExt, StreamExt};
use std::collections::BTreeMap;
use std::io::{Read, Write};

pub fn read_wire_kv_stream<R>(
    reader: R,
) -> impl futures::Stream<Item = std::io::Result<(SpecHash, IndexEntry)>>
where
    R: AsyncReadExt + std::marker::Unpin,
{
    futures::stream::try_unfold(reader, |mut reader| async move {
        match read_wire_kv_async(&mut reader).await {
            Ok(kv_pair) => Ok(Some((kv_pair, reader))),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
            Err(e) => Err(e),
        }
    })
}

fn read_wire_kv<R: Read>(reader: &mut R) -> std::io::Result<(SpecHash, IndexEntry)> {
    let mut buf = [0u8; 32];
    reader.read_exact(&mut buf[..])?;
    let spec_hash = SpecHash::from_bytes(buf);

    Ok((spec_hash, IndexEntry::read_wire(reader)?))
}

async fn read_wire_kv_async<R: AsyncReadExt + std::marker::Unpin>(
    reader: &mut R,
) -> std::io::Result<(SpecHash, IndexEntry)> {
    let mut buf = [0u8; 32];
    reader.read_exact(&mut buf[..]).await?;
    let spec_hash = SpecHash::from_bytes(buf);

    Ok((spec_hash, IndexEntry::read_wire_async(reader).await?))
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

    pub(crate) async fn read_wire_async<R: AsyncReadExt + std::marker::Unpin>(
        reader: &mut R,
    ) -> std::io::Result<IndexEntry> {
        let mut flags = [0u8; 4];
        reader.read_exact(&mut flags[..]).await?;
        if flags != [0u8; 4] {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Unexpected flags value: this index might be in an updated format that requires an update to minimal",
            ));
        }

        let mut sha256 = [0u8; 32];
        reader.read_exact(&mut sha256[..]).await?;

        Ok(Self { sha256 })
    }

    pub(crate) fn write_wire<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&[0u8; 4])?;
        writer.write_all(&self.sha256[..])
    }
}

/// An in-memory index of build outputs accessible remotely.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
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

    /// Asynchronously loads a remote index that was previously serialized with [Self::write_to].
    pub async fn from_reader_async<R: AsyncReadExt + std::marker::Unpin>(
        reader: &mut R,
    ) -> std::io::Result<Self> {
        let stream = read_wire_kv_stream(reader);
        futures::pin_mut!(stream);

        let mut idx = BTreeMap::new();
        while let Some(result) = stream.next().await {
            match result {
                Ok((spec_hash, index_entry)) => {
                    idx.insert(spec_hash, index_entry);
                }
                Err(e) => {
                    return Err(e);
                }
            }
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
}

impl Extend<(SpecHash, [u8; 32])> for RemoteIndex {
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
