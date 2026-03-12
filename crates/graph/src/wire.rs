//! Streaming wire format for [`Graph`] serialization.
//!
//! Uses a custom length-delimited framing: **1-byte tag + unsigned LEB128 varint
//! length + payload bytes**.  Individual record payloads are JSON (via `serde_json`)
//! except [`TAG_LOCAL_FILE_DATA`] which carries raw file bytes.
//!
//! ## Stream order
//!
//! ```text
//! Header → BuildSpec* (each optionally followed by LocalFileData records)
//!        → TopLevels → Profile* → Harness* → SupplyChain → Footer
//! ```

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use generational_arena::{Arena, Index};
use serde::{Deserialize, Serialize};

use crate::{BuildDep, BuildSpec, BuildSpecRef, Graph, RuntimeDep, SubsetInput};
use common::SpecOrigin;
use decode::{Harness, Profile};

// ── Constants ────────────────────────────────────────────────────────────────

const STREAM_VERSION: u32 = 1;

const TAG_HEADER: u8 = 0x01;
const TAG_BUILD_SPEC: u8 = 0x02;
const TAG_LOCAL_FILE_DATA: u8 = 0x03;
const TAG_TOP_LEVELS: u8 = 0x04;
const TAG_PROFILE: u8 = 0x05;
const TAG_HARNESS: u8 = 0x06;
const TAG_SUPPLY_CHAIN: u8 = 0x07;
const TAG_FOOTER: u8 = 0xFF;

// ── WireError ────────────────────────────────────────────────────────────────

/// Errors that can occur during wire-format (de)serialization.
#[derive(Debug)]
pub enum WireError {
    Io(io::Error),
    Json(serde_json::Error),
    InvalidTag(u8),
    UnexpectedRecord { expected: &'static str, got: u8 },
    DanglingRef { wire_ref: (usize, u64) },
    ChecksumMismatch,
    UnsupportedVersion(u32),
    FileHashMismatch { filename: String },
}

impl From<io::Error> for WireError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for WireError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "wire I/O error: {e}"),
            Self::Json(e) => write!(f, "wire JSON error: {e}"),
            Self::InvalidTag(t) => write!(f, "invalid record tag 0x{t:02x}"),
            Self::UnexpectedRecord { expected, got } => {
                write!(f, "expected {expected} record, got tag 0x{got:02x}")
            }
            Self::DanglingRef { wire_ref } => {
                write!(f, "dangling arena ref ({}, {})", wire_ref.0, wire_ref.1)
            }
            Self::ChecksumMismatch => write!(f, "stream checksum mismatch"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported stream version {v}"),
            Self::FileHashMismatch { filename } => {
                write!(f, "blake3 hash mismatch for file {filename:?}")
            }
        }
    }
}

impl std::error::Error for WireError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Json(e) => Some(e),
            _ => None,
        }
    }
}

// ── Varint helpers ───────────────────────────────────────────────────────────

#[cfg(test)]
fn encode_varint(value: u64, buf: &mut Vec<u8>) {
    let mut v = value;
    loop {
        let mut byte = (v & 0x7F) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if v == 0 {
            break;
        }
    }
}

fn decode_varint<R: Read>(reader: &mut R) -> io::Result<u64> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte)?;
        result |= ((byte[0] & 0x7F) as u64) << shift;
        if byte[0] & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "varint overflow",
            ));
        }
    }
    Ok(result)
}

/// Encodes a varint into a small stack buffer and returns a slice of the used bytes.
fn varint_bytes(value: u64) -> ([u8; 10], usize) {
    let mut buf = [0u8; 10];
    let mut v = value;
    let mut i = 0;
    loop {
        let mut byte = (v & 0x7F) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        buf[i] = byte;
        i += 1;
        if v == 0 {
            break;
        }
    }
    (buf, i)
}

// ── Wire record types ────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct HeaderRecord {
    version: u32,
    build_count: usize,
}

#[derive(Serialize, Deserialize)]
struct BuildSpecRecord {
    arena_idx: usize,
    arena_gen: u64,
    spec: BuildSpec,
}

#[derive(Serialize, Deserialize)]
struct LocalFileHeader {
    filename: String,
    file_hash: blake3::Hash,
    data_len: u64,
}

#[derive(Serialize, Deserialize)]
struct ProfileRecord {
    name: String,
    profile: Profile,
}

#[derive(Serialize, Deserialize)]
struct HarnessRecord {
    name: String,
    harness: Harness,
}

// ── GraphWriter (sync) ──────────────────────────────────────────────────────

/// Writes a [`Graph`] to any [`Write`] sink using the streaming wire format.
pub struct GraphWriter<W: Write> {
    writer: W,
    hasher: blake3::Hasher,
}

impl<W: Write> GraphWriter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            hasher: blake3::Hasher::new(),
        }
    }

    /// Writes tag + varint(len) + payload, hashing the entire frame.
    fn write_record(&mut self, tag: u8, payload: &[u8]) -> Result<(), WireError> {
        let (vbuf, vlen) = varint_bytes(payload.len() as u64);

        // Hash and write tag
        self.hasher.update(&[tag]);
        self.writer.write_all(&[tag])?;
        // Hash and write varint
        self.hasher.update(&vbuf[..vlen]);
        self.writer.write_all(&vbuf[..vlen])?;
        // Hash and write payload
        self.hasher.update(payload);
        self.writer.write_all(payload)?;

        Ok(())
    }

    /// Serialises the entire graph into the underlying writer.
    pub fn write_graph(mut self, graph: &Graph) -> Result<(), WireError> {
        // ── Header ──
        let header = HeaderRecord {
            version: STREAM_VERSION,
            build_count: graph.len(),
        };
        self.write_record(TAG_HEADER, &serde_json::to_vec(&header)?)?;

        // ── BuildSpecs + LocalFileData ──
        for (bsr, spec) in graph.iter() {
            let (arena_idx, arena_gen) = bsr.0.into_raw_parts();
            let record = BuildSpecRecord {
                arena_idx,
                arena_gen,
                spec: spec.clone(),
            };
            self.write_record(TAG_BUILD_SPEC, &serde_json::to_vec(&record)?)?;

            // Inline local files immediately after the spec
            for dep in &spec.build_deps {
                if let BuildDep::Local {
                    full_path,
                    filename,
                    file_hash,
                } = dep
                {
                    self.write_local_file(full_path, filename, file_hash)?;
                }
            }
        }

        // ── TopLevels ──
        let top_levels: Vec<(usize, u64)> = graph
            .top_levels
            .iter()
            .map(|bsr| bsr.0.into_raw_parts())
            .collect();
        self.write_record(TAG_TOP_LEVELS, &serde_json::to_vec(&top_levels)?)?;

        // ── Profiles ──
        for (name, profile) in graph.iter_profiles() {
            let record = ProfileRecord {
                name: name.clone(),
                profile: profile.clone(),
            };
            self.write_record(TAG_PROFILE, &serde_json::to_vec(&record)?)?;
        }

        // ── Harnesses ──
        for (name, harness) in graph.iter_harnesses() {
            let record = HarnessRecord {
                name: name.clone(),
                harness: harness.clone(),
            };
            self.write_record(TAG_HARNESS, &serde_json::to_vec(&record)?)?;
        }

        // ── SupplyChain ──
        self.write_record(
            TAG_SUPPLY_CHAIN,
            &serde_json::to_vec(graph.software_supply_chain())?,
        )?;

        // ── Footer ── (NOT hashed itself)
        let hash = self.hasher.finalize();
        let (vbuf, vlen) = varint_bytes(32);
        self.writer.write_all(&[TAG_FOOTER])?;
        self.writer.write_all(&vbuf[..vlen])?;
        self.writer.write_all(hash.as_bytes())?;

        Ok(())
    }

    fn write_local_file(
        &mut self,
        full_path: &PathBuf,
        filename: &str,
        file_hash: &blake3::Hash,
    ) -> Result<(), WireError> {
        let file_data = std::fs::read(full_path)?;

        let header = LocalFileHeader {
            filename: filename.to_string(),
            file_hash: *file_hash,
            data_len: file_data.len() as u64,
        };
        let header_json = serde_json::to_vec(&header)?;

        // Payload = varint(header_json.len) + header_json + file_data
        let (vbuf, vlen) = varint_bytes(header_json.len() as u64);
        let mut payload = Vec::with_capacity(vlen + header_json.len() + file_data.len());
        payload.extend_from_slice(&vbuf[..vlen]);
        payload.extend_from_slice(&header_json);
        payload.extend_from_slice(&file_data);

        self.write_record(TAG_LOCAL_FILE_DATA, &payload)?;
        Ok(())
    }
}

// ── GraphReader (sync) ──────────────────────────────────────────────────────

/// Reads a [`Graph`] from any [`Read`] source using the streaming wire format.
pub struct GraphReader<R: Read> {
    reader: R,
    hasher: blake3::Hasher,
}

impl<R: Read> GraphReader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            hasher: blake3::Hasher::new(),
        }
    }

    /// Reads one framed record.  For the footer record, the frame is NOT hashed.
    fn read_record(&mut self) -> Result<(u8, Vec<u8>), WireError> {
        // Read tag
        let mut tag_buf = [0u8; 1];
        self.reader.read_exact(&mut tag_buf)?;
        let tag = tag_buf[0];

        // Read varint length (we need to reconstruct the encoded bytes for hashing)
        let mut varint_buf: Vec<u8> = Vec::with_capacity(10);
        let len = {
            let mut result: u64 = 0;
            let mut shift: u32 = 0;
            loop {
                let mut byte = [0u8; 1];
                self.reader.read_exact(&mut byte)?;
                varint_buf.push(byte[0]);
                result |= ((byte[0] & 0x7F) as u64) << shift;
                if byte[0] & 0x80 == 0 {
                    break;
                }
                shift += 7;
                if shift >= 64 {
                    return Err(
                        io::Error::new(io::ErrorKind::InvalidData, "varint overflow").into(),
                    );
                }
            }
            result
        };

        // Read payload
        let mut payload = vec![0u8; len as usize];
        self.reader.read_exact(&mut payload)?;

        // Hash the full frame (tag + varint + payload) UNLESS this is the footer
        if tag != TAG_FOOTER {
            self.hasher.update(&tag_buf);
            self.hasher.update(&varint_buf);
            self.hasher.update(&payload);
        }

        Ok((tag, payload))
    }

    /// Deserialises a full graph from the underlying reader.
    ///
    /// Returns the graph and an optional [`tempfile::TempDir`] holding any
    /// materialised local files.  The caller must keep the `TempDir` alive for
    /// as long as the graph is used (the `BuildDep::Local` paths point into it).
    pub fn read_graph(mut self) -> Result<(Graph, Option<tempfile::TempDir>), WireError> {
        // ── Header ──
        let (tag, payload) = self.read_record()?;
        if tag != TAG_HEADER {
            return Err(WireError::UnexpectedRecord {
                expected: "Header",
                got: tag,
            });
        }
        let header: HeaderRecord = serde_json::from_slice(&payload)?;
        if header.version != STREAM_VERSION {
            return Err(WireError::UnsupportedVersion(header.version));
        }

        let mut arena: Arena<BuildSpec> = Arena::with_capacity(header.build_count);
        let mut remap: HashMap<Index, BuildSpecRef> = HashMap::with_capacity(header.build_count);
        let mut temp_dir: Option<tempfile::TempDir> = None;

        let mut top_levels_raw: Vec<(usize, u64)> = Vec::new();
        let mut profiles: HashMap<String, Profile> = HashMap::new();
        let mut harnesses: HashMap<String, Harness> = HashMap::new();
        let mut supply_chain: Vec<SpecOrigin> = Vec::new();

        // ── Body ──
        loop {
            let (tag, payload) = self.read_record()?;

            match tag {
                TAG_BUILD_SPEC => {
                    let record: BuildSpecRecord = serde_json::from_slice(&payload)?;
                    let old_idx = Index::from_raw_parts(record.arena_idx, record.arena_gen);
                    let mut spec = record.spec;

                    // Identify positions of Local build-deps so we can read their
                    // data records and update the paths.
                    let local_dep_positions: Vec<usize> = spec
                        .build_deps
                        .iter()
                        .enumerate()
                        .filter_map(|(i, d)| {
                            if matches!(d, BuildDep::Local { .. }) {
                                Some(i)
                            } else {
                                None
                            }
                        })
                        .collect();

                    for &dep_idx in &local_dep_positions {
                        let (ftag, fpayload) = self.read_record()?;
                        if ftag != TAG_LOCAL_FILE_DATA {
                            return Err(WireError::UnexpectedRecord {
                                expected: "LocalFileData",
                                got: ftag,
                            });
                        }

                        let dest_path = materialize_local_file(&fpayload, &mut temp_dir)?;

                        if let BuildDep::Local { full_path, .. } = &mut spec.build_deps[dep_idx] {
                            *full_path = dest_path;
                        }
                    }

                    let new_idx = arena.insert(spec);
                    remap.insert(old_idx, BuildSpecRef(new_idx));
                }

                TAG_TOP_LEVELS => {
                    top_levels_raw = serde_json::from_slice(&payload)?;
                }

                TAG_PROFILE => {
                    let record: ProfileRecord = serde_json::from_slice(&payload)?;
                    profiles.insert(record.name, record.profile);
                }

                TAG_HARNESS => {
                    let record: HarnessRecord = serde_json::from_slice(&payload)?;
                    harnesses.insert(record.name, record.harness);
                }

                TAG_SUPPLY_CHAIN => {
                    supply_chain = serde_json::from_slice(&payload)?;
                }

                TAG_FOOTER => {
                    let expected_hash = self.hasher.finalize();
                    if payload.len() != 32 || payload != expected_hash.as_bytes() {
                        return Err(WireError::ChecksumMismatch);
                    }
                    break;
                }

                _ => return Err(WireError::InvalidTag(tag)),
            }
        }

        // ── Fixup pass: remap all BuildSpecRef values ──
        for (_idx, spec) in arena.iter_mut() {
            fixup_spec(spec, &remap)?;
        }

        // Remap top_levels
        let top_levels: Vec<BuildSpecRef> = top_levels_raw
            .iter()
            .map(|&(idx, generation)| {
                let old = Index::from_raw_parts(idx, generation);
                remap.get(&old).copied().ok_or(WireError::DanglingRef {
                    wire_ref: (idx, generation),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Build by_name index
        let mut by_name = HashMap::with_capacity(arena.len());
        for (idx, build) in arena.iter() {
            by_name.insert(build.name.clone(), BuildSpecRef(idx));
        }

        Ok((
            Graph::from_parts(
                arena,
                top_levels,
                profiles,
                harnesses,
                by_name,
                supply_chain,
            ),
            temp_dir,
        ))
    }
}

/// Parses a [`TAG_LOCAL_FILE_DATA`] payload, materialises the file into a
/// temp directory, and returns the path the file was written to.
fn materialize_local_file(
    payload: &[u8],
    temp_dir: &mut Option<tempfile::TempDir>,
) -> Result<PathBuf, WireError> {
    let mut cursor = io::Cursor::new(payload);
    let header_len = decode_varint(&mut cursor)? as usize;
    let pos = cursor.position() as usize;

    let file_header: LocalFileHeader = serde_json::from_slice(&payload[pos..pos + header_len])?;
    let data_start = pos + header_len;
    let data_end = data_start + file_header.data_len as usize;
    let file_data = &payload[data_start..data_end];

    // Verify hash
    let actual_hash = blake3::hash(file_data);
    if actual_hash != file_header.file_hash {
        return Err(WireError::FileHashMismatch {
            filename: file_header.filename.clone(),
        });
    }

    // Materialise
    let td = temp_dir.get_or_insert_with(|| tempfile::TempDir::new().unwrap());
    let dest = td.path().join(&file_header.filename);
    std::fs::write(&dest, file_data)?;

    Ok(dest)
}

// ── Fixup helpers ────────────────────────────────────────────────────────────

fn fixup_ref(
    bsr: &mut BuildSpecRef,
    remap: &HashMap<Index, BuildSpecRef>,
) -> Result<(), WireError> {
    let old = bsr.0;
    let (idx, generation) = old.into_raw_parts();
    *bsr = *remap.get(&old).ok_or(WireError::DanglingRef {
        wire_ref: (idx, generation),
    })?;
    Ok(())
}

fn fixup_subset(
    si: &mut SubsetInput,
    remap: &HashMap<Index, BuildSpecRef>,
) -> Result<(), WireError> {
    fixup_ref(&mut si.from, remap)
}

fn fixup_spec(spec: &mut BuildSpec, remap: &HashMap<Index, BuildSpecRef>) -> Result<(), WireError> {
    // build_deps
    for dep in spec.build_deps.iter_mut() {
        match dep {
            BuildDep::Build(bsr) => fixup_ref(bsr, remap)?,
            BuildDep::Subset(si) => fixup_subset(si, remap)?,
            BuildDep::Source(_) | BuildDep::HostPath(_) | BuildDep::Local { .. } => {}
        }
    }
    // runtime_deps
    for dep in spec.runtime_deps.iter_mut() {
        match dep {
            RuntimeDep::Build(bsr) => fixup_ref(bsr, remap)?,
            RuntimeDep::Subset(si) => fixup_subset(si, remap)?,
        }
    }
    // replace_on_cycle
    if let Some(bsr) = &mut spec.replace_on_cycle {
        fixup_ref(bsr, remap)?;
    }
    // tests
    if let Some(tests) = &mut spec.tests {
        for (_name, test) in tests.iter_mut() {
            if let Some(deps) = &mut test.deps {
                for bsr in deps.iter_mut() {
                    fixup_ref(bsr, remap)?;
                }
            }
        }
    }
    Ok(())
}

// ── Async variants ──────────────────────────────────────────────────────────

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Async variant of [`GraphWriter`].
pub struct AsyncGraphWriter<W: AsyncWrite + Unpin> {
    writer: W,
    hasher: blake3::Hasher,
}

impl<W: AsyncWrite + Unpin> AsyncGraphWriter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            hasher: blake3::Hasher::new(),
        }
    }

    async fn write_record(&mut self, tag: u8, payload: &[u8]) -> Result<(), WireError> {
        let (vbuf, vlen) = varint_bytes(payload.len() as u64);

        self.hasher.update(&[tag]);
        self.writer.write_all(&[tag]).await?;
        self.hasher.update(&vbuf[..vlen]);
        self.writer.write_all(&vbuf[..vlen]).await?;
        self.hasher.update(payload);
        self.writer.write_all(payload).await?;

        Ok(())
    }

    pub async fn write_graph(mut self, graph: &Graph) -> Result<(), WireError> {
        // Header
        let header = HeaderRecord {
            version: STREAM_VERSION,
            build_count: graph.len(),
        };
        self.write_record(TAG_HEADER, &serde_json::to_vec(&header)?)
            .await?;

        // BuildSpecs + LocalFileData
        for (bsr, spec) in graph.iter() {
            let (arena_idx, arena_gen) = bsr.0.into_raw_parts();
            let record = BuildSpecRecord {
                arena_idx,
                arena_gen,
                spec: spec.clone(),
            };
            self.write_record(TAG_BUILD_SPEC, &serde_json::to_vec(&record)?)
                .await?;

            for dep in &spec.build_deps {
                if let BuildDep::Local {
                    full_path,
                    filename,
                    file_hash,
                } = dep
                {
                    self.write_local_file(full_path, filename, file_hash)
                        .await?;
                }
            }
        }

        // TopLevels
        let top_levels: Vec<(usize, u64)> = graph
            .top_levels
            .iter()
            .map(|bsr| bsr.0.into_raw_parts())
            .collect();
        self.write_record(TAG_TOP_LEVELS, &serde_json::to_vec(&top_levels)?)
            .await?;

        // Profiles
        for (name, profile) in graph.iter_profiles() {
            let record = ProfileRecord {
                name: name.clone(),
                profile: profile.clone(),
            };
            self.write_record(TAG_PROFILE, &serde_json::to_vec(&record)?)
                .await?;
        }

        // Harnesses
        for (name, harness) in graph.iter_harnesses() {
            let record = HarnessRecord {
                name: name.clone(),
                harness: harness.clone(),
            };
            self.write_record(TAG_HARNESS, &serde_json::to_vec(&record)?)
                .await?;
        }

        // SupplyChain
        self.write_record(
            TAG_SUPPLY_CHAIN,
            &serde_json::to_vec(graph.software_supply_chain())?,
        )
        .await?;

        // Footer (NOT hashed)
        let hash = self.hasher.finalize();
        let (vbuf, vlen) = varint_bytes(32);
        self.writer.write_all(&[TAG_FOOTER]).await?;
        self.writer.write_all(&vbuf[..vlen]).await?;
        self.writer.write_all(hash.as_bytes()).await?;

        Ok(())
    }

    async fn write_local_file(
        &mut self,
        full_path: &PathBuf,
        filename: &str,
        file_hash: &blake3::Hash,
    ) -> Result<(), WireError> {
        let file_data = std::fs::read(full_path)?;

        let header = LocalFileHeader {
            filename: filename.to_string(),
            file_hash: *file_hash,
            data_len: file_data.len() as u64,
        };
        let header_json = serde_json::to_vec(&header)?;

        let (vbuf, vlen) = varint_bytes(header_json.len() as u64);
        let mut payload = Vec::with_capacity(vlen + header_json.len() + file_data.len());
        payload.extend_from_slice(&vbuf[..vlen]);
        payload.extend_from_slice(&header_json);
        payload.extend_from_slice(&file_data);

        self.write_record(TAG_LOCAL_FILE_DATA, &payload).await?;
        Ok(())
    }
}

/// Async variant of [`GraphReader`].
pub struct AsyncGraphReader<W: AsyncRead + Unpin> {
    reader: W,
    hasher: blake3::Hasher,
}

impl<R: AsyncRead + Unpin> AsyncGraphReader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            hasher: blake3::Hasher::new(),
        }
    }

    async fn read_record(&mut self) -> Result<(u8, Vec<u8>), WireError> {
        let mut tag_buf = [0u8; 1];
        self.reader.read_exact(&mut tag_buf).await?;
        let tag = tag_buf[0];

        // Decode varint, tracking raw bytes
        let mut varint_buf: Vec<u8> = Vec::with_capacity(10);
        let len = {
            let mut result: u64 = 0;
            let mut shift: u32 = 0;
            loop {
                let mut byte = [0u8; 1];
                self.reader.read_exact(&mut byte).await?;
                varint_buf.push(byte[0]);
                result |= ((byte[0] & 0x7F) as u64) << shift;
                if byte[0] & 0x80 == 0 {
                    break;
                }
                shift += 7;
                if shift >= 64 {
                    return Err(
                        io::Error::new(io::ErrorKind::InvalidData, "varint overflow").into(),
                    );
                }
            }
            result
        };

        let mut payload = vec![0u8; len as usize];
        self.reader.read_exact(&mut payload).await?;

        if tag != TAG_FOOTER {
            self.hasher.update(&tag_buf);
            self.hasher.update(&varint_buf);
            self.hasher.update(&payload);
        }

        Ok((tag, payload))
    }

    pub async fn read_graph(mut self) -> Result<(Graph, Option<tempfile::TempDir>), WireError> {
        // Header
        let (tag, payload) = self.read_record().await?;
        if tag != TAG_HEADER {
            return Err(WireError::UnexpectedRecord {
                expected: "Header",
                got: tag,
            });
        }
        let header: HeaderRecord = serde_json::from_slice(&payload)?;
        if header.version != STREAM_VERSION {
            return Err(WireError::UnsupportedVersion(header.version));
        }

        let mut arena: Arena<BuildSpec> = Arena::with_capacity(header.build_count);
        let mut remap: HashMap<Index, BuildSpecRef> = HashMap::with_capacity(header.build_count);
        let mut temp_dir: Option<tempfile::TempDir> = None;

        let mut top_levels_raw: Vec<(usize, u64)> = Vec::new();
        let mut profiles: HashMap<String, Profile> = HashMap::new();
        let mut harnesses: HashMap<String, Harness> = HashMap::new();
        let mut supply_chain: Vec<SpecOrigin> = Vec::new();

        loop {
            let (tag, payload) = self.read_record().await?;

            match tag {
                TAG_BUILD_SPEC => {
                    let record: BuildSpecRecord = serde_json::from_slice(&payload)?;
                    let old_idx = Index::from_raw_parts(record.arena_idx, record.arena_gen);
                    let mut spec = record.spec;

                    let local_dep_positions: Vec<usize> = spec
                        .build_deps
                        .iter()
                        .enumerate()
                        .filter_map(|(i, d)| {
                            if matches!(d, BuildDep::Local { .. }) {
                                Some(i)
                            } else {
                                None
                            }
                        })
                        .collect();

                    for &dep_idx in &local_dep_positions {
                        let (ftag, fpayload) = self.read_record().await?;
                        if ftag != TAG_LOCAL_FILE_DATA {
                            return Err(WireError::UnexpectedRecord {
                                expected: "LocalFileData",
                                got: ftag,
                            });
                        }
                        let dest_path = materialize_local_file(&fpayload, &mut temp_dir)?;
                        if let BuildDep::Local { full_path, .. } = &mut spec.build_deps[dep_idx] {
                            *full_path = dest_path;
                        }
                    }

                    let new_idx = arena.insert(spec);
                    remap.insert(old_idx, BuildSpecRef(new_idx));
                }

                TAG_TOP_LEVELS => {
                    top_levels_raw = serde_json::from_slice(&payload)?;
                }

                TAG_PROFILE => {
                    let record: ProfileRecord = serde_json::from_slice(&payload)?;
                    profiles.insert(record.name, record.profile);
                }

                TAG_HARNESS => {
                    let record: HarnessRecord = serde_json::from_slice(&payload)?;
                    harnesses.insert(record.name, record.harness);
                }

                TAG_SUPPLY_CHAIN => {
                    supply_chain = serde_json::from_slice(&payload)?;
                }

                TAG_FOOTER => {
                    let expected_hash = self.hasher.finalize();
                    if payload.len() != 32 || payload != expected_hash.as_bytes() {
                        return Err(WireError::ChecksumMismatch);
                    }
                    break;
                }

                _ => return Err(WireError::InvalidTag(tag)),
            }
        }

        for (_idx, spec) in arena.iter_mut() {
            fixup_spec(spec, &remap)?;
        }

        let top_levels: Vec<BuildSpecRef> = top_levels_raw
            .iter()
            .map(|&(idx, generation)| {
                let old = Index::from_raw_parts(idx, generation);
                remap.get(&old).copied().ok_or(WireError::DanglingRef {
                    wire_ref: (idx, generation),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut by_name = HashMap::with_capacity(arena.len());
        for (idx, build) in arena.iter() {
            by_name.insert(build.name.clone(), BuildSpecRef(idx));
        }

        Ok((
            Graph::from_parts(
                arena,
                top_levels,
                profiles,
                harnesses,
                by_name,
                supply_chain,
            ),
            temp_dir,
        ))
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builds::SpecTest;
    use common::SpecOrigin;
    use smallvec::smallvec;
    use std::sync::Arc;

    /// Helper: serialise and deserialise, returning the round-tripped graph.
    fn roundtrip(graph: &Graph) -> (Graph, Option<tempfile::TempDir>) {
        let mut buf = Vec::new();
        GraphWriter::new(&mut buf).write_graph(graph).unwrap();
        GraphReader::new(io::Cursor::new(buf)).read_graph().unwrap()
    }

    #[test]
    fn empty_graph_roundtrip() {
        let graph = Graph::new();
        let (restored, td) = roundtrip(&graph);
        assert!(td.is_none());
        assert_eq!(restored.len(), 0);
        assert!(restored.top_levels.is_empty());
    }

    #[test]
    fn basic_roundtrip() {
        // Build a small graph by hand.
        let mut graph = Graph::new();
        let origin = Arc::new(SpecOrigin::Inline);
        let shared = graph.insert_build(BuildSpec {
            name: "shared".into(),
            cmds: vec![vec!["make".into()]],
            from: origin.clone(),
            ..Default::default()
        });
        let top = graph.insert_build(BuildSpec {
            name: "top".into(),
            build_deps: smallvec![BuildDep::Build(shared)],
            runtime_deps: smallvec![RuntimeDep::Build(shared)],
            from: origin.clone(),
            ..Default::default()
        });
        graph.top_levels = vec![top];

        let (restored, td) = roundtrip(&graph);
        assert!(td.is_none());

        // Structural checks
        assert_eq!(restored.len(), 2);
        assert!(restored.by_name("shared").is_some());
        assert!(restored.by_name("top").is_some());

        // Spec hashes match
        for (bsr, spec) in graph.iter() {
            let r_bsr = restored.by_name(&spec.name).unwrap();
            assert_eq!(
                graph.spec_hash(&bsr),
                restored.spec_hash(r_bsr),
                "spec_hash mismatch for {}",
                spec.name
            );
        }

        // Cross-references intact
        let top_spec = restored.get(restored.by_name("top").unwrap()).unwrap();
        let shared_ref = restored.by_name("shared").unwrap();
        assert_eq!(top_spec.build_deps[0].as_build().unwrap(), shared_ref);
        assert_eq!(top_spec.runtime_deps[0].bsr(), shared_ref);

        // Top-levels length preserved
        assert_eq!(restored.top_levels.len(), 1);
    }

    #[test]
    fn roundtrip_with_local_files() {
        let tmp = tempfile::TempDir::new().unwrap();
        let file_path = tmp.path().join("patch.diff");
        std::fs::write(&file_path, b"--- a/foo\n+++ b/foo\n").unwrap();
        let file_hash = blake3::hash(b"--- a/foo\n+++ b/foo\n");

        let mut graph = Graph::new();
        let origin = Arc::new(SpecOrigin::Inline);
        let bsr = graph.insert_build(BuildSpec {
            name: "pkg".into(),
            build_deps: smallvec![BuildDep::Local {
                full_path: file_path.clone(),
                filename: "patch.diff".into(),
                file_hash,
            }],
            from: origin,
            ..Default::default()
        });
        graph.top_levels = vec![bsr];

        let (restored, td) = roundtrip(&graph);
        assert!(td.is_some(), "should have materialised files");

        let spec = restored.get(restored.by_name("pkg").unwrap()).unwrap();
        let BuildDep::Local {
            full_path,
            filename,
            file_hash: h,
        } = &spec.build_deps[0]
        else {
            panic!("expected Local dep");
        };
        assert_eq!(filename, "patch.diff");
        assert_eq!(*h, file_hash);
        // Path should point into the temp dir, not the original
        assert_ne!(full_path, &file_path);
        assert_eq!(
            std::fs::read_to_string(full_path).unwrap(),
            "--- a/foo\n+++ b/foo\n"
        );
    }

    #[test]
    fn corrupt_stream_detected() {
        let graph = Graph::new();
        let mut buf = Vec::new();
        GraphWriter::new(&mut buf).write_graph(&graph).unwrap();

        // Flip a byte in the middle of the stream (before footer)
        if buf.len() > 10 {
            buf[5] ^= 0xFF;
        }

        let result = GraphReader::new(io::Cursor::new(buf)).read_graph();
        assert!(result.is_err());
    }

    #[test]
    fn footer_checksum_validation() {
        let graph = Graph::new();
        let mut buf = Vec::new();
        GraphWriter::new(&mut buf).write_graph(&graph).unwrap();

        // Corrupt the last byte (part of the checksum)
        let last = buf.len() - 1;
        buf[last] ^= 0xFF;

        let err = GraphReader::new(io::Cursor::new(buf))
            .read_graph()
            .unwrap_err();
        assert!(
            matches!(err, WireError::ChecksumMismatch),
            "expected ChecksumMismatch, got: {err}"
        );
    }

    #[test]
    fn version_mismatch_error() {
        // Craft a header with version 99
        let header = HeaderRecord {
            version: 99,
            build_count: 0,
        };
        let payload = serde_json::to_vec(&header).unwrap();
        let mut buf = Vec::new();
        buf.push(TAG_HEADER);
        encode_varint(payload.len() as u64, &mut buf);
        buf.extend_from_slice(&payload);

        let err = GraphReader::new(io::Cursor::new(buf))
            .read_graph()
            .unwrap_err();
        assert!(
            matches!(err, WireError::UnsupportedVersion(99)),
            "expected UnsupportedVersion(99), got: {err}"
        );
    }

    #[test]
    fn roundtrip_with_tests_and_replace_on_cycle() {
        let mut graph = Graph::new();
        let origin = Arc::new(SpecOrigin::Inline);

        let fallback = graph.insert_build(BuildSpec {
            name: "fallback".into(),
            from: origin.clone(),
            ..Default::default()
        });
        let main_pkg = graph.insert_build(BuildSpec {
            name: "main".into(),
            replace_on_cycle: Some(fallback),
            tests: Some(
                [(
                    "smoke".to_string(),
                    SpecTest {
                        build_test: false,
                        deps: Some(smallvec![fallback]),
                        cmds: vec![vec!["test".into()]],
                    },
                )]
                .into(),
            ),
            from: origin,
            ..Default::default()
        });
        graph.top_levels = vec![main_pkg];

        let (restored, _) = roundtrip(&graph);
        let spec = restored.get(restored.by_name("main").unwrap()).unwrap();

        // replace_on_cycle should point to fallback
        let fb_ref = restored.by_name("fallback").unwrap();
        assert_eq!(spec.replace_on_cycle.as_ref().unwrap(), fb_ref);

        // test deps should point to fallback
        let test = spec.tests.as_ref().unwrap().get("smoke").unwrap();
        assert_eq!(&test.deps.as_ref().unwrap()[0], fb_ref);
    }

    #[test]
    fn varint_roundtrip() {
        for &value in &[0u64, 1, 127, 128, 16383, 16384, u32::MAX as u64, u64::MAX] {
            let mut buf = Vec::new();
            encode_varint(value, &mut buf);
            let decoded = decode_varint(&mut io::Cursor::new(&buf)).unwrap();
            assert_eq!(value, decoded, "varint roundtrip failed for {value}");
        }
    }
}
