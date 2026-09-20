//! The audit chain as pure functions over bytes: the hash each line of the log
//! carries, the walk that checks them, and where a walk breaks.
//!
//! [`crate::audit`] writes the chain: a record's `previous_hash` is the
//! SHA-256 of the line before it, that line's own `previous_hash` included, or
//! [`Hash::ZERO`] for the first record of a log (BEP-048). Reading it back is a
//! walk over bytes — every line's carried hash against the hash of the line
//! before it, from the hash the first line must carry: [`Hash::ZERO`] at the
//! start of a log, and the previous segment's final hash for a walk that
//! begins mid-log (BEP-068).
//!
//! The walk lives apart from the writer and from any file, so `min doctor`
//! (BEP-049), the segment rotator and the bounded proofs share one
//! construction. What a bare chain sees is a record altered or removed without
//! recomputing the hashes that follow; an edit followed by a recomputation of
//! the whole log, which the host's own root can do, is the residual the
//! specification accepts.

use std::fmt;

use crate::audit::{Hash, Record};

/// One link of the chain as a verifier sees it: a record's line as the log
/// holds it, without the trailing newline, and the hash that line carries as
/// its predecessor's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Link<'a> {
    line: &'a [u8],
    carried: Hash,
}

impl<'a> Link<'a> {
    /// The link `line` makes while carrying `carried`.
    #[must_use]
    pub fn new(line: &'a [u8], carried: Hash) -> Self {
        Self { line, carried }
    }

    /// The line's bytes, as the next link's hash covers them.
    #[must_use]
    pub fn line(&self) -> &'a [u8] {
        self.line
    }

    /// The hash the line carries as its predecessor's.
    #[must_use]
    pub fn carried(&self) -> Hash {
        self.carried
    }

    /// The hash the link after this one must carry.
    #[must_use]
    pub fn hash(&self) -> Hash {
        Hash::of_line(self.line)
    }
}

/// Where a chain breaks: the first link whose carried hash is not the hash of
/// the line before it (BEP-049).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Break {
    /// The link's position, counted from the first link of the walk.
    pub at: usize,
    /// The hash the link carries.
    pub carried: Hash,
    /// The hash it had to carry: the hash of the line before it, or the hash
    /// the walk started from when the break is at the first link.
    pub expected: Hash,
}

impl fmt::Display for Break {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "record {} carries {} where the record before it hashes to {}",
            self.at + 1,
            self.carried,
            self.expected
        )
    }
}

/// A line no link can be read from: it is no audit record, so the hash it
/// carries is unknown.
#[derive(Debug, thiserror::Error)]
#[error("line {line} is no audit record: {source}")]
pub struct Malformed {
    /// The line's number, counted from one.
    pub line: usize,
    /// What reading the record failed on.
    #[source]
    pub source: serde_json_lenient::Error,
}

/// The hash each of `lines` carries in a chain starting from `from`: `from` for
/// the first line, and the hash of the line before it for every other
/// (BEP-048).
///
/// This is the writer's own step as a function over bytes: what
/// [`crate::audit::Log`] puts in each record's `previous_hash`, with no file
/// and no record shape in the way.
#[must_use]
pub fn chained<'a>(lines: impl IntoIterator<Item = &'a [u8]>, from: Hash) -> Vec<Hash> {
    let mut carried = Vec::new();
    let mut previous = from;
    for line in lines {
        carried.push(previous);
        previous = Hash::of_line(line);
    }
    carried
}

/// The hash the chain over `links` ends on — what a record appended after them
/// carries — or the first link that does not follow the one before it.
///
/// `from` is the hash the first link must carry: [`Hash::ZERO`] for a walk over
/// a whole log, and the final hash of the segment before it for a walk that
/// begins mid-log. A walk over no link ends on `from`.
///
/// # Errors
///
/// [`Break`] naming the first link whose carried hash is not the hash of the
/// line before it: a record altered or removed without recomputing the hashes
/// that follow (BEP-049).
pub fn verify<'a>(links: impl IntoIterator<Item = Link<'a>>, from: Hash) -> Result<Hash, Break> {
    let mut expected = from;
    for (at, link) in links.into_iter().enumerate() {
        if link.carried != expected {
            return Err(Break {
                at,
                carried: link.carried,
                expected,
            });
        }
        expected = link.hash();
    }
    Ok(expected)
}

/// The links the bytes of one log segment hold: one per whole line, in the
/// order the segment holds them.
///
/// A final line with no newline yet is the proxy still writing it, so it is no
/// link; a blank line is no link either.
///
/// # Errors
///
/// [`Malformed`] when a line of the segment is no audit record.
pub fn links(bytes: &[u8]) -> Result<Vec<Link<'_>>, Malformed> {
    let mut links = Vec::new();
    for (at, line) in bytes.split_inclusive(|byte| *byte == b'\n').enumerate() {
        // A line the proxy has not finished writing is no link yet.
        let Some(bare) = line.strip_suffix(b"\n") else {
            break;
        };
        if bare.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let text = String::from_utf8_lossy(bare);
        let record: Record = serde_json_lenient::from_str(&text).map_err(|source| Malformed {
            line: at + 1,
            source,
        })?;
        links.push(Link::new(bare, record.previous_hash));
    }
    Ok(links)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::audit::{Decision, Event, Kind, Log, Mapping};

    /// An event of the field shape the proxy records, with enough variation
    /// that two events rarely make the same record.
    fn event() -> impl Strategy<Value = Event> {
        (
            "[a-z0-9]{0,6}",
            "[a-z.]{0,8}",
            proptest::option::of("[a-z:-]{0,8}"),
            any::<bool>(),
            any::<bool>(),
        )
            .prop_map(|(box_id, authority, credential, mapped, admit)| Event {
                kind: Kind::Decision,
                box_id,
                authority,
                credential,
                mapping: if mapped {
                    Mapping::mapped("repo:acme/web", "contents:write")
                } else {
                    Mapping::Unmapped
                },
                decision: if admit {
                    Decision::Admit
                } else {
                    Decision::Refuse
                },
                marker: None,
            })
    }

    /// The records `events` make in a chain from the zero hash, as the log
    /// would append them.
    fn records(events: &[Event]) -> Vec<Record> {
        let mut previous = Hash::ZERO;
        events
            .iter()
            .map(|event| {
                let record = Record::new(event, previous);
                previous = record.line_hash();
                record
            })
            .collect()
    }

    fn lines_of(records: &[Record]) -> Vec<String> {
        records.iter().map(Record::line).collect()
    }

    fn links_of<'a>(lines: &'a [String], carried: &[Hash]) -> Vec<Link<'a>> {
        lines
            .iter()
            .zip(carried)
            .map(|(line, hash)| Link::new(line.as_bytes(), *hash))
            .collect()
    }

    /// The links of a segment are its whole lines with the hash each carries, a
    /// half-written line and a blank line left out, and a line that is no
    /// record named rather than skipped.
    #[test]
    fn links_read_the_whole_lines_of_a_segment() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let mut log = Log::open(&path).unwrap();
        for authority in ["api.github.com", "github.com"] {
            log.append(&Event {
                kind: Kind::Decision,
                box_id: "web".to_owned(),
                authority: authority.to_owned(),
                credential: None,
                mapping: Mapping::Unmapped,
                decision: Decision::Admit,
                marker: None,
            })
            .unwrap();
        }
        let held = std::fs::read(&path).unwrap();
        let read = links(&held).unwrap();
        assert_eq!(read.len(), 2);
        assert_eq!(read[0].carried(), Hash::ZERO);
        assert_eq!(read[1].carried(), read[0].hash());
        assert_eq!(
            verify(read.iter().copied(), Hash::ZERO).unwrap(),
            log.head()
        );

        // A blank line and a line still being written are no links.
        let mut growing = held.clone();
        growing.extend_from_slice(b"\n");
        growing.extend_from_slice(&held[..held.len() / 2]);
        assert_eq!(links(&growing).unwrap().len(), 2);

        // A line that is no record is named, with the line number.
        let mut broken = held.clone();
        broken.extend_from_slice(b"not a record\n");
        let error = links(&broken).expect_err("a line that is no record is an error");
        assert_eq!(error.line, 3);
    }

    proptest! {
        /// BEP-049: the chain built from a sequence of records verifies, and
        /// every sequence got by altering or removing one record that has a
        /// successor — leaving the hashes that follow as they were — fails
        /// verification, naming the link that no longer follows.
        #[test]
        fn prop_audit_chain_detects_unrecomputed_edit(
            events in prop::collection::vec(event(), 1..6),
            edit in event(),
            pick in any::<usize>(),
        ) {
            let built = records(&events);
            let lines = lines_of(&built);
            let carried: Vec<Hash> = built.iter().map(|record| record.previous_hash).collect();

            // The writer's chaining is the chain over the lines: what each
            // record carries is what the pure function computes.
            prop_assert_eq!(
                chained(lines.iter().map(String::as_bytes), Hash::ZERO),
                carried.clone()
            );
            let head = verify(links_of(&lines, &carried), Hash::ZERO)
                .expect("the chain the writer built verifies");
            prop_assert_eq!(head, built.last().unwrap().line_hash());

            // Only a record with a successor is covered: no hash in the log
            // stands over the last record's line.
            if built.len() > 1 {
                let at = pick % (built.len() - 1);

                // Altered: the record replaced, carrying what it carried, and
                // no hash after it recomputed.
                let replacement = Record::new(&edit, carried[at]);
                prop_assume!(replacement.line() != lines[at]);
                let mut altered = lines.clone();
                altered[at] = replacement.line();
                let broken = verify(links_of(&altered, &carried), Hash::ZERO)
                    .expect_err("an altered record breaks the chain");
                prop_assert_eq!(broken.at, at + 1);
                prop_assert_eq!(broken.carried, carried[at + 1]);

                // Removed: the record taken out, and again no hash after it
                // recomputed.
                let mut removed = lines.clone();
                let mut removed_carried = carried.clone();
                removed.remove(at);
                removed_carried.remove(at);
                let broken = verify(links_of(&removed, &removed_carried), Hash::ZERO)
                    .expect_err("a removed record breaks the chain");
                prop_assert_eq!(broken.at, at);
            }
        }
    }
}

/// Bounded proof of BEP-049 over the walk's own bytes: at most four records of
/// at most 64 bytes, every byte and every length symbolic.
///
/// Run: `cargo kani -p bep` (or `just kani`). Kani pinned at 0.68.0 in CI.
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// The record bound the specification's harness names.
    const RECORDS: usize = 4;
    /// The line bound it names: at most 64 bytes to a record.
    const LINE: usize = 64;

    /// A line of at most [`LINE`] bytes, its bytes and its length symbolic.
    fn any_line() -> Vec<u8> {
        let bytes: [u8; LINE] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= LINE);
        bytes[..len].to_vec()
    }

    fn links_of<'a>(lines: &'a [Vec<u8>], carried: &[Hash]) -> Vec<Link<'a>> {
        lines
            .iter()
            .zip(carried)
            .map(|(line, hash)| Link::new(line, *hash))
            .collect()
    }

    /// BEP-049: the chain over a sequence of lines verifies, and altering or
    /// removing a line that has a successor — leaving every hash after it as it
    /// was — breaks the walk, unless what replaces the line hashes to what the
    /// line hashed to. SHA-256's collision resistance is the assumption the
    /// chain rests on and not a thing the chain can establish, so the collision
    /// is named in the property rather than assumed away.
    #[kani::proof]
    #[kani::unwind(6)]
    fn kani_audit_chain_detects_edit() {
        let count: usize = kani::any();
        kani::assume(count >= 2 && count <= RECORDS);
        let mut lines: Vec<Vec<u8>> = Vec::new();
        for _ in 0..RECORDS {
            if lines.len() < count {
                lines.push(any_line());
            }
        }
        let carried = chained(lines.iter().map(Vec::as_slice), Hash::ZERO);
        assert!(verify(links_of(&lines, &carried), Hash::ZERO).is_ok());

        let at: usize = kani::any();
        kani::assume(at + 1 < count);

        // Altered: one line replaced, every hash after it left as it was.
        let mut altered = lines.clone();
        altered[at] = any_line();
        assert!(
            verify(links_of(&altered, &carried), Hash::ZERO).is_err()
                || Hash::of_line(&altered[at]) == Hash::of_line(&lines[at])
        );

        // Removed: one line taken out, every hash after it left as it was.
        let mut removed = lines.clone();
        let mut removed_carried = carried.clone();
        removed.remove(at);
        removed_carried.remove(at);
        let expected = if at == 0 {
            Hash::ZERO
        } else {
            Hash::of_line(&lines[at - 1])
        };
        assert!(
            verify(links_of(&removed, &removed_carried), Hash::ZERO).is_err()
                || Hash::of_line(&lines[at]) == expected
        );
    }
}
