//! A box's lifecycle events (BOX-040): what happened to the box and when,
//! one record per transition, in the order the daemon wrote them.
//!
//! The daemon alone writes a box's events (BOX-041). They live in
//! [`EVENTS_FILE`] beside the box's `record.json`, in the box's state
//! directory, which no path mounted into the box reaches. The file is
//! newline-delimited JSON, one [`BoxEvent`] per line, appended and never
//! rewritten, so the order of the lines is the order of the writes
//! (BOX-162).

use serde::{Deserialize, Serialize};

use crate::{BoxId, Record};

/// The name of the file beside `record.json` that holds the box's events.
pub const EVENTS_FILE: &str = "events.jsonl";

/// The type of a lifecycle event (BOX-040).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoxEventType {
    /// The box's record was created.
    Created,
    /// The box's entrypoint started and the record entered `running`.
    Started,
    /// An exec started in the box.
    ExecStarted,
    /// An exec in the box exited.
    ExecExited,
    /// The kernel killed a process in the box for memory.
    OomKilled,
    /// The record entered `stopped` or `exited`.
    Exited,
    /// The box was renamed.
    Renamed,
    /// The box was resumed.
    Resumed,
    /// A client detached from the box.
    Detached,
}

impl BoxEventType {
    /// The event type as it is written on the wire and on disk.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Started => "started",
            Self::ExecStarted => "exec_started",
            Self::ExecExited => "exec_exited",
            Self::OomKilled => "oom_killed",
            Self::Exited => "exited",
            Self::Renamed => "renamed",
            Self::Resumed => "resumed",
            Self::Detached => "detached",
        }
    }
}

/// One lifecycle event of one box (BOX-040).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoxEvent {
    /// The box the event is about: its record's id.
    #[serde(rename = "box")]
    pub box_id: BoxId,
    /// The box's parent, as its record names it. `None` for a box created
    /// outside any box.
    pub parent: Option<BoxId>,
    /// When the daemon wrote the event, in milliseconds since the Unix
    /// epoch (UTC).
    pub ts: u64,
    /// What happened.
    #[serde(rename = "type")]
    pub kind: BoxEventType,
}

impl BoxEvent {
    /// An event of `kind` about the box `record` describes, stamped now.
    #[must_use]
    pub fn for_record(record: &Record, kind: BoxEventType) -> Self {
        Self {
            box_id: record.id,
            parent: record.parent,
            ts: now_ms(),
            kind,
        }
    }

    /// The event as one line of [`EVENTS_FILE`]: its JSON and a newline.
    ///
    /// # Errors
    ///
    /// Never in practice: every field serialises.
    pub fn to_line(&self) -> Result<Vec<u8>, std::io::Error> {
        let mut line = serde_json_lenient::to_vec(self).map_err(std::io::Error::other)?;
        line.push(b'\n');
        Ok(line)
    }
}

/// The events [`decode_lines`] read, and how far it read.
#[derive(Debug, Default)]
pub struct DecodedEvents {
    /// The events of every complete line, in file order.
    pub events: Vec<BoxEvent>,
    /// The complete lines that did not parse as an event, as
    /// `(byte offset of the line, parse error)`.
    pub refused: Vec<(u64, String)>,
    /// The bytes consumed: every complete line. A partial last line, one
    /// still being written, is left for the next read.
    pub consumed: u64,
}

/// Decodes the complete lines of `buf`, which starts at byte `base` of the
/// events file. A line without its newline is not read.
#[must_use]
pub fn decode_lines(buf: &[u8], base: u64) -> DecodedEvents {
    let mut out = DecodedEvents::default();
    let mut start = 0usize;
    while let Some(len) = buf[start..].iter().position(|b| *b == b'\n') {
        let line = &buf[start..start + len];
        if !line.iter().all(u8::is_ascii_whitespace) {
            match serde_json_lenient::from_slice::<BoxEvent>(line) {
                Ok(event) => out.events.push(event),
                Err(e) => out.refused.push((base + start as u64, e.to_string())),
            }
        }
        start += len + 1;
    }
    out.consumed = start as u64;
    out
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_serialises_with_box_parent_ts_and_type() {
        let event = BoxEvent {
            box_id: BoxId::mint(),
            parent: None,
            ts: 1,
            kind: BoxEventType::ExecStarted,
        };
        let value: serde_json_lenient::Value =
            serde_json_lenient::from_slice(&event.to_line().unwrap()).unwrap();
        assert_eq!(value["type"], "exec_started");
        assert_eq!(value["parent"], serde_json_lenient::Value::Null);
        assert_eq!(value["ts"], 1);
        assert_eq!(value["box"], event.box_id.to_string());
    }

    #[test]
    fn decode_leaves_a_partial_line_and_reports_a_bad_one() {
        let event = BoxEvent {
            box_id: BoxId::mint(),
            parent: None,
            ts: 2,
            kind: BoxEventType::Created,
        };
        let mut buf = event.to_line().unwrap();
        let bad_at = buf.len() as u64;
        buf.extend_from_slice(b"not json\n{\"box\"");
        let decoded = decode_lines(&buf, 10);
        assert_eq!(decoded.events, vec![event]);
        assert_eq!(decoded.refused.len(), 1);
        assert_eq!(decoded.refused[0].0, 10 + bad_at);
        assert_eq!(decoded.consumed, bad_at + 9);
    }
}
