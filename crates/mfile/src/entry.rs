//! Box entries: the named tables of `minimal.toml` that a box is created
//! from.
//!
//! `[boxes.<name>]` is the general form. Each type-noun table is sugar for it
//! (BOX-046): `[sessions.<name>]`, `[tasks.<name>]`, `[agents.<name>]` and
//! `[services.<name>]` read as `[boxes.<name>]` with `type` set to the
//! noun's type. A sugar table can repeat that `type`, and any other `type`
//! in it fails with exit 3. A `type` that is not a string fails with exit 3
//! in every table. The entry keeps the table it came from, so a later step
//! can refuse `[agents.*]` and `[services.*]` per entry (BOX-063).
//!
//! Every entry name must be DNS-safe, unique across the file, and not
//! `self` (BOX-007, BOX-046). An entry that breaks a rule fails with
//! [`Error::InvalidEntryName`], which exits 3 and names the entry.

use std::collections::BTreeMap;

use crate::Error;
use crate::error::EntryNameRule;

/// The name that no entry and no box can take: it addresses the caller's
/// own box.
pub const RESERVED_ENTRY_NAME: &str = "self";

/// The longest DNS label, and so the longest entry name.
const MAX_ENTRY_NAME_LEN: usize = 63;

/// The table that declares an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EntryTable {
    /// `[boxes.<name>]`, the general form.
    Boxes,
    /// `[sessions.<name>]`, sugar for `type = "session"`.
    Sessions,
    /// `[tasks.<name>]`, sugar for `type = "task"`.
    Tasks,
    /// `[agents.<name>]`, sugar for `type = "agent"`.
    Agents,
    /// `[services.<name>]`, sugar for `type = "service"`.
    Services,
}

impl EntryTable {
    /// Every entry table, in the order the file is read.
    pub const ALL: [EntryTable; 5] = [
        EntryTable::Boxes,
        EntryTable::Sessions,
        EntryTable::Tasks,
        EntryTable::Agents,
        EntryTable::Services,
    ];

    /// The top-level key of the table, as the file spells it.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            EntryTable::Boxes => "boxes",
            EntryTable::Sessions => "sessions",
            EntryTable::Tasks => "tasks",
            EntryTable::Agents => "agents",
            EntryTable::Services => "services",
        }
    }

    /// The Box Type that a sugar table sets. `[boxes.*]` sets none.
    #[must_use]
    pub const fn box_type(self) -> Option<&'static str> {
        match self {
            EntryTable::Boxes => None,
            EntryTable::Sessions => Some("session"),
            EntryTable::Tasks => Some("task"),
            EntryTable::Agents => Some("agent"),
            EntryTable::Services => Some("service"),
        }
    }
}

/// One entry of `minimal.toml`, read as `[boxes.<name>]`.
#[derive(Debug, Clone, PartialEq)]
pub struct BoxEntry {
    /// The entry name: the key under its table.
    pub name: String,
    /// The table that declares the entry.
    pub table: EntryTable,
    /// The entry's Box Type: the noun of its sugar table, or the `type` key
    /// of a `[boxes.*]` entry. `None` only for a `[boxes.*]` entry without
    /// `type`.
    pub box_type: Option<String>,
    /// The entry's keys as the file wrote them, with `type` set to
    /// [`BoxEntry::box_type`] when it is known.
    pub body: toml::Table,
}

/// The entry tables of a `minimal.toml`. Every other key is ignored here.
#[derive(Debug, Default, serde::Deserialize)]
struct EntryTables {
    #[serde(default)]
    boxes: BTreeMap<String, toml::Table>,
    #[serde(default)]
    sessions: BTreeMap<String, toml::Table>,
    #[serde(default)]
    tasks: BTreeMap<String, toml::Table>,
    #[serde(default)]
    agents: BTreeMap<String, toml::Table>,
    #[serde(default)]
    services: BTreeMap<String, toml::Table>,
}

impl EntryTables {
    fn take(&mut self, table: EntryTable) -> BTreeMap<String, toml::Table> {
        std::mem::take(match table {
            EntryTable::Boxes => &mut self.boxes,
            EntryTable::Sessions => &mut self.sessions,
            EntryTable::Tasks => &mut self.tasks,
            EntryTable::Agents => &mut self.agents,
            EntryTable::Services => &mut self.services,
        })
    }
}

/// Reads every entry of a `minimal.toml` as a `[boxes.<name>]` entry, in
/// table order and then name order.
///
/// # Errors
///
/// [`Error::Format`] when the bytes are not TOML or an entry table is not a
/// table of tables. [`Error::InvalidEntryName`] for the first entry whose
/// name is `self`, is not DNS-safe, or names an earlier entry, or whose
/// `type` is not a string or differs from its sugar table's noun.
pub fn read_entries(bytes: &[u8]) -> Result<Vec<BoxEntry>, Error> {
    let mut tables: EntryTables = toml::from_slice(bytes).map_err(Error::Format)?;
    let mut seen: BTreeMap<String, EntryTable> = BTreeMap::new();
    let mut entries = Vec::new();
    for table in EntryTable::ALL {
        for (name, mut body) in tables.take(table) {
            check_entry_name(table, &name)?;
            if let Some(&first) = seen.get(&name) {
                return Err(Error::InvalidEntryName {
                    table: table.key(),
                    name,
                    rule: EntryNameRule::Duplicate {
                        other_table: first.key(),
                    },
                });
            }
            seen.insert(name.clone(), table);
            let box_type = entry_type(table, &name, body.get("type"))?;
            if let Some(t) = &box_type {
                body.insert("type".to_owned(), toml::Value::String(t.clone()));
            }
            entries.push(BoxEntry {
                name,
                table,
                box_type,
                body,
            });
        }
    }
    Ok(entries)
}

/// The Box Type of one entry, from its table and its `type` key.
fn entry_type(
    table: EntryTable,
    name: &str,
    written: Option<&toml::Value>,
) -> Result<Option<String>, Error> {
    let rule = match (written, table.box_type()) {
        (None, noun) => return Ok(noun.map(str::to_owned)),
        (Some(toml::Value::String(t)), None) => return Ok(Some(t.clone())),
        (Some(toml::Value::String(t)), Some(noun)) if t == noun => {
            return Ok(Some(noun.to_owned()));
        }
        (Some(toml::Value::String(t)), Some(noun)) => EntryNameRule::TypeMismatch {
            expected: noun,
            found: t.clone(),
        },
        (Some(_), _) => EntryNameRule::TypeNotString,
    };
    Err(Error::InvalidEntryName {
        table: table.key(),
        name: name.to_owned(),
        rule,
    })
}

/// Checks one entry name against the reserved name and the DNS-label rule.
fn check_entry_name(table: EntryTable, name: &str) -> Result<(), Error> {
    let rule = if name == RESERVED_ENTRY_NAME {
        EntryNameRule::Reserved
    } else if !is_dns_safe(name) {
        EntryNameRule::NotDnsSafe
    } else {
        return Ok(());
    };
    Err(Error::InvalidEntryName {
        table: table.key(),
        name: name.to_owned(),
        rule,
    })
}

/// Whether `name` is a DNS label (RFC 1123) in lowercase: 1 to 63 of
/// `a-z`, `0-9` and `-`, with no `-` first or last.
#[must_use]
pub fn is_dns_safe(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_ENTRY_NAME_LEN
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invalid(src: &str) -> (Error, String) {
        let err = read_entries(src.as_bytes()).expect_err("the name is invalid");
        let msg = err.to_string();
        (err, msg)
    }

    // BOX-007: `self` names no entry, in any table, and exits 3.
    #[test]
    fn self_as_name_is_exit3() {
        for table in EntryTable::ALL {
            let (err, msg) = invalid(&format!("[{}.self]\n", table.key()));
            assert_eq!(err.exit_code(), Some(3), "{msg}");
            assert!(
                matches!(
                    &err,
                    Error::InvalidEntryName { name, rule: EntryNameRule::Reserved, .. }
                        if name == "self"
                ),
                "{err:?}"
            );
            assert_eq!(
                msg,
                format!(
                    "entry `[{}.self]` in minimal.toml: `self` is reserved and \
                     cannot name an entry. Rename the entry.",
                    table.key()
                )
            );
        }
    }

    // BOX-046: each type-noun table reads as `[boxes.<name>]` with its type.
    #[test]
    fn type_noun_tables_are_boxes_sugar() {
        let src = r#"
            [boxes.plain]
            type = "session"
            timeout = "1h"

            [boxes.untyped]

            [sessions.dev]
            packages = ["git"]

            [tasks.test]
            exec = ["cargo", "test"]

            [agents.helper]

            [services.db]

            [sessions.same]
            type = "session"

            [defaults]
            timeout = "2h"
        "#;
        let entries = read_entries(src.as_bytes()).expect("entries read");
        let by_name = |n: &str| {
            entries
                .iter()
                .find(|e| e.name == n)
                .unwrap_or_else(|| panic!("entry {n} read"))
        };

        let expect = [
            ("plain", EntryTable::Boxes, Some("session")),
            ("untyped", EntryTable::Boxes, None),
            ("dev", EntryTable::Sessions, Some("session")),
            ("test", EntryTable::Tasks, Some("task")),
            ("helper", EntryTable::Agents, Some("agent")),
            ("db", EntryTable::Services, Some("service")),
            ("same", EntryTable::Sessions, Some("session")),
        ];
        assert_eq!(entries.len(), expect.len(), "{entries:?}");
        for (name, table, ty) in expect {
            let e = by_name(name);
            assert_eq!(e.table, table, "{name}");
            assert_eq!(e.box_type.as_deref(), ty, "{name}");
            assert_eq!(
                e.body.get("type").and_then(toml::Value::as_str),
                ty,
                "{name}"
            );
        }

        // The sugar table is the same entry as the `[boxes.*]` form.
        let sugar = by_name("dev");
        let general = read_entries(b"[boxes.dev]\ntype = \"session\"\npackages = [\"git\"]\n")
            .expect("entries read");
        assert_eq!(sugar.body, general[0].body);
        assert_eq!(sugar.box_type, general[0].box_type);

        // Other keys are kept as written.
        assert_eq!(
            by_name("test").body.get("exec"),
            Some(&toml::Value::Array(vec!["cargo".into(), "test".into()]))
        );
        assert_eq!(
            by_name("plain")
                .body
                .get("timeout")
                .and_then(toml::Value::as_str),
            Some("1h")
        );

        // A sugar table sets its noun's type. Any other `type` exits 3.
        for (value, found) in [("\"task\"", "task"), ("\"rust-dev\"", "rust-dev")] {
            let (err, msg) = invalid(&format!("[sessions.x]\ntype = {value}\n"));
            assert_eq!(err.exit_code(), Some(3), "{msg}");
            assert_eq!(
                msg,
                format!(
                    "entry `[sessions.x]` in minimal.toml: a `[sessions.*]` table \
                     always has `type = \"session\"`, so it cannot set \
                     `type = \"{found}\"`. Remove the `type` key, or move the \
                     entry to `[boxes.x]`."
                )
            );
        }

        // A `type` that is not a string exits 3, in every table.
        for table in EntryTable::ALL {
            let (err, msg) = invalid(&format!("[{}.x]\ntype = 5\n", table.key()));
            assert_eq!(err.exit_code(), Some(3), "{msg}");
            assert_eq!(
                msg,
                format!(
                    "entry `[{}.x]` in minimal.toml: `type` must be a quoted \
                     string, such as `type = \"session\"`. Fix the `type` key.",
                    table.key()
                )
            );
        }

        // A file with no entry tables has no entries.
        assert!(read_entries(b"[defaults]\n").expect("reads").is_empty());
    }

    // BOX-046: a name that is not DNS-safe, not unique, or `self` exits 3
    // and names the entry.
    #[test]
    fn entry_name_invalid_exit3_names_entry() {
        for (src, entry) in [
            ("[sessions.My_Dev]\n", "[sessions.My_Dev]"),
            ("[tasks.-lead]\n", "[tasks.-lead]"),
            ("[tasks.trail-]\n", "[tasks.trail-]"),
            ("[boxes.\"a.b\"]\n", "[boxes.\"a.b\"]"),
            ("[boxes.\"\"]\n", "[boxes.\"\"]"),
            (
                &format!("[services.{}]\n", "a".repeat(64)),
                &format!("[services.{}]", "a".repeat(64)),
            ),
        ] {
            let (err, msg) = invalid(src);
            assert_eq!(err.exit_code(), Some(3), "{msg}");
            assert!(
                matches!(
                    err,
                    Error::InvalidEntryName {
                        rule: EntryNameRule::NotDnsSafe,
                        ..
                    }
                ),
                "{err:?}"
            );
            assert_eq!(
                msg,
                format!(
                    "entry `{entry}` in minimal.toml: an entry name must be 1 to \
                     63 lowercase letters, digits or hyphens, and cannot start \
                     or end with a hyphen. Rename the entry."
                )
            );
        }

        let (err, msg) = invalid("[sessions.web]\n[tasks.web]\n");
        assert_eq!(err.exit_code(), Some(3), "{msg}");
        assert_eq!(
            msg,
            "entry `[tasks.web]` in minimal.toml: the name `web` also names \
             `[sessions.web]`. Entry names must be unique in the file. Rename \
             one of the entries."
        );

        let (err, msg) = invalid("[boxes.self]\ntype = \"task\"\n");
        assert_eq!(err.exit_code(), Some(3), "{msg}");
        assert!(msg.starts_with("entry `[boxes.self]`"), "{msg}");

        // Valid names at the edges of the rule read.
        let edge = format!("[tasks.{}]\n[tasks.a]\n[tasks.0-9]\n", "z".repeat(63));
        assert_eq!(read_entries(edge.as_bytes()).expect("reads").len(), 3);
    }
}
