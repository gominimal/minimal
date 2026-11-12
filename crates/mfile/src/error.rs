use std::fmt;
use std::path::PathBuf;

/// The errors possible when working with the minimal file.
#[derive(Debug)]
pub enum Error {
    IO(&'static str, PathBuf, std::io::Error),
    Format(toml::de::Error),
    /// An `[upstream]` or sideload table does not deserialize into the
    /// untagged `LinkConfig` enum — a missing key, but also a wrong
    /// field type — so serde's error names neither the file nor the
    /// offending field. Carries the file (when it is known), the 1-based
    /// line the bad table starts on, and that table's header (when one
    /// precedes it), so the message can point at the table to fix.
    LinkConfig {
        path: Option<PathBuf>,
        line: Option<usize>,
        table: Option<String>,
        source: Box<toml::de::Error>,
    },
    NotFound,
    ConflictingLayouts(Vec<PathBuf>),
    MissingParamDefault(String),
    /// A task sets more than one action key: the task name, then the keys.
    MultipleTaskActions(String, Vec<String>),
    /// The file names the pre-v0.5.0 `harness` key, which sets no
    /// stack: the named stack is silently absent, and the missing
    /// toolchain surfaces much later as a bare linker error. Carries
    /// the path of the offending file when it is known.
    HarnessTable(Option<PathBuf>),
    /// An entry breaks a naming rule or a `type` rule (BOX-007, BOX-046).
    /// Carries the table key (`sessions`), the entry name and the rule.
    /// Exits 3.
    InvalidEntryName {
        table: &'static str,
        name: String,
        rule: EntryNameRule,
    },
    /// An expanded box spec carries a key it cannot carry, or a value of
    /// the wrong shape (BOX-066). Carries the key, the layer that set it,
    /// as the message names it, and the problem. Exits 3.
    InvalidSpecKey {
        key: String,
        layer: String,
        problem: SpecKeyProblem,
    },
    /// The file carries a legacy table, and this release is past the one
    /// release that read it (BOX-050). Carries the file, when it is known,
    /// and the table. Exits 3.
    LegacyTable {
        path: Option<PathBuf>,
        legacy: crate::legacy::LegacyTable,
    },
    /// A `[tasks.<name>]` entry sets `interactive = true` (BOX-054). Carries
    /// the task name. Exits 3.
    InteractiveTask(String),
}

/// What is wrong with a key of an expanded box spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecKeyProblem {
    /// No box setting has this name.
    Unknown,
    /// The key is inside an `[upstream]` table, and is not one of the
    /// registry pin's keys.
    UnknownUpstream,
    /// The value has the wrong shape. Carries what the key takes and what
    /// the layer wrote, each as the message names it.
    WrongShape {
        expected: &'static str,
        found: &'static str,
    },
    /// The value is a string, but not one the key accepts. Carries the
    /// value the layer wrote and the values the key accepts, in order.
    UnknownValue {
        found: String,
        accepted: &'static [&'static str],
    },
}

/// The naming rule that an entry name breaks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryNameRule {
    /// The name is `self`, which addresses the caller's own box.
    Reserved,
    /// The name is not a lowercase DNS label.
    NotDnsSafe,
    /// An earlier entry, in the table this carries, has the same name.
    Duplicate { other_table: &'static str },
    /// The entry's `type` key is not a string.
    TypeNotString,
    /// A type-noun table sets a `type` other than its noun's type. Carries
    /// the noun's type and the `type` the entry wrote.
    TypeMismatch {
        expected: &'static str,
        found: String,
    },
}

/// Writes an entry as its table header, `[sessions.dev]`, and quotes a name
/// that TOML cannot write as a bare key.
pub(crate) struct EntryHeader<'a>(pub(crate) &'a str, pub(crate) &'a str);

impl fmt::Display for EntryHeader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let EntryHeader(table, name) = self;
        let bare = !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if bare {
            write!(f, "[{table}.{name}]")
        } else {
            write!(f, "[{table}.{name:?}]")
        }
    }
}

impl Error {
    /// The exit code a command ends with on this error, when the
    /// architecture's exit-code table fixes one. An invalid entry name is a
    /// configuration error: exit 3.
    #[must_use]
    pub fn exit_code(&self) -> Option<u8> {
        match self {
            Error::InvalidEntryName { .. }
            | Error::InvalidSpecKey { .. }
            | Error::LegacyTable { .. }
            | Error::InteractiveTask(_) => Some(3),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::IO(ctx, path, e) => {
                write!(f, "{} I/O error at path {}: {}", ctx, path.display(), e)
            }
            // `Display` carries the parse error and `source()` returns none,
            // so `{}` and `{:#}` each print its snippet once.
            Error::Format(e) => write!(f, "invalid TOML: {}", e),
            Error::LinkConfig {
                path, line, table, ..
            } => {
                write!(f, "invalid link")?;
                if let Some(path) = path {
                    write!(f, " in {}", path.display())?;
                }
                if let Some(line) = line {
                    write!(f, " at line {line}")?;
                }
                if let Some(table) = table {
                    write!(f, " ({table})")?;
                }
                write!(
                    f,
                    ": an `[upstream]` or sideload table must be \
                     either `repo` (a git URL string, with optional string \
                     `branch` and `locked_commit`) or `dir` (a directory \
                     path string)"
                )
            }
            Error::NotFound => write!(f, "not found"),
            Error::ConflictingLayouts(paths) => write!(
                f,
                "multiple minimal configurations detected at [{}]. Remove the erroneous one.",
                paths
                    .iter()
                    .map(|p| p.as_os_str().to_str().unwrap())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            Error::MissingParamDefault(e) => {
                write!(f, "invalid parameter: `{}` does not define a default", e)
            }
            Error::MultipleTaskActions(task, keys) => write!(
                f,
                "task `{}` sets more than one action ({}); set exactly one",
                task,
                keys.join(", ")
            ),
            Error::HarnessTable(path) => {
                if let Some(path) = path {
                    write!(f, "{}: ", path.display())?;
                }
                write!(
                    f,
                    "the `harness` key (the pre-v0.5.0 name of `stack`) is \
                     no longer accepted: it sets no stack, so its toolchain \
                     would be missing. Replace it with a `[stack]` table: \
                     rename a `[harness]` table, and write `harness = \"x\"` \
                     as `name = \"x\"` under `[stack]`.",
                )
            }
            Error::InvalidEntryName { table, name, rule } => {
                write!(f, "entry `{}` in minimal.toml: ", EntryHeader(table, name))?;
                match rule {
                    EntryNameRule::Reserved => write!(
                        f,
                        "`self` is reserved and cannot name an entry. \
                         Rename the entry."
                    ),
                    EntryNameRule::NotDnsSafe => write!(
                        f,
                        "an entry name must be 1 to 63 lowercase letters, \
                         digits or hyphens, and cannot start or end with a \
                         hyphen. Rename the entry."
                    ),
                    EntryNameRule::Duplicate { other_table } => write!(
                        f,
                        "the name `{name}` also names `{}`. Entry names must \
                         be unique in the file. Rename one of the entries.",
                        EntryHeader(other_table, name)
                    ),
                    EntryNameRule::TypeNotString => write!(
                        f,
                        "`type` must be a quoted string, such as \
                         `type = \"session\"`. Fix the `type` key."
                    ),
                    EntryNameRule::TypeMismatch { expected, found } => write!(
                        f,
                        "a `[{table}.*]` table always has `type = \"{expected}\"`, \
                         so it cannot set `type = {found:?}`. Remove the `type` \
                         key, or move the entry to `{}`.",
                        EntryHeader("boxes", name)
                    ),
                }
            }
            Error::InvalidSpecKey {
                key,
                layer,
                problem,
            } => match problem {
                SpecKeyProblem::Unknown => write!(
                    f,
                    "{layer} sets `{key}`, which is not a box setting. \
                     Remove the key or correct its name."
                ),
                SpecKeyProblem::UnknownUpstream => write!(
                    f,
                    "{layer} sets `{key}`, which is not an `[upstream]` setting. \
                     The `[upstream]` settings are `repo_url`, `branch`, \
                     `commit` and `build_cache_url`. Remove the key or correct \
                     its name."
                ),
                SpecKeyProblem::WrongShape { expected, found } => write!(
                    f,
                    "{layer} sets `{key}` to {found}, but `{key}` takes \
                     {expected}. Fix the value."
                ),
                SpecKeyProblem::UnknownValue { found, accepted } => {
                    let accepted: Vec<String> = accepted.iter().map(|a| format!("`{a}`")).collect();
                    write!(
                        f,
                        "{layer} sets `{key}` to {found:?}. `{key}` accepts only \
                         {}. Fix the value.",
                        accepted.join(" or ")
                    )
                }
            },
            Error::LegacyTable { path, legacy } => {
                match path {
                    Some(path) => write!(f, "{}: ", path.display())?,
                    None => write!(f, "minimal.toml: ")?,
                }
                write!(
                    f,
                    "this release no longer reads {}.\n{legacy}",
                    legacy.what()
                )
            }
            Error::InteractiveTask(name) => write!(
                f,
                "`{}` in minimal.toml sets `interactive = true`, and a task \
                 cannot be interactive. Declare the entry as `{}` instead.",
                EntryHeader("tasks", name),
                EntryHeader("sessions", name)
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::IO(_, _, e) => Some(e),
            // `Display` carries the parse error, so a chain printer such as
            // `{:#}` prints it once.
            Error::Format(_) => None,
            // The serde error only restates serde's internal enum name,
            // which the Display above replaces; it stays for Debug.
            Error::LinkConfig { .. } => None,
            Error::NotFound => None,
            Error::ConflictingLayouts(_) => None,
            Error::MissingParamDefault(_) => None,
            Error::MultipleTaskActions(..) => None,
            Error::HarnessTable(_) => None,
            Error::InvalidEntryName { .. } => None,
            Error::InvalidSpecKey { .. } => None,
            Error::LegacyTable { .. } => None,
            Error::InteractiveTask(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Error;
    use std::error::Error as _;

    /// Renders an error the way anyhow's `{:#}` does: the error, then each
    /// cause in its `source()` chain, joined with `": "`.
    fn render_chain(e: &(dyn std::error::Error + 'static)) -> String {
        let mut out = e.to_string();
        let mut cur = e.source();
        while let Some(cause) = cur {
            out.push_str(": ");
            out.push_str(&cause.to_string());
            cur = cause.source();
        }
        out
    }

    #[test]
    fn format_error_display_carries_toml_error_once() {
        let err = crate::entry::read_entries(b"[boxes.dev\ntype = \"session\"\n")
            .expect_err("an unterminated table header must not parse");
        assert!(matches!(err, Error::Format(_)), "got {err:?}");
        let shown = err.to_string();
        assert_eq!(shown.matches("TOML parse error").count(), 1, "{shown}");
        assert_eq!(shown.matches("[boxes.dev").count(), 1, "{shown}");
        assert!(err.source().is_none());
        let chained = render_chain(&err);
        assert_eq!(chained.matches("TOML parse error").count(), 1, "{chained}");
    }
}
