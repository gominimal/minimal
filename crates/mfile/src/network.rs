//! The `[network]` section of a box spec: its modes, their legacy
//! spellings, and the flat egress keys.
//!
//! [`canonicalize`] runs on an expanded spec, after [`crate::expand::expand`].
//! It rewrites a legacy `mode` spelling to the current value (BOX-079) and
//! moves each flat egress key to its nested `egress.*` key (BOX-157). Each
//! rewrite returns one hint for the caller to print. The spec then carries
//! only the canonical form, so its bytes and its projection never hold a
//! legacy spelling. It also refuses `mode = "none"` with any egress key
//! (BOX-080). It checks that `egress` and `bep` are tables and that
//! `ingress` is a list, as `box.toml` writes them.
//! Their contents pass to the daemon unchanged.
//!
//! The `--network` flag of `min` takes its hint from [`legacy_mode_hint`],
//! so the flag and the table print the same line for the same spelling.

use std::fmt;

/// The `[network] mode` values, in their current spelling.
pub const MODES: [&str; 3] = ["none", "host_ip", "own_ip"];

/// The legacy `mode` spellings (NET-037) and the current value of each.
pub const LEGACY_MODES: [(&str, &str); 3] = [
    ("no-net", "none"),
    ("host-net", "host_ip"),
    ("own-ip", "own_ip"),
];

/// The flat `[network]` egress keys and the nested `egress.*` key that
/// each one is written as (BOX-157).
pub const FLAT_EGRESS_KEYS: [(&str, &str); 3] = [
    ("egress_allow_dns", "allow_dns_hosts"),
    ("egress_allow_subnets", "allow_subnets"),
    ("egress_deny_subnets", "deny_subnets"),
];

/// The current spelling of a mode value, for a current or a legacy
/// spelling. `None` when `raw` is not a mode.
#[must_use]
pub fn canonical_mode(raw: &str) -> Option<&'static str> {
    if let Some(mode) = MODES.iter().find(|m| **m == raw) {
        return Some(mode);
    }
    LEGACY_MODES
        .iter()
        .find(|(legacy, _)| *legacy == raw)
        .map(|(_, current)| *current)
}

/// The hint for a legacy mode spelling, the same line for the `--network`
/// flag and for `[network] mode`. `None` for a current spelling.
#[must_use]
pub fn legacy_mode_hint(raw: &str) -> Option<String> {
    let (legacy, current) = LEGACY_MODES.iter().find(|(legacy, _)| *legacy == raw)?;
    Some(format!(
        "note: --network {legacy} and mode = \"{legacy}\" still work for one release. \
         The current spelling is --network {current}, \
         or mode = \"{current}\" under [network] in minimal.toml."
    ))
}

/// The hint for a flat egress key. `None` when `flat` is not one.
#[must_use]
pub fn flat_egress_hint(flat: &str) -> Option<String> {
    let (flat, nested) = FLAT_EGRESS_KEYS.iter().find(|(key, _)| *key == flat)?;
    Some(format!(
        "note: {flat} under [network] still works for one release. \
         The current key is {nested} under [network.egress] in minimal.toml."
    ))
}

/// A `[network]` section that the spec cannot carry. Each one exits 3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkError {
    /// `mode` is not a mode in any spelling. Carries the value as written.
    UnknownMode(String),
    /// `mode` is not a string.
    ModeNotString,
    /// A key that takes a table or a list has some other value. Carries
    /// the key, as `network.<key>`, and what it takes.
    WrongShape { key: String, expected: &'static str },
    /// `mode = "none"` with an egress key. Carries the first egress key,
    /// as `network.egress.<key>`.
    ModeNoneWithEgress { key: String },
}

impl NetworkError {
    /// The exit code: a configuration error, exit 3.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        3
    }
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkError::UnknownMode(raw) => write!(
                f,
                "[network] sets mode = {raw:?}, which is not a network mode. \
                 Set mode to none, host_ip or own_ip."
            ),
            NetworkError::ModeNotString => write!(
                f,
                "[network] sets mode to a value that is not a string. \
                 Set mode to \"none\", \"host_ip\" or \"own_ip\"."
            ),
            NetworkError::WrongShape { key, expected } => {
                write!(f, "`{key}` takes {expected}. Fix the value.")
            }
            NetworkError::ModeNoneWithEgress { key } => write!(
                f,
                "[network] sets mode = \"none\" and `{key}`. \
                 A box with no network has no egress rules. \
                 Remove the egress settings, or set mode to host_ip or own_ip."
            ),
        }
    }
}

impl std::error::Error for NetworkError {}

/// Rewrites the `network` table of an expanded `spec` to its canonical
/// form, and checks it. Returns one hint for each legacy spelling that it
/// rewrote, in the order it found them: the mode first, then the flat
/// egress keys in the order of [`FLAT_EGRESS_KEYS`]. A spec with no
/// `network` table is left as it is.
///
/// # Errors
///
/// A [`NetworkError`] for a mode that is not a mode, a value of the wrong
/// shape, or `mode = "none"` with an egress key.
pub fn canonicalize(spec: &mut toml::Table) -> Result<Vec<String>, NetworkError> {
    let mut hints = Vec::new();
    let Some(toml::Value::Table(network)) = spec.get_mut("network") else {
        return Ok(hints);
    };

    let mut mode = None;
    if let Some(value) = network.get_mut("mode") {
        let raw = value.as_str().ok_or(NetworkError::ModeNotString)?;
        let current =
            canonical_mode(raw).ok_or_else(|| NetworkError::UnknownMode(raw.to_owned()))?;
        if let Some(hint) = legacy_mode_hint(raw) {
            hints.push(hint);
            *value = toml::Value::String(current.to_owned());
        }
        mode = Some(current);
    }

    for (flat, nested) in FLAT_EGRESS_KEYS {
        let Some(value) = network.remove(flat) else {
            continue;
        };
        let toml::Value::Array(items) = value else {
            return Err(NetworkError::WrongShape {
                key: format!("network.{flat}"),
                expected: "a list",
            });
        };
        let egress = network
            .entry("egress")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        let toml::Value::Table(egress) = egress else {
            return Err(NetworkError::WrongShape {
                key: "network.egress".to_owned(),
                expected: "a table",
            });
        };
        let target = egress
            .entry(nested)
            .or_insert_with(|| toml::Value::Array(Vec::new()));
        let toml::Value::Array(have) = target else {
            return Err(NetworkError::WrongShape {
                key: format!("network.egress.{nested}"),
                expected: "a list",
            });
        };
        for item in items {
            if !have.contains(&item) {
                have.push(item);
            }
        }
        hints.extend(flat_egress_hint(flat));
    }

    // `box.toml` writes `ingress = [{ proto = "tcp", port = 8080 }]`, a
    // list of tables. `egress` and `bep` are tables.
    for (section, is_shape, expected) in [
        (
            "egress",
            toml::Value::is_table as fn(&toml::Value) -> bool,
            "a table",
        ),
        ("ingress", toml::Value::is_array, "a list"),
        ("bep", toml::Value::is_table, "a table"),
    ] {
        if network.get(section).is_some_and(|v| !is_shape(v)) {
            return Err(NetworkError::WrongShape {
                key: format!("network.{section}"),
                expected,
            });
        }
    }

    if mode == Some("none")
        && let Some(toml::Value::Table(egress)) = network.get("egress")
        && let Some(key) = egress.keys().next()
    {
        return Err(NetworkError::ModeNoneWithEgress {
            key: format!("network.egress.{key}"),
        });
    }

    Ok(hints)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::entry::read_entries;
    use crate::expand::{Expansion, Layers, expand};

    /// Expands the entry `name` of `file` with no other layers, then
    /// canonicalizes its network table.
    fn expand_network(file: &str, name: &str) -> (Expansion, Result<Vec<String>, NetworkError>) {
        let entries = read_entries(file.as_bytes()).expect("entries read");
        let entry = entries
            .iter()
            .find(|e| e.name == name)
            .unwrap_or_else(|| panic!("entry {name} read"));
        let layers = Layers::default().with_file_defaults(
            &toml::Table::new(),
            entry.box_type.as_deref(),
            &BTreeSet::new(),
        );
        let mut expansion = expand(entry, &layers).expect("the entry expands");
        let result = canonicalize(&mut expansion.spec);
        (expansion, result)
    }

    // BOX-079: a legacy mode spelling prints one hint naming the new value,
    // and the expanded spec, and its bytes, carry only the new value.
    #[test]
    fn network_mode_legacy_spelling_hint_and_canonical_value() {
        for (legacy, current) in LEGACY_MODES {
            let file = format!("[sessions.dev]\nnetwork = {{ mode = \"{legacy}\" }}\n");
            let (expansion, hints) = expand_network(&file, "dev");
            let hints = hints.expect("a legacy spelling is accepted");
            assert_eq!(hints.len(), 1, "one hint for {legacy}: {hints:?}");
            assert!(hints[0].contains(legacy), "{}", hints[0]);
            assert!(
                hints[0].contains(&format!("mode = \"{current}\"")),
                "the hint names the new value: {}",
                hints[0]
            );
            assert_eq!(
                expansion.spec["network"]["mode"].as_str(),
                Some(current),
                "{legacy} is stored as {current}"
            );
            let bytes = expansion.spec_bytes().expect("spec writes");
            assert!(
                bytes.contains(&format!("mode = \"{current}\"")) && !bytes.contains(legacy),
                "the spec bytes carry {current}, never {legacy}: {bytes}"
            );
        }

        for current in MODES {
            let file = format!("[sessions.dev]\nnetwork = {{ mode = \"{current}\" }}\n");
            let (expansion, hints) = expand_network(&file, "dev");
            assert_eq!(hints, Ok(Vec::new()), "{current} prints no hint");
            assert_eq!(expansion.spec["network"]["mode"].as_str(), Some(current));
        }

        let (_, err) = expand_network("[sessions.dev]\nnetwork = { mode = \"wifi\" }\n", "dev");
        let err = err.expect_err("an unknown mode is refused");
        assert_eq!(err, NetworkError::UnknownMode("wifi".to_owned()));
        assert_eq!(err.exit_code(), 3);
    }

    // BOX-080: `mode = "none"` with any egress key exits 3, whether the
    // key is nested or flat.
    #[test]
    fn mode_none_with_egress_exit3() {
        let cases = [
            (
                "[sessions.dev.network]\nmode = \"none\"\n\
                 [sessions.dev.network.egress]\nallow_subnets = [\"10.0.0.0/8\"]\n",
                "network.egress.allow_subnets",
            ),
            (
                "[sessions.dev.network]\nmode = \"no-net\"\n\
                 egress_allow_dns = [\"example.com\"]\n",
                "network.egress.allow_dns_hosts",
            ),
        ];
        for (file, key) in cases {
            let (_, err) = expand_network(file, "dev");
            let err = err.expect_err("mode none with egress is refused");
            assert_eq!(
                err,
                NetworkError::ModeNoneWithEgress {
                    key: key.to_owned()
                }
            );
            assert_eq!(err.exit_code(), 3);
            let text = err.to_string();
            assert!(text.contains(key) && text.contains("none"), "{text}");
        }

        // `none` with no egress key, and `own_ip` with one, are accepted.
        let (_, ok) = expand_network("[sessions.dev]\nnetwork = { mode = \"none\" }\n", "dev");
        assert_eq!(ok, Ok(Vec::new()));
        let (_, ok) = expand_network(
            "[sessions.dev.network]\nmode = \"own_ip\"\n\
             [sessions.dev.network.egress]\nallow_subnets = [\"10.0.0.0/8\"]\n",
            "dev",
        );
        assert_eq!(ok, Ok(Vec::new()));
    }

    // BOX-157: each flat egress key prints one hint naming the nested key,
    // and the expanded spec carries only the nested key. BOX-080: the
    // other `[network]` sections pass through unchanged.
    #[test]
    fn flat_egress_keys_hint_and_canonical_nested_keys() {
        let file = "[sessions.dev.network]\n\
                    mode = \"own_ip\"\n\
                    egress_allow_dns = [\"a.example\"]\n\
                    egress_allow_subnets = [\"10.0.0.0/8\"]\n\
                    egress_deny_subnets = [\"10.1.0.0/16\"]\n\
                    ingress = [{ proto = \"tcp\", port = 8080 }]\n\
                    [sessions.dev.network.egress]\n\
                    allow_dns_hosts = [\"b.example\", \"a.example\"]\n\
                    [sessions.dev.network.bep]\n\
                    enabled = true\n";
        let (expansion, hints) = expand_network(file, "dev");
        let hints = hints.expect("flat keys are accepted");
        assert_eq!(hints.len(), 3, "one hint per flat key: {hints:?}");
        for ((flat, nested), hint) in FLAT_EGRESS_KEYS.iter().zip(&hints) {
            assert!(
                hint.contains(flat) && hint.contains(nested) && hint.contains("[network.egress]"),
                "{hint}"
            );
        }

        let network = expansion.spec["network"].as_table().expect("a table");
        for (flat, _) in FLAT_EGRESS_KEYS {
            assert!(!network.contains_key(flat), "{flat} is not stored");
        }
        let egress = network["egress"].as_table().expect("a table");
        let strings = |key: &str| -> Vec<&str> {
            egress[key]
                .as_array()
                .expect("a list")
                .iter()
                .map(|v| v.as_str().expect("a string"))
                .collect()
        };
        assert_eq!(strings("allow_dns_hosts"), ["b.example", "a.example"]);
        assert_eq!(strings("allow_subnets"), ["10.0.0.0/8"]);
        assert_eq!(strings("deny_subnets"), ["10.1.0.0/16"]);
        assert_eq!(
            network["ingress"],
            toml::from_str::<toml::Table>("ingress = [{ proto = \"tcp\", port = 8080 }]").unwrap()
                ["ingress"]
        );
        assert_eq!(
            network["bep"],
            toml::Value::Table(toml::from_str("enabled = true").unwrap())
        );

        let bytes = expansion.spec_bytes().expect("spec writes");
        assert!(
            !bytes.contains("egress_"),
            "no flat key in the bytes: {bytes}"
        );

        let (_, err) = expand_network(
            "[sessions.dev.network]\negress_allow_subnets = \"10.0.0.0/8\"\n",
            "dev",
        );
        assert_eq!(
            err,
            Err(NetworkError::WrongShape {
                key: "network.egress_allow_subnets".to_owned(),
                expected: "a list",
            })
        );

        // `ingress` is a list of tables, as `box.toml` writes it. A table
        // `ingress` exits 3 naming `network.ingress`.
        let (_, err) = expand_network(
            "[sessions.dev.network.ingress]\nports = [\"8080:80\"]\n",
            "dev",
        );
        let err = err.expect_err("a table ingress is refused");
        assert_eq!(
            err,
            NetworkError::WrongShape {
                key: "network.ingress".to_owned(),
                expected: "a list",
            }
        );
        assert_eq!(err.exit_code(), 3);
        assert!(err.to_string().contains("network.ingress"), "{err}");
    }
}
