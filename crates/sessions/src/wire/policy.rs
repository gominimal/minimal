//! Wire-form policy verdicts.
//!
//! Sent from the client to the daemon in response to the daemon's
//! batch of pending items ([`super::primitives::WirePendingVar`] /
//! [`super::primitives::WirePendingPatch`]). Each verdict carries the
//! [`PendingId`] from the corresponding pending item so the daemon
//! can correlate without relying on slice ordering.

use super::primitives::{PendingId, WireResolvedVar};

/// The client's decision about one pending variable. Every variant
/// carries the variable name so logs and audit records are
/// self-describing without joining against the pending batch.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WireVarVerdict {
    /// User policy or prompt approved this var. The value is included
    /// because the daemon doesn't have the client's env.
    Approved {
        /// Matches the corresponding `WirePendingVar::id`.
        id: PendingId,
        /// Resolved name + value.
        value: WireResolvedVar,
    },
    /// User policy or prompt rejected this var.
    Denied {
        /// Matches the corresponding `WirePendingVar::id`.
        id: PendingId,
        /// Name of the rejected variable.
        name: String,
    },
    /// User policy's `ignore` rule matched; silently drop.
    Ignored {
        /// Matches the corresponding `WirePendingVar::id`.
        id: PendingId,
        /// Name of the dropped variable.
        name: String,
    },
}

/// The client's decision about a single file matched by a pending
/// patch's source pattern.
///
/// One [`WirePendingPatch`](super::primitives::WirePendingPatch) can
/// fan out to multiple files (its `source_pattern` is a glob), so
/// each is voted on independently. `id` correlates back to the
/// pending patch; `host_path` is the canonical absolute path the
/// daemon will copy from.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WirePatchVerdict {
    /// User policy or prompt approved this file.
    Approved {
        /// Matches the corresponding `WirePendingPatch::id`.
        id: PendingId,
        /// Absolute host path of the matched file.
        host_path: paths::HostAbsPath,
    },
    /// User policy or prompt rejected this file.
    Denied {
        /// Matches the corresponding `WirePendingPatch::id`.
        id: PendingId,
        /// Absolute host path of the rejected file.
        host_path: paths::HostAbsPath,
    },
    /// User policy's `ignore` rule matched; silently drop this file.
    /// `host_path` is carried for audit/logging parity with the
    /// other variants — the daemon must not copy the file.
    Ignored {
        /// Matches the corresponding `WirePendingPatch::id`.
        id: PendingId,
        /// Absolute host path of the dropped file. Logging only.
        host_path: paths::HostAbsPath,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip<T>(value: &T) -> T
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let json = serde_json::to_string(value).expect("serialize");
        serde_json::from_str(&json).expect("deserialize")
    }

    #[test]
    fn var_verdict_round_trips_all_variants() {
        let cases = [
            WireVarVerdict::Approved {
                id: PendingId::new(1),
                value: WireResolvedVar {
                    name: "EDITOR".into(),
                    value: "hx".into(),
                },
            },
            WireVarVerdict::Denied {
                id: PendingId::new(2),
                name: "AWS_KEY".into(),
            },
            WireVarVerdict::Ignored {
                id: PendingId::new(3),
                name: "_TMP".into(),
            },
        ];
        for v in cases {
            assert_eq!(round_trip(&v), v);
        }
    }

    #[test]
    fn patch_verdict_round_trips_all_variants() {
        let cases = [
            WirePatchVerdict::Approved {
                id: PendingId::new(1),
                host_path: paths::HostAbsPath::try_new("/home/u/.gitconfig").unwrap(),
            },
            WirePatchVerdict::Denied {
                id: PendingId::new(2),
                host_path: paths::HostAbsPath::try_new("/home/u/secret").unwrap(),
            },
            WirePatchVerdict::Ignored {
                id: PendingId::new(3),
                host_path: paths::HostAbsPath::try_new("/home/u/.cache").unwrap(),
            },
        ];
        for v in cases {
            assert_eq!(round_trip(&v), v);
        }
    }

    #[test]
    fn var_verdict_uses_explicit_kind_tag() {
        let v = WireVarVerdict::Denied {
            id: PendingId::new(7),
            name: "x".into(),
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(
            json.contains(r#""kind":"denied""#),
            "expected `kind` tag, got: {json}"
        );
    }
}
