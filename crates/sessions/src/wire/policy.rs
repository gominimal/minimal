//! Wire-form policy verdicts.
//!
//! Sent from the client to the daemon in response to the daemon's
//! batch of pending items ([`super::primitives::WirePendingVar`] /
//! [`super::primitives::WirePendingPatch`]). Each verdict carries the
//! [`PendingId`] from the corresponding pending item so the daemon
//! can correlate without relying on slice ordering.

use super::primitives::{PendingId, WireResolvedVar};

/// The client's decision about one pending variable.
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
    },
    /// User policy's `ignore` rule matched; silently drop.
    Ignored {
        /// Matches the corresponding `WirePendingVar::id`.
        id: PendingId,
    },
}

/// The client's decision about one pending patch.
///
/// Approved patches' file contents arrive separately as a tarball
/// stream — not in this message.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WirePatchVerdict {
    /// User policy or prompt approved. Content streamed out-of-band.
    Approved {
        /// Matches the corresponding `WirePendingPatch::id`.
        id: PendingId,
    },
    /// User policy or prompt rejected.
    Denied {
        /// Matches the corresponding `WirePendingPatch::id`.
        id: PendingId,
    },
    /// User policy's `ignore` rule matched; silently drop.
    Ignored {
        /// Matches the corresponding `WirePendingPatch::id`.
        id: PendingId,
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
            },
            WireVarVerdict::Ignored {
                id: PendingId::new(3),
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
            },
            WirePatchVerdict::Denied {
                id: PendingId::new(2),
            },
            WirePatchVerdict::Ignored {
                id: PendingId::new(3),
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
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(
            json.contains(r#""kind":"denied""#),
            "expected `kind` tag, got: {json}"
        );
    }
}
