//! Wire-form error envelope.
//!
//! Rich local error types — [`ComposeError`], `PatchError`, `VarError`,
//! `ExpandError` — stay local. They carry source chains, IO errors,
//! and other non-serializable detail. Anything that needs to cross the
//! RPC boundary collapses to [`WireError`] with a string summary.
//!
//! Conversions live here so the boundary is the only place a rich
//! error is degraded.
//!
//! [`ComposeError`]: crate::core::compose::ComposeError

/// Errors the daemon may send back to the client (or vice versa) in
/// response to a wire-form request.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, thiserror::Error)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WireError {
    /// The client's contribution failed validation. `message` is a
    /// human-readable explanation; structured detail (which var,
    /// which patch) is intentionally omitted to keep the wire schema
    /// small. Use telemetry for forensic detail.
    #[error("invalid contribution: {message}")]
    InvalidContribution {
        /// Free-form explanation.
        message: String,
    },
    /// The wire protocol version the client sent is not one the
    /// daemon supports.
    #[error("unsupported protocol version {got}; daemon supports {supported}")]
    UnknownProtocolVersion {
        /// Version the client sent.
        got: u32,
        /// Highest version the daemon understands.
        supported: u32,
    },
    /// A response referenced a session id the daemon doesn't have.
    /// Typically means the session was torn down (timeout, abort)
    /// before this message arrived.
    #[error("unknown session id")]
    UnknownSessionId,
    /// The session id exists but its current state doesn't permit
    /// this operation (e.g. attaching before composition finalizes,
    /// or submitting a verdict for an already-`Active` session).
    #[error("wrong session state: {what}")]
    WrongState {
        /// Short human-readable description of why the operation
        /// isn't valid in the current state. Used by clients for log
        /// surfaces; not parsed.
        what: String,
    },
    /// Anything else — daemon-internal bug, transient infrastructure
    /// failure, etc. Clients should surface as a generic failure and
    /// not retry blindly.
    #[error("internal: {message}")]
    Internal {
        /// Free-form explanation.
        message: String,
    },
}

impl From<crate::core::compose::ComposeError> for WireError {
    /// Collapse a rich local compose error to the wire envelope. The
    /// `Display` summary is used; the source chain is dropped at the
    /// boundary.
    ///
    /// `InvalidWireItem` — the one variant that represents bad client
    /// input rather than a daemon-internal problem — maps to
    /// [`WireError::InvalidContribution`]. Everything else collapses
    /// to [`WireError::Internal`].
    fn from(e: crate::core::compose::ComposeError) -> Self {
        let message = e.to_string();
        match e {
            crate::core::compose::ComposeError::InvalidWireItem { .. } => {
                Self::InvalidContribution { message }
            }
            _ => Self::Internal { message },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip<T>(value: &T) -> T
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let json = serde_json_lenient::to_string(value).expect("serialize");
        serde_json_lenient::from_str(&json).expect("deserialize")
    }

    #[test]
    fn round_trips_all_variants() {
        let cases = [
            WireError::InvalidContribution {
                message: "vars[3] has no name".into(),
            },
            WireError::UnknownProtocolVersion {
                got: 99,
                supported: 1,
            },
            WireError::UnknownSessionId,
            WireError::WrongState {
                what: "session is pending; cannot exec".into(),
            },
            WireError::Internal {
                message: "fs walk failed".into(),
            },
        ];
        for e in cases {
            assert_eq!(round_trip(&e), e);
        }
    }

    #[test]
    fn uses_explicit_kind_tag() {
        let e = WireError::UnknownSessionId;
        let json = serde_json_lenient::to_string(&e).unwrap();
        assert!(
            json.contains(r#""kind":"unknown_session_id""#),
            "expected `kind` tag, got: {json}"
        );
    }

    /// `Display` (via `thiserror`) gives a human-readable summary for
    /// each variant. Used by callers logging errors locally.
    #[test]
    fn display_formats_each_variant_readably() {
        assert_eq!(
            WireError::UnknownSessionId.to_string(),
            "unknown session id",
        );
        assert_eq!(
            WireError::UnknownProtocolVersion {
                got: 99,
                supported: 1
            }
            .to_string(),
            "unsupported protocol version 99; daemon supports 1",
        );
    }

    /// `From<ComposeError>` collapses most variants to `Internal`
    /// with the local error's `Display` text.
    #[test]
    fn from_compose_error_collapses_to_internal() {
        let local = crate::core::compose::ComposeError::Aborted;
        let wire: WireError = local.into();
        assert!(
            matches!(wire, WireError::Internal { .. }),
            "expected Internal, got: {wire:?}",
        );
    }

    /// `InvalidWireItem` represents bad client input and maps to
    /// `InvalidContribution`, not `Internal`.
    #[test]
    fn from_compose_error_invalid_wire_item_maps_to_invalid_contribution() {
        let local = crate::core::compose::ComposeError::InvalidWireItem {
            what: "lifecycle hook with no callbacks",
            context: "empty hook".into(),
        };
        let wire: WireError = local.into();
        assert!(
            matches!(wire, WireError::InvalidContribution { .. }),
            "expected InvalidContribution, got: {wire:?}",
        );
    }
}
