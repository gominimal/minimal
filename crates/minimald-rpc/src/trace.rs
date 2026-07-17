//! W3C-shaped trace context, propagated CLI → daemon over the SSH channel
//! environment.
//!
//! Part of the wire contract: the client sends [`TRACEPARENT_ENV`] as a
//! channel `env` request (the same mechanism as `MINIMAL_SESSION_ID`), the
//! daemon adopts the trace id into its dispatch span, and both sides stamp
//! the ids into their file logs — correlation across host and guest becomes
//! a `trace_id` grep. Formats follow the W3C Trace Context `traceparent`
//! header (version `00`), so a future OTLP export copies fields instead of
//! translating them. No OTEL runtime is involved: ids are 16/8 random
//! bytes, hex-encoded to the 32/16-char forms OTLP requires.

/// Channel-environment variable name carrying the [`traceparent`] value.
/// Client (`set_env`) and daemon (`env_request` handler) both reference this
/// constant — the name cannot skew.
///
/// [`traceparent`]: TraceContext::traceparent
pub const TRACEPARENT_ENV: &str = "TRACEPARENT";

/// One operation's identity: a 16-byte trace id shared by every span in the
/// operation, and this span's own 8-byte id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceContext {
    trace_id: [u8; 16],
    span_id: [u8; 8],
}

impl TraceContext {
    /// Mints a fresh context: random non-zero trace and span ids (all-zero
    /// ids are invalid per W3C and mean "absent" in OTLP).
    pub fn mint() -> Self {
        Self {
            trace_id: non_zero_random(),
            span_id: non_zero_random(),
        }
    }

    /// A child context: same trace, fresh span id. What a server mints when
    /// adopting a propagated context — its work is a new span *within* the
    /// caller's trace.
    #[must_use]
    pub fn child(&self) -> Self {
        Self {
            trace_id: self.trace_id,
            span_id: non_zero_random(),
        }
    }

    /// The 32-lowercase-hex trace id (the OTLP `trace_id` form).
    pub fn trace_id_hex(&self) -> String {
        hex::encode(self.trace_id)
    }

    /// The 16-lowercase-hex span id (the OTLP `span_id` form).
    pub fn span_id_hex(&self) -> String {
        hex::encode(self.span_id)
    }

    /// The W3C `traceparent` value: `00-{trace_id}-{span_id}-01`
    /// (version 00, sampled).
    pub fn traceparent(&self) -> String {
        format!("00-{}-{}-01", self.trace_id_hex(), self.span_id_hex())
    }

    /// Parses a version-00 `traceparent` value. Anything malformed — wrong
    /// shape, wrong lengths, non-hex, all-zero ids — is `None`; the receiver
    /// mints fresh instead of erroring (a diagnostic aid must never fail a
    /// request).
    pub fn parse_traceparent(value: &str) -> Option<Self> {
        let mut parts = value.split('-');
        let version = parts.next()?;
        let trace_hex = parts.next()?;
        let span_hex = parts.next()?;
        let flags = parts.next()?;
        if parts.next().is_some() || version != "00" || flags.len() != 2 {
            return None;
        }
        u8::from_str_radix(flags, 16).ok()?;
        let trace_id: [u8; 16] = hex::decode(trace_hex).ok()?.try_into().ok()?;
        let span_id: [u8; 8] = hex::decode(span_hex).ok()?.try_into().ok()?;
        if trace_id == [0u8; 16] || span_id == [0u8; 8] {
            return None;
        }
        Some(Self { trace_id, span_id })
    }
}

/// Random bytes, re-drawn on the (astronomically unlikely) all-zero draw —
/// all-zero ids are the W3C/OTLP "invalid" sentinel.
fn non_zero_random<const N: usize>() -> [u8; N] {
    loop {
        let bytes: [u8; N] = rand::random();
        if bytes != [0u8; N] {
            return bytes;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minted_ids_have_otlp_shapes() {
        let ctx = TraceContext::mint();
        assert_eq!(ctx.trace_id_hex().len(), 32);
        assert_eq!(ctx.span_id_hex().len(), 16);
        assert!(ctx.trace_id_hex().chars().all(|c| c.is_ascii_hexdigit()));
        let tp = ctx.traceparent();
        assert_eq!(tp.len(), 2 + 1 + 32 + 1 + 16 + 1 + 2);
        assert!(tp.starts_with("00-") && tp.ends_with("-01"), "got: {tp}");
    }

    #[test]
    fn traceparent_round_trips() {
        let ctx = TraceContext::mint();
        let parsed = TraceContext::parse_traceparent(&ctx.traceparent()).unwrap();
        assert_eq!(parsed, ctx);
    }

    #[test]
    fn child_shares_the_trace_and_changes_the_span() {
        let parent = TraceContext::mint();
        let child = parent.child();
        assert_eq!(child.trace_id_hex(), parent.trace_id_hex());
        assert_ne!(child.span_id_hex(), parent.span_id_hex());
    }

    #[test]
    fn malformed_traceparents_parse_to_none() {
        for bad in [
            "",
            "00",
            "garbage",
            // wrong version
            "01-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
            // short trace id
            "00-0af7651916cd43dd8448eb211c8031-b7ad6b7169203331-01",
            // non-hex trace id
            "00-0af7651916cd43dd8448eb211c80319g-b7ad6b7169203331-01",
            // short span id
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b71692033-01",
            // all-zero trace id (W3C invalid)
            "00-00000000000000000000000000000000-b7ad6b7169203331-01",
            // all-zero span id
            "00-0af7651916cd43dd8448eb211c80319c-0000000000000000-01",
            // missing flags
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331",
            // trailing part
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01-xx",
        ] {
            assert!(
                TraceContext::parse_traceparent(bad).is_none(),
                "should reject: {bad}"
            );
        }
        // A valid value with different flags still parses (flags are hex).
        assert!(
            TraceContext::parse_traceparent(
                "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-00"
            )
            .is_some()
        );
    }
}
