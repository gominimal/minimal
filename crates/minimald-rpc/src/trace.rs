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

/// Channel-environment variable a client sets to [`OTEL_OFF`] on every
/// channel when its own telemetry decision is off (not opted in,
/// `DO_NOT_TRACK`, `OTEL_SDK_DISABLED`): the request's opt-out, carried
/// beside (instead of) [`TRACEPARENT_ENV`]. The daemon then records the
/// request's span and everything under it nowhere, and keeps its command
/// line out of its own records. Backwards compatible both ways: a daemon
/// predating the marker stores an unknown channel env and never forwards
/// it (nothing but `MINIMAL_TASK_ENV_*` and the attach allowlist reaches a
/// box); a client predating it sends neither marker nor opt-out and is
/// recorded as before.
pub const OTEL_ENV: &str = "MINIMAL_OTEL";

/// The one value of [`OTEL_ENV`] that means anything: `off`.
pub const OTEL_OFF: &str = "off";

/// The same opt-out on a `direct-tcpip` open, whose originator address is
/// where the native client puts its `traceparent` (there is no channel env
/// before an open is decided): `MINIMAL_OTEL=off` in that field.
pub const OTEL_OFF_ORIGINATOR: &str = "MINIMAL_OTEL=off";

/// Whether a channel's environment carries the opt-out marker
/// ([`OTEL_ENV`] = [`OTEL_OFF`]). Any other value is ignored.
#[must_use]
pub fn opted_out(env: &std::collections::BTreeMap<String, String>) -> bool {
    env.get(OTEL_ENV).is_some_and(|v| v == OTEL_OFF)
}

/// One operation's identity: a 16-byte trace id shared by every span in the
/// operation, and this span's own 8-byte id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceContext {
    trace_id: [u8; 16],
    span_id: [u8; 8],
    /// W3C trace-flags byte, masked to [`DEFINED_FLAGS`]: a parsed parent's
    /// sampling decision survives `child()` and re-emission rather than
    /// being rewritten to sampled, and bits version 00 does not define are
    /// never carried.
    flags: u8,
}

/// The `sampled` trace-flags bit. `mint()` sets it: this system has no
/// sampler, so every trace it originates is collected.
const SAMPLED: u8 = 0x01;

/// The trace-flags bits version 00 defines: `sampled` alone. A receiver
/// accepts any flags byte, but the header forbids a sender to emit bits it
/// does not know, so every flags byte that enters a context, parsed or
/// given to [`TraceContext::from_parts`], is masked to these first. The OTel
/// SDK's own propagator masks the same way (`TraceFlags::new(x) &
/// TraceFlags::SAMPLED`), so the two recognisers in one binary agree.
const DEFINED_FLAGS: u8 = SAMPLED;

/// The one shape accepted: `00-` + 32 hex + `-` + 16 hex + `-` + 2 hex.
const TRACEPARENT_LEN: usize = 55;

impl TraceContext {
    /// Mints a fresh context: random non-zero trace and span ids (all-zero
    /// ids are invalid per W3C and mean "absent" in OTLP), sampled.
    pub fn mint() -> Self {
        Self {
            trace_id: non_zero_random(),
            span_id: non_zero_random(),
            flags: SAMPLED,
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
            flags: self.flags,
        }
    }

    /// This context with the `sampled` flag cleared: what a daemon mints
    /// for a request whose client opted out, so the ids still join its own
    /// file-log lines while nothing exported or spooled carries them.
    #[must_use]
    pub fn unsampled(self) -> Self {
        Self { flags: 0, ..self }
    }

    /// A context from raw ids, e.g. the ids an OTel exporter assigned to a
    /// span, so the exported span and the logged/propagated ids agree. The
    /// flags are masked to [`DEFINED_FLAGS`].
    pub fn from_parts(trace_id: [u8; 16], span_id: [u8; 8], flags: u8) -> Self {
        Self {
            trace_id,
            span_id,
            flags: flags & DEFINED_FLAGS,
        }
    }

    /// The raw `(trace_id, span_id, flags)`.
    pub fn parts(&self) -> ([u8; 16], [u8; 8], u8) {
        (self.trace_id, self.span_id, self.flags)
    }

    /// The 32-lowercase-hex trace id (the OTLP `trace_id` form).
    pub fn trace_id_hex(&self) -> String {
        hex::encode(self.trace_id)
    }

    /// The 16-lowercase-hex span id (the OTLP `span_id` form).
    pub fn span_id_hex(&self) -> String {
        hex::encode(self.span_id)
    }

    /// The W3C `traceparent` value: `00-{trace_id}-{span_id}-{flags}`
    /// (version 00). A minted context is sampled (`01`); a parsed one
    /// re-emits its parent's defined flags (see [`DEFINED_FLAGS`]).
    pub fn traceparent(&self) -> String {
        format!(
            "00-{}-{}-{:02x}",
            self.trace_id_hex(),
            self.span_id_hex(),
            self.flags
        )
    }

    /// Parses a `traceparent` value. The accepted language is exactly the
    /// 55-byte version-00 form, `00-<32 hex>-<16 hex>-<2 hex>` in lowercase
    /// hex with neither id all zero. The whole value is checked against that
    /// shape before any field is decoded, and the digits are decoded here,
    /// not by a number parser, so no library leniency (a `+` sign, spaces,
    /// uppercase) can widen the language. Anything else is `None`; the
    /// receiver mints fresh instead of erroring (a diagnostic aid must never
    /// fail a request). The flags are masked to [`DEFINED_FLAGS`].
    ///
    /// Versions other than `00`: W3C Trace Context 3.2.4 says a receiver
    /// SHOULD try to parse a higher version by its version-00 prefix (`ff`
    /// is invalid). This parser does not. No other version is published,
    /// every forwarding site in this tree regenerates the value through this
    /// one function and re-emits `00`, and a rejected value fails safe into
    /// a fresh trace (TEL-021). Revisit when a version `01` exists; until then
    /// the choice is pinned by `versions_other_than_00_are_rejected_by_policy`
    /// here and minvmd's `only_a_well_formed_traceparent_crosses`.
    pub fn parse_traceparent(value: &str) -> Option<Self> {
        let v = value.as_bytes();
        if v.len() != TRACEPARENT_LEN
            || !v.starts_with(b"00-")
            || v.get(35) != Some(&b'-')
            || v.get(52) != Some(&b'-')
        {
            return None;
        }
        let trace_id = lower_hex::<16>(v.get(3..35)?)?;
        let span_id = lower_hex::<8>(v.get(36..52)?)?;
        let [flags] = lower_hex::<1>(v.get(53..55)?)?;
        if trace_id == [0u8; 16] || span_id == [0u8; 8] {
            return None;
        }
        Some(Self {
            trace_id,
            span_id,
            flags: flags & DEFINED_FLAGS,
        })
    }
}

/// The `N` bytes spelled by exactly `2 * N` lowercase hex digits; `None` for
/// any other byte or length. Decodes nothing but `[0-9a-f]`, so the accepted
/// language is the header's `HEXDIGLC` and not a number parser's.
fn lower_hex<const N: usize>(s: &[u8]) -> Option<[u8; N]> {
    fn nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        }
    }
    if s.len() != 2 * N {
        return None;
    }
    let mut out = [0u8; N];
    for (byte, pair) in out.iter_mut().zip(s.chunks_exact(2)) {
        let &[hi, lo] = pair else { return None };
        *byte = (nibble(hi)? << 4) | nibble(lo)?;
    }
    Some(out)
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

    /// The opt-out marker is `MINIMAL_OTEL=off` exactly; any other value
    /// (an old client's absence included) is not an opt-out. An unsampled
    /// context keeps its ids and emits flags `00`.
    #[test]
    fn the_opt_out_marker_is_off_and_nothing_else() {
        let env = |pairs: &[(&str, &str)]| -> std::collections::BTreeMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect()
        };
        assert!(opted_out(&env(&[(OTEL_ENV, OTEL_OFF)])));
        assert!(opted_out(&env(&[
            (OTEL_ENV, "off"),
            (TRACEPARENT_ENV, "x")
        ])));
        assert!(!opted_out(&env(&[])));
        assert!(!opted_out(&env(&[(OTEL_ENV, "on")])));
        assert!(!opted_out(&env(&[(OTEL_ENV, "OFF")])));
        assert!(!opted_out(&env(&[(OTEL_ENV, "")])));
        assert_eq!(OTEL_OFF_ORIGINATOR, format!("{OTEL_ENV}={OTEL_OFF}"));

        let ctx = TraceContext::mint();
        let off = ctx.unsampled();
        assert_eq!(off.trace_id_hex(), ctx.trace_id_hex());
        assert_eq!(off.span_id_hex(), ctx.span_id_hex());
        assert!(off.traceparent().ends_with("-00"));
        assert!(off.child().traceparent().ends_with("-00"));
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
            // uppercase trace id (W3C fields are lowercase hex)
            "00-0AF7651916CD43DD8448EB211C80319C-b7ad6b7169203331-01",
            // uppercase span id
            "00-0af7651916cd43dd8448eb211c80319c-B7AD6B7169203331-01",
            // uppercase flags
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-0A",
            // a sign or whitespace in the flags: what a number parser would
            // take and the header's `2HEXDIGLC` does not
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-+1",
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-+f",
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331- 1",
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-1 ",
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331--1",
            // a sign in an id
            "00-+af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
            // right length, wrong separators
            "00_0af7651916cd43dd8448eb211c80319c_b7ad6b7169203331_01",
            // a trailing newline (what `env` or a file read might carry)
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01\n",
            // a leading space
            " 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
        ] {
            assert!(
                TraceContext::parse_traceparent(bad).is_none(),
                "should reject: {bad}"
            );
        }
    }

    /// Policy for versions other than `00` (W3C Trace Context 3.2.4 says a
    /// receiver SHOULD parse them by their version-00 prefix, `ff` being
    /// invalid): not accepted. No other version is published, every
    /// forwarding site regenerates through `parse_traceparent`, and a
    /// rejected value fails safe into a fresh trace (TEL-021). minvmd's
    /// `only_a_well_formed_traceparent_crosses` pins the same choice at the
    /// guest boot line.
    #[test]
    fn versions_other_than_00_are_rejected_by_policy() {
        for tp in [
            "01-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
            "fe-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
            "ff-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
            // the higher-version form with trailing fields that 3.2.4 allows
            "01-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01-extra",
        ] {
            assert!(TraceContext::parse_traceparent(tp).is_none(), "{tp}");
        }
    }

    /// F13: version 00 defines only the `sampled` bit. A parent's other bits
    /// are accepted (the spec says a receiver must) but never stored or
    /// re-emitted, as the OTel SDK's own propagator does; `from_parts` masks
    /// the same way so every emission path agrees.
    #[test]
    fn reserved_flag_bits_are_masked_on_parse_and_from_parts() {
        let prefix = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331";
        for (given, kept) in [
            ("ff", "01"),
            ("fe", "00"),
            ("03", "01"),
            ("fd", "01"),
            ("02", "00"),
        ] {
            let ctx = TraceContext::parse_traceparent(&format!("{prefix}-{given}")).unwrap();
            assert_eq!(
                ctx.traceparent(),
                format!("{prefix}-{kept}"),
                "flags {given}"
            );
            assert_eq!(ctx.child().parts().2, u8::from_str_radix(kept, 16).unwrap());
        }
        let (t, s, _) = TraceContext::mint().parts();
        assert_eq!(TraceContext::from_parts(t, s, 0xfd).parts().2, 0x01);
        assert_eq!(TraceContext::from_parts(t, s, 0xfe).parts().2, 0x00);
        assert!(
            TraceContext::from_parts(t, s, 0xff)
                .traceparent()
                .ends_with("-01")
        );
    }

    #[test]
    fn parsed_flags_are_preserved_not_rewritten_to_sampled() {
        // A non-sampled (`00`) parent must re-emit `00`, not be flipped to `01`.
        let tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-00";
        let ctx = TraceContext::parse_traceparent(tp).unwrap();
        assert_eq!(ctx.traceparent(), tp);
        // child() keeps the trace and inherits the parent's flags.
        assert!(ctx.child().traceparent().ends_with("-00"));
    }
}
