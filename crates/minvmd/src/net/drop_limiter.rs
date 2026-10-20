//! The drop limiter: the rate limiter both policy warning paths answer to.
//!
//! The gate's drop lines and the DNS pins' refusal lines share one window
//! table, so the limiter lives in its own module: `dns_pins` and
//! `egress_gate` each import it without importing each other.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// One drop warning per source address per rule per interval — the cadence the
/// daemon's policy warnings use, so a host's log speaks with one voice.
pub(super) const DROP_WARN_MIN_INTERVAL: Duration = Duration::from_secs(60);

/// How many distinct `(source, rule)` pairs the limiter keeps a window for —
/// the gate's memory bound on the lines it writes, a drop's and the interim
/// admit's alike. The source address a line is keyed by is the frame's own
/// bytes, read off the wire, and the guest chooses those: flooding the shuttle
/// with frames from ever-different spoofed addresses would otherwise grow host
/// memory one entry per frame, an amplification against the very path the gate
/// exists to protect. Past the cap, a pair the table holds no window for
/// shares one line per rule ([`DropKey::Overflow`]), so a flood costs at most
/// one line per rule per interval and no memory at all.
///
/// The cap sits far past any honest host's need: the pairs that exist
/// legitimately are the published boxes' few addresses under a closed
/// handful of rules, while more distinct sources writing within one
/// interval than this is a spoofed flood by shape. Stale windows are pruned
/// before the fallback is taken, so a flood that has ended restores
/// per-source lines within one interval.
pub(super) const DROP_WARN_MAX_TRACKED_PAIRS: usize = 1024;

/// The rate-limit key: a dropped frame's source address under the rule that
/// dropped it — `None` for a frame with no readable source — a DNS
/// refusal's source, rule and name, or, past
/// [`DROP_WARN_MAX_TRACKED_PAIRS`], the rule alone.
#[derive(Debug, Hash, PartialEq, Eq)]
pub(super) enum DropKey {
    /// One source address under one rule: the two things the drop line names.
    Source(Option<[u8; 4]>, &'static str),
    /// One DNS refusal: the box whose resolution refused, the rule that
    /// refused the answer, and the name the box asked for — the three things
    /// the refusal line names, so one name's burst of refused answers is one
    /// line per rule while two names refusing under the same rule say so
    /// separately.
    Refusal([u8; 4], &'static str, String),
    /// The rule's shared window, which every pair the table held no room for
    /// is folded into.
    Overflow(&'static str),
}

/// What the limiter decided for one dropped frame: whether a warning fires,
/// and which window it fires under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WarnDecision {
    /// The pair's own window fired: emit the line naming its source.
    Named,
    /// The pair table is full of live windows, so the rule's shared window
    /// fired instead: emit the flood line, naming no source.
    Overflow,
    /// A window fired inside the interval: emit nothing.
    Silent,
}

/// The gate's rate limiter: one warning per source address per rule per
/// [`DROP_WARN_MIN_INTERVAL`], keyed by the things the line names — a
/// drop's two, the interim admit's, or a DNS refusal's three. Keyed per
/// source and per rule both, so one address's flood neither silences
/// another's single line nor merges two rules into one.
///
/// The window table is bounded at [`DROP_WARN_MAX_TRACKED_PAIRS`] — the
/// source address it keys by is the frame's own bytes, chosen by the guest,
/// and the guest is the side this gate exists to contain — so the throttling
/// cannot be turned into host-memory growth.
#[derive(Debug, Default)]
pub(crate) struct DropLimiter {
    pub(super) last: Mutex<HashMap<DropKey, Instant>>,
}

impl DropLimiter {
    /// A fresh limiter that has never emitted for any source or rule.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The decision every line this limiter gates answers to, under whatever
    /// key names it: one window per key per interval, the same table, the
    /// same bound and the same flood fallback for drop, admit and refusal
    /// lines alike.
    fn decide(&self, key: DropKey, rule: &'static str, now: Instant) -> WarnDecision {
        let mut last = self
            .last
            .lock()
            .expect("the limiter's lock is held only across this lookup, never across a panic");
        if let Some(prev) = last.get(&key)
            && now.duration_since(*prev) < DROP_WARN_MIN_INTERVAL
        {
            return WarnDecision::Silent;
        }
        if last.len() >= DROP_WARN_MAX_TRACKED_PAIRS {
            // The table is at its bound. Drop the windows that have gone
            // stale — their pairs would fire afresh on re-insertion anyway —
            // before folding this one into a shared line: a flood that has
            // ended must not leave honest sources unnamed forever after.
            last.retain(|_, at| now.duration_since(*at) < DROP_WARN_MIN_INTERVAL);
        }
        if last.len() < DROP_WARN_MAX_TRACKED_PAIRS {
            last.insert(key, now);
            return WarnDecision::Named;
        }
        // Still full: every window is live, so more distinct sources are
        // dropping within this interval than the table holds — a spoofed
        // flood by shape. One shared window per rule, so the flood costs no
        // memory and at most one line per rule per interval.
        match last.get(&DropKey::Overflow(rule)) {
            Some(prev) if now.duration_since(*prev) < DROP_WARN_MIN_INTERVAL => {
                WarnDecision::Silent
            }
            _ => {
                last.insert(DropKey::Overflow(rule), now);
                WarnDecision::Overflow
            }
        }
    }

    /// Whether the drop of `src` under `rule` warns at `now`, and which
    /// window the warning comes under, recording `now` in that window when
    /// one fires. Split from [`emit`](Self::emit) so the rate-limit decision
    /// is testable without a clock or a `tracing` subscriber.
    pub(super) fn should_warn_at(
        &self,
        src: Option<[u8; 4]>,
        rule: &'static str,
        now: Instant,
    ) -> WarnDecision {
        self.decide(DropKey::Source(src, rule), rule, now)
    }

    /// The refusal arm of [`should_warn_at`](Self::should_warn_at): the same
    /// decision under the key that names the refused name — one line per box
    /// per name per rule per interval, so a box's one name refusing many
    /// answers says so once while two names refusing under one rule each say
    /// so. Split from [`warn_dns_refusal`](Self::warn_dns_refusal) for the
    /// same testability.
    pub(super) fn should_warn_refusal_at(
        &self,
        src: [u8; 4],
        name: &str,
        rule: &'static str,
        now: Instant,
    ) -> WarnDecision {
        self.decide(DropKey::Refusal(src, rule, name.to_string()), rule, now)
    }

    /// Emits the mandated refusal for one DNS answer that resolved into a
    /// range the box may not reach (NET-067: the name and the answer say so):
    /// the same rate limit a drop's line answers to, keyed by the box, the
    /// name and the rule, in the shared refusal format — the same message and
    /// fields the in-VM gate's refusal line carries (`PolicyWarnLimiter`'s
    /// `warn_dns_refusal`), with `source` naming the box whose resolution
    /// refused, the way the drop lines here name the frame's source. One
    /// rate-limited line per refused answer is what the diagnostics ask for:
    /// a DNS box whose destination was refused reads so in a bundle.
    /// Returns whether a line was written.
    pub(crate) fn warn_dns_refusal(
        &self,
        src: [u8; 4],
        name: &str,
        answer: Ipv4Addr,
        rule: &'static str,
    ) -> bool {
        match self.should_warn_refusal_at(src, name, rule, Instant::now()) {
            WarnDecision::Silent => false,
            WarnDecision::Named => {
                tracing::warn!(
                    source = %Ipv4Addr::from(src),
                    name,
                    %answer,
                    rule_matched = rule,
                    "an allowed name resolved into a refused range",
                );
                true
            }
            WarnDecision::Overflow => {
                tracing::warn!(
                    rule_matched = rule,
                    "allowed names resolving into refused ranges from more distinct boxes \
                     and names than the gate keeps a window for; one line per rule covers \
                     the rest",
                );
                true
            }
        }
    }
}
