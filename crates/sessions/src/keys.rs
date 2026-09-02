//! The session leader/subcommand key model: parsing logical key names from
//! config, deriving their wire encodings across terminal keyboard protocols,
//! and validating leaders against termios-special and wrapping-ambiguous
//! chords.
//!
//! Two consumers share this module:
//! - The *client* config ([`crate::client::config`]) holds keys as logical
//!   names and validates them loudly at load (the UX gate).
//! - The *daemon* reads the same names from per-channel SSH env vars at
//!   attach and re-runs [`validate_leader`] as a silent safety backstop
//!   before acting on the chord (the trust-boundary gate).
//!
//! ## Why the leader must not be termios-special
//!
//! A leader chord is *swallowed* by the daemon that sees it first, but the
//! verbatim-forward subcommand writes a literal leader byte down the PTY, and
//! a leaked leader could reach the PTY too. If that byte is a termios
//! `c_cc` special — e.g. `ctrl-\` (`0x1c`, `VQUIT`) delivers `SIGQUIT` — the
//! kernel line discipline acts on it *before* the application reads it,
//! turning a detach gesture into a signal. [`validate_leader`] rejects such
//! chords; see `termios(3)`. This is the finding that retired the issue's
//! proposed `ctrl-\` default in favour of `ctrl-]` (`0x1d`, not special).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Env var carrying the negotiated leader chord, e.g. `MINIMAL_SESSION_LEADER=ctrl-]`.
///
/// Sent by the client on the attach channel (alongside `MINIMAL_SESSION_ID`)
/// and read back by the daemon's per-channel env handler. Each session-key
/// var is independently optional; the daemon falls back per field.
pub const LEADER_ENV: &str = "MINIMAL_SESSION_LEADER";
/// Env var carrying the detach subcommand key, e.g. `MINIMAL_DETACH_KEY=d`.
pub const DETACH_KEY_ENV: &str = "MINIMAL_DETACH_KEY";
/// Env var carrying the verbatim-forward subcommand key, e.g.
/// `MINIMAL_FORWARD_KEY=ctrl-]`.
pub const FORWARD_KEY_ENV: &str = "MINIMAL_FORWARD_KEY";
/// Env var carrying the bell-on-leader flag, e.g. `MINIMAL_BELL_ON_LEADER=0`.
pub const BELL_ENV: &str = "MINIMAL_BELL_ON_LEADER";

/// Control bytes the kernel line discipline consumes before the application
/// reads them (the termios `c_cc` set on Linux). Binding the leader to one
/// means a leaked or verbatim-forwarded leader triggers kernel behavior — a
/// signal, flow control, or line editing — not an application binding. See
/// `termios(3)`.
///
/// Note this includes the *old* default `ctrl-w` (`0x17`, `VWERASE`), which
/// the hard-cut to `ctrl-]` retires as a latent footgun.
///
/// DEL (`0x7f`, `VERASE` on Linux) is absent deliberately: no parseable
/// [`Key`] can produce it — `ctrl-?` is rejected and plain keys stop at
/// `0x7e` — so a `0x7f` entry would be dead weight suggesting a hazard that
/// cannot arise. The *other* erase char, `ctrl-h` (`0x08`), is parseable and
/// lives in [`AMBIGUOUS`] instead.
const TERMIOS_SPECIAL: &[u8] = &[
    0x03, // ctrl-C  VINTR   (SIGINT)
    0x04, // ctrl-D  VEOF
    0x0f, // ctrl-O  VDISCARD
    0x11, // ctrl-Q  VSTART  (XON)
    0x12, // ctrl-R  VREPRINT
    0x13, // ctrl-S  VSTOP   (XOFF)
    0x15, // ctrl-U  VKILL
    0x16, // ctrl-V  VLNEXT
    0x17, // ctrl-W  VWERASE
    0x1a, // ctrl-Z  VSUSP   (SIGTSTP)
    0x1c, // ctrl-\  VQUIT   (SIGQUIT)
];

/// Control bytes that alias another commonly-typed key, so binding the leader
/// to one is fragile across terminals. Each entry names the aliased key so
/// the validation error can say *which* collision the user would hit:
/// `ctrl-@` = `NUL`, `ctrl-h` = `Backspace` wherever the tty erase char is
/// `^H` (the default on the BSDs, vs Linux's `^?`), `ctrl-i` = `TAB`,
/// `ctrl-j` = `LF`, `ctrl-m` = `CR`, `ctrl-[` = `ESC`.
///
/// The parser's `ctrl-<glyph>` range (`@`..`~`, codepoint `0x40`..`0x7e`)
/// already excludes `ctrl-<digit>` forms, so the historical case-wrapping
/// aliases (`ctrl-2` = `ctrl-@`, `ctrl-6` = `ctrl-^`, …) — which depend on
/// terminal-specific digit mappings — cannot arise; users get the canonical
/// `ctrl-@`/`ctrl-^` forms or a parse error.
const AMBIGUOUS: &[(u8, &str)] = &[
    (0x00, "NUL (also ctrl-Space)"),
    (0x08, "Backspace (tty erase is ^H on the BSDs)"),
    (0x09, "TAB"),
    (0x0a, "LF"),
    (0x0d, "CR (Enter)"),
    (0x1b, "ESC"),
];

/// A logical key as expressed in config: a base glyph plus an optional Ctrl
/// modifier. Alt/Shift are not configurable yet; the parser rejects them.
///
/// Canonical config forms: `"ctrl-]"` (Ctrl + `]`), `"d"` (the plain glyph).
/// Ctrl-chords accept any single ASCII glyph in `@`..`~` (codepoint
/// `0x40`..`0x7e`); their wire byte is `codepoint & 0x1f`, the standard
/// control-code mapping the kernel line discipline uses. Letters are
/// normalised to lowercase, since `Ctrl+a` and `Ctrl+A` produce the same
/// control code and terminals send the lowercase codepoint. Plain keys accept
/// any single printable ASCII glyph (`0x20`..`0x7e`) and are case-sensitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Key {
    codepoint: u32,
    ctrl: bool,
}

/// Failure parsing or validating a [`Key`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum KeyError {
    /// The string was not a single ASCII glyph or `ctrl-<glyph>`: e.g. `""`,
    /// `"ctrl-"`, `"ctrl-foo"`, or a multi-byte glyph.
    #[error("unknown key `{0}`: expected a single ASCII glyph or `ctrl-<glyph>`")]
    UnknownKey(String),
    /// A modifier other than `ctrl-` was used. Only `ctrl-` is configurable.
    #[error("unsupported modifier in `{0}`: only `ctrl-` is configurable")]
    UnsupportedModifier(String),
    /// The leader is a termios `c_cc` special the kernel line discipline
    /// consumes before the app (see `termios(3)`).
    #[error(
        "termios-special leader `{0}`: the kernel line discipline consumes it before the app (see termios(3))"
    )]
    TermiosSpecial(String),
    /// The leader aliases another commonly-typed key; the second field
    /// names what it aliases (e.g. `ctrl-i` aliases `TAB`).
    #[error("wrapping-ambiguous leader `{0}`: it aliases {1}")]
    Ambiguous(String, &'static str),
    /// The detach key equals the leader or the forward key: command mode
    /// checks the detach key first, so the other binding would be
    /// unreachable. The second field names the shadowed binding.
    #[error("conflicting session keys: the detach key `{0}` shadows {1}")]
    ConflictingDetach(String, &'static str),
}

/// A tiny stack buffer for rendering one wire-form encoding without a heap
/// allocation. The longest form is `\x1b[27;5;<cp>~`; parsed codepoints are
/// ASCII (`<= 0x7e`, at most 3 digits), so 32 bytes is generous. Pushes past
/// the end panic rather than truncate — the parse invariants make that
/// unreachable, and a panic beats a silently wrong encoding.
#[derive(Default)]
struct Scratch {
    buf: [u8; 32],
    len: usize,
}

impl Scratch {
    fn clear(&mut self) {
        self.len = 0;
    }

    fn push(&mut self, b: u8) -> &mut Self {
        self.buf[self.len] = b;
        self.len += 1;
        self
    }

    fn push_str(&mut self, s: &str) -> &mut Self {
        self.buf[self.len..self.len + s.len()].copy_from_slice(s.as_bytes());
        self.len += s.len();
        self
    }

    fn push_dec(&mut self, n: u32) -> &mut Self {
        let mut digits = [0u8; 10];
        let mut i = digits.len();
        let mut n = n;
        loop {
            i -= 1;
            // `n % 10` is a single digit; the cast cannot truncate.
            #[allow(clippy::cast_possible_truncation)]
            {
                digits[i] = b'0' + (n % 10) as u8;
            }
            n /= 10;
            if n == 0 {
                break;
            }
        }
        let end = self.len + (digits.len() - i);
        self.buf[self.len..end].copy_from_slice(&digits[i..]);
        self.len = end;
        self
    }

    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl Key {
    /// Parses a logical key name.
    ///
    /// Accepts `"ctrl-<glyph>"` (case-insensitive `ctrl-` prefix; the glyph
    /// is a single ASCII char in `@`..`~`, letters normalised to lowercase)
    /// and `"<glyph>"` (a single printable ASCII char, case-sensitive).
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::UnsupportedModifier`] for `alt-`/`shift-`/etc., and
    /// [`KeyError::UnknownKey`] for anything else unparseable.
    pub fn parse(s: &str) -> Result<Self, KeyError> {
        let lower = s.to_ascii_lowercase();
        if let Some(glyph) = lower.strip_prefix("ctrl-") {
            return Self::parse_ctrl(glyph, s);
        }
        for other in ["alt-", "shift-", "meta-", "super-"] {
            if lower.starts_with(other) {
                return Err(KeyError::UnsupportedModifier(s.to_string()));
            }
        }
        // Plain single printable ASCII glyph.
        let Some(ch) = s.chars().next() else {
            return Err(KeyError::UnknownKey(s.to_string()));
        };
        if s.chars().count() == 1 && ch.is_ascii() && (0x20..=0x7e).contains(&(ch as u32)) {
            Ok(Self {
                codepoint: ch as u32,
                ctrl: false,
            })
        } else {
            Err(KeyError::UnknownKey(s.to_string()))
        }
    }

    fn parse_ctrl(glyph: &str, original: &str) -> Result<Self, KeyError> {
        let Some(ch) = glyph.chars().next() else {
            return Err(KeyError::UnknownKey(original.to_string()));
        };
        if glyph.chars().count() != 1 || !ch.is_ascii() || !(0x40..=0x7e).contains(&(ch as u32)) {
            return Err(KeyError::UnknownKey(original.to_string()));
        }
        // Normalise letters to lowercase: Ctrl+a and Ctrl+A are the same
        // control code, and terminals send the lowercase codepoint.
        let codepoint = if ch.is_ascii_uppercase() {
            ch.to_ascii_lowercase() as u32
        } else {
            ch as u32
        };
        Ok(Self {
            codepoint,
            ctrl: true,
        })
    }

    /// The single-byte form: the control code for a Ctrl-chord
    /// (`codepoint & 0x1f`), or the glyph's own byte for a plain key.
    ///
    /// Safe: `parse` validates codepoints to the ASCII range (`0x20`..`0x7e`
    /// for plain glyphs, `0x40`..`0x7e` for Ctrl-chords), so the cast never
    /// truncates.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn plain_byte(&self) -> u8 {
        if self.ctrl {
            // `& 0x1f` yields 0..=31 regardless of the codepoint.
            (self.codepoint & 0x1f) as u8
        } else {
            self.codepoint as u8
        }
    }

    /// All wire forms this key can arrive as, across the plain, kitty, and
    /// modifyOtherKeys keyboard protocols.
    ///
    /// The kitty and modifyOtherKeys modifier field is `1 + bitmask`, where
    /// Control is bit `4` — so a Ctrl-chord uses `5` (matching the shipped
    /// `ctrl-w` encodings), and a plain key uses `1`. Kitty *omits* the
    /// modifier field entirely when it would be `1`, so a plain key needs
    /// both kitty forms (`CSI <cp> u` and `CSI <cp> ; 1 u`) or terminals in
    /// report-all-keys mode go unmatched. modifyOtherKeys only CSI-encodes
    /// *modified* keys, so plain keys have no modifyOtherKeys form (they
    /// arrive as [`Self::plain_byte`]); the kitty forms are still included
    /// since kitty can CSI-encode unmodified keys under "report all keys",
    /// and they cannot false-match another key.
    #[must_use]
    pub fn encodings(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::with_capacity(4);
        self.for_each_form(|form| out.push(form.to_vec()));
        out
    }

    /// Runs `f` over every wire form, rendering each into a stack buffer —
    /// the allocation-free path the matchers use (one call per received
    /// chunk in the daemon's stdin hot loop; `format!`-per-form would heap-
    /// allocate 2–3 strings a keystroke). Kept private so the test-facing
    /// [`Self::encodings`] stays the single ordered rendering of the forms,
    /// and `encodings()` derives from this so the two can never drift.
    ///
    /// Two properties the chord matcher relies on:
    /// - No form is a prefix of another form of the same key: the bare byte
    ///   and any CSI differ at the first byte, and the kitty forms diverge
    ///   at the `u` vs `;` after the codepoint digits. Exact-prefix matching
    ///   is therefore unambiguous.
    /// - Every multi-byte form starts with a byte that cannot be a plain
    ///   keystroke (`0x1b`), so a plain byte and a CSI never alias.
    fn for_each_form(self, mut f: impl FnMut(&[u8])) {
        f(&[self.plain_byte()]);
        let mods = 1 + u32::from(self.ctrl) * 4;
        let mut scratch = Scratch::default();
        // Kitty without the modifier field (omitted when it would be 1).
        // Applies to plain keys only; Ctrl-chords always carry `;5`.
        if !self.ctrl {
            scratch
                .push_str("\x1b[")
                .push_dec(self.codepoint)
                .push(b'u');
            f(scratch.as_bytes());
            scratch.clear();
        }
        scratch
            .push_str("\x1b[")
            .push_dec(self.codepoint)
            .push(b';')
            .push_dec(mods)
            .push(b'u');
        f(scratch.as_bytes());
        if self.ctrl {
            scratch.clear();
            scratch
                .push_str("\x1b[27;")
                .push_dec(mods)
                .push(b';')
                .push_dec(self.codepoint)
                .push(b'~');
            f(scratch.as_bytes());
        }
    }

    /// The length of the longest wire form that is a prefix of `buf` — i.e.
    /// a complete occurrence of this key at the start of `buf`, possibly
    /// with more bytes after. The streaming chord matcher uses this to
    /// consume a key out of a coalesced chunk.
    fn match_prefix_len(self, buf: &[u8]) -> Option<usize> {
        let mut best = None;
        self.for_each_form(|form| {
            if buf.len() >= form.len()
                && buf[..form.len()] == *form
                && best.is_none_or(|l: usize| form.len() > l)
            {
                best = Some(form.len());
            }
        });
        best
    }

    /// Whether `prefix` is a *strict* prefix of some wire form — a partial
    /// keypress, i.e. an escape sequence split across chunk boundaries.
    fn is_form_prefix(self, prefix: &[u8]) -> bool {
        let mut hit = false;
        self.for_each_form(|form| {
            hit |= prefix.len() < form.len() && form.starts_with(prefix);
        });
        hit
    }

    /// Whether a received stdin chunk is exactly this key, across all its
    /// wire forms (plain, kitty, modifyOtherKeys). A chunk that is the key
    /// plus more bytes — a paste — is not a match; this whole-chunk equality
    /// is the unit of the paste guard the streaming matcher ([`ChordMatcher`])
    /// composes into partial-chunk matching.
    #[must_use]
    pub fn matches_chunk(&self, chunk: &[u8]) -> bool {
        let mut hit = false;
        self.for_each_form(|form| hit |= form == chunk);
        hit
    }

    /// The canonical config-string form, for display and round-tripping.
    #[must_use]
    pub fn as_config_str(&self) -> String {
        let Some(ch) = char::from_u32(self.codepoint) else {
            return String::new();
        };
        if self.ctrl {
            format!("ctrl-{ch}")
        } else {
            ch.to_string()
        }
    }
}

impl Serialize for Key {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.as_config_str())
    }
}

impl<'de> Deserialize<'de> for Key {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Validates a leader chord, rejecting termios-special and wrapping-ambiguous
/// keys. This is the shared check both gates run: loudly at client config
/// load (UX), and again at the daemon before acting on the negotiated chord
/// (safety).
///
/// Only Ctrl-chords can be termios-special or ambiguous — plain keys are
/// printable bytes (`0x20`..`0x7e`), never control codes — so a plain leader
/// always passes. (A plain-printable leader is a poor choice — every press
/// enters command mode — but it is the user's explicit choice and not a
/// correctness or safety hazard, so it is not rejected here.)
///
/// # Errors
///
/// Returns [`KeyError::TermiosSpecial`] or [`KeyError::Ambiguous`] when the
/// leader's control byte is in the corresponding reject set.
pub fn validate_leader(key: &Key) -> Result<(), KeyError> {
    if key.ctrl {
        let byte = key.plain_byte();
        if TERMIOS_SPECIAL.contains(&byte) {
            return Err(KeyError::TermiosSpecial(key.as_config_str()));
        }
        if let Some((_, alias)) = AMBIGUOUS.iter().find(|(b, _)| *b == byte) {
            return Err(KeyError::Ambiguous(key.as_config_str(), alias));
        }
    }
    Ok(())
}

/// Validates the binding *set*, catching shadowed keys [`validate_leader`]
/// can't see (it only judges the leader in isolation). Command mode checks
/// the detach key before the forward key, and the leader is consumed before
/// either, so a detach key equal to the leader or the forward key makes that
/// other binding unreachable. `forward` == `leader` is *not* a conflict — it
/// is the shipped default (a double-press forwards).
///
/// Like [`validate_leader`], this runs loudly at client config load and
/// silently at the daemon (which falls the colliding field back to default).
///
/// # Errors
///
/// Returns [`KeyError::ConflictingDetach`] when the detach key aliases the
/// leader or the forward key.
pub fn validate_detach_unaliased(keys: &SessionKeys) -> Result<(), KeyError> {
    if keys.detach_key == keys.leader {
        return Err(KeyError::ConflictingDetach(
            keys.detach_key.as_config_str(),
            "the leader chord",
        ));
    }
    if keys.detach_key == keys.forward_key {
        return Err(KeyError::ConflictingDetach(
            keys.detach_key.as_config_str(),
            "the forward key",
        ));
    }
    Ok(())
}

/// The negotiated per-channel session-key config: the leader chord that
/// enters command mode, the subcommand keys, and whether entering command
/// mode rings the terminal bell.
///
/// Defaults match the shipped config: `leader = ctrl-]`, `detach = d`,
/// `forward = ctrl-]` (forward defaults to the leader, so a double-press
/// verbatim-forwards), `bell_on_leader = false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionKeys {
    /// The chord that enters command mode (swallowed, never forwarded except
    /// via the forward subcommand).
    pub leader: Key,
    /// The command-mode key that detaches this channel.
    pub detach_key: Key,
    /// The command-mode key that verbatim-forwards a leader byte down the PTY
    /// (hands the next keystroke to the layer below, for nested sessions).
    pub forward_key: Key,
    /// Whether entering command mode writes BEL (`0x07`) to the channel.
    pub bell_on_leader: bool,
}

/// State of the per-channel session-key command mode: idle (keystrokes
/// forward to the PTY) or awaiting the subcommand that follows a swallowed
/// leader. Held per attach channel on the daemon; reset whenever a new
/// channel attaches.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CommandMode {
    /// No leader pending; keystrokes forward to the PTY verbatim.
    #[default]
    Idle,
    /// The leader was swallowed; the next keystroke is the subcommand.
    AwaitingSubcommand,
}

/// A non-forward effect the chord matcher decided for received bytes. The
/// daemon maps each variant to its I/O effect; the decision itself is pure,
/// so the transitions are unit-testable without a PTY or ssh channel. Bytes
/// to forward arrive as data in [`FeedOutcome::Forward`], not as an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAction {
    /// Swallow an unbound command-mode token — a keypress (or an escape
    /// sequence that proved not to be a bound subcommand) drops as a unit
    /// and cancels command mode (mirroring tmux); subsequent bytes are back
    /// in idle mode and forward normally.
    Swallow,
    /// The leader matched: swallow it and enter command mode.
    EnterCommandMode,
    /// The detach subcommand matched: tear down the attach channel (detach,
    /// not exit — the session and its process keep running).
    Detach,
    /// The forward subcommand matched: write a leader byte down the PTY —
    /// a nested daemon *that negotiated the same leader*, if any, swallows
    /// it and enters its own command mode.
    ForwardLeader,
}

impl Default for SessionKeys {
    fn default() -> Self {
        // `parse` is infallible for these shipped defaults; panicking here
        // would mean the defaults themselves are broken, which is a
        // programmer error worth surfacing immediately.
        let leader = Key::parse("ctrl-]").expect("default leader parses");
        Self {
            leader,
            detach_key: Key::parse("d").expect("default detach key parses"),
            forward_key: leader, // forward defaults to the leader
            bell_on_leader: false,
        }
    }
}

impl SessionKeys {
    /// Parses the per-channel session keys from the SSH channel's env vars,
    /// falling back per field to the defaults when a var is absent (so an old
    /// `min` client, or a non-`min` ssh client, still gets a working leader).
    ///
    /// `forward` falls back to the negotiated `leader`, not a hardcoded key,
    /// so a remapped leader still gets a sensible default forward. Parse
    /// failures are silent here — the daemon's [`Self::validated_or_default`]
    /// is the backstop that logs and falls back on a *valid-but-unsafe* chord.
    #[must_use]
    pub fn from_env(env: &BTreeMap<String, String>) -> Self {
        let default = Self::default();
        let leader = env
            .get(LEADER_ENV)
            .and_then(|v| Key::parse(v).ok())
            .unwrap_or(default.leader);
        let detach_key = env
            .get(DETACH_KEY_ENV)
            .and_then(|v| Key::parse(v).ok())
            .unwrap_or(default.detach_key);
        let forward_key = env
            .get(FORWARD_KEY_ENV)
            .and_then(|v| Key::parse(v).ok())
            .unwrap_or(leader);
        let bell_on_leader = env
            .get(BELL_ENV)
            .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
        Self {
            leader,
            detach_key,
            forward_key,
            bell_on_leader,
        }
    }

    /// Re-validates the negotiated keys at the trust boundary (the daemon),
    /// falling back *per field*: a termios-special or ambiguous leader a
    /// buggy or malicious client could send reverts to the default leader
    /// without touching valid subcommand remaps, and a detach key that
    /// shadows the leader or the forward key reverts to the default detach
    /// key. The client's load-time validation is the loud/UX gate; this is
    /// the silent safety backstop — bad input degrades the smallest field,
    /// never garbling the screen.
    #[must_use]
    pub fn validated_or_default(mut self) -> Self {
        let default = Self::default();
        if let Err(e) = validate_leader(&self.leader) {
            tracing::warn!(
                error = %e,
                leader = self.leader.as_config_str(),
                "rejecting negotiated session leader; falling back to the default leader",
            );
            // A forward that only ever *defaulted* to this rejected leader
            // moves with it (`from_env` falls forward back to the leader when
            // the client sent no explicit forward); an explicit forward remap
            // is a distinct, safe field and survives.
            if self.forward_key == self.leader {
                self.forward_key = default.leader;
            }
            self.leader = default.leader;
        }
        if let Err(e) = validate_detach_unaliased(&self) {
            tracing::warn!(
                error = %e,
                "conflicting negotiated keys; falling back to the default detach key",
            );
            self.detach_key = default.detach_key;
            if let Err(e) = validate_detach_unaliased(&self) {
                // Degenerate config (e.g. a plain `d` leader colliding with
                // the default `d` detach): detach still fires on a second
                // press of the leader, so leave the binding in place, but
                // make the shadowing loud in the log.
                tracing::warn!(
                    error = %e,
                    "detach key still conflicts after fallback; keeping the shadowing binding",
                );
            }
        }
        self
    }
}

/// One decision the streaming chord matcher made for some received bytes.
/// Outcomes arrive in stream order; the daemon maps each to its I/O effect
/// (writes the forwarded bytes down the PTY, rings the terminal bell on the
/// channel, tears the channel down on detach).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedOutcome {
    /// Bytes that are not part of any chord: write them to the PTY.
    Forward(Vec<u8>),
    /// A non-forward effect of a matched chord or an unbound command-mode
    /// token.
    Action(KeyAction),
}

/// The streaming session-key chord matcher: one per attach channel, fed each
/// stdin chunk as it arrives off the SSH channel.
///
/// Whole-chunk matching (`advance` before this) silently broke the moment SSH
/// coalesced the leader and its subcommand into one message (`\x1dd`), split
/// a multi-byte kitty encoding across two messages, or coalesced a fast
/// double-press in command mode. This matcher consumes a byte stream instead:
/// it scans positionally, matches a key's wire forms as prefixes anywhere in
/// the stream (longest form wins), and holds a trailing *strict prefix* of
/// some form in a small buffer until the next chunk resolves it. The buffer
/// is bounded by the longest wire form (under 16 bytes), so it cannot grow.
///
/// Two consequences of the streaming model:
///
/// - There is no paste guard at the chord layer: a leader byte mid-chunk is a
///   chord, indistinguishable from coalesced keystrokes. Real pastes are the
///   terminal's and the app's business (bracketed paste), not this layer's.
/// - A chunk *ending* in a strict prefix of some form (e.g. a bare `ESC`,
///   which prefixes every kitty form) is held until the next chunk proves or
///   disproves it — a one-keystroke delay on such bytes, versus silently
///   missing split multi-byte chords.
///
/// The matcher owns the [`CommandMode`] and the pending buffer, so a fresh
/// attach constructs a fresh matcher and can never inherit a stale
/// awaiting-subcommand state or half a candidate.
pub struct ChordMatcher {
    keys: SessionKeys,
    mode: CommandMode,
    /// Held strict prefix of some wire form (split across chunks). Never
    /// longer than the key's longest form minus one byte.
    pending: Vec<u8>,
}

impl ChordMatcher {
    /// A fresh matcher in [`CommandMode::Idle`] acting on `keys`.
    #[must_use]
    pub fn new(keys: SessionKeys) -> Self {
        Self {
            keys,
            mode: CommandMode::Idle,
            pending: Vec::new(),
        }
    }

    /// The negotiated keys this matcher acts on (for host-side effects like
    /// the bell flag and the verbatim leader byte).
    #[must_use]
    pub fn keys(&self) -> &SessionKeys {
        &self.keys
    }

    /// The current command-mode state (observability and tests).
    #[must_use]
    pub fn mode(&self) -> CommandMode {
        self.mode
    }

    /// Whether a split candidate is currently held in the pending buffer —
    /// the last chunk ended mid-form and the next chunk (or an idle flush)
    /// must resolve it.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Whether `prefix` is a strict prefix of a wire form of either bound
    /// subcommand key.
    fn is_subcommand_form_prefix(&self, prefix: &[u8]) -> bool {
        self.keys.detach_key.is_form_prefix(prefix) || self.keys.forward_key.is_form_prefix(prefix)
    }

    /// Feed one stdin chunk, returning the ordered decisions taken. Each
    /// `Forward` outcome is one contiguous run of data bytes in stream order;
    /// chord bytes themselves are consumed.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<FeedOutcome> {
        let mut out = Vec::new();
        // Reassemble: any held partial candidate continues into this chunk.
        let owned;
        let buf: &[u8] = if self.pending.is_empty() {
            chunk
        } else {
            let mut v = std::mem::take(&mut self.pending);
            v.extend_from_slice(chunk);
            owned = v;
            owned.as_slice()
        };

        // `i` walks the stream; `frs` marks the start of the current run of
        // data bytes awaiting a single `Forward` outcome.
        let mut i = 0;
        let mut frs = 0;
        while i < buf.len() {
            match self.mode {
                CommandMode::Idle => {
                    if let Some(len) = self.keys.leader.match_prefix_len(&buf[i..]) {
                        if frs < i {
                            out.push(FeedOutcome::Forward(buf[frs..i].to_vec()));
                        }
                        out.push(FeedOutcome::Action(KeyAction::EnterCommandMode));
                        i += len;
                        frs = i;
                        self.mode = CommandMode::AwaitingSubcommand;
                    } else if self.keys.leader.is_form_prefix(&buf[i..]) {
                        // Trailing split candidate: flush the data run, hold
                        // the candidate until the next chunk resolves it.
                        if frs < i {
                            out.push(FeedOutcome::Forward(buf[frs..i].to_vec()));
                        }
                        self.pending.extend_from_slice(&buf[i..]);
                        return out;
                    } else {
                        i += 1;
                    }
                }
                CommandMode::AwaitingSubcommand => {
                    let rest = &buf[i..];
                    if let Some(len) = self.keys.detach_key.match_prefix_len(rest) {
                        out.push(FeedOutcome::Action(KeyAction::Detach));
                        self.mode = CommandMode::Idle;
                        i += len;
                        frs = i;
                        continue;
                    }
                    if let Some(len) = self.keys.forward_key.match_prefix_len(rest) {
                        out.push(FeedOutcome::Action(KeyAction::ForwardLeader));
                        self.mode = CommandMode::Idle;
                        i += len;
                        frs = i;
                        continue;
                    }
                    // No whole subcommand here; could one be split across
                    // chunks? Walk the longest run from `i` that stays a
                    // strict prefix of some subcommand form: `end` lands on
                    // the first byte that breaks it.
                    let mut end = i;
                    while end < buf.len() && self.is_subcommand_form_prefix(&buf[i..=end]) {
                        end += 1;
                    }
                    if end == buf.len() {
                        // The remainder is a strict prefix: hold it and stay
                        // awaiting (a split CSI completing on the next chunk).
                        self.pending.extend_from_slice(&buf[i..]);
                        return out;
                    }
                    // Not a subcommand and never going to be: swallow the
                    // token — the longest partial candidate plus the byte
                    // that broke it — as a unit (so a failed partial CSI
                    // never leaks half a sequence to the PTY) and cancel
                    // command mode, tmux-style. Bytes after resume in idle.
                    out.push(FeedOutcome::Action(KeyAction::Swallow));
                    i = end + 1;
                    frs = i;
                    self.mode = CommandMode::Idle;
                }
            }
        }
        if frs < buf.len() {
            out.push(FeedOutcome::Forward(buf[frs..].to_vec()));
        }
        out
    }

    /// Release any held split candidate as data, cancelling command mode.
    ///
    /// A held candidate is a *strict* prefix of some wire form, so on its own
    /// it can never complete a chord — the stream stopped mid-keystroke. The
    /// caller invokes this after an idle gap (see the daemon's stdin loop) so
    /// a lone `ESC` (a prefix of every kitty form) is forwarded to the PTY
    /// instead of being held until the next, possibly never-arriving, chunk —
    /// which would wedge it in e.g. vim insert mode. Command mode is
    /// cancelled, tmux-style, since the subcommand never completed.
    ///
    /// Returns the held bytes (empty when nothing is held); the daemon writes
    /// them to the PTY as ordinary data.
    pub fn flush(&mut self) -> Vec<u8> {
        if self.pending.is_empty() {
            return Vec::new();
        }
        self.mode = CommandMode::Idle;
        std::mem::take(&mut self.pending)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ctrl_chord() {
        assert_eq!(
            Key::parse("ctrl-]").unwrap(),
            Key {
                codepoint: 93,
                ctrl: true
            }
        );
        assert_eq!(
            Key::parse("ctrl-w").unwrap(),
            Key {
                codepoint: 119,
                ctrl: true
            }
        );
    }

    #[test]
    fn ctrl_prefix_is_case_insensitive() {
        assert_eq!(
            Key::parse("CTRL-]").unwrap(),
            Key {
                codepoint: 93,
                ctrl: true
            }
        );
        assert_eq!(
            Key::parse("Ctrl-]").unwrap(),
            Key {
                codepoint: 93,
                ctrl: true
            }
        );
    }

    #[test]
    fn ctrl_letter_normalised_to_lowercase() {
        // Ctrl+A and Ctrl+a are the same control code; terminals send the
        // lowercase codepoint, so both parse to 97 (not 65).
        assert_eq!(
            Key::parse("ctrl-A").unwrap(),
            Key {
                codepoint: 97,
                ctrl: true
            }
        );
        assert_eq!(
            Key::parse("ctrl-a").unwrap(),
            Key {
                codepoint: 97,
                ctrl: true
            }
        );
    }

    #[test]
    fn parses_plain_glyph_case_sensitive() {
        assert_eq!(
            Key::parse("d").unwrap(),
            Key {
                codepoint: 100,
                ctrl: false
            }
        );
        assert_eq!(
            Key::parse("D").unwrap(),
            Key {
                codepoint: 68,
                ctrl: false
            }
        );
    }

    #[test]
    fn rejects_unparseable() {
        assert!(matches!(Key::parse(""), Err(KeyError::UnknownKey(_))));
        assert!(matches!(Key::parse("ctrl-"), Err(KeyError::UnknownKey(_))));
        assert!(matches!(
            Key::parse("ctrl-foo"),
            Err(KeyError::UnknownKey(_))
        ));
        // ctrl-<digit> is outside the @..~ range: rejected, so the
        // ctrl-2=ctrl-@ case-wrapping alias cannot arise.
        assert!(matches!(Key::parse("ctrl-2"), Err(KeyError::UnknownKey(_))));
        assert!(matches!(Key::parse("ctrl-?"), Err(KeyError::UnknownKey(_))));
        assert!(matches!(Key::parse("ab"), Err(KeyError::UnknownKey(_))));
        assert!(matches!(Key::parse("é"), Err(KeyError::UnknownKey(_))));
    }

    #[test]
    fn rejects_other_modifiers() {
        assert!(matches!(
            Key::parse("alt-x"),
            Err(KeyError::UnsupportedModifier(_))
        ));
        assert!(matches!(
            Key::parse("shift-x"),
            Err(KeyError::UnsupportedModifier(_))
        ));
    }

    #[test]
    fn default_leader_encodings_match_plan() {
        let leader = Key::parse("ctrl-]").unwrap();
        assert_eq!(leader.plain_byte(), 0x1d);
        assert_eq!(
            leader.encodings(),
            vec![
                vec![0x1d],
                b"\x1b[93;5u".to_vec(),
                b"\x1b[27;5;93~".to_vec(),
            ]
        );
    }

    #[test]
    fn encodings_match_shipped_ctrl_w_forms() {
        // The derived forms for ctrl-w must equal the old hardcoded constants,
        // proving the derivation is a faithful generalisation.
        let w = Key::parse("ctrl-w").unwrap();
        assert_eq!(w.plain_byte(), 0x17);
        assert_eq!(
            w.encodings(),
            vec![
                vec![0x17],
                b"\x1b[119;5u".to_vec(),
                b"\x1b[27;5;119~".to_vec(),
            ]
        );
    }

    #[test]
    fn plain_key_has_no_modifyotherkeys_form() {
        let d = Key::parse("d").unwrap();
        assert_eq!(
            d.encodings(),
            vec![
                vec![0x64],
                // Kitty omits the modifier field when it would be 1.
                b"\x1b[100u".to_vec(),
                b"\x1b[100;1u".to_vec(),
            ]
        );
    }

    #[test]
    fn config_str_round_trips() {
        for s in ["ctrl-]", "ctrl-w", "ctrl-a", "d", "D", "^", "@"] {
            assert_eq!(Key::parse(s).unwrap().as_config_str(), s);
        }
    }

    #[test]
    fn validate_accepts_safe_leaders() {
        assert!(validate_leader(&Key::parse("ctrl-]").unwrap()).is_ok());
        assert!(validate_leader(&Key::parse("ctrl-^").unwrap()).is_ok());
        // `ctrl-_` is `0x1f`, the highest control byte: the upper boundary of
        // the accepted set, next to the rejected `ctrl-^`+1 range edge.
        assert!(validate_leader(&Key::parse("ctrl-_").unwrap()).is_ok());
        // A plain-printable leader is a poor choice but not unsafe.
        assert!(validate_leader(&Key::parse("d").unwrap()).is_ok());
    }

    #[test]
    fn validate_rejects_termios_special() {
        for bad in [
            "ctrl-c", "ctrl-d", "ctrl-o", "ctrl-q", "ctrl-r", "ctrl-s", "ctrl-u", "ctrl-v",
            "ctrl-w", "ctrl-z", "ctrl-\\",
        ] {
            let err = validate_leader(&Key::parse(bad).unwrap()).unwrap_err();
            assert!(
                matches!(err, KeyError::TermiosSpecial(_)),
                "{bad} should be termios-special, got {err:?}"
            );
        }
    }

    #[test]
    fn validate_rejects_ambiguous() {
        for bad in ["ctrl-@", "ctrl-h", "ctrl-i", "ctrl-j", "ctrl-m", "ctrl-["] {
            let err = validate_leader(&Key::parse(bad).unwrap()).unwrap_err();
            assert!(
                matches!(err, KeyError::Ambiguous(..)),
                "{bad} should be ambiguous, got {err:?}"
            );
        }
    }

    #[test]
    fn from_env_uses_defaults_when_empty() {
        let keys = SessionKeys::from_env(&BTreeMap::new());
        assert_eq!(keys, SessionKeys::default());
    }

    #[test]
    fn from_env_parses_all_fields() {
        let mut env = BTreeMap::new();
        env.insert(LEADER_ENV.to_string(), "ctrl-^".to_string());
        env.insert(DETACH_KEY_ENV.to_string(), "x".to_string());
        env.insert(FORWARD_KEY_ENV.to_string(), "ctrl-]".to_string());
        env.insert(BELL_ENV.to_string(), "1".to_string());
        let keys = SessionKeys::from_env(&env);
        assert_eq!(keys.leader, Key::parse("ctrl-^").unwrap());
        assert_eq!(keys.detach_key, Key::parse("x").unwrap());
        assert_eq!(keys.forward_key, Key::parse("ctrl-]").unwrap());
        assert!(keys.bell_on_leader);
    }

    #[test]
    fn from_env_forward_falls_back_to_leader() {
        // forward absent -> defaults to the negotiated leader, not ctrl-].
        let mut env = BTreeMap::new();
        env.insert(LEADER_ENV.to_string(), "ctrl-^".to_string());
        let keys = SessionKeys::from_env(&env);
        assert_eq!(keys.forward_key, Key::parse("ctrl-^").unwrap());
    }

    #[test]
    fn from_env_silently_ignores_unparseable() {
        let mut env = BTreeMap::new();
        env.insert(LEADER_ENV.to_string(), "nonsense".to_string());
        let keys = SessionKeys::from_env(&env);
        assert_eq!(keys.leader, SessionKeys::default().leader);
    }

    #[test]
    fn from_env_bell_truthy_values() {
        for (val, expected) in [
            ("0", false),
            ("1", true),
            ("true", true),
            ("TRUE", true),
            ("yes", false),
        ] {
            let mut env = BTreeMap::new();
            env.insert(BELL_ENV.to_string(), val.to_string());
            assert_eq!(
                SessionKeys::from_env(&env).bell_on_leader,
                expected,
                "bell={val:?}"
            );
        }
    }

    #[test]
    fn validated_or_default_keeps_safe_leader() {
        let mut env = BTreeMap::new();
        env.insert(LEADER_ENV.to_string(), "ctrl-^".to_string());
        let keys = SessionKeys::from_env(&env);
        assert_eq!(
            keys.validated_or_default().leader,
            Key::parse("ctrl-^").unwrap()
        );
    }

    #[test]
    fn validated_or_default_falls_back_on_termios_special() {
        let mut env = BTreeMap::new();
        env.insert(LEADER_ENV.to_string(), "ctrl-c".to_string());
        let keys = SessionKeys::from_env(&env);
        // A malicious/buggy client sending ctrl-c falls back to the default,
        // never acting on the unsafe chord.
        assert_eq!(keys.validated_or_default(), SessionKeys::default());
    }

    #[test]
    fn default_forward_is_the_leader() {
        let default = SessionKeys::default();
        assert_eq!(default.forward_key, default.leader);
        assert_eq!(default.leader, Key::parse("ctrl-]").unwrap());
        assert_eq!(default.detach_key, Key::parse("d").unwrap());
        assert!(!default.bell_on_leader);
    }

    #[test]
    fn matches_chunk_accepts_every_encoding() {
        let leader = Key::parse("ctrl-]").unwrap();
        // Plain byte, kitty, and modifyOtherKeys forms all match.
        assert!(leader.matches_chunk(&[0x1d]));
        assert!(leader.matches_chunk(b"\x1b[93;5u"));
        assert!(leader.matches_chunk(b"\x1b[27;5;93~"));
    }

    #[test]
    fn matches_chunk_rejects_paste_and_prefix() {
        let leader = Key::parse("ctrl-]").unwrap();
        // A paste (leader byte plus more) is not a match.
        assert!(!leader.matches_chunk(b"\x1dxyz"));
        // A bare prefix of a multi-byte form is not a match.
        assert!(!leader.matches_chunk(b"\x1b[93"));
        // A different key is not a match.
        assert!(!leader.matches_chunk(b"\x1b[119;5u"));
    }

    #[test]
    fn feed_forwards_plain_data() {
        let mut m = ChordMatcher::new(SessionKeys::default());
        assert_eq!(
            m.feed(b"hello"),
            vec![FeedOutcome::Forward(b"hello".to_vec())]
        );
        assert_eq!(m.mode(), CommandMode::Idle);
    }

    #[test]
    fn feed_idle_leader_enters_command_mode() {
        // Every leader encoding enters command mode.
        for chunk in [&[0x1d][..], b"\x1b[93;5u", b"\x1b[27;5;93~"] {
            let mut m = ChordMatcher::new(SessionKeys::default());
            assert_eq!(
                m.feed(chunk),
                vec![FeedOutcome::Action(KeyAction::EnterCommandMode)],
                "chunk={chunk:?}",
            );
            assert_eq!(m.mode(), CommandMode::AwaitingSubcommand);
        }
    }

    #[test]
    fn feed_coalesced_leader_and_detach() {
        // SSH coalescing `ctrl-]` and `d` into one message must still detach:
        // the whole-chunk matcher model silently failed here.
        let mut m = ChordMatcher::new(SessionKeys::default());
        assert_eq!(
            m.feed(b"\x1dd"),
            vec![
                FeedOutcome::Action(KeyAction::EnterCommandMode),
                FeedOutcome::Action(KeyAction::Detach),
            ],
        );
        assert_eq!(m.mode(), CommandMode::Idle);
    }

    #[test]
    fn feed_data_before_leader_still_fires_chord() {
        let mut m = ChordMatcher::new(SessionKeys::default());
        assert_eq!(
            m.feed(b"ab\x1dd"),
            vec![
                FeedOutcome::Forward(b"ab".to_vec()),
                FeedOutcome::Action(KeyAction::EnterCommandMode),
                FeedOutcome::Action(KeyAction::Detach),
            ],
        );
    }

    #[test]
    fn feed_command_mode_detach_key_detaches() {
        let mut m = ChordMatcher::new(SessionKeys::default());
        assert_eq!(
            m.feed(&[0x1d]),
            vec![FeedOutcome::Action(KeyAction::EnterCommandMode)]
        );
        assert_eq!(m.feed(b"d"), vec![FeedOutcome::Action(KeyAction::Detach)]);
        assert_eq!(m.mode(), CommandMode::Idle);
    }

    #[test]
    fn feed_command_mode_forward_key_forwards_leader() {
        // Default forward key is the leader itself: a double-press forwards.
        let mut m = ChordMatcher::new(SessionKeys::default());
        assert_eq!(
            m.feed(&[0x1d]),
            vec![FeedOutcome::Action(KeyAction::EnterCommandMode)]
        );
        assert_eq!(
            m.feed(&[0x1d]),
            vec![FeedOutcome::Action(KeyAction::ForwardLeader)]
        );
        assert_eq!(m.mode(), CommandMode::Idle);
    }

    #[test]
    fn feed_command_mode_unbound_key_swallows_and_cancels() {
        let mut m = ChordMatcher::new(SessionKeys::default());
        assert_eq!(
            m.feed(&[0x1d]),
            vec![FeedOutcome::Action(KeyAction::EnterCommandMode)]
        );
        // An unbound key is swallowed (not forwarded) and exits command mode.
        assert_eq!(m.feed(b"x"), vec![FeedOutcome::Action(KeyAction::Swallow)]);
        // After the cancel, idle resumes: a normal key forwards again.
        assert_eq!(m.feed(b"x"), vec![FeedOutcome::Forward(b"x".to_vec())]);
    }

    #[test]
    fn feed_command_mode_double_press_eats_nothing() {
        // A fast `dd` arriving in one chunk detaches and forwards the second
        // `d` — the whole-chunk matcher swallowed both bytes as "unbound".
        let mut m = ChordMatcher::new(SessionKeys::default());
        assert_eq!(
            m.feed(b"\x1ddd"),
            vec![
                FeedOutcome::Action(KeyAction::EnterCommandMode),
                FeedOutcome::Action(KeyAction::Detach),
                FeedOutcome::Forward(b"d".to_vec()),
            ],
        );
    }

    #[test]
    fn feed_command_mode_paste_detach_fires_then_forwards_rest() {
        // No paste guard at the chord layer (see the ChordMatcher docs): a
        // pasted "detach" in command mode begins with the detach byte and is
        // indistinguishable from coalesced keystrokes. Real pastes are
        // bracketed-paste's business.
        let mut m = ChordMatcher::new(SessionKeys::default());
        assert_eq!(
            m.feed(&[0x1d]),
            vec![FeedOutcome::Action(KeyAction::EnterCommandMode)]
        );
        assert_eq!(
            m.feed(b"detach"),
            vec![
                FeedOutcome::Action(KeyAction::Detach),
                FeedOutcome::Forward(b"etach".to_vec()),
            ],
        );
    }

    #[test]
    fn feed_split_kitty_leader_across_chunks() {
        let mut m = ChordMatcher::new(SessionKeys::default());
        // A kitty form split at a chunk boundary: nothing forwards while the
        // candidate is pending...
        assert_eq!(m.feed(b"\x1b[9"), vec![]);
        // ...and the chord fires when the form completes.
        assert_eq!(
            m.feed(b"3;5u"),
            vec![FeedOutcome::Action(KeyAction::EnterCommandMode)]
        );
    }

    #[test]
    fn feed_split_detach_kitty_form_across_chunks() {
        let mut m = ChordMatcher::new(SessionKeys::default());
        assert_eq!(
            m.feed(&[0x1d]),
            vec![FeedOutcome::Action(KeyAction::EnterCommandMode)]
        );
        assert_eq!(m.feed(b"\x1b[10"), vec![]);
        assert_eq!(m.feed(b"0u"), vec![FeedOutcome::Action(KeyAction::Detach)]);
        assert_eq!(m.mode(), CommandMode::Idle);
    }

    #[test]
    fn feed_held_candidate_flushes_as_data_on_mismatch() {
        // A bare ESC ends the chunk: held as a possible kitty prefix...
        let mut m = ChordMatcher::new(SessionKeys::default());
        assert_eq!(m.feed(b"\x1b"), vec![]);
        // ...but it wasn't one, so it and the next byte forward as data.
        assert_eq!(m.feed(b"x"), vec![FeedOutcome::Forward(b"\x1bx".to_vec())]);
        assert_eq!(m.mode(), CommandMode::Idle);
    }

    #[test]
    fn feed_held_idle_candidate_flushes_before_a_real_leader() {
        // ESC held idle, then the leader byte arrives: the ESC is data, the
        // leader is the chord.
        let mut m = ChordMatcher::new(SessionKeys::default());
        assert_eq!(m.feed(b"\x1b"), vec![]);
        assert_eq!(
            m.feed(&[0x1d]),
            vec![
                FeedOutcome::Forward(b"\x1b".to_vec()),
                FeedOutcome::Action(KeyAction::EnterCommandMode),
            ],
        );
    }

    #[test]
    fn feed_held_subcommand_candidate_swallows_as_a_unit_on_mismatch() {
        // In command mode, ESC is a prefix of the bound subcommands' kitty
        // forms, so it is held. When `[A` proves it is none of them, the
        // whole failed token drops: no half-sequence leaks to the PTY.
        let mut m = ChordMatcher::new(SessionKeys::default());
        assert_eq!(
            m.feed(&[0x1d]),
            vec![FeedOutcome::Action(KeyAction::EnterCommandMode)]
        );
        assert_eq!(m.feed(b"\x1b"), vec![]);
        assert_eq!(m.feed(b"[A"), vec![FeedOutcome::Action(KeyAction::Swallow)]);
        assert_eq!(m.mode(), CommandMode::Idle);
    }

    #[test]
    fn flush_empty_is_a_noop() {
        let mut m = ChordMatcher::new(SessionKeys::default());
        assert!(!m.has_pending());
        assert_eq!(m.flush(), Vec::<u8>::new());
    }

    #[test]
    fn flush_releases_held_idle_candidate_as_data() {
        // A bare ESC ends the chunk: held as a possible kitty prefix of the
        // leader. The stream goes quiet, so the idle flush releases it as
        // data instead of holding it for a next chunk that never comes.
        let mut m = ChordMatcher::new(SessionKeys::default());
        assert_eq!(m.feed(b"\x1b"), vec![]);
        assert!(m.has_pending());
        assert_eq!(m.mode(), CommandMode::Idle);
        assert_eq!(m.flush(), vec![0x1b]);
        assert!(!m.has_pending());
        // A second flush is a no-op.
        assert_eq!(m.flush(), Vec::<u8>::new());
    }

    #[test]
    fn flush_cancels_command_mode_and_releases_held_subcommand() {
        // In command mode, a bare ESC is a prefix of the bound subcommands'
        // kitty forms, so it is held. The stream goes quiet: the idle flush
        // releases the ESC as data and cancels command mode (the subcommand
        // never completed).
        let mut m = ChordMatcher::new(SessionKeys::default());
        assert_eq!(
            m.feed(&[0x1d]),
            vec![FeedOutcome::Action(KeyAction::EnterCommandMode)]
        );
        assert_eq!(m.feed(b"\x1b"), vec![]);
        assert!(m.has_pending());
        assert_eq!(m.mode(), CommandMode::AwaitingSubcommand);
        assert_eq!(m.flush(), vec![0x1b]);
        assert_eq!(m.mode(), CommandMode::Idle);
        assert!(!m.has_pending());
    }

    #[test]
    fn feed_remapped_leader_uses_negotiated_keys() {
        // A client that remapped leader=ctrl-^, detach=x, forward=ctrl-].
        let mut env = BTreeMap::new();
        env.insert(LEADER_ENV.to_string(), "ctrl-^".to_string());
        env.insert(DETACH_KEY_ENV.to_string(), "x".to_string());
        env.insert(FORWARD_KEY_ENV.to_string(), "ctrl-]".to_string());
        let keys = SessionKeys::from_env(&env);

        // The old default leader (ctrl-], 0x1d) no longer enters command mode.
        let mut m = ChordMatcher::new(keys);
        assert_eq!(m.feed(&[0x1d]), vec![FeedOutcome::Forward(vec![0x1d])]);
        // The remapped leader (ctrl-^, 0x1e) coalesced with the remapped
        // detach key (x) detaches.
        assert_eq!(
            m.feed(b"\x1ex"),
            vec![
                FeedOutcome::Action(KeyAction::EnterCommandMode),
                FeedOutcome::Action(KeyAction::Detach),
            ],
        );
        // The remapped forward key (ctrl-]) forwards the leader.
        let mut m = ChordMatcher::new(keys);
        assert_eq!(
            m.feed(b"\x1e\x1d"),
            vec![
                FeedOutcome::Action(KeyAction::EnterCommandMode),
                FeedOutcome::Action(KeyAction::ForwardLeader),
            ],
        );
    }

    #[test]
    fn matches_chunk_accepts_plain_key_kitty_forms() {
        // Kitty report-all-keys mode sends `d` without the modifier field.
        let d = Key::parse("d").unwrap();
        assert!(d.matches_chunk(b"d"));
        assert!(d.matches_chunk(b"\x1b[100u"));
        assert!(d.matches_chunk(b"\x1b[100;1u"));
    }

    #[test]
    fn validate_detach_unaliased_accepts_shipped_default() {
        // forward == leader is the shipped default: not a conflict.
        assert!(validate_detach_unaliased(&SessionKeys::default()).is_ok());
    }

    #[test]
    fn validate_detach_unaliased_rejects_shadowing() {
        // detach == leader shadows the forward binding (the default forward
        // is the leader; the leader is consumed before either).
        let err = validate_detach_unaliased(&SessionKeys {
            detach_key: SessionKeys::default().leader,
            ..SessionKeys::default()
        })
        .unwrap_err();
        assert!(matches!(
            err,
            KeyError::ConflictingDetach(ref d, s) if d == "ctrl-]" && s == "the leader chord"
        ));
        // detach == forward (distinct from the leader) shadows the forward key.
        let err = validate_detach_unaliased(&SessionKeys {
            detach_key: Key::parse("x").unwrap(),
            forward_key: Key::parse("x").unwrap(),
            ..SessionKeys::default()
        })
        .unwrap_err();
        assert!(matches!(
            err,
            KeyError::ConflictingDetach(ref d, s) if d == "x" && s == "the forward key"
        ));
    }

    #[test]
    fn validated_or_default_is_field_scoped_for_a_bad_leader() {
        // A bad leader reverts; valid subcommand remaps survive.
        let mut env = BTreeMap::new();
        env.insert(LEADER_ENV.to_string(), "ctrl-c".to_string());
        env.insert(DETACH_KEY_ENV.to_string(), "x".to_string());
        let keys = SessionKeys::from_env(&env).validated_or_default();
        assert_eq!(keys.leader, SessionKeys::default().leader);
        assert_eq!(keys.detach_key, Key::parse("x").unwrap());
    }

    #[test]
    fn validated_or_default_reverts_a_shadowing_detach_key() {
        // detach == leader reaches forward-of-leader unreachable; the detach
        // field alone reverts.
        let default = SessionKeys::default();
        let keys = SessionKeys {
            detach_key: default.leader,
            ..default
        };
        let keys = keys.validated_or_default();
        assert_eq!(keys.detach_key, default.detach_key);
        assert_eq!(keys.leader, default.leader);
    }
}
