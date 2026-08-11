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
    0x7f, // DEL     VERASE
];

/// Control bytes that alias another commonly-typed key, so binding the leader
/// to one is fragile across terminals: `NUL` (`ctrl-@`), `TAB` (`ctrl-i`),
/// `LF` (`ctrl-j`), `CR` (`ctrl-m`), `ESC` (`ctrl-[`).
///
/// The parser's `ctrl-<glyph>` range (`@`..`~`, codepoint `0x40`..`0x7e`)
/// already excludes `ctrl-<digit>` forms, so the historical case-wrapping
/// aliases (`ctrl-2` = `ctrl-@`, `ctrl-6` = `ctrl-^`, …) — which depend on
/// terminal-specific digit mappings — cannot arise; users get the canonical
/// `ctrl-@`/`ctrl-^` forms or a parse error.
const AMBIGUOUS: &[u8] = &[0x00, 0x09, 0x0a, 0x0d, 0x1b];

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
    /// The leader aliases another commonly-typed key (e.g. `ctrl-i` = `TAB`).
    #[error("wrapping-ambiguous leader `{0}`: it aliases another key (e.g. ctrl-i = TAB)")]
    Ambiguous(String),
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
    /// modifyOtherKeys keyboard protocols. A keystroke matches this key when
    /// the *whole* received chunk equals any form (matching mirrors the
    /// existing chord matcher: a chunk that is the chord plus more bytes is
    /// not a match, so pastes never trigger command mode).
    ///
    /// The kitty and modifyOtherKeys modifier field is `1 + bitmask`, where
    /// Control is bit `4` — so a Ctrl-chord uses `5` (matching the shipped
    /// `ctrl-w` encodings), and a plain key uses `1`. modifyOtherKeys only
    /// CSI-encodes *modified* keys, so plain keys have no modifyOtherKeys
    /// form (they arrive as [`Self::plain_byte`]); the kitty form is still
    /// included since kitty can CSI-encode unmodified keys under "report all
    /// keys", and it cannot false-match another key.
    #[must_use]
    pub fn encodings(&self) -> Vec<Vec<u8>> {
        let mods = 1 + u32::from(self.ctrl) * 4;
        let cp = self.codepoint;
        let mut out = Vec::with_capacity(3);
        out.push(vec![self.plain_byte()]);
        out.push(format!("\x1b[{cp};{mods}u").into_bytes());
        if self.ctrl {
            out.push(format!("\x1b[27;{mods};{cp}~").into_bytes());
        }
        out
    }

    /// Whether a received stdin chunk is exactly this key, across all its
    /// wire forms (plain, kitty, modifyOtherKeys). A chunk that is the key
    /// plus more bytes — a paste — is not a match, so pastes never trigger
    /// command mode. This is the whole-chunk match the daemon's chord matcher
    /// has always used, now derived from the key instead of hardcoded.
    #[must_use]
    pub fn matches_chunk(&self, chunk: &[u8]) -> bool {
        self.encodings().iter().any(|e| e.as_slice() == chunk)
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
        if AMBIGUOUS.contains(&byte) {
            return Err(KeyError::Ambiguous(key.as_config_str()));
        }
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

/// What the session-key state machine does with one stdin chunk. The daemon
/// maps each variant to its I/O effect; the decision itself is pure, so the
/// transitions are unit-testable without a PTY or ssh channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAction {
    /// Forward the chunk verbatim to the PTY.
    Forward,
    /// Swallow the chunk — an unbound command-mode key that cancels command
    /// mode (the key is dropped, not forwarded, mirroring tmux).
    Swallow,
    /// The leader matched: swallow it and enter command mode.
    EnterCommandMode,
    /// The detach subcommand matched: tear down the attach channel (detach,
    /// not exit — the session and its process keep running).
    Detach,
    /// The forward subcommand matched: write a leader byte down the PTY so a
    /// nested daemon, if any, swallows it and enters its own command mode.
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

    /// Re-validates the leader at the trust boundary (the daemon). On failure
    /// — a termios-special or ambiguous chord a buggy or malicious client
    /// could send — returns the default keys so a bad chord never garbles the
    /// screen. The client's load-time validation is the loud/UX gate; this is
    /// the silent safety backstop.
    #[must_use]
    pub fn validated_or_default(self) -> Self {
        match validate_leader(&self.leader) {
            Ok(()) => self,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    leader = self.leader.as_config_str(),
                    "rejecting negotiated session leader; falling back to default",
                );
                Self::default()
            }
        }
    }

    /// Advance the command-mode state machine by one stdin chunk, returning
    /// the next state and the action to take. Pure: no I/O.
    ///
    /// In [`CommandMode::Idle`], a chunk matching the leader enters command
    /// mode (the leader is swallowed); anything else forwards. In
    /// [`CommandMode::AwaitingSubcommand`], the next chunk is the subcommand:
    /// the detach key detaches, the forward key verbatim-forwards a leader
    /// byte, and any other key is swallowed and cancels command mode — so a
    /// stray leader can always be cancelled by pressing any unbound key (no
    /// stuck state, no explicit cancel key).
    #[must_use]
    pub fn advance(&self, mode: CommandMode, chunk: &[u8]) -> (CommandMode, KeyAction) {
        match mode {
            CommandMode::Idle => {
                if self.leader.matches_chunk(chunk) {
                    (CommandMode::AwaitingSubcommand, KeyAction::EnterCommandMode)
                } else {
                    (CommandMode::Idle, KeyAction::Forward)
                }
            }
            CommandMode::AwaitingSubcommand => {
                if self.detach_key.matches_chunk(chunk) {
                    (CommandMode::Idle, KeyAction::Detach)
                } else if self.forward_key.matches_chunk(chunk) {
                    (CommandMode::Idle, KeyAction::ForwardLeader)
                } else {
                    (CommandMode::Idle, KeyAction::Swallow)
                }
            }
        }
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
        assert_eq!(d.encodings(), vec![vec![0x64], b"\x1b[100;1u".to_vec(),]);
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
        for bad in ["ctrl-@", "ctrl-i", "ctrl-j", "ctrl-m", "ctrl-["] {
            let err = validate_leader(&Key::parse(bad).unwrap()).unwrap_err();
            assert!(
                matches!(err, KeyError::Ambiguous(_)),
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
    fn advance_idle_forwards_non_leader() {
        let keys = SessionKeys::default();
        assert_eq!(
            keys.advance(CommandMode::Idle, b"hello"),
            (CommandMode::Idle, KeyAction::Forward),
        );
    }

    #[test]
    fn advance_idle_leader_enters_command_mode() {
        let keys = SessionKeys::default();
        // Every leader encoding enters command mode.
        for chunk in [&[0x1d][..], b"\x1b[93;5u", b"\x1b[27;5;93~"] {
            assert_eq!(
                keys.advance(CommandMode::Idle, chunk),
                (CommandMode::AwaitingSubcommand, KeyAction::EnterCommandMode),
                "chunk={chunk:?}",
            );
        }
    }

    #[test]
    fn advance_command_mode_detach_key_detaches() {
        let keys = SessionKeys::default();
        // The leader enters command mode; `d` detaches and returns to idle.
        let (mode, _) = keys.advance(CommandMode::Idle, &[0x1d]);
        assert_eq!(mode, CommandMode::AwaitingSubcommand);
        assert_eq!(
            keys.advance(mode, b"d"),
            (CommandMode::Idle, KeyAction::Detach),
        );
    }

    #[test]
    fn advance_command_mode_forward_key_forwards_leader() {
        let keys = SessionKeys::default();
        // Default forward key is the leader itself: a double-press forwards.
        let (mode, _) = keys.advance(CommandMode::Idle, &[0x1d]);
        assert_eq!(
            keys.advance(mode, &[0x1d]),
            (CommandMode::Idle, KeyAction::ForwardLeader),
        );
    }

    #[test]
    fn advance_command_mode_unbound_key_swallows_and_cancels() {
        let keys = SessionKeys::default();
        let (mode, _) = keys.advance(CommandMode::Idle, &[0x1d]);
        // An unbound key is swallowed (not forwarded) and exits command mode.
        assert_eq!(
            keys.advance(mode, b"x"),
            (CommandMode::Idle, KeyAction::Swallow),
        );
        // After the cancel, idle resumes: a normal key forwards again.
        assert_eq!(
            keys.advance(CommandMode::Idle, b"x"),
            (CommandMode::Idle, KeyAction::Forward),
        );
    }

    #[test]
    fn advance_command_mode_paste_is_unbound_swallow() {
        let keys = SessionKeys::default();
        let (mode, _) = keys.advance(CommandMode::Idle, &[0x1d]);
        // A multi-byte paste in command mode matches no subcommand: swallowed,
        // command mode cancelled (the paste is dropped, not forwarded).
        assert_eq!(
            keys.advance(mode, b"detach"),
            (CommandMode::Idle, KeyAction::Swallow),
        );
    }

    #[test]
    fn advance_remapped_leader_uses_negotiated_keys() {
        // A client that remapped leader=ctrl-^, detach=x, forward=ctrl-].
        let mut env = BTreeMap::new();
        env.insert(LEADER_ENV.to_string(), "ctrl-^".to_string());
        env.insert(DETACH_KEY_ENV.to_string(), "x".to_string());
        env.insert(FORWARD_KEY_ENV.to_string(), "ctrl-]".to_string());
        let keys = SessionKeys::from_env(&env);

        // The old default leader (ctrl-]) no longer enters command mode.
        assert_eq!(
            keys.advance(CommandMode::Idle, &[0x1d]),
            (CommandMode::Idle, KeyAction::Forward),
        );
        // The remapped leader (ctrl-^, 0x1e) does.
        assert_eq!(
            keys.advance(CommandMode::Idle, &[0x1e]),
            (CommandMode::AwaitingSubcommand, KeyAction::EnterCommandMode),
        );
        // The remapped detach key (x) detaches.
        assert_eq!(
            keys.advance(CommandMode::AwaitingSubcommand, b"x"),
            (CommandMode::Idle, KeyAction::Detach),
        );
        // The remapped forward key (ctrl-]) forwards.
        assert_eq!(
            keys.advance(CommandMode::AwaitingSubcommand, &[0x1d]),
            (CommandMode::Idle, KeyAction::ForwardLeader),
        );
    }
}
