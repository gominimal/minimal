//! The DEC private-mode vocabulary a session teardown speaks.
//!
//! A session hands the outer terminal to a program that may switch it into
//! modes a shell does not expect — mouse reporting, bracketed paste, the
//! alternate screen — and something has to put it back when that program
//! goes away. Two places do: `minimald` computes a *narrow* set per session
//! from its own screen model (it knows which modes are actually set), and the
//! `min` client keeps a blind fallback for the case where the daemon's bytes
//! never reach the tty because the transport broke.
//!
//! Both need the same escape sequences, and a sequence that drifted between
//! them would leave exactly one of the two paths wrong. So the byte literals
//! live here once, named for what they do, and neither call site spells one
//! out itself.
//!
//! Every constant is a *reset*: the terminal ends in the state a shell
//! expects. There is deliberately no constant here that turns a mode on.

/// X10 mouse reporting (press only) off.
pub const MOUSE_X10_OFF: &str = "\x1b[?9l";

/// Normal mouse tracking (press and release) off.
pub const MOUSE_PRESS_RELEASE_OFF: &str = "\x1b[?1000l";

/// Button-event mouse tracking (motion while a button is down) off.
pub const MOUSE_BUTTON_MOTION_OFF: &str = "\x1b[?1002l";

/// Any-event mouse tracking (motion whether or not a button is down) off.
pub const MOUSE_ANY_MOTION_OFF: &str = "\x1b[?1003l";

/// UTF-8 mouse coordinate encoding off.
pub const MOUSE_ENCODING_UTF8_OFF: &str = "\x1b[?1005l";

/// SGR mouse coordinate encoding off.
pub const MOUSE_ENCODING_SGR_OFF: &str = "\x1b[?1006l";

/// urxvt mouse coordinate encoding off.
pub const MOUSE_ENCODING_URXVT_OFF: &str = "\x1b[?1015l";

/// Bracketed paste off.
pub const BRACKETED_PASTE_OFF: &str = "\x1b[?2004l";

/// Application cursor keys off — back to the normal cursor-key mode.
pub const APPLICATION_CURSOR_KEYS_OFF: &str = "\x1b[?1l";

/// Application keypad off (`DECKPNM`, the numeric-keypad *reset*).
///
/// Note this is not a DEC private mode: it is the two-byte `ESC >`, the
/// counterpart of `ESC =`.
pub const APPLICATION_KEYPAD_OFF: &str = "\x1b>";

/// Leave the alternate screen (`rmcup`).
///
/// The one sequence in this module that is **not** inert when the terminal
/// was never on the alternate screen: on xterm-family terminals rmcup from
/// the normal buffer still performs a `DECRC`-style cursor restore, which can
/// jump the cursor to a stale saved position. Send it only when the screen is
/// known to be on the alternate buffer, or when the alternative is leaving a
/// terminal stuck there.
pub const LEAVE_ALT_SCREEN: &str = "\x1b[?1049l";

/// Cursor visible again (`DECTCEM` set — the safe direction of this mode).
pub const SHOW_CURSOR: &str = "\x1b[?25h";

/// Reset every drawing attribute: colors, bold, reverse, and the rest.
pub const SGR_RESET: &str = "\x1b[m";

/// Focus in/out reporting off.
pub const FOCUS_REPORTING_OFF: &str = "\x1b[?1004l";
