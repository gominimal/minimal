//! The host-side ask dialog (NET-045): a small raw-mode Allow/Deny selector
//! drawn on the real terminal while the attach's relay is suspended.
//!
//! The dialog is offered to every interactive attach on a box's row, and the
//! first answer wins: the VM host daemon then dismisses the ask in every
//! other attach. A prompt library that owns its read loop cannot be torn
//! down from outside, so each overtaken dialog would stay on screen, and its
//! suspended relay would hold that session, until someone pressed a key.
//! This selector instead waits on the terminal and on the subscription at
//! once: a dismissal clears the dialog's lines and hands the terminal back,
//! with nothing recorded.
//!
//! The selector is a state machine ([`AskSelector`]) driven by
//! [`run_selector`] over a [`DialogIo`]: the real one ([`TtyDialogIo`]) puts
//! the terminal in raw mode and restores it when dropped, so the termios the
//! relay handed over is back on every exit path (an answer, a dismissal, an
//! error, an unwind). Its reader joins an escape sequence split across
//! reads, so an arrow key arrives whole even when the terminal delivers its
//! bytes one at a time, and a lone Escape is still read as a deny.

use std::io::{IsTerminal as _, Write as _};
use std::os::fd::{AsFd, OwnedFd};

use nix::fcntl::OFlag;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::stat::Mode;
use nix::sys::termios::{SetArg, Termios, cfmakeraw, tcgetattr, tcsetattr};

use crate::attach::AskWatch;

/// The ask dialog's question: the native dialog's own frame
/// (`minimald::session_host::ASK_PROMPT`), so a human, and the e2e's pty
/// driver, meet one dialog wherever the box runs.
pub const ASK_DIALOG_PROMPT: &str = "Allow the publish to the host?";

/// The line under the choices.
const ASK_DIALOG_HELP: &str = "[Enter picks; Esc or Ctrl-C denies]";

/// How long the reader waits for the rest of a split escape sequence. A
/// raw-mode read returns as soon as any byte is queued (`cfmakeraw` clears
/// `ICANON`), so an arrow key's `\x1b[B` can arrive as a lone ESC and then
/// its tail — and the lone ESC is what a denied Escape press looks like.
/// Terminals send one keypress as one burst, so a real Escape press has
/// nothing behind it: this window is what tells the two apart. Terminal
/// programs make the same wait for the same reason (vim's `ttimeoutlen`).
const ESCAPE_BURST_WINDOW_MS: u16 = 100;
/// The most bytes the reader will join into one event while it waits out an
/// escape sequence's tail. A sequence a human's keypress produced is a
/// handful of bytes; one still growing past this is not a key, and the wait
/// stops rather than follow it.
const ESCAPE_BURST_WINDOW_BYTES: usize = 64;

/// How a dialog ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AskDialogEnd {
    /// The human answered here; the answer is recorded through the host
    /// door, and a late one is told how the ask had already ended.
    Answered(minimald_rpc::AskAnswer),
    /// The host took the ask away (another attach answered first, or the
    /// ask was cancelled) before this dialog was answered: its lines are
    /// cleared and nothing is recorded.
    Dismissed,
}

/// One thing the dialog waits for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DialogEvent {
    /// Bytes typed at the terminal: one read's burst, with the tail of an
    /// escape sequence the read split it from joined on when it arrived
    /// inside [`ESCAPE_BURST_WINDOW_MS`].
    Keys(Vec<u8>),
    /// The host dismissed the ask, or the subscription carrying it ended.
    Dismissed,
    /// The terminal's input closed.
    InputClosed,
}

/// The dialog's terminal and its dismissal source, abstracted so the
/// selector's loop is testable without a tty.
pub trait DialogIo {
    /// Block until the next event. When keys and a dismissal are ready
    /// together the keys come first: a human who pressed Enter answered,
    /// and the host says how a late answer ended.
    ///
    /// # Errors
    ///
    /// Reading the terminal or the subscription failed.
    fn next_event(&mut self) -> std::io::Result<DialogEvent>;

    /// Write `bytes` to the terminal.
    ///
    /// # Errors
    ///
    /// Writing the terminal failed.
    fn draw(&mut self, bytes: &[u8]) -> std::io::Result<()>;
}

/// The two choices, the refusal first and highlighted, as the native dialog
/// orders them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Choice {
    #[default]
    Deny,
    Allow,
}

impl Choice {
    const ALL: [Self; 2] = [Self::Deny, Self::Allow];

    fn label(self) -> &'static str {
        match self {
            Self::Deny => "Deny",
            Self::Allow => "Allow",
        }
    }

    fn other(self) -> Self {
        match self {
            Self::Deny => Self::Allow,
            Self::Allow => Self::Deny,
        }
    }

    fn answer(self) -> minimald_rpc::AskAnswer {
        match self {
            Self::Deny => minimald_rpc::AskAnswer::No,
            Self::Allow => minimald_rpc::AskAnswer::Yes,
        }
    }
}

/// The selector's state: which choice is highlighted.
#[derive(Debug, Default)]
pub struct AskSelector {
    highlighted: Choice,
}

impl AskSelector {
    /// Feed the bytes of one terminal read. `Some` is the answer the keys
    /// end the dialog with: a yes only for Enter on Allow; a no for Enter
    /// on Deny, Ctrl-C, Ctrl-D and an Escape that stands alone — the reader
    /// joins a sequence split across reads, so an ESC reaching here alone is
    /// a pressed Escape and not an arrow key's first byte. An arrow key
    /// moves the highlight; anything else is ignored.
    #[must_use]
    pub fn feed(&mut self, keys: &[u8]) -> Option<minimald_rpc::AskAnswer> {
        match keys {
            [] => None,
            [b'\r' | b'\n', ..] => Some(self.highlighted.answer()),
            // Ctrl-C, Ctrl-D, and an Escape with nothing after it.
            [0x03 | 0x04, ..] | [0x1b] => Some(minimald_rpc::AskAnswer::No),
            // An arrow key, CSI or SS3 form: with two choices every
            // direction moves to the other one.
            [0x1b, b'[' | b'O', b'A'..=b'D', rest @ ..] => {
                self.highlighted = self.highlighted.other();
                self.feed(rest)
            }
            [_, rest @ ..] => self.feed(rest),
        }
    }

    /// The dialog's frame: the lead-in, the question, the choices and the
    /// help line, `\r\n`-separated with the cursor left at the end of the
    /// last line.
    fn frame(&self, lead_in: &str) -> String {
        let choices = Choice::ALL.map(|choice| {
            let marker = if choice == self.highlighted { ">" } else { " " };
            format!("{marker} {}", choice.label())
        });
        [
            lead_in.to_string(),
            format!("? {ASK_DIALOG_PROMPT}"),
            choices.join("\r\n"),
            ASK_DIALOG_HELP.to_string(),
        ]
        .join("\r\n")
    }
}

/// Erase a frame of `lines` lines drawn with the cursor at the end of its
/// last line, leaving the cursor at the start of the frame's first line.
fn erase(lines: usize) -> String {
    match lines {
        0 => "\r\x1b[J".to_string(),
        up => format!("\r\x1b[{up}A\x1b[J"),
    }
}

/// The number of line breaks in `frame`: how far up its first line is.
fn breaks(frame: &str) -> usize {
    frame.matches('\n').count()
}

/// Run the selector over `io` until it is answered or dismissed.
///
/// The frame is drawn on a fresh line and redrawn in place on every move.
/// An answer replaces it with the lead-in and the chosen line; a dismissal
/// erases it, lead-in included. A closed input is a no.
///
/// # Errors
///
/// The terminal or the subscription failed; the frame is erased on a
/// best-effort basis first.
pub fn run_selector(io: &mut impl DialogIo, lead_in: &str) -> std::io::Result<AskDialogEnd> {
    let mut selector = AskSelector::default();
    let mut frame = selector.frame(lead_in);
    io.draw(format!("\r\n{frame}").as_bytes())?;
    loop {
        let event = match io.next_event() {
            Ok(event) => event,
            Err(error) => {
                // Already failing: the read error is the one worth
                // reporting, so a failed erase is not.
                let _ = io.draw(erase(breaks(&frame)).as_bytes());
                return Err(error);
            }
        };
        let answer = match event {
            DialogEvent::Dismissed => {
                io.draw(erase(breaks(&frame)).as_bytes())?;
                return Ok(AskDialogEnd::Dismissed);
            }
            DialogEvent::InputClosed => Some(minimald_rpc::AskAnswer::No),
            DialogEvent::Keys(keys) => selector.feed(&keys),
        };
        let next = match answer {
            Some(answer) => {
                let chosen = match answer {
                    minimald_rpc::AskAnswer::Yes => Choice::Allow,
                    _ => Choice::Deny,
                };
                format!("{lead_in}\r\n? {ASK_DIALOG_PROMPT} {}\r\n", chosen.label())
            }
            None => selector.frame(lead_in),
        };
        io.draw(format!("{}{next}", erase(breaks(&frame))).as_bytes())?;
        if let Some(answer) = answer {
            return Ok(AskDialogEnd::Answered(answer));
        }
        frame = next;
    }
}

/// The real dialog terminal: the tty the suspended relay handed back, in
/// raw mode for the dialog's life, and the ask's subscription for its
/// dismissal. Dropping it puts back the termios it found.
pub struct TtyDialogIo<'w, 'a> {
    input: OwnedFd,
    output: std::fs::File,
    saved: Termios,
    watch: &'w mut AskWatch<'a>,
}

impl<'w, 'a> TtyDialogIo<'w, 'a> {
    /// Take `input` (the terminal keys are read from) into raw mode, drawing
    /// on `output`, watching `watch` for the ask's dismissal.
    ///
    /// # Errors
    ///
    /// `input` is not a terminal, or its termios could not be set.
    pub fn new(
        input: OwnedFd,
        output: OwnedFd,
        watch: &'w mut AskWatch<'a>,
    ) -> Result<Self, nix::Error> {
        let saved = tcgetattr(&input)?;
        let mut raw = saved.clone();
        cfmakeraw(&mut raw);
        tcsetattr(&input, SetArg::TCSANOW, &raw)?;
        Ok(Self {
            input,
            output: std::fs::File::from(output),
            saved,
            watch,
        })
    }

    /// The real terminal by crossterm's (and the relay's) rule: stdin when
    /// it is a terminal, `/dev/tty` otherwise; drawn on stderr when that is
    /// a terminal, on the input terminal otherwise. `None` when there is no
    /// terminal at all.
    fn real_fds() -> Option<(OwnedFd, OwnedFd)> {
        let input = if std::io::stdin().is_terminal() {
            std::io::stdin().as_fd().try_clone_to_owned().ok()?
        } else {
            nix::fcntl::open(
                "/dev/tty",
                OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .ok()?
        };
        let output = if std::io::stderr().is_terminal() {
            std::io::stderr().as_fd().try_clone_to_owned().ok()?
        } else {
            input.try_clone().ok()?
        };
        Some((input, output))
    }

    /// Wait out [`ESCAPE_BURST_WINDOW_MS`] for the tail of an escape
    /// sequence a read split. `true` when the terminal has bytes by the
    /// window's end. A dismissal that lands inside the window is left
    /// queued: the keys were read first, and an answer they hold is still
    /// recorded — the same order as the unsplit case.
    fn wait_out_escape_burst(&mut self) -> bool {
        let mut fds = [PollFd::new(self.input.as_fd(), PollFlags::POLLIN)];
        // `u16` converts into the poll timeout as milliseconds, which is
        // what the constant's name carries.
        match poll(&mut fds, ESCAPE_BURST_WINDOW_MS) {
            Ok(_) | Err(nix::Error::EINTR) => {}
            // The window is a grace period, not a promise: a failed poll
            // leaves the bytes read as the event.
            Err(_) => return false,
        }
        fds[0]
            .revents()
            .is_some_and(|r| r.intersects(PollFlags::POLLIN))
    }

    /// Finish a read that ended inside an escape sequence: wait the burst
    /// window for the rest of the key, and return the joined bytes when it
    /// arrives. A tail that never comes leaves the bytes read as the event,
    /// which the selector reads — a lone ESC among them as a deny.
    fn finish_escape_head(&mut self, mut keys: Vec<u8>) -> std::io::Result<DialogEvent> {
        // A key a human pressed is a handful of bytes; anything still
        // growing past this is not one, and the wait stops rather than
        // follow it.
        while keys.len() < ESCAPE_BURST_WINDOW_BYTES && self.wait_out_escape_burst() {
            let mut tail = [0u8; 64];
            match nix::unistd::read(&self.input, &mut tail) {
                // More of the key: join it, and wait again when it is
                // itself still missing a final byte.
                Ok(m) if m > 0 => {
                    keys.extend(keep(&tail, m));
                    if !ends_in_escape_sequence(&keys) {
                        return Ok(DialogEvent::Keys(keys));
                    }
                }
                // A closed input has nothing behind what was read.
                Ok(_) | Err(nix::Error::EIO) => break,
                // The window closed, a signal landed, or a spurious wake:
                // the bytes already read are the honest event.
                Err(nix::Error::EINTR | nix::Error::EAGAIN) => break,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(DialogEvent::Keys(keys))
    }
}

/// The first `n` bytes of `buf`, as a Vec: the part of a raw-mode read the
/// terminal actually filled. The panic-free form of `&buf[..n]`.
fn keep(buf: &[u8], n: usize) -> Vec<u8> {
    buf.iter().take(n).copied().collect()
}

/// Whether a read ended inside an escape sequence: it holds an ESC whose
/// final byte has not arrived. Arrow keys go out as one burst but are not
/// always delivered as one read, so this is where a split key is caught and
/// rejoined — and where a lone ESC is held back long enough to tell it from
/// the same first byte of an arrow key.
fn ends_in_escape_sequence(keys: &[u8]) -> bool {
    // The ESC that matters is the last one: a key before it is already
    // complete.
    let Some(esc) = keys.iter().rposition(|&byte| byte == 0x1b) else {
        return false;
    };
    let mut after = keys.iter().skip(esc + 1);
    match after.next() {
        // A lone ESC: the sequence's head, waiting for the rest.
        None => true,
        // CSI or SS3: collecting while every byte after the introducer is a
        // parameter or intermediate one (0x20..=0x3f). The final byte
        // (0x40..=0x7e) is what ends the sequence.
        Some(b'[' | b'O') => after.all(|byte| matches!(byte, 0x20..=0x3f)),
        // Any other ESC is complete the moment it is read.
        Some(_) => false,
    }
}

impl Drop for TtyDialogIo<'_, '_> {
    fn drop(&mut self) {
        if let Err(error) = tcsetattr(&self.input, SetArg::TCSANOW, &self.saved) {
            tracing::warn!(%error, "the ask dialog could not restore the terminal's termios");
        }
    }
}

impl DialogIo for TtyDialogIo<'_, '_> {
    fn next_event(&mut self) -> std::io::Result<DialogEvent> {
        loop {
            // Lines already read off the socket never wake a poll.
            if self.watch.has_buffered() {
                if self.watch.take_line() {
                    return Ok(DialogEvent::Dismissed);
                }
                continue;
            }
            let (keys_ready, watch_ready) = {
                let ready = PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR;
                let mut fds = [
                    PollFd::new(self.input.as_fd(), PollFlags::POLLIN),
                    PollFd::new(self.watch.as_fd(), PollFlags::POLLIN),
                ];
                match poll(&mut fds, PollTimeout::NONE) {
                    Ok(_) => {}
                    Err(nix::Error::EINTR) => continue,
                    Err(error) => return Err(error.into()),
                }
                let is_ready = |fd: &PollFd<'_>| fd.revents().is_some_and(|r| r.intersects(ready));
                (is_ready(&fds[0]), is_ready(&fds[1]))
            };
            if keys_ready {
                let mut buf = [0u8; 64];
                match nix::unistd::read(&self.input, &mut buf) {
                    Ok(0) => return Ok(DialogEvent::InputClosed),
                    Ok(n) => {
                        let keys = keep(&buf, n);
                        if ends_in_escape_sequence(&keys) {
                            return self.finish_escape_head(keys);
                        }
                        return Ok(DialogEvent::Keys(keys));
                    }
                    Err(nix::Error::EINTR | nix::Error::EAGAIN) => continue,
                    // A pty whose other end closed reads EIO.
                    Err(nix::Error::EIO) => return Ok(DialogEvent::InputClosed),
                    Err(error) => return Err(error.into()),
                }
            }
            if watch_ready && self.watch.take_line() {
                return Ok(DialogEvent::Dismissed);
            }
        }
    }

    fn draw(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.output.write_all(bytes)?;
        self.output.flush()
    }
}

/// The dialog's lead-in, built from the offer's host-row fields alone: the
/// box's name as the host row holds it, the port and the protocol. Control
/// characters are dropped so nothing in a name can drive the terminal.
#[must_use]
pub fn ask_dialog_lead_in(offer: &minimald_rpc::PendingAskOffer) -> String {
    let name: String = offer.name.chars().filter(|c| !c.is_control()).collect();
    format!(
        "{name} asks to publish port {}/{}.",
        offer.port, offer.proto
    )
}

/// Render the ask dialog on the real terminal, in the attach-start termios
/// the suspended relay put back, until it is answered or `watch` sees the
/// ask dismissed. No terminal at all is recorded as no-tty; a terminal that
/// fails mid-dialog is a no.
#[must_use]
pub fn render_ask_dialog(
    offer: &minimald_rpc::PendingAskOffer,
    watch: &mut AskWatch<'_>,
) -> AskDialogEnd {
    let Some((input, output)) = TtyDialogIo::real_fds() else {
        return AskDialogEnd::Answered(minimald_rpc::AskAnswer::NoTty);
    };
    let mut io = match TtyDialogIo::new(input, output, watch) {
        Ok(io) => io,
        Err(error) => {
            tracing::warn!(%error, "the ask dialog could not take the terminal");
            return AskDialogEnd::Answered(minimald_rpc::AskAnswer::NoTty);
        }
    };
    run_selector(&mut io, &ask_dialog_lead_in(offer)).unwrap_or_else(|error| {
        tracing::warn!(%error, "the ask dialog failed; treated as no");
        AskDialogEnd::Answered(minimald_rpc::AskAnswer::No)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use minimald_rpc::AskAnswer;
    use std::collections::VecDeque;
    use std::io::Read as _;

    /// A scripted terminal: events handed out in order, everything drawn
    /// kept.
    struct Scripted {
        events: VecDeque<DialogEvent>,
        screen: Vec<u8>,
    }

    impl Scripted {
        fn new(events: impl IntoIterator<Item = DialogEvent>) -> Self {
            Self {
                events: events.into_iter().collect(),
                screen: Vec::new(),
            }
        }

        fn screen(&self) -> String {
            String::from_utf8_lossy(&self.screen).into_owned()
        }
    }

    impl DialogIo for Scripted {
        fn next_event(&mut self) -> std::io::Result<DialogEvent> {
            self.events
                .pop_front()
                .ok_or_else(|| std::io::Error::other("the script ran out"))
        }

        fn draw(&mut self, bytes: &[u8]) -> std::io::Result<()> {
            self.screen.extend_from_slice(bytes);
            Ok(())
        }
    }

    const DOWN: &[u8] = b"\x1b[B";
    const LEAD_IN: &str = "web asks to publish port 3000/tcp.";

    #[test]
    fn keys_map_to_answers() {
        let answer = |keys: &[u8]| AskSelector::default().feed(keys);
        assert_eq!(
            answer(b"\r"),
            Some(AskAnswer::No),
            "Deny is highlighted first"
        );
        assert_eq!(answer(b"\x1b[B\r"), Some(AskAnswer::Yes));
        assert_eq!(answer(b"\x1bOB\r"), Some(AskAnswer::Yes), "SS3 arrows move");
        assert_eq!(answer(b"\x1b[B\x1b[A\r"), Some(AskAnswer::No));
        assert_eq!(answer(b"\x03"), Some(AskAnswer::No), "Ctrl-C denies");
        assert_eq!(answer(b"\x04"), Some(AskAnswer::No), "Ctrl-D denies");
        assert_eq!(answer(b"\x1b"), Some(AskAnswer::No), "Escape denies");
        assert_eq!(answer(b"\x1b[B"), None, "a move alone answers nothing");
        assert_eq!(answer(b"yx"), None, "other keys are ignored");
    }

    /// A read ends inside an escape sequence when the tail a split delivery
    /// withheld has not arrived, and only then. Complete keys and lone
    /// non-ESC tails never wait.
    #[test]
    fn reads_ending_inside_an_escape_sequence() {
        let ends = |keys: &[u8]| ends_in_escape_sequence(keys);
        assert!(ends(b"\x1b"), "a lone ESC waits for a tail");
        assert!(ends(b"\x1b["), "CSI waits for its final byte");
        assert!(ends(b"\x1bO"), "SS3 waits for its final byte");
        assert!(ends(b"\x1b[1;"), "parameters wait for the final byte");
        assert!(ends(b"a\x1b"), "only the last ESC matters");
        assert!(!ends(b"\x1b[B"), "a complete arrow key waits for nothing");
        assert!(!ends(b"\x1bOB"), "a complete SS3 key waits for nothing");
        assert!(!ends(b""), "an empty read waits for nothing");
        assert!(!ends(b"a"), "a plain key waits for nothing");
        assert!(
            ends(b"\x1b\x1b"),
            "the last ESC is a head, and waits for its tail"
        );
        assert!(
            !ends(b"\x1b\x1b[B"),
            "an earlier ESC does not hold a complete key open"
        );
    }

    #[test]
    fn answered_dialog_leaves_the_chosen_line() {
        let mut io = Scripted::new([
            DialogEvent::Keys(DOWN.to_vec()),
            DialogEvent::Keys(b"\r".to_vec()),
        ]);
        let end = run_selector(&mut io, LEAD_IN).unwrap();
        assert_eq!(end, AskDialogEnd::Answered(AskAnswer::Yes));
        let screen = io.screen();
        assert!(
            screen.contains("> Allow"),
            "the move redrew the highlight: {screen:?}"
        );
        assert!(
            screen.ends_with(&format!(
                "\x1b[J{LEAD_IN}\r\n? {ASK_DIALOG_PROMPT} Allow\r\n"
            )),
            "the frame is replaced by the answer: {screen:?}"
        );
    }

    /// Enter is read before the dismissal behind it: the answer stands,
    /// and the serving loop records it as a late answer.
    #[test]
    fn answer_read_before_a_dismissal_stands() {
        let mut io = Scripted::new([DialogEvent::Keys(b"\r".to_vec()), DialogEvent::Dismissed]);
        assert_eq!(
            run_selector(&mut io, LEAD_IN).unwrap(),
            AskDialogEnd::Answered(AskAnswer::No)
        );
    }

    #[test]
    fn closed_input_is_a_no() {
        let mut io = Scripted::new([DialogEvent::InputClosed]);
        assert_eq!(
            run_selector(&mut io, LEAD_IN).unwrap(),
            AskDialogEnd::Answered(AskAnswer::No)
        );
    }

    #[test]
    fn dismissal_before_an_answer_erases_the_dialog() {
        let mut io = Scripted::new([DialogEvent::Keys(DOWN.to_vec()), DialogEvent::Dismissed]);
        assert_eq!(
            run_selector(&mut io, LEAD_IN).unwrap(),
            AskDialogEnd::Dismissed
        );
        let screen = io.screen();
        // The frame is five lines: lead-in, question, two choices, help.
        assert!(
            screen.ends_with("\r\x1b[4A\x1b[J"),
            "the last thing drawn erases the whole frame: {screen:?}"
        );
    }

    #[test]
    fn failed_read_erases_the_dialog() {
        let mut io = Scripted::new([]);
        assert!(run_selector(&mut io, LEAD_IN).is_err());
        assert!(io.screen().ends_with("\r\x1b[4A\x1b[J"));
    }

    /// A pty pair standing in for the user's terminal: the dialog takes the
    /// slave; the test types into the master and drains what is drawn.
    struct Pty {
        master: std::fs::File,
        slave: OwnedFd,
        screen: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl Pty {
        fn new() -> Self {
            let pty = nix::pty::openpty(None, None).unwrap();
            let master = std::fs::File::from(pty.master);
            let screen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let mut reader = master.try_clone().unwrap();
            let sink = std::sync::Arc::clone(&screen);
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = reader.read(&mut buf)
                    && n > 0
                {
                    sink.lock().unwrap().extend_from_slice(&buf[..n]);
                }
            });
            Self {
                master,
                slave: pty.slave,
                screen,
            }
        }

        fn type_bytes(&self, bytes: &[u8]) {
            (&self.master).write_all(bytes).unwrap();
        }

        fn termios(&self) -> Termios {
            tcgetattr(&self.slave).unwrap()
        }

        /// Run the real dialog on the slave, against `subscription`.
        fn dialog(
            &self,
            ask_id: minimald_rpc::AskId,
            subscription: std::os::unix::net::UnixStream,
        ) -> std::io::Result<AskDialogEnd> {
            let mut subscription = std::io::BufReader::new(subscription);
            let mut held = VecDeque::new();
            let mut watch = AskWatch::new(ask_id, &mut subscription, &mut held);
            let mut io = TtyDialogIo::new(
                self.slave.try_clone().unwrap(),
                self.slave.try_clone().unwrap(),
                &mut watch,
            )
            .unwrap();
            run_selector(&mut io, LEAD_IN)
        }
    }

    fn dismissal(ask_id: minimald_rpc::AskId) -> Vec<u8> {
        let mut line =
            serde_json_lenient::to_string(&minimald_rpc::BoxControlReply::PendingAskDismissed {
                ask_id,
                dismissed: true,
            })
            .unwrap();
        line.push('\n');
        line.into_bytes()
    }

    fn ask_id() -> minimald_rpc::AskId {
        serde_json_lenient::from_str("\"9f1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e\"").unwrap()
    }

    /// The local modes the dialog sets and restores. `PENDIN` is left out:
    /// the kernel raises it by itself when input typed in one mode is still
    /// queued at a mode change.
    fn lflags(t: &Termios) -> nix::sys::termios::LocalFlags {
        t.local_flags - nix::sys::termios::LocalFlags::PENDIN
    }

    /// The real terminal answered: the keys decide, and the termios the
    /// dialog found is back afterwards.
    #[test]
    fn tty_answer_restores_termios() {
        let pty = Pty::new();
        let before = pty.termios();
        let (_host, subscription) = std::os::unix::net::UnixStream::pair().unwrap();
        pty.type_bytes(b"\x1b[B\r");
        let end = pty.dialog(ask_id(), subscription).unwrap();
        assert_eq!(end, AskDialogEnd::Answered(AskAnswer::Yes));
        assert_eq!(lflags(&pty.termios()), lflags(&before), "termios restored");
    }

    /// The host's dismissal arrives with the dialog up and unanswered: the
    /// dialog comes down by itself, erased, with the termios restored.
    #[test]
    fn tty_dismissal_before_answer_tears_down() {
        let pty = Pty::new();
        let before = pty.termios();
        let (mut host, subscription) = std::os::unix::net::UnixStream::pair().unwrap();
        let id = ask_id();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            host.write_all(&dismissal(id)).unwrap();
            host
        });
        let end = pty.dialog(id, subscription).unwrap();
        assert_eq!(end, AskDialogEnd::Dismissed);
        assert_eq!(lflags(&pty.termios()), lflags(&before), "termios restored");
        drop(writer.join());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !String::from_utf8_lossy(&pty.screen.lock().unwrap()).ends_with("\x1b[J") {
            assert!(
                std::time::Instant::now() < deadline,
                "the erase reached the screen"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// An answer and the dismissal are ready together: the answer wins
    /// here, and is recorded so the host can say how the ask already ended.
    #[test]
    fn tty_answer_racing_dismissal_is_kept() {
        let pty = Pty::new();
        let (mut host, subscription) = std::os::unix::net::UnixStream::pair().unwrap();
        let id = ask_id();
        host.write_all(&dismissal(id)).unwrap();
        pty.type_bytes(b"\x1b[B\r");
        // Both are queued before the dialog first polls.
        std::thread::sleep(std::time::Duration::from_millis(50));
        let end = pty.dialog(id, subscription).unwrap();
        assert_eq!(end, AskDialogEnd::Answered(AskAnswer::Yes));
    }

    /// A raw-mode read returns as soon as any byte is queued, so an arrow
    /// key can arrive as a lone ESC and then its tail. The tail is joined
    /// within the burst window: the arrow moves the highlight instead of
    /// being read as a denied Escape.
    #[test]
    fn tty_arrow_key_split_across_reads_still_moves() {
        let pty = std::sync::Arc::new(Pty::new());
        let (_host, subscription) = std::os::unix::net::UnixStream::pair().unwrap();
        let typist = {
            let sh = std::sync::Arc::clone(&pty);
            std::thread::spawn(move || {
                sh.type_bytes(b"\x1b");
                std::thread::sleep(std::time::Duration::from_millis(30));
                sh.type_bytes(b"[B\r");
            })
        };
        let end = pty.dialog(ask_id(), subscription).unwrap();
        assert_eq!(
            end,
            AskDialogEnd::Answered(AskAnswer::Yes),
            "the split arrow reached Allow and Enter answered"
        );
        drop(typist.join());
    }

    /// A lone ESC with nothing behind it is a denied Escape, not an arrow
    /// key's head: the window closes, and the deny stands. The dialog must
    /// take the window rather than answer on the byte alone, so this also
    /// bounds the wait — the answer comes back within a few windows.
    #[test]
    fn tty_lone_escape_denies_after_the_burst_window() {
        let pty = Pty::new();
        let (_host, subscription) = std::os::unix::net::UnixStream::pair().unwrap();
        pty.type_bytes(b"\x1b");
        let start = std::time::Instant::now();
        let end = pty.dialog(ask_id(), subscription).unwrap();
        let took = start.elapsed();
        assert_eq!(end, AskDialogEnd::Answered(AskAnswer::No));
        assert!(
            took >= std::time::Duration::from_millis(u64::from(ESCAPE_BURST_WINDOW_MS)),
            "the window was waited out before the deny: {took:?}"
        );
        assert!(
            took < std::time::Duration::from_millis(10 * u64::from(ESCAPE_BURST_WINDOW_MS)),
            "the deny did not wait a second window: {took:?}"
        );
    }

    /// A dismissal for another ask does not take this dialog down; it is
    /// held for the serving loop.
    #[test]
    fn other_asks_dismissal_is_held() {
        let other: minimald_rpc::AskId =
            serde_json_lenient::from_str("\"0123456789abcdef0123456789abcdef\"").unwrap();
        let (mut host, subscription) = std::os::unix::net::UnixStream::pair().unwrap();
        host.write_all(&dismissal(other)).unwrap();
        host.write_all(&dismissal(ask_id())).unwrap();
        let mut subscription = std::io::BufReader::new(subscription);
        let mut held = VecDeque::new();
        let mut watch = AskWatch::new(ask_id(), &mut subscription, &mut held);
        assert!(
            !watch.take_line(),
            "another ask's dismissal is not this one's"
        );
        assert!(watch.take_line(), "this ask's dismissal ends the dialog");
        assert_eq!(held.len(), 1);
    }
}
