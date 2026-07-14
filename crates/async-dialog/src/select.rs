//! A single-choice selection prompt.

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::error::{DialogError, Result};
use crate::key::{Key, KeyStream};

/// Hide the cursor while the menu is interactive.
const HIDE_CURSOR: &[u8] = b"\x1b[?25l";
/// Restore the cursor on teardown.
const SHOW_CURSOR: &[u8] = b"\x1b[?25h";
/// Reset all SGR (color / attribute) state.
const RESET_SGR: &[u8] = b"\x1b[0m";
/// Erase from the cursor to the end of the screen.
const CLEAR_DOWN: &[u8] = b"\x1b[0J";
/// Reverse-video, used to highlight the active row.
const REVERSE: &[u8] = b"\x1b[7m";

/// The result of running a [`Select`] prompt.
///
/// A single-choice prompt has exactly two outcomes — a confirmed index or a
/// cancellation — so this enum is exhaustive; callers can `match` it without a
/// wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection {
    /// The user confirmed the item at this index.
    At(usize),
    /// The user dismissed the prompt (`Ctrl-C`, `Ctrl-D`, `q`, `Escape`, or
    /// end of input) without choosing.
    Cancelled,
}

impl Selection {
    /// The chosen index, or `None` if the prompt was cancelled.
    #[must_use]
    pub fn index(self) -> Option<usize> {
        match self {
            Selection::At(i) => Some(i),
            Selection::Cancelled => None,
        }
    }
}

/// A single-choice menu driven over an async terminal.
///
/// Arrow keys (or `j`/`k`, `Ctrl-N`/`Ctrl-P`) move the highlight, `Enter`
/// confirms, and `Ctrl-C`/`Ctrl-D`/`q`/`Escape` cancel. The prompt assumes the
/// backing terminal is in raw mode (keystrokes arrive unbuffered and unechoed),
/// which is the state an SSH/PTY client is already in.
///
/// Each item is expected to occupy a single terminal line. Set [`Self::width`]
/// to have over-long items truncated so they don't wrap and desync the
/// redraw geometry.
#[derive(Debug, Clone, Default)]
#[must_use]
pub struct Select {
    prompt: Option<String>,
    items: Vec<String>,
    default: usize,
    width: Option<usize>,
}

impl Select {
    /// Creates an empty prompt. Add items with [`Self::item`] / [`Self::items`].
    pub fn new() -> Self {
        <Self as Default>::default()
    }

    /// Sets the header line shown above the items.
    pub fn with_prompt(mut self, prompt: impl Into<String>) -> Self {
        self.prompt = Some(prompt.into());
        self
    }

    /// Appends a single selectable item.
    pub fn item(mut self, item: impl Into<String>) -> Self {
        self.items.push(item.into());
        self
    }

    /// Appends a sequence of selectable items.
    pub fn items(mut self, items: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.items.extend(items.into_iter().map(Into::into));
        self
    }

    /// Sets the initially-highlighted index. Clamped to the item range when the
    /// prompt runs, so an out-of-range default lands on the last item.
    pub fn default(mut self, index: usize) -> Self {
        self.default = index;
        self
    }

    /// Sets the terminal width used to truncate over-long item text, keeping
    /// each rendered row to one physical line.
    pub fn width(mut self, cols: usize) -> Self {
        self.width = Some(cols);
        self
    }

    /// Runs the prompt to completion, reading keys from `reader` and drawing to
    /// `writer`.
    ///
    /// The `reader`/`writer` are the two halves of the terminal — for an SSH
    /// channel, that's the channel's read and write halves.
    ///
    /// # Errors
    ///
    /// Returns [`DialogError::NoItems`] if no items were added, or
    /// [`DialogError::Io`] if reading or writing the terminal fails.
    pub async fn interact<R, W>(&self, reader: R, mut writer: W) -> Result<Selection>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        if self.items.is_empty() {
            return Err(DialogError::NoItems);
        }

        let mut selected = self.default.min(self.items.len() - 1);
        let mut keys = KeyStream::new(reader);

        let mut opening = Vec::from(HIDE_CURSOR);
        self.render_into(&mut opening, selected, false);
        writer.write_all(&opening).await?;
        writer.flush().await?;

        let outcome = loop {
            let Some(key) = keys.next().await? else {
                break Selection::Cancelled; // EOF
            };
            match key {
                Key::Up | Key::Char('k') => selected = self.step_back(selected),
                Key::Down | Key::Char('j') => selected = self.step_forward(selected),
                Key::Enter => break Selection::At(selected),
                Key::CtrlC | Key::CtrlD | Key::Escape | Key::Char('q') => {
                    break Selection::Cancelled;
                }
                // Ignore everything else without repainting.
                _ => continue,
            }

            let mut frame = Vec::new();
            self.render_into(&mut frame, selected, true);
            writer.write_all(&frame).await?;
            writer.flush().await?;
        };

        let mut closing = Vec::new();
        self.move_to_top(&mut closing);
        closing.extend_from_slice(CLEAR_DOWN);
        closing.extend_from_slice(RESET_SGR);
        closing.extend_from_slice(SHOW_CURSOR);
        writer.write_all(&closing).await?;
        writer.flush().await?;

        Ok(outcome)
    }

    /// Total number of terminal lines the menu occupies.
    fn height(&self) -> usize {
        usize::from(self.prompt.is_some()) + self.items.len()
    }

    /// Emits the escape sequence that moves the cursor from the last drawn row
    /// back to column 1 of the menu's first row.
    fn move_to_top(&self, out: &mut Vec<u8>) {
        let up = self.height() - 1;
        if up > 0 {
            out.extend_from_slice(format!("\x1b[{up}A").as_bytes());
        }
        out.push(b'\r');
    }

    /// Truncates `text` to fit the configured width (leaving room for the
    /// 2-column row prefix), or returns it unchanged when no width is set.
    fn fit<'a>(&self, text: &'a str) -> std::borrow::Cow<'a, str> {
        match self.width {
            Some(cols) => {
                std::borrow::Cow::Owned(text.chars().take(cols.saturating_sub(2)).collect())
            }
            None => std::borrow::Cow::Borrowed(text),
        }
    }

    /// Renders the full menu into `out`. When `redraw` is set, the cursor is
    /// first walked back up to the menu's top and the region cleared, so a
    /// repaint lands exactly over the previous frame.
    fn render_into(&self, out: &mut Vec<u8>, selected: usize, redraw: bool) {
        if redraw {
            self.move_to_top(out);
        } else {
            out.push(b'\r');
        }
        out.extend_from_slice(CLEAR_DOWN);

        if let Some(prompt) = &self.prompt {
            out.extend_from_slice(RESET_SGR);
            out.extend_from_slice(prompt.as_bytes());
            out.extend_from_slice(b"\r\n");
        }

        let last = self.items.len() - 1;
        for (i, item) in self.items.iter().enumerate() {
            let text = self.fit(item);
            if i == selected {
                out.extend_from_slice(REVERSE);
                out.extend_from_slice(b"> ");
                out.extend_from_slice(text.as_bytes());
                out.extend_from_slice(RESET_SGR);
            } else {
                out.extend_from_slice(b"  ");
                out.extend_from_slice(text.as_bytes());
            }
            if i != last {
                out.extend_from_slice(b"\r\n");
            }
        }
    }

    /// Highlight index one row up, wrapping to the bottom.
    fn step_back(&self, current: usize) -> usize {
        match current {
            0 => self.items.len() - 1,
            n => n - 1,
        }
    }

    /// Highlight index one row down, wrapping to the top.
    fn step_forward(&self, current: usize) -> usize {
        if current + 1 == self.items.len() {
            0
        } else {
            current + 1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drives a prompt with a canned input byte stream, returning the outcome
    /// and everything written to the terminal.
    async fn run(select: &Select, input: &[u8]) -> (Selection, Vec<u8>) {
        let mut output = Vec::new();
        let outcome = select
            .interact(input, &mut output)
            .await
            .expect("prompt failed");
        (outcome, output)
    }

    fn menu() -> Select {
        Select::new()
            .with_prompt("pick one")
            .items(["alpha", "beta", "gamma"])
    }

    #[tokio::test]
    async fn empty_prompt_is_rejected() {
        let err = Select::new()
            .interact(&b""[..], Vec::new())
            .await
            .unwrap_err();
        assert!(matches!(err, DialogError::NoItems));
    }

    #[tokio::test]
    async fn enter_confirms_the_default() {
        let (outcome, _) = run(&menu(), b"\r").await;
        assert_eq!(outcome, Selection::At(0));
    }

    #[tokio::test]
    async fn arrow_down_then_enter_selects_second() {
        let (outcome, _) = run(&menu(), b"\x1b[B\r").await;
        assert_eq!(outcome, Selection::At(1));
    }

    #[tokio::test]
    async fn vim_keys_navigate() {
        let (outcome, _) = run(&menu(), b"jj\r").await;
        assert_eq!(outcome, Selection::At(2));
    }

    #[tokio::test]
    async fn up_wraps_to_last_item() {
        let (outcome, _) = run(&menu(), b"\x1b[A\r").await;
        assert_eq!(outcome, Selection::At(2));
    }

    #[tokio::test]
    async fn down_wraps_around_to_first() {
        // Three down presses on a three-item menu returns to the top.
        let (outcome, _) = run(&menu(), b"\x1b[B\x1b[B\x1b[B\r").await;
        assert_eq!(outcome, Selection::At(0));
    }

    #[tokio::test]
    async fn ctrl_c_cancels() {
        let (outcome, _) = run(&menu(), b"\x03").await;
        assert_eq!(outcome, Selection::Cancelled);
        assert_eq!(outcome.index(), None);
    }

    #[tokio::test]
    async fn eof_cancels() {
        let (outcome, _) = run(&menu(), b"").await;
        assert_eq!(outcome, Selection::Cancelled);
    }

    #[tokio::test]
    async fn default_is_clamped_into_range() {
        let (outcome, _) = run(&menu().default(99), b"\r").await;
        assert_eq!(outcome, Selection::At(2));
    }

    #[tokio::test]
    async fn restores_cursor_and_clears_on_exit() {
        let (_, output) = run(&menu(), b"\r").await;
        // Cursor hidden on entry, shown on exit; menu cleared at teardown.
        assert!(output.starts_with(HIDE_CURSOR));
        assert!(output.ends_with(SHOW_CURSOR));
        let cleared = output.windows(CLEAR_DOWN.len()).any(|w| w == CLEAR_DOWN);
        assert!(cleared);
    }

    #[tokio::test]
    async fn width_truncates_long_items() {
        let select = Select::new().item("abcdefghij").width(6);
        let (_, output) = run(&select, b"\r").await;
        // Row prefix is 2 cols, so at width 6 only 4 chars of text survive.
        let rendered = String::from_utf8(output).unwrap();
        assert!(rendered.contains("abcd"));
        assert!(!rendered.contains("abcde"));
    }
}
