//! Interactive terminal prompts over any async reader/writer.
//!
//! Unlike terminal-prompt libraries built on [`console`]/[`dialoguer`], nothing
//! here needs a file descriptor or a real TTY: a prompt drives an arbitrary
//! [`AsyncRead`](tokio::io::AsyncRead) + [`AsyncWrite`](tokio::io::AsyncWrite)
//! pair. That makes it usable over transports that have no backing `fd` — the
//! motivating case being an SSH channel (e.g. a `russh` channel split into its
//! read and write halves).
//!
//! The backing terminal is assumed to be in **raw mode**: keystrokes arrive as
//! raw bytes (arrows as escape sequences), and the prompt owns all rendering via
//! ANSI escape codes. For an SSH/PTY session the client has already put the
//! terminal into that state, so no local `termios` handling is required.
//!
//! # Example
//!
//! ```no_run
//! use async_dialog::{Select, Selection};
//!
//! # async fn demo(
//! #     reader: impl tokio::io::AsyncRead + Unpin,
//! #     writer: impl tokio::io::AsyncWrite + Unpin,
//! # ) {
//! let choice = Select::new()
//!     .with_prompt("How do you want to proceed?")
//!     .items(["Detach", "Terminate"])
//!     .interact(reader, writer)
//!     .await
//!     .unwrap();
//!
//! match choice {
//!     Selection::At(0) => { /* detach */ }
//!     Selection::At(_) => { /* terminate */ }
//!     Selection::Cancelled => { /* left as-is */ }
//! }
//! # }
//! ```

mod error;
mod key;
mod select;

pub use error::{DialogError, Result};
pub use key::{Key, KeyStream};
pub use select::{Select, Selection};
