//! Shared plumbing for rendering `codespan-reporting` diagnostics.

use codespan_reporting::term::termcolor::{ColorChoice, StandardStream, WriteColor};

/// Renders a diagnostic to stderr, letting the caller supply the formatting.
///
/// The `write` closure receives a color-aware stderr writer, which is exactly
/// what an error type's own `report_to` takes. Keeping the closure here means
/// each type's diagnostic layout stays with that type, while the terminal
/// setup lives in one place.
pub fn report_to_stderr(write: impl FnOnce(&mut dyn WriteColor)) {
    write(&mut StandardStream::stderr(ColorChoice::Auto).lock());
}
