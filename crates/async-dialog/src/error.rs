//! Error types for the crate.

/// A specialized [`Result`](std::result::Result) for dialog operations.
pub type Result<T> = std::result::Result<T, DialogError>;

/// The set of failures a prompt can surface.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DialogError {
    /// The underlying reader or writer failed.
    #[error("terminal i/o failed: {0}")]
    Io(#[from] std::io::Error),

    /// A prompt was asked to display an empty set of items. A selection prompt
    /// over zero items has no valid answer, so this is rejected up front rather
    /// than rendering an empty menu.
    #[error("cannot present a selection prompt with no items")]
    NoItems,
}
