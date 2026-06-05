# 0001 — Rust error-handling strategy

- Status: Accepted
- Date: 2026-06-02
- Deciders: Evan, Tom DNetto, Norrie Taylor
- Refs: [#352](https://github.com/gominimal/minimal/issues/352)

## Context

New Rust crates need a consistent error-handling convention. The prior pattern
hand-writes `Display`, `From`, and `std::error::Error` impls for every error
enum — high boilerplate, easy to drift across crates. Constraint: user-facing
errors must stay actionable, not just structurally tidy.

## Decision

Two layers, chosen by the role of the code.

### Library crates — structured errors via `thiserror`

- `#[derive(Debug, thiserror::Error)]` on error enums.
- `#[error("...")]` generates `Display`; `#[from]` generates `From`. This
  removes the manual `Display` / `From` / `Error::source` impls.
- Keep `#[non_exhaustive]` on public error enums.

Before:

```rust
/// Errors produced while composing a [`Composable`] into a [`Composer`].
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    Var { source: crate::vars::Error },
    Patch { source: crate::patches::Error },
    LifecycleHook { source: crate::lifecyclehook::Error },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Var { source } => write!(f, "variable contribution failed: {source}"),
            Self::Patch { source } => write!(f, "patch contribution failed: {source}"),
            Self::LifecycleHook { source } => write!(f, "lifecycle hook contribution failed: {source}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Var { source } => Some(source),
            Self::Patch { source } => Some(source),
            Self::LifecycleHook { source } => Some(source),
        }
    }
}

impl From<crate::vars::Error> for Error {
    fn from(source: crate::vars::Error) -> Self { Self::Var { source } }
}
// ... one From impl per variant
```

After:

```rust
/// Errors produced while composing a [`Composable`] into a [`Composer`].
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("variable contribution failed: {source}")]
    Var {
        #[from]
        source: crate::vars::Error,
    },
    #[error("patch contribution failed: {source}")]
    Patch {
        #[from]
        source: crate::patches::Error,
    },
    #[error("lifecycle hook contribution failed: {source}")]
    LifecycleHook {
        #[from]
        source: crate::lifecyclehook::Error,
    },
}
```

### Application / binary code — opaque propagation via `anyhow`

Use `anyhow` where the specific error type does not matter and errors are only
propagated upward. This is the common case in application (non-library) code.

### User-facing CLIs — `color_eyre` instead of `anyhow`

For CLIs that surface errors to a human, use `color_eyre` for better-formatted
error reports. `eyre` is a fork of `anyhow` and fills the same
opaque-propagation role, so it is a drop-in substitute at the application
boundary.

### Rationale

`thiserror` (library, structured) and `anyhow` / `eyre` (application, opaque)
solve different problems and compose — they are complementary, not
alternatives. `thiserror` does not compromise actionable messages: it only
removes the `Display` / `From` boilerplate; the message strings remain fully
under our control.

## Consequences

- New crates adopt this convention from the start.
- No retrofit mandate for existing crates. Migration of existing hand-rolled
  error enums is out of scope for this ADR unless raised separately.
- Adds `thiserror` (library deps) and `anyhow` / `color_eyre` (binary deps) to
  the dependency set.

## Sign-off & Rationale Summary

This decision was reached by team consensus (Evan, Tom DNetto, Norrie Taylor)
during an engineering discussion in June 2026. The two-layer approach —
`thiserror` for library crates, `anyhow`/`color_eyre` for application crates —
was selected because it separates structural error contracts (library boundaries)
from opaque propagation (application plumbing). All three deciders confirmed that
the approach eliminates boilerplate without sacrificing the ability to craft
actionable user-facing messages, and that it aligns with the Rust community's
widely-adopted conventions for this problem. No dissenting views were recorded.
