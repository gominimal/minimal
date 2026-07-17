# Architecture Decision Records

Records of significant, hard-to-reverse technical decisions: the context, the
decision, and its consequences. An ADR is a point-in-time record — once
accepted it is not edited to say something different; a new ADR supersedes it.

## Conventions

- **Filename**: `NNNN-kebab-title.md`, zero-padded and monotonically
  increasing (`0001-...`, `0002-...`). Existing files are never renamed —
  other documents link to them by path.
- **Statuses**: `proposed` (open for discussion), `accepted` (in force),
  `superseded` (replaced; name the successor ADR).
- **Structure**: title, status/date header, Context, Decision, Consequences.

## Adding an ADR

1. Copy the structure of an existing ADR into the next free
   `NNNN-kebab-title.md`.
2. Open it as `proposed` in a pull request; the discussion happens there.
3. On merge with maintainer agreement, set the status to `accepted`.
4. To change an accepted decision, write a new ADR that supersedes the old
   one, and update the old ADR's status line to `superseded`.

## Index

| ADR | Title | Status |
|---|---|---|
| [0001](0001-rust-error-handling-strategy.md) | Rust error-handling strategy | accepted |
