# Rust Coding Standards

## Functional over Imperative

- Iterator chains over manual loops. map, filter, collect, try_fold, flat_map instead of for with mutable accumulators. Use for only when side effects dominate or control flow makes a chain awkward.
- Combinators on Option/Result. map, and_then, ok_or, unwrap_or_else, map_err — not match that reconstructs the same enum.
- Immutable by default. Only mut when required. Building a Vec by push? Try .collect().
- No index-based iteration. .iter(), .enumerate(), .zip(), .windows(), .chunks() over for i in 0..xs.len().

## Idiomaticity

- Cheapest reference that works. &str over &String, &[T] over &Vec<T>, &Path over &PathBuf, impl AsRef<Path> at boundaries.
- impl IntoIterator<Item = T> for consuming a sequence; impl Iterator<Item = T> for returning one (avoid allocating).
- Make illegal states unrepresentable. Encode invariants in the type system: enums for mutually exclusive states (not bool flags + Options), non-empty collections via Vec1 or (T, Vec<T>), parsed types instead of
validated-then-passed-as-string. If a function can't be called in some state, that state shouldn't typecheck.
- Newtypes for domain values (struct UserId(u64)) over bare primitives. Use the https://crates.io/crates/nutype crate when the type needs trivial invariants enforced (non-empty, range bounds, regex, trimmed, etc.) — it generates the
validating constructor and keeps the inner value unconstructable elsewhere.
- Default only when the default is meaningful.
- Cow<'_, str> for sometimes-owned, sometimes-borrowed values.
- Builder pattern for types with more than a couple of fields or any optional config. Owned style: pub fn with_x(mut self, x: T) -> Self, never &mut self -> &mut Self.
- Cloning discipline. .clone() is fine for Arc/Rc and small Copy-ish types; cloning a String/Vec/HashMap to dodge the borrow checker means restructure or borrow instead.
- Captured-identifier formatting. format!("{path}") over format!("{}", path).
- Display for users, Debug for developers. Don't reuse one for the other.
- Generics / impl Trait over dyn Trait. Reach for dyn only for heterogeneous collections or when monomorphization causes real code bloat.

## Error Handling

- Library crates: typed error enum. Variants are distinct failure modes.
- Application crates: anyhow::Result. Attach .context(...) / .with_context(|| ...) at layer boundaries.
- unwrap()/panic! only for broken invariants. unwrap() in tests only; in production use expect("why the invariant holds"). Never for recoverable conditions.
- Never swallow errors. No let _ = result; or .ok() discards without a comment justifying it.
- Preserve the source chain. Wrap, don't replace; errors trace back via source().
- No string-typed errors crossing crate boundaries.
- Validate at the boundary, trust within.

## Async & Concurrency

- No blocking in async context. No std::fs, std::thread::sleep, blocking network, or sync Mutex held across .await — use tokio::fs, tokio::time::sleep, tokio::sync::Mutex.
- Don't reach for Arc<Mutex<T>> reflexively. Plain Arc<T> suffices if T is immutable after construction. Spawned tasks must satisfy Send + 'static — design data flow accordingly.

## Logging

- Use tracing — no println!/eprintln! outside user-facing CLI output. Structured fields and spans, not interpolated strings: tracing::info!(pkg = %name, "building"), not info!("building {name}").

## Conventions

- Every change: cargo clippy --all-targets -- -D warnings, cargo test. Justify any #[allow(...)] with a comment.
- unsafe requires a // SAFETY: comment covering every caller invariant.
- #[must_use] on Result-shaped returns, builders, and anything where silently dropping the value is a bug.
- #[non_exhaustive] on public enums/structs that may grow.
- Private by default. Widen to pub(crate) before pub. Curate the public API via pub use at the crate root — internal module paths shouldn't be part of the public surface.
- Testing: behavior, not implementation; one concept per test; insta for snapshot-shaped output; integration tests under tests/ for cross-crate flows.
- No dead code, commented-out code, or ownerless TODOs.
- Dependencies: prefer std, then crates already in the workspace, then crates listed on https://blessed.rs before reaching elsewhere. Versions are pinned in the workspace Cargo.toml; crate-level Cargo.tomls inherit via workspace = true,
never specifying their own version.
