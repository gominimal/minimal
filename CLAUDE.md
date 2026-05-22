# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

When iterating on code changes, frequently run `cargo test -p <crate name>` to spot compilation errors, issues,
and test failures.

When you are done making code changes, or you want to check your code for compatibility across other crates,
finish off by running `cargo fmt && cargo test -- --include-ignored` to catch any test failures, as well as
`cargo clippy --allow-dirty --fix --all-targets -- -D warnings` to catch any code smells.


## Architecture Overview

This codebase is for the **minimal package manager** a declarative build system (similar to Nix), developer environment tool,
and task runner.

### High-Level Components

Where possible, different features live in different crates to maximize modularity & parallelize compile time as much as possible.

Notable crates:

1. **decode**: Parses a `Layer` of declarative config, typically a codebase of nickel files, into an in-memory representation.
2. **graph**: In-memory representation of the dependency graph of packages, built by consuming objects from the decode crate.
3. **lcache**: Manages the local cache of built artifacts, content-addressed and keyed using blake3 hashes
4. **mfile**: The `minimal.toml` file is the entry-point of minimal configuration for a project. This crate parses that file.
5. **mctx**: This crate provides a 'minimal context': a higher-level API that tries to bring together all the main features into a simple API
6. **op**: Complex operations that work on the graph or packages. If its complicated enough to have its own place/process-name, it probably should live here.
7. **orchestrator**: Layer that owns runtime orchestration of package builds
8. **sandbox2**: Sandboxed build/task execution API using Linux namespaces
9. **minimal**: Entry-point, CLI and execution coordination

### Overall operation

1. Relevant `minimal.toml`/`.minimal/minimal.toml` file is read, scanned down the directory tree to locate if not in cwd
2. Declarative packages are read: The _decode_ crate is invoked to evaluate nickel files into in-memory structures. The `minimal.toml` file
   typically defines an upstream repo it is based on, so this process is done recursively to get the full chain.
3. These decoded structures are loaded into a single in-memory representation, the dependency graph (`graph` crate).
4. From here, the next steps depend on what is being called for by the user/API.

#### Building packages

1. When a set of packages are needed (we call this the "top level"), we compute the transient dependencies (that is, all the packages
runtime dependencies and all those packages runtime dependencies, and so on).
2. Based on that set, we compute an ordered sequence of builds to build each package, such that at the moment of build each
package has all its build/runtime dependencies (and transitive dependencies) satisfied. This is implemented in the `planner` module
of the `graph` crate.
3. This plan is used to setup an impl of `orchestrator::Backend` which will actually do the builds in the correct order, kicking
off further builds as dictated by the plan as soon as dependencies are satisfied.
4. When a package build is complete, the files collected from the build are committed to the local cache. The key for a packages'
files (the 'build artifacts') is a hash of the declaration of that package, including the build steps and all its dependencies, and
all their dependencies, and so on (like derivation hashes in Nix).

#### Executing tasks

Users can define tasks in their `minimal.toml`. When a task is executed, we build a sandbox (`sandbox2` crate) where the rootfs
composes all the files for all the packages (and their transitive runtime dependencies) which are needed, before launching
the task with the project directory mapped into the same path in the sandbox. If a needed package is not available, we build it,
or if it exists in the remote cache, we download it.


### Key Architectural Decisions

**Cache System**:
- **Content-addressed**: Uses Blake3 hash of complete build specification
- **Deterministic**: Same inputs always produce same cache key
- **Persistent**: Located at `~/.cache/minimal/built/` by default
- **Hierarchical**: Organized by hash prefix for filesystem performance

**Sandbox Isolation Strategy**:
- **Linux**: User namespaces + mount namespaces for filesystem isolation
- **File mounting**: Package files hardlinked into a rootfs, which is mounted in the sandbox read-only
- **Input copying**: Source files and local inputs copied to TMPDIR
- **Output staging**: Builds write to `OUTPUT_DIR`, enumerated outputs copied to cache

## Critical Implementation Details

**Spec Hashing**:
- Complete build specification (including transitive dependencies) hashed with Blake3
- Cache keys are deterministic and include all inputs that affect build output
- Local file inputs include file content hash to detect changes

**TMPDIR Management**: 
- Build scripts receive `OUTPUT_DIR` environment variable pointing to staging area
- Only enumerated outputs are copied from staging to cache


## Development Notes

### Cache Inspection
- Cache entries are content-addressed by Blake3 hash of complete build spec
- Use `find ~/.cache/built -name "*pattern*"` to locate specific builds
- Each cache entry contains the complete build output directory tree

## Rust Coding Standards

### Functional over Imperative

- Iterator chains over manual loops. map, filter, collect, try_fold, flat_map instead of for with mutable accumulators. Use for only when side effects dominate or control flow makes a chain awkward.
- Combinators on Option/Result. map, and_then, ok_or, unwrap_or_else, map_err — not match that reconstructs the same enum.
- Immutable by default. Only mut when required. Building a Vec by push? Try .collect().
- No index-based iteration. .iter(), .enumerate(), .zip(), .windows(), .chunks() over for i in 0..xs.len().

### Idiomaticity

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

### Error Handling

- Library crates: typed error enum. Variants are distinct failure modes.
- Application crates: anyhow::Result. Attach .context(...) / .with_context(|| ...) at layer boundaries.
- unwrap()/panic! only for broken invariants. unwrap() in tests only; in production use expect("why the invariant holds"). Never for recoverable conditions.
- Never swallow errors. No let _ = result; or .ok() discards without a comment justifying it.
- Preserve the source chain. Wrap, don't replace; errors trace back via source().
- No string-typed errors crossing crate boundaries.
- Validate at the boundary, trust within.

### Async & Concurrency

- No blocking in async context. No std::fs, std::thread::sleep, blocking network, or sync Mutex held across .await — use tokio::fs, tokio::time::sleep, tokio::sync::Mutex.
- Don't reach for Arc<Mutex<T>> reflexively. Plain Arc<T> suffices if T is immutable after construction. Spawned tasks must satisfy Send + 'static — design data flow accordingly.

### Logging

- Use tracing — no println!/eprintln! outside user-facing CLI output. Structured fields and spans, not interpolated strings: tracing::info!(pkg = %name, "building"), not info!("building {name}").

### Conventions

- Every change: cargo clippy --all-targets -- -D warnings, cargo test. Justify any #[allow(...)] with a comment.
- unsafe requires a // SAFETY: comment covering every caller invariant.
- #[must_use] on Result-shaped returns, builders, and anything where silently dropping the value is a bug.
- #[non_exhaustive] on public enums/structs that may grow.
- Private by default. Widen to pub(crate) before pub. Curate the public API via pub use at the crate root — internal module paths shouldn't be part of the public surface.
- Testing: behavior, not implementation; one concept per test; insta for snapshot-shaped output; integration tests under tests/ for cross-crate flows.
- No dead code, commented-out code, or ownerless TODOs.
- Dependencies: prefer std, then crates already in the workspace, then crates listed on https://blessed.rs before reaching elsewhere. Versions are pinned in the workspace Cargo.toml; crate-level Cargo.tomls inherit via workspace = true,
never specifying their own version.
