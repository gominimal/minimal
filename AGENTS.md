# AGENTS.md

Orientation for coding agents and contributors working in this repository.
Tool-neutral and canonical: tool-specific instruction files (e.g.
`CLAUDE.md`) include or link this document rather than restating it.

## Orientation

Minimal is a declarative, content-addressed package/build system plus a
session plane for sandboxed development environments. The system is two
cooperating planes: the **build plane** (declarative packages → dependency
graph → sandboxed builds → content-addressed cache) and the **session plane**
(long-lived isolated dev environments, natively on Linux or inside a libkrun
microVM). Start with [docs/architecture.md](docs/architecture.md).

Four binaries come out of this workspace:

| Binary | Role | Reference |
|---|---|---|
| `min` | Session CLI (built from the `minimal` crate; its `[[bin]]` target is `min`) | [docs/reference/cli-min.md](docs/reference/cli-min.md) |
| `mip` | Package/build CLI | [docs/reference/cli-mip.md](docs/reference/cli-mip.md) |
| `minimald` | Session daemon: SSH server hosting sessions and task/sandbox executions | [docs/reference/cli-minimald.md](docs/reference/cli-minimald.md) |
| `minvmd` | MicroVM host daemon: boots Linux guests via libkrun, bridges host UDS to in-VM vsock | [docs/reference/cli-minvmd.md](docs/reference/cli-minvmd.md) |

The CLI reference overview is [docs/reference/cli.md](docs/reference/cli.md).

## Crate map

31 crates. One line each; the long-form map with plane assignments is in
[docs/architecture.md](docs/architecture.md) §3.

| Crate | Role |
|---|---|
| `args` | Types for the argument schema of tasks and sideload parameters. |
| `async-dialog` | Interactive terminal prompts over any async reader/writer (no TTY required). |
| `check` | `mip check` linting of `minimal.toml`, packages, profiles, and stacks. |
| `checkouts` | Git checkouts of upstream layer repositories at pinned versions. |
| `common` | Common types and utilities (e.g. `SpecHash`) used across the codebase. |
| `decode` | Evaluates a Nickel config layer into in-memory packages/profiles/stacks. |
| `diagnostics` | App-agnostic machinery for diagnostic support bundles. |
| `graph` | In-memory dependency graph; its `planner` module orders builds. |
| `lcache` | Local cache of built artifacts, keyed by `SpecHash`. |
| `mctx` | Top-level 'minimal context' API tying configuration, decoding, graph, and cache together. |
| `mfile` | Finding and reading the `minimal.toml` file. |
| `minimal` | The `min` session CLI, which pairs with and talks to `minimald`. |
| `minimal-client` | SSH client transport to `minimald` over the UDS bridge, shared by `min` and the TUI. |
| `minimal-tui` | `min dash`: the session-manager TUI (ratatui/crossterm, Elm-style loop). |
| `minimald` | The session daemon: an SSH server hosting sessions and task/sandbox executions. |
| `minimald-rpc` | Wire contract for `minimald`'s oneshot SSH RPCs. |
| `minvmd` | Host daemon that boots Linux microVMs via libkrun and bridges host UDS to in-VM vsock. |
| `mip` | The Minimal package/build CLI. |
| `mlog` | JSON file-log layer both `minimald` and `minvmd` write through; one definition of the on-disk log format. |
| `op` | Complex operations over the graph and packages (builds, cache object construction). |
| `orchestrator` | Runtime orchestration of builds behind a pluggable `Backend`. |
| `ot` | Operation tracking for progress rendering (render-agnostic core + drivers). |
| `paths` | Realm-tagged path types distinguishing host, sandbox, and daemon filesystems. |
| `rcache` | Remote cache: fetch/upload build artifacts over the network. |
| `remote-client` | Client for the Remote Execution Service, driving remote builds against the graph. |
| `remote-proto` | Protobuf / wire types for the Remote Execution Service (RES). |
| `sandbox2` | Low-level sandbox implementation (Linux user + mount namespaces). |
| `sessions` | Session primitives: lifecycle hooks, loadouts, and the composition pipeline. |
| `stdlib` | The embedded Minimal standard library. |
| `switch` | gvproxy-switch primitives: subnet arithmetic, MAC derivation, vsock constants, config rendering. |
| `version` | Shared build-time version identity for `min`, `mip`, `minimald`, and `minvmd`. |

## Platform matrix

| Platform | What you can build and test |
|---|---|
| Linux amd64 / arm64 | Full workspace natively: `just ci` builds, lints, and tests everything; all four binaries. |
| macOS arm64 | Session stack natively (`just ci`); every Linux-only crate via `just test-cross`. |

**Build and test only through `just`.** The recipes carry the per-OS scoping,
the pinned flags, and the ordering constraints (notably the macOS codesign);
a hand-rolled `cargo` invocation silently drops them. If something has no
recipe, add one — the justfile is where local build knowledge lives.

`minimald` does not build **natively** on macOS: its sandbox stack
(`hakoniwa` → `libcgroups` → `procfs`) is Linux-only. That is a native-host
limit, not a coverage gap. Consequences:

- `just test`, `just clippy`, and `just fix` scope themselves: on macOS they
  resolve to `-p minvmd -p sessions` automatically (the justfile's `scope`
  variable), on Linux to `--workspace`.
- `just test-cross` covers the Linux-only crates — `minimald` and the `min`
  CLI's test targets included — by cross-compiling to musl in Docker
  (`--workspace --exclude minvmd`). It is the macOS answer for anything the
  darwin scope skips. The first run compiles under emulation and can take an
  hour+.
- The `min` CLI's macOS coverage is also proved end-to-end (`scripts/session-e2e.sh`,
  driven by `just e2e`), run in CI on the self-hosted Apple Silicon runner
  against a real microVM.

The native scoping is temporary: CI widens to `--workspace` once the tree is
mac-buildable (see the comments in `.github/workflows/ci-macos.yml`).

## System dependencies

- **Rust**: pinned by [rust-toolchain.toml](rust-toolchain.toml) (rustup picks
  it up automatically; components `rustfmt` and `clippy`).
- **protoc**: required by `crates/remote-proto/build.rs` (prost + tonic).
  Needs proto3 `optional` support; current Debian/Ubuntu `protobuf-compiler`
  qualifies (install `libprotobuf-dev` too; it carries the well-known protos
  and is only a "recommends" of `protobuf-compiler`). The musl cross image
  pins protoc 25.1 in [Cross.toml](Cross.toml) because its base image's apt
  protoc is too old.
- **Linux build deps** (per [README.md](README.md)):
  `build-essential openssl pkg-config libssl-dev git protobuf-compiler`.
- **VM bring-up on Linux** (`just up-kvm`, `just test-vm`, `just e2e`): a KVM
  host with durable `kvm` group membership, plus `jq`, `cpio`, and `zstd`; `cross`
  (Docker) when no native musl toolchain is present
  (`scripts/build-initramfs.sh` auto-detects).
- **macOS**: Xcode CLT (`codesign`, `otool`, `install_name_tool`); libkrun via
  Homebrew (`brew install slp/krun/libkrun`) for the VM recipes (`just up`,
  `just test-vm`, `just e2e`); `jq`, `zstd`, and `cpio` (`brew install jq zstd
  cpio`) for the `artifacts`/`initramfs` scripts those recipes run.
- **python3**, on any host running `just e2e` / `just e2e-native`: the session
  e2e drives its interactive attaches through a real pty
  ([scripts/e2e-attach-pty.py](scripts/e2e-attach-pty.py)), because only a tty
  can answer the session-exit prompt. Stdlib only — no packages to install —
  but the interpreter must be on `PATH`.

## justfile recipes

**Run `just --list` to see every recipe available here, each with its own
description.** Bare `just` prints the same list. That output is generated from
the justfile, so it cannot drift; this section deliberately does not restate it.
`[linux]`/`[macos]` attributes scope recipes per OS, so the list on your host
already shows only what you can run on it.

The justfile is the local twin of the frozen CI workflows:
the CI YAML schedules, the logic lives here and in `scripts/`
(docs/ci-strategy.md §8). `.scratch/` is a shared scratchpad; recipes manage
only their own artifacts there (which is why `clean` is scoped, never
`rm -rf .scratch` wholesale).

## Footguns

Verified against the current tree; sources in parentheses.

- **Codesign last on macOS.** The hypervisor-entitlement `codesign` must be
  the last thing to touch the `minvmd` binary; any later cargo call that
  relinks it drops the signature (EINVAL from `krun_start_enter`), so
  re-sign after every build (justfile `minvmd-build` / `test-vm`).
- **`mip update` rewrites `locked_commit`.** It re-resolves the upstream pins
  and edits `minimal.toml` in place (`crates/op/src/project/update.rs`);
  an easy accidental diff, and it turns pinned cache fetches into new
  resolutions. The fetch scripts warn explicitly: do not run it as part of
  artifact fetching (`scripts/fetch-libkrun.sh`).
- **Initramfs features come from the `FEATURES` env.**
  `scripts/build-initramfs.sh` compiles the guest `minimald` with
  `FEATURES` (empty by default; the justfile passes `networking-proxy`).
  Calling the script directly yields a guest daemon without networking
  features; with a prebuilt `MINIMALD_BIN`, `TARGET`/`FEATURES` are ignored.
- **macOS `--output` must stay under the repo.** On macOS the `minimal` shim
  runs the CLI inside a VM and only syncs the project dir back to the host,
  so `materialize --output` paths outside the repo tree are not visible to
  it (`crates/minvmd/README.md`).
- **SIGTTOU wedges foreground boots.** With a TTY on stdin and
  `MINVMD_BOOT_LOG` unset, libkrun's console setup `tcsetattr()`s the
  terminal from a background process group, so SIGTTOU stops the whole group
  and the boot dies silently at the timeout. Redirect stdin from `/dev/null`
  or set `MINVMD_BOOT_LOG` (`scripts/bench-minvmd-boot.sh`).
- **Cold VM boots overrun the default timeouts.** The generic guest kernel
  can spend 40–70 s probing hardware before pid-1 starts, overrunning the
  60 s READY / 75 s autospawn / 30 s lifecycle defaults; the justfile
  exports 150 s `MINVMD_READY_TIMEOUT_SECS` /
  `MINIMAL_SPAWN_TIMEOUT_SECS` / `MINVMD_LIFECYCLE_BOOT_TIMEOUT_SECS` for
  every recipe; do the same for manual cold boots outside `just`
  (justfile header exports).
- **Leaked VMMs hold the bridge socket.** A VM in `krun_start_enter` ignores
  SIGTERM; a Ctrl-C'd or killed boot can leave a detached `__krun-vmm` (and
  the gvproxy switch) alive, making every subsequent boot fail. Reap with
  `just reap` (`scripts/reap-vms.sh`), which SIGKILLs this checkout's
  stranded `minvmd`/`__krun-vmm`/`gvproxy` processes; matching is scoped
  to this checkout's binaries, so parallel checkouts are safe.
- **`min` vs `minimal` naming.** The CLI crate is `minimal` but its binary is
  `min`; build with `-p minimal`, run `target/debug/min`. Cargo never
  removes old binary names, so a stale pre-rename `target/debug/minimal` can
  linger; don't invoke or PATH-resolve it. On macOS, `minimal` on `PATH` is
  typically the distribution shim (`~/.minimal/shim/bin/minimal`), distinct
  from anything this repo builds (justfile comments,
  `crates/minvmd/README.md`).

## CI lane map

Canonical docs: [docs/ci-strategy.md](docs/ci-strategy.md) (design and
rationale) and
[docs/internal/release-pipeline.md](docs/internal/release-pipeline.md)
(release/promotion mechanics). The 12 workflows on `main`:

| Workflow | One line |
|---|---|
| `ci` | Repo-wide checks: rustfmt, clippy, cargo-deny, a dogfood build smoke (Minimal building itself, reading prebuilt packages via the R2 mirror canary), `mip check`. |
| `ci-linux-native` | Linux-native target lane: workspace tests, root-integration harnesses, session e2e against a host-native `minimald` (no VM). |
| `ci-linux-kvm` | Linux/KVM target lane (hosted x86_64): build-once/test-on-KVM split, minvmd VM harnesses, VM-backed session e2e. |
| `ci-macos` | macOS/HVF target lane: hosted arm64 unit/clippy tier (`minvmd` + `sessions`) plus the hypervisor e2e on the self-hosted Apple Silicon runner. |
| `ci-shell-installer` | POSIX-sh gate for the shell installer and the AppArmor profile installer (shellcheck + harness under sh/dash/macOS sh). |
| `commitlint` | Conventional Commits enforcement on PRs. |
| `nightly-tests` | 06:00 UTC **test tier**: advisory re-checks, session-e2e soak, toolchain/dependency canaries, workflow hygiene; failures file tracking issues. |
| `nightly` | 10:00 UTC **channel cut**: reuses `release.yml` to build/stage, then blesses the `nightly` channel after smoke tests. |
| `release` | Manual build/sign/stage of all shipped artifacts; its verify-ci gate requires the five lane aggregators green on the commit. |
| `promote` | Manual, gated pointer flip of the `stable`/`unstable` channels to a staged version. |
| `docs-hotfix` | Manual: repoint the public docs on `gominimal/webapp` to a chosen `main` sha between releases, without cutting or promoting a binary release. |
| `prune-releases` | Scheduled housekeeping: deletes aged auto-cut `release-<sha>` GitHub Releases (never tagged `vX.Y.Z` releases). |

The required-check vocabulary is the **five aggregators**: `ci-success`,
`ci-linux-native-success`, `ci-linux-kvm-success`, `ci-macos-success`,
`ci-shell-installer-success`. Each is green when its lane's jobs succeeded
or were path-skipped. The two nightlies are distinct on purpose: `nightly-tests`
proves, `nightly` ships.

## Conventions and hard rules

- **Never commit to `main`.** Branch first, with a `feat/`, `fix/`, `docs/`,
  `chore/`, or `refactor/` prefix.
- **Conventional Commits**, enforced by commitlint:
  [docs/commit-conventions.md](docs/commit-conventions.md).
- **Rust standards**:
  [docs/rust-coding-standards.md](docs/rust-coding-standards.md).
- **`.github/workflows/` is frozen** and CODEOWNER-gated. Do not edit it.
  Extend CI coverage through convention-discovered tests, `scripts/`, and the
  `justfile`, per the test-extension contract in
  [CONTRIBUTING.md](CONTRIBUTING.md) and the design in
  [docs/ci-strategy.md](docs/ci-strategy.md).

### Pre-PR verification

The canonical pre-PR command is `just ci`, per
[CONTRIBUTING.md](CONTRIBUTING.md#building-and-testing) ("Before opening a
PR"): it runs the same gates the PR lanes run (fmt, clippy, cargo-deny,
the test suite, doctests; plus `just test-ignored` on Linux), dispatched
for your OS. Platform notes for agents:

- **macOS**: the workspace does not build natively (see
  [Platform matrix](#platform-matrix)); `just ci` runs the darwin-capable
  scope, and `just test-cross` covers the Linux-only crates via `cross`
  (Docker required). A change touching `minimald` or the `min` CLI's tests
  is unverified until `just test-cross` has run.
- **VM/daemon-path changes**: also run `just e2e` (the session proof)
  and/or `just test-vm` (the VM integration harnesses).
- **Tight iteration loops**: `just fix` (fmt → `clippy --fix` → fmt, with
  `--allow-dirty` so it runs mid-edit) then `just test`. Both carry this
  host's scope; neither needs a hand-written `cargo` line.
