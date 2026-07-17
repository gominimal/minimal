# AGENTS.md

Orientation for coding agents and contributors working in this repository.
Tool-neutral and canonical: tool-specific instruction files (e.g.
`CLAUDE.md`) include or link this document rather than restating it.

## Orientation

Minimal is a declarative, content-addressed package/build system plus a
session plane for sandboxed development environments. The system is two
cooperating planes — the **build plane** (declarative packages → dependency
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

28 crates. One line each; the long-form map with plane assignments is in
[docs/architecture.md](docs/architecture.md) §3.

| Crate | Role |
|---|---|
| `args` | Types for the argument schema of tasks and sideload parameters. |
| `async-dialog` | Interactive terminal prompts over any async reader/writer (no TTY required). |
| `check` | `minimal check` linting of `minimal.toml`, packages, profiles, and harnesses. |
| `checkouts` | Git checkouts of upstream layer repositories at pinned versions. |
| `common` | Common types and utilities (e.g. `SpecHash`) used across the codebase. |
| `decode` | Evaluates a Nickel config layer into in-memory packages/profiles/stacks. |
| `diagnostics` | App-agnostic machinery for diagnostic support bundles. |
| `graph` | In-memory dependency graph; its `planner` module orders builds. |
| `lcache` | Local cache of built artifacts, keyed by `SpecHash`. |
| `mctx` | Top-level 'minimal context' API tying configuration, decoding, graph, and cache together. |
| `mfile` | Finding and reading the `minimal.toml` file. |
| `minimal` | The `min` session CLI, which pairs with and talks to `minimald`. |
| `minimald` | The session daemon: an SSH server hosting sessions and task/sandbox executions. |
| `minimald-rpc` | Wire contract for `minimald`'s oneshot SSH RPCs. |
| `minvmd` | Host daemon that boots Linux microVMs via libkrun and bridges host UDS to in-VM vsock. |
| `mip` | The Minimal package/build CLI. |
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
| Linux amd64 / arm64 | Full workspace: builds, `cargo test --workspace`, all four binaries. |
| macOS arm64 | Session stack only — see below. |

On macOS, `minimald` does **not** build: its sandbox stack
(`hakoniwa` → `libcgroups` → `procfs`) is Linux-only. Consequences:

- Test scope is `cargo test -p minvmd -p sessions` (clippy: `-p minvmd`).
- `cargo build -p minimal` works, but `cargo test -p minimal` does not — the
  CLI's dev-dependencies pull `minimald` (test support).
- The `min` CLI's macOS coverage is the end-to-end proof
  (`scripts/session-e2e.sh`), run in CI on the self-hosted Apple Silicon
  runner against a real microVM.

This scoping is temporary: CI widens to `--workspace` once the tree is
mac-buildable (see the comments in `.github/workflows/ci-macos.yml`).

## System dependencies

- **Rust**: pinned by [rust-toolchain.toml](rust-toolchain.toml) (rustup picks
  it up automatically; components `rustfmt` and `clippy`).
- **protoc**: required by `crates/remote-proto/build.rs` (prost + tonic).
  Needs proto3 `optional` support; current Debian/Ubuntu `protobuf-compiler`
  qualifies (install `libprotobuf-dev` too — it carries the well-known protos
  and is only a "recommends" of `protobuf-compiler`). The musl cross image
  pins protoc 25.1 in [Cross.toml](Cross.toml) because its base image's apt
  protoc is too old.
- **Linux build deps** (per [README.md](README.md)):
  `build-essential openssl pkg-config libssl-dev git protobuf-compiler`.
- **VM bring-up on Linux** (`just dm3`): a KVM host with durable `kvm` group
  membership, plus `jq` and `cpio`; `cross` (Docker) when no native musl
  toolchain is present (`scripts/build-initramfs.sh` auto-detects).
- **macOS**: Xcode CLT (`codesign`, `otool`, `install_name_tool`); libkrun via
  Homebrew (`brew install slp/krun/libkrun`) for `just dm1`.
- **Docs site**: Node >= 22; `npm ci`, then `npm run docs:build` (VitePress
  over `docs/`).

## justfile recipes

19 recipes (`just --summary`). `.scratch/` is a shared scratchpad; recipes
manage only their own artifacts there (which is why `clean` is scoped —
never `rm -rf .scratch` wholesale).

Build artifacts and prerequisites:

- `artifacts` — materialize/fetch the guest kernel + generic rootfs into `.scratch` (skips when present; `clean` to force refresh).
- `libkrun` — fetch libkrun + libkrunfw into `~/.krun` (Linux; no-op on macOS, which uses Homebrew).
- `initramfs` — cross-compile `minimald` (static musl, `FEATURES` baked in) and pack it as the initramfs `/init`.
- `gvproxy` — fetch the pinned gvproxy switch binary into `.scratch`.
- `minvmd-build` — build debug `minvmd` (codesigns on macOS; exports `LIBKRUN_PREFIX` on Linux).
- `minimald-build` — build a host-native `minimald` with the networking features (for DM2).
- `minimal-cli` — build the `min` CLI (`cargo build -p minimal`; the binary is `target/debug/min`).
- `codesign-minvmd` — release-build `minvmd` and codesign it with the hypervisor entitlement.

VM / daemon lifecycle:

- `min *args` — build `min` + `minimald`, then run `min` with `target/debug` on `PATH` (so auto-spawn finds the sibling daemons by name).
- `env` — print `export` lines wiring the dev-built binaries and guest artifacts into the environment (`eval "$(just env)"`).
- `shell` — subshell with that environment loaded.
- `status` — report the supervised `minvmd` lifecycle state.
- `stop` — stop the supervised `minvmd` (SIGTERM → SIGKILL).

Deployment-model test environments (DM numbers from
`docs/specs/03-spec-networking`):

- `dm1` — macOS host + Linux VM over Hypervisor.framework: full-stack bring-up (clean SKIP on Linux).
- `dm2` — native Linux: host-native `minimald` (no VM) under a dedicated state dir, reached via `min --minimal-dir`.
- `dm2-down` — stop the DM2 host-native `minimald`.
- `dm3` — native Linux + one Linux VM over KVM; `minvmd` binds the CLI socket directly.

Cleanup and checks:

- `clean` — remove only the bring-up artifacts the justfile manages (never all of `.scratch`).
- `test-installer` — run the curl|sh installer's test harness under every available POSIX sh (+ shellcheck when present).

## Footguns

Verified against the current tree; sources in parentheses.

- **Codesign last on macOS.** The hypervisor-entitlement `codesign` must be
  the last thing to touch the `minvmd` binary — any rebuild invalidates it,
  so re-sign after every build (justfile `minvmd-build` / `codesign-minvmd`).
- **`mip update` rewrites `locked_commit`.** It re-resolves the upstream pins
  and edits `minimal.toml` in place (`crates/op/src/project/update.rs`) —
  an easy accidental diff, and it turns pinned cache fetches into new
  resolutions. The fetch scripts warn explicitly: do not run it as part of
  artifact fetching (`scripts/fetch-libkrun.sh`).
- **Initramfs features come from the `FEATURES` env.**
  `scripts/build-initramfs.sh` compiles the guest `minimald` with
  `FEATURES` (empty by default; the justfile passes `networking-proxy`).
  Calling the script directly yields a guest daemon without networking
  features; with a prebuilt `MINIMALD_BIN`, `TARGET`/`FEATURES` are ignored.
- **macOS `--output` must stay under the repo.** On macOS the `minimal` shim
  runs the CLI inside a VM, so `materialize --output` paths outside the repo
  tree are not visible to it (justfile header comments).
- **SIGTTOU wedges foreground boots.** With a TTY on stdin and
  `MINVMD_BOOT_LOG` unset, libkrun's console setup `tcsetattr()`s the
  terminal from a background process group — SIGTTOU stops the whole group
  and the boot dies silently at the timeout. Redirect stdin from `/dev/null`
  or set `MINVMD_BOOT_LOG` (`scripts/bench-minvmd-boot.sh`).
- **Cold VM boots overrun the default READY timeout.** The generic guest
  kernel can spend 40–50 s probing hardware before pid-1 starts, overrunning
  `minvmd`'s 60 s READY default; `just dm3` exports
  `MINVMD_READY_TIMEOUT_SECS=150` — do the same for manual cold boots
  (justfile `dm3`).
- **Leaked VMMs hold the bridge socket.** A VM in `krun_start_enter` ignores
  SIGTERM; a Ctrl-C'd or killed boot can leave a detached `__krun-vmm` (and
  the gvproxy switch) alive, making every subsequent boot fail. Reap with
  SIGKILL: `pkill -9 -f __krun-vmm`, plus stray `minvmd`/`gvproxy`
  (`scripts/bench-minvmd-boot.sh`, the reap step in
  `.github/workflows/ci-macos.yml`, `scripts/reap-vms.sh`).
- **`min` vs `minimal` naming.** The CLI crate is `minimal` but its binary is
  `min` — build with `-p minimal`, run `target/debug/min`. Cargo never
  removes old binary names, so a stale pre-rename `target/debug/minimal` can
  linger; don't invoke or PATH-resolve it. On macOS, `minimal` on `PATH` is
  typically the distribution shim (`~/.minimal/shim/bin/minimal`), distinct
  from anything this repo builds (justfile comments).
- **`min attach -c` is not a general remote shell.** The daemon's exec
  handler accepts only `min run <task>` (and the internal
  `git-receive-pack min://` path); anything else fails the channel. Task
  execs inherit the session's no-net/host-net mode, but an own-IP session's
  task exec currently falls back to host networking — use an interactive
  attach when the session's network identity matters
  (`crates/minimald/src/exec.rs`).

## CI lane map

Canonical docs: [docs/ci-strategy.md](docs/ci-strategy.md) (design and
rationale) and
[docs/internal/release-pipeline.md](docs/internal/release-pipeline.md)
(release/promotion mechanics). The 11 workflows on `main`:

| Workflow | One line |
|---|---|
| `ci` | Repo-wide checks: rustfmt, clippy, cargo-deny, a dogfood build smoke (Minimal building itself), `minimal check`. |
| `ci-linux-native` | Linux-native target lane: workspace tests, root-integration harnesses, DM2 session e2e against a host-native `minimald`. |
| `ci-linux-kvm` | Linux/KVM target lane (hosted x86_64): build-once/test-on-KVM split, minvmd VM harnesses, VM-backed session e2e. |
| `ci-macos` | macOS/HVF target lane: hosted arm64 unit/clippy tier (`minvmd` + `sessions`) plus the hypervisor e2e on the self-hosted Apple Silicon runner. |
| `ci-shell-installer` | POSIX-sh gate for the shell installer and the AppArmor profile installer (shellcheck + harness under sh/dash/macOS sh). |
| `commitlint` | Conventional Commits enforcement on PRs. |
| `nightly-tests` | 06:00 UTC **test tier**: advisory re-checks, session-e2e soak, toolchain/dependency canaries, workflow hygiene; failures file tracking issues. |
| `nightly` | 10:00 UTC **channel cut**: reuses `release.yml` to build/stage, then blesses the `nightly` channel after smoke tests. |
| `release` | Manual build/sign/stage of all shipped artifacts; its verify-ci gate requires the five lane aggregators green on the commit. |
| `promote` | Manual, gated pointer flip of the `stable`/`unstable` channels to a staged version. |
| `prune-releases` | Scheduled housekeeping: deletes aged auto-cut `release-<sha>` GitHub Releases (never tagged `vX.Y.Z` releases). |

The required-check vocabulary is the **five aggregators** — `ci-success`,
`ci-linux-native-success`, `ci-linux-kvm-success`, `ci-macos-success`,
`ci-shell-installer-success` — each green when its lane's jobs succeeded or
were path-skipped. The two nightlies are distinct on purpose: `nightly-tests`
proves, `nightly` ships.

## Conventions and hard rules

- **Never commit to `main`.** Branch first, with a `feat/`, `fix/`, `docs/`,
  `chore/`, or `refactor/` prefix.
- **Conventional Commits**, enforced by commitlint:
  [docs/commit-conventions.md](docs/commit-conventions.md).
- **Rust standards**:
  [docs/rust-coding-standards.md](docs/rust-coding-standards.md).
- **`.github/workflows/` is frozen** and CODEOWNER-gated — do not edit it.
  Extend CI coverage through convention-discovered tests, `scripts/`, and the
  `justfile`, per the test-extension contract in
  [CONTRIBUTING.md](CONTRIBUTING.md) and the design in
  [docs/ci-strategy.md](docs/ci-strategy.md).

### Pre-PR verification

The canonical command block lives in
[CONTRIBUTING.md](CONTRIBUTING.md#building-and-testing) ("Before opening a
PR"). Platform notes for agents:

- **Linux** — run the CONTRIBUTING.md block as-is. Agents iterating on a
  working tree may prefer the auto-fixing clippy variant:
  `cargo clippy --allow-dirty --fix --all-targets -- -D warnings`.
- **macOS** — the workspace does not fully build (see
  [Platform matrix](#platform-matrix)); use the scoped equivalents:
  `cargo fmt`, `cargo test -p minvmd -p sessions`, and
  `cargo clippy -p minvmd --all-targets -- -D warnings`.
