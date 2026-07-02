---
id: spec-installer
title: "feat(installer): POSIX-sh curl|bash fallback installer"
kind: spec
status: planned
tracking-issue:
supersedes:
---

# feat(installer): POSIX-sh curl|bash fallback installer

## Context

`minimal` ships a handful of discrete binaries (`minimal`, `minimald`,
`minvmd`, …) and data files (`rootfs` etc) for macOS and Linux across
`x86_64`/`aarch64`. Users need a way to get those binaries onto a machine without
a pre-existing package manager.

This spec describes **the fallback installer only**: a single POSIX-sh script
served for `curl … | sh`. The intended primary paths are native, platform-specific packages —
Homebrew (`brew`), Debian/Ubuntu (`apt`/`.deb`), Arch (`pacman`/AUR), and
similar — which integrate with system update tooling, signing, and uninstall.

The curl|bash installer exists to cover the gap for platforms and users those
packages do not yet reach, and to bootstrap the others. It must therefore be
maximally portable and make as few assumptions about the host as possible.

Distribution artifacts are published to a public GCS bucket. Mutable pointer
files at the bucket root (`stable`, `unstable`, …) each contain a single version
string. Each version has an immutable, self-contained manifest at
`versions/<VERSION>/components` describing every downloadable component.

## Introduction/Overview

The installer resolves a **target** (default `stable`) to a **version** via a
pointer file, fetches that version's **components manifest**, and for each
component that applies to the host's OS/arch it verifies whether the correct
file is already installed (by hashing the on-disk file) and, if not, downloads,
checksum-verifies, and atomically installs it. Reruns re-download only
components whose hash changed.

The whole script targets POSIX `sh` (not bash) so it runs identically under
`dash`, macOS's frozen bash 3.2, busybox, and zsh-invoked-`sh`. It depends only
on tools present by default on every target: a downloader (`curl` **or**
`wget`), a SHA-256 tool (`sha256sum` **or** `shasum` **or** `openssl`), and
`awk`/`uname`/`mkdir`/`mv`/`chmod`.

## Goals

1. A single `curl … | sh` invocation installs the correct binaries for the
   host OS/arch into user-writable locations with no root and no pre-existing
   package manager.
2. Reruns are cheap: a component whose on-disk file already matches the manifest
   hash is skipped without downloading.
3. Runs identically across macOS (last two releases) and mainstream Linux
   distros from the last two years, using only default-present tooling.
4. A partially-completed or interrupted run never leaves a corrupt or
   half-written binary in place.
5. A malformed manifest, version string, or destination path is rejected before
   it can cause a path traversal or arbitrary-code execution.

## User Stories

- **As a developer on a fresh machine**, I run the documented `curl … | sh` line
  and get working `minimal` binaries on my `PATH`, without installing a package
  manager first.
- **As a returning user**, I re-run the installer after a release and only the
  components that actually changed are downloaded.
- **As a minimal employee**, I pass `unstable` as an argument and get the
  bleeding-edge version through the identical mechanism.

## Demoable Units of Work

### Unit 1 — Environment probing (downloader, hasher, platform)

**R1.1** — The script selects a downloader at runtime: prefer `curl`, else
`wget`, else exit with a clear error. Both wrappers enforce HTTPS and a TLS 1.2
floor and refuse redirect downgrades:

```sh
# curl
curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL "$url" -o "$out"
# wget
wget --https-only --secure-protocol=TLSv1_2 -qO "$out" "$url"
```

**R1.2** — The script selects a SHA-256 implementation at runtime: prefer
`sha256sum`, else `shasum -a 256`, else `openssl dgst -sha256`. Each wrapper
emits the bare lowercase hex digest on stdout (no filename, no leading marker).

**R1.3** — The host platform is derived from `uname -s` (→ `linux`/`darwin`) and
`uname -m`, with arch normalized so the same CPU has one name across platforms:
`amd64|x86_64 → amd64`, `arm64|aarch64 → arm64`. An unrecognized OS or arch
exits with a clear error.

**R1.4** — Tool discovery uses `command -v`, never `which`.

### Unit 2 — Target → version → manifest resolution

**R2.1** — The script takes an optional first argument, the **target**,
defaulting to `stable`. The target is validated against `^[A-Za-z0-9._-]+$`
before use; a value containing any other character exits with an error.

**R2.2** — The script fetches `<BUCKET>/<target>` to obtain a version string.
The result is validated against `^[A-Za-z0-9._-]+$` (command substitution having
already stripped the trailing newline); a malformed value exits with an error.
`<BUCKET>` is hardcoded into the script, but can be overridden with an environment
variable `MINIMAL_OVERRIDE_INSTALLER_BUCKET`.

**R2.3** — The script fetches `<BUCKET>/versions/<VERSION>/components` — the
components manifest — into a temp file. A fetch failure exits with an error.

**R2.4** — The manifest's `# format:` header is read; if it names a format
version the installer does not support, it exits with an actionable error rather
than misparsing.

**Proof artifacts**:

- **Test**: Passing `../evil` (or an empty string) as the target argument exits
  non-zero without performing any fetch.
- **Test**: A manifest whose `# format:` line names an unsupported version exits
  non-zero with a message naming the supported version.

### Unit 3 — Manifest format and field extraction

**R3.1** — The manifest is a flat, line-oriented table: `#`-prefixed comment
lines and blank lines are ignored; every data line is one component variant with
fields separated by runs of whitespace (so columns may be space-padded for
readability). Column order is fixed and documented in the header:

```
# component  os      arch     version  sha256   kind    dest              src
minimald     linux   x86_64   1.4.2    3a7b…    file    bin/minimald      minimald/1.4.2/minimald-linux-x86_64
minimald     darwin  arm64    1.4.2    2c26…    file    bin/minimald      minimald/1.4.2/minimald-darwin-arm64
```

- `component` — logical name (primary key with `os`/`arch`).
- `os`/`arch` — normalized platform (matches R1.3 output).
- `version` — component version (informational; the artifact identity is the
  hash).
- `sha256` — lowercase hex digest of the artifact at `src`.
- `kind` — `file` for a directly-placed file (only kind in v1; the column
  exists so multi-file/archive kinds can be added without a format break).
- `dest` — install destination as `<prefix-token>/<subpath>` (see R4).
- `src` — download path **relative to the bucket root** (not to `stable/`).

**R3.2** — No field ever contains whitespace; this invariant is what makes
`awk` field-splitting safe. Extraction uses exact field equality, never
substring `grep`:

```sh
# components that apply to this platform
awk -v o="$os" -v a="$arch" \
  '!/^#/ && NF && $2==o && $3==a {print $1}' "$manifest"
# a single field for one component variant (e.g. $6 = dest)
awk -v c="$comp" -v o="$os" -v a="$arch" \
  '!/^#/ && NF && $1==c && $2==o && $3==a {print $6}' "$manifest"
```

**R3.3** — Parsing uses `awk` (which splits on whitespace runs), never
`cut -d' '` (which treats each space as a delimiter and breaks on padding).

**Proof artifacts**:

- **Test**: Against a fixture manifest with padded columns and comment lines, the
  platform-filter query returns exactly the expected component names for a given
  `os`/`arch`, and the per-field query returns the expected `dest`/`src`/`sha256`.

### Unit 4 — Destination prefix resolution and path safety

**R4.1** — The `dest` prefix token is mapped to an absolute directory through a
fixed `case` — **never** shell-expanded or `eval`ed from the manifest string:

| token   | resolves to                                             |
|---------|---------------------------------------------------------|
| `bin`   | `${MINIMAL_BIN:-$HOME/.local/bin}`                      |
| `data`  | `${XDG_DATA_HOME:-$HOME/.local/share}/minimal`          |
| `state` | `${XDG_STATE_HOME:-$HOME/.local/state}/minimal`         |
| `cache` | `${XDG_CACHE_HOME:-$HOME/.cache}/minimal`               |

An unknown token exits with an error. (Note the correct XDG variable names —
`XDG_DATA_HOME`/`XDG_STATE_HOME`/`XDG_CACHE_HOME` — and that `~/.local/bin` has
no XDG variable, hence the `MINIMAL_BIN` override.)

**R4.2** — The `dest` subpath is rejected before use if it is absolute (`/…`) or
contains a `..` component, preventing a manifest from writing outside the
resolved prefix.

**R4.3** — The resolved destination directory is created with `mkdir -p` before
any write.

**Proof artifacts**:

- **Test**: A `dest` of `../../etc/x` or `/etc/x` exits non-zero and writes
  nothing.
- **Test**: With `XDG_DATA_HOME` set to a temp dir, a `data`-prefixed component
  resolves under that temp dir; with it unset, it resolves under
  `$HOME/.local/share/minimal`.

### Unit 5 — Skip-check, download, verify, atomic install

**R5.1** — For each applicable component, if the resolved destination file
already exists **and** its on-disk SHA-256 equals the manifest `sha256`, the
component is skipped with no download. The on-disk file — not any recorded
state — is the source of truth for "already installed".

**R5.2** — Otherwise the artifact is downloaded from `<BUCKET>/<src>` to a
temp sibling **in the destination directory** (`<dest>.tmp.$$`), so the final
rename is same-filesystem and atomic.

**R5.3** — The downloaded temp file's SHA-256 is compared to the manifest
`sha256`; on mismatch the temp file is removed and the run exits non-zero
naming the component. The partially-written file is never installed.

**R5.4** — For files installed to a prefix token of `bin`, the temp file is
`chmod +x`ed **before** the rename, so it appears already-executable at its
final path. The install is completed with `mv -f <dest>.tmp.$$ <dest>`
(atomic within one filesystem).

```sh
target="$(resolve_prefix "$prefix")/$subpath"
if [ -f "$target" ] && [ "$(sha256 "$target")" = "$want" ]; then
  continue                                   # up to date, no download
fi
mkdir -p "$(dirname "$target")"
fetch "$BUCKET/$src" "$target.tmp.$$"
got=$(sha256 "$target.tmp.$$")
[ "$got" = "$want" ] || { rm -f "$target.tmp.$$"; die "checksum mismatch: $comp"; }
[ "$kind" = bin ] && chmod +x "$target.tmp.$$"
mv -f "$target.tmp.$$" "$target"
```

**Proof artifacts**:

- **Test**: Running twice against the same fixture manifest downloads on the
  first pass and performs zero downloads on the second (assert via a
  download-count stub).
- **Test**: A manifest whose `sha256` disagrees with the served artifact exits
  non-zero and leaves no file (and no `.tmp.` file) at the destination.

### Unit 6 — Install record and PATH advisory

**R6.1** — After a successful run the installer writes a record of what it
installed to `<state>/installed` — the resolved `(component, dest, sha256)`
rows for this platform. The record enables future uninstall and surfaces
prefix drift if `XDG_*` variables change between runs.

**R6.2** — If the resolved `bin` directory is not on `$PATH`, the installer
prints an advisory telling the user to add it — it does **not** silently edit
any shell rc file.

**Proof artifacts**:

- **Test**: After a successful install into temp prefixes, `<state>/installed`
  exists and lists the installed components with their destinations and hashes.
- **Test**: With the `bin` prefix absent from `PATH`, the advisory is printed;
  with it present, it is not.

## Non-Goals

- **Uninstall.** The install record (R6.1) is written to enable it later; the
  uninstall command itself is out of scope.
- **Multi-file / archive components.** v1 handles `kind = file` single files only.
  The `kind` column reserves room for archive kinds without a format break.
- **Signing/verification beyond TLS + SHA-256.** See Security Considerations for
  the future `minisign` path.
- **Windows.** POSIX-sh targets macOS and Linux only.

## Design Considerations

**Why POSIX `sh`, not bash.** macOS ships bash 3.2 (frozen over GPLv3) and
Debian/Ubuntu's `/bin/sh` is `dash`; users are told to pipe to either `bash` or
`sh`. Targeting strict POSIX `sh` — single `=` in `[ ]`, `printf` over
`echo -e`, `case` over `[[ =~ ]]`, no arrays — is the only way one script runs
across all of them. Correctness is enforced in CI (see Verification).

**Why a flat table, not JSON/YAML.** The installer must parse the manifest with
tooling that is always present. `jq` is not installed by default on macOS or
minimal Linux images, so a JSON manifest creates a bootstrap problem;
grep/sed JSON parsing is fragile. A whitespace-delimited table is what `awk`
parses natively with zero dependencies. YAML has no portable CLI parser at all.

**Why not a `source`-able manifest.** Sourcing a fetched `KEY=value` file is
remote code execution — anyone who can write the bucket runs code as the
installer. The manifest is strictly *data*; prefix tokens are mapped through a
`case`, never expanded.

**On-disk hash as the skip oracle.** Comparing the manifest hash against the
actual destination file (R5.1) is more robust than trusting a recorded state
file, which drifts when a user deletes a binary or a prior run dies mid-install.
A local SHA-256 is far cheaper than the download it avoids.

**Atomic install.** Downloading to a `.tmp` sibling in the destination directory
and `mv`-ing into place makes the swap a same-filesystem atomic rename, so an
interrupted run never leaves a truncated, executable binary. `chmod +x` precedes
the rename so executability appears atomically.

**Source vs destination are distinct columns.** `src` (bucket download path) and
`dest` (on-disk install location) are independent; conflating them into one
field loses information. `src` is bucket-root-relative to keep versioned
artifacts addressable independent of the `stable`/`unstable` pointer.

## Repository Standards

The installer is a standalone shell script (not a Rust crate) plus a small
POSIX-sh test harness. Conventional Commits scope is `installer`. No
architecture record; design rationale is captured above.

## Open Questions

- **Script location and publication.** Where the script lives in-repo and how it
  is published to the bucket root (and under what stable URL the docs cite) is a
  CI/release concern to settle when wiring publication.

## Technical Considerations

- **GCS cache headers.** Mutable pointers (`stable`, `unstable`) must be served
  `Cache-Control: no-cache` (or short max-age); immutable `versions/<V>/…`
  objects should be `public, max-age=31536000, immutable`. Otherwise a CDN/proxy
  serves a stale pointer and users get an old version.
- **Command substitution** strips trailing newlines, so `VERSION=$(fetch …)`
  handles a pointer file's trailing `\n` for free; internal whitespace is caught
  by the R2.2 charset validation.
- **`awk` portability.** Only POSIX awk features are used (`-v`, field vars,
  `NF`, pattern-action) so macOS's BWK awk and GNU gawk behave identically. No
  `gensub`/`\<`/PCRE.
- **Avoided non-portable tools.** `sed -i` (BSD requires an arg, GNU forbids it),
  `grep -P` (no macOS), `readlink -f`/`realpath` (not on older macOS), `stat`
  (incompatible BSD/GNU flags), and GNU `date -d` are not used anywhere.
- **`mktemp` for the manifest** uses `mktemp -d 2>/dev/null || mktemp -d -t
  minimal` to bridge BSD/GNU template differences, with a `trap … EXIT` cleanup.

## Security Considerations

- **Trust anchor is HTTPS + SHA-256.** TLS (1.2 floor, no redirect downgrade)
  authenticates the bucket in transit; the manifest `sha256` protects each
  artifact against corruption or truncation. This is proportionate for a public
  installer whose bucket is the trust root.
- **Input validation at every boundary.** The target argument (R2.1), the
  fetched version string (R2.2), and every `dest` subpath (R4.2) are validated
  before being used in a URL or filesystem path, closing path-traversal vectors.
  The manifest is treated as data only — no field is ever `eval`ed or expanded.
- **No privilege escalation.** The installer never invokes `sudo` and writes only
  to user-owned directories.
- **Future hardening (out of scope).** To defend against a compromised bucket
  (beyond TLS), the manifest can be signed with `minisign`/`signify` and the
  public key embedded in the script. Deferred until it is in the threat model.

## Verification

1. **Static**: `shellcheck --shell=sh` passes on the installer with no warnings.
2. **Dash conformance**: the installer's test harness runs the script under
   `dash` (and, where available, macOS `/bin/sh`) — not just `bash` — in CI.
3. **Unit tests** (Units 1–6) pass against fixture pointer files, manifests, and
   a stubbed bucket/downloader, asserting: downloader/hasher/platform selection;
   target and version validation; field extraction; prefix resolution and
   traversal rejection; skip-on-rerun and checksum-mismatch handling; install
   record and PATH advisory.
4. **End-to-end**: against a real (or local mock) bucket, `curl … | sh` installs
   the current `stable` binaries into temp prefixes; a second run performs zero
   downloads; corrupting one on-disk binary makes the next run re-fetch only that
   component.
