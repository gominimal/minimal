---
id: spec-installer
title: "feat(installer): POSIX-sh curl|bash fallback installer"
kind: spec
status: shipped
tracking-issue:
supersedes:
---

# feat(installer): POSIX-sh curl|bash fallback installer

## Context

`minimal` ships a handful of discrete binaries (`minimal`, `minimald`,
`minvmd`, …) and data files (`rootfs` etc) for macOS and Linux across
`x86_64`/`aarch64`. Users need a way to get those binaries onto a machine without
a pre-existing package manager.

The user-facing command is **`min`**: the `minimal` CLI component's manifest
`dest` is `bin/min`, so that is the name written to disk (the component and
release-artifact names keep the crate name `minimal`).

This spec describes **the fallback installer only**: a single POSIX-sh script
served for `curl … | sh`. The intended primary paths are native, platform-specific packages,
Homebrew (`brew`), Debian/Ubuntu (`apt`/`.deb`), Arch (`pacman`/AUR), and
similar, which integrate with system update tooling, signing, and uninstall.

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

After the files are placed, the installer wires up shell integration (Unit 9):
it generates per-shell init files that put the bin dir on `PATH`, installs tab
completions for `min` by running the freshly-installed binary, and hooks the
user's login-shell rc file with an idempotent, marker-fenced block. Uninstall
(Units 7-8) undoes all of it.

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
6. After one install and one new shell, `min` is on `PATH` and tab-completes
   in bash, zsh, and fish (Unit 9).

## User Stories

- **As a developer on a fresh machine**, I run the documented `curl … | sh` line
  and get working `minimal` binaries on my `PATH`, without installing a package
  manager first.
- **As a returning user**, I re-run the installer after a release and only the
  components that actually changed are downloaded.
- **As a minimal employee**, I pass `unstable` as an argument and get the
  bleeding-edge version through the identical mechanism.
- **As a user with long-running sessions**, an upgrade tells me what is running
  and asks before it ends any of it, so I decide whether the upgrade is worth
  the work it costs; scripted upgrades pass a flag and never stop to ask.

## Demoable Units of Work

### Unit 1 - Environment probing (downloader, hasher, platform)

**R1.1**, The script selects a downloader at runtime: prefer `curl`, else
`wget`, else exit with a clear error. Both wrappers enforce HTTPS and a TLS 1.2
floor and refuse redirect downgrades:

```sh
# curl
curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL "$url" -o "$out"
# wget
wget --https-only --secure-protocol=TLSv1_2 -qO "$out" "$url"
```

**R1.2**, The script selects a SHA-256 implementation at runtime: prefer
`sha256sum`, else `shasum -a 256`, else `openssl dgst -sha256`. Each wrapper
emits the bare lowercase hex digest on stdout (no filename, no leading marker).

**R1.3**, The host platform is derived from `uname -s` (→ `linux`/`darwin`) and
`uname -m`, with arch normalized so the same CPU has one name across platforms:
`amd64|x86_64 → amd64`, `arm64|aarch64 → arm64`. An unrecognized OS or arch
exits with a clear error.

**R1.4**, Tool discovery uses `command -v`, never `which`.

### Unit 2 - Target → version → manifest resolution

**R2.1**, The script takes an optional first argument, the **target**,
defaulting to `stable`. The target is validated against `^[A-Za-z0-9._-]+$`
before use; a value containing any other character exits with an error. Install
mode's one option, `--force-stop` (R5.5), is recognized wherever it appears in
the arguments and removed from them before the target is read, so the target
stays the sole positional on either side of the flag.

**R2.2**, The script fetches `<BUCKET>/<target>` to get a version string.
The result is validated against `^[A-Za-z0-9._-]+$` (command substitution having
already stripped the trailing newline); a malformed value exits with an error.
`<BUCKET>` is hardcoded into the script, but can be overridden with an environment
variable `MINIMAL_OVERRIDE_INSTALLER_BUCKET`.

**R2.3**, The script fetches `<BUCKET>/versions/<VERSION>/components`, the
components manifest, into a temp file. A fetch failure exits with an error.

**R2.4**, The manifest's `# format:` header is read; if it names a format
version the installer does not support, it exits with an actionable error rather
than misparsing.

**Proof artifacts**:

- **Test**: Passing `../evil` (or an empty string) as the target argument exits
  non-zero without performing any fetch.
- **Test**: A manifest whose `# format:` line names an unsupported version exits
  non-zero with a message naming the supported version.

### Unit 3 - Manifest format and field extraction

**R3.1**, The manifest is a flat, line-oriented table: `#`-prefixed comment
lines and blank lines are ignored; every data line is one component variant with
fields separated by runs of whitespace (so columns may be space-padded for
readability). Column order is fixed and documented in the header:

```
# component  os      arch     version  sha256   kind    dest              src
minimald     linux   x86_64   1.4.2    3a7b…    file    bin/minimald      minimald/1.4.2/minimald-linux-x86_64
minimald     darwin  arm64    1.4.2    2c26…    file    bin/minimald      minimald/1.4.2/minimald-darwin-arm64
```

- `component`, logical name (primary key with `os`/`arch`).
- `os`/`arch`, normalized platform (matches R1.3 output).
- `version`, component version (informational; the artifact identity is the
  hash).
- `sha256`, lowercase hex digest of the artifact at `src`.
- `kind`, `file` for a directly-placed file, or `symlink` for a symbolic
  link the installer creates (R5.6). The column exists so further kinds
  (e.g. archives) can be added without a format break.
- `dest`, install destination as `<prefix-token>/<subpath>` (see R4).
- `src`, download path **relative to the bucket root** (not to `stable/`).
  For `symlink` rows, `src` is instead the **link target**, a path the OS
  resolves relative to the link's own directory, and `sha256` is the
  literal placeholder `-` (there is no artifact to hash).

**R3.2**, No field ever contains whitespace; this invariant is what makes
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

**R3.3**, Parsing uses `awk` (which splits on whitespace runs), never
`cut -d' '` (which treats each space as a delimiter and breaks on padding).

**Proof artifacts**:

- **Test**: Against a fixture manifest with padded columns and comment lines, the
  platform-filter query returns exactly the expected component names for a given
  `os`/`arch`, and the per-field query returns the expected `dest`/`src`/`sha256`.

### Unit 4 - Destination prefix resolution and path safety

**R4.1**, The `dest` prefix token is mapped to an absolute directory through a
fixed `case`, **never** shell-expanded or `eval`ed from the manifest string:

| token   | resolves to                                             |
|---------|---------------------------------------------------------|
| `bin`   | `${MINIMAL_BIN:-$HOME/.local/bin}`                      |
| `data`  | `${XDG_DATA_HOME:-$HOME/.local/share}/minimal`          |
| `state` | `${XDG_STATE_HOME:-$HOME/.local/state}/minimal`         |
| `cache` | `${XDG_CACHE_HOME:-$HOME/.cache}/minimal`               |

An unknown token exits with an error. (Note the correct XDG variable names,
`XDG_DATA_HOME`/`XDG_STATE_HOME`/`XDG_CACHE_HOME`, and that `~/.local/bin` has
no XDG variable, hence the `MINIMAL_BIN` override.)

**R4.2**, The `dest` subpath is rejected before use if it is absolute (`/…`) or
contains a `..` component, preventing a manifest from writing outside the
resolved prefix.

**R4.3**, The resolved destination directory is created with `mkdir -p` before
any write.

**Proof artifacts**:

- **Test**: A `dest` of `../../etc/x` or `/etc/x` exits non-zero and writes
  nothing.
- **Test**: With `XDG_DATA_HOME` set to a temp dir, a `data`-prefixed component
  resolves under that temp dir; with it unset, it resolves under
  `$HOME/.local/share/minimal`.

### Unit 5 - Skip-check, download, verify, atomic install

**R5.1**, For each applicable component, if the resolved destination file
already exists **and** its on-disk SHA-256 equals the manifest `sha256`, the
component is skipped with no download. The on-disk file, not any recorded
state, is the source of truth for "already installed".

A macOS `bin` file is the one exception: it is ad-hoc code-signed after download
(R5.4 / Security), which rewrites the Mach-O so its installed bytes no longer
equal the manifest `sha256`. To keep reruns cheap there, the installer also skips
a component whose on-disk hash equals the **installed hash it recorded last run
for the same manifest `sha256`** (R6.1). Keying on the manifest hash is
load-bearing: a new release changes `sha256`, so the recorded row no longer
matches the current `want` and the (now stale) signed file is re-downloaded
instead of being wrongly judged up to date, the signed bytes would otherwise
still equal the old recorded installed hash forever. The record is only ever a
positive-match optimization; a deleted or tampered file matches nothing and is
reinstalled.

**R5.2**, Otherwise the artifact is downloaded from `<BUCKET>/<src>` to a
temp sibling **in the destination directory** (`<dest>.tmp.$$`), so the final
rename is same-filesystem and atomic.

**R5.3**, The downloaded temp file's SHA-256 is compared to the manifest
`sha256`; on mismatch the temp file is removed and the run exits non-zero
naming the component. The partially-written file is never installed.

**R5.4**, For files installed to a prefix token of `bin`, the temp file is
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

**R5.5**, Installing a new version over a **running daemon** wedges it: the
daemon goes on serving from the old image while the newly-installed `min` speaks
to it. Before the first component file is replaced, the installer therefore stops
it with the `min` **already on disk**, which is the build that matches the daemon
it started and is the one about to be overwritten. Only `<bin>/min` is ever run,
never a `min` found on `$PATH`, which is not this installer's footprint.

The stop is **graceful first**: `<bin>/min stop`, which succeeds when nothing is
running and refuses while sessions are live. That refusal, recognized by the
message the CLI prints for it rather than by a bare non-zero exit, is the one
outcome an upgrade must not decide on the user's behalf: it means live work is
about to be destroyed. The installer then lists the running sessions
(`<bin>/min ls`), asks whether to end them, and only on an explicit yes runs
`<bin>/min stop --force` and carries on. A declined upgrade exits non-zero
before the first **executable** replacement, dropping the temp download and
leaving the daemon, its sessions, every installed executable, and the install
record exactly as they were. It claims no more than that: the stop is attempted
at the first `bin`/`lib` component, so a `data` component ordered ahead of it in
the manifest may already have been replaced.

The question is asked on the **controlling terminal**, never on stdin: in a
`curl … | sh` pipeline stdin is the script itself, so reading the answer there
would consume it. Where no controlling terminal can be opened (CI, any
non-interactive invocation) there is nobody to consent, so the installer exits
non-zero naming the escape hatch instead of hanging on a read or ending sessions
unasked. That escape hatch — a `--force-stop` argument, or a non-empty
`MINIMAL_INSTALL_FORCE_STOP` in the environment for a pipeline with no argv —
skips both the graceful stop and the question and force-stops outright, so
scripted upgrades never block. It is deliberately not spelled `--force`, which
already means "remove modified files too" in uninstall mode.

Every other outcome stays **best-effort and silent**, output discarded and exit
status ignored: "no `min` installed yet" (a fresh install), "no daemon running"
(`min stop` merely connects; it never autospawns, so this is a failed connect
and nothing more), "the installed `min` is too old to know `stop`", and a
transport drop on an otherwise successful stop are all just *nothing to stop*.
None of them may fail an install whose binaries are otherwise fine, and none of
them may raise the question — treating a bare failure as "sessions are live"
would make every upgrade ask one. They fall through to the force stop, which
remains unconditional for them.

It is attempted **at most once per run**, and only from the path that actually
replaces a file: a rerun where every component is already up to date, or a run
that dies fetching or checksum-verifying, must leave a healthy daemon running.

**R5.6**, A `kind = symlink` component places a symbolic link at `dest`
pointing at `src` (the link target, see R3.1). The target is validated with
the same discipline as a `dest` subpath (R4.2), never absolute, no `..`
component, so a manifest can only point a link within the tree of its own
prefix. The link itself is the skip oracle: a symlink already at `dest`
whose `readlink` equals `src` is up to date. Installation mirrors
R5.2/R5.4's atomicity: the link is created as a temp sibling (`ln -s`) and
`mv -f`ed over whatever holds the path, notably a stale regular file from
a release that shipped the component as a copy. Nothing is downloaded for a
symlink row either way. The record row (R6.1) carries `link:<target>` in
both hash columns in place of digests.

**Proof artifacts**:

- **Test**: Running twice against the same fixture manifest downloads on the
  first pass and performs zero downloads on the second (assert via a
  download-count stub).
- **Test**: A manifest whose `sha256` disagrees with the served artifact exits
  non-zero and leaves no file (and no `.tmp.` file) at the destination.
- **Test** (macOS staleness): after a signed-`bin` install, a rerun against the
  *same* manifest performs zero downloads and no re-sign, but a rerun against a
  manifest whose `sha256` for that component *changed* re-downloads and re-signs
  it, the recorded installed hash does not mask a new release.
- **Test** (R5.5): a fresh install stops nothing (no `min` on disk yet) and an
  up-to-date rerun stops nothing (nothing replaced); an upgrade whose components
  are stale runs the on-disk `min` with exactly `stop`, once, however many
  components it replaces, never escalating to `--force` and never asking
  anything when the graceful stop succeeds.
- **Test** (R5.5): an installed `min` whose `stop` exits non-zero and writes to
  both stdout and stderr still yields exit 0, leaks neither stream into the
  installer's output, asks nothing, and completes the upgrade.
- **Test** (R5.5): an on-disk `min` whose graceful `stop` refuses with the
  active-sessions message makes the installer list the running sessions and ask
  on the terminal (a stand-in for `/dev/tty`, since stdin is the script pipe);
  answering yes escalates to `stop --force` and completes the upgrade.
- **Test** (R5.5): answering no exits non-zero, never runs `stop --force`,
  leaves the stale component and no temp file behind, and reports that no
  executable was replaced.
- **Test** (R5.5): the refusal message the installer matches on is asserted, by
  the workspace test suite, to still be present in the CLI source that prints
  it. The signal crosses a language boundary with nothing else holding the two
  ends together, and a reword on the CLI side would otherwise return every
  upgrade to an unconditional force-stop with the installer's own tests — which
  supply their own copy of the message — still green.
- **Test** (R5.5): with the same refusal and no openable terminal, the run exits
  non-zero naming the escape hatch, without prompting, force-stopping, or
  installing anything.
- **Test** (R5.5): the escape hatch, given as an argument or through the
  environment, force-stops without a graceful attempt and without asking, and
  completes the upgrade; given after the target, the target still resolves.
- **Test** (R5.6): a `symlink` component lands as a symlink at its `dest`
  pointing at the manifest target, with no download; a rerun skips it, and a
  retargeted link is repaired on the next run, still with no download.

### Unit 6 - Install record and PATH advisory

**R6.1**, After a successful run the installer writes a record of what it
installed to `<state>/installed`, the resolved
`(component, dest, manifest-sha256, installed-sha256)` rows for this platform,
tab-delimited. `manifest-sha256` is the artifact's `sha256` from the manifest;
`installed-sha256` is the SHA-256 of the bytes actually on disk, which equals
`manifest-sha256` except for a macOS-signed `bin` file. Pairing the two is what
lets the R5.1 signed-file skip stay correct across releases (skip only while the
manifest still wants that artifact). A `symlink` row (R5.6) records
`link:<target>` in both hash columns instead of digests, the `link:` prefix
cannot collide with a hex digest and is what the uninstaller keys on (R7.3).
The record also enables uninstall (Units 7-8) and surfaces prefix drift if
`XDG_*` variables change between runs.

**R6.1a**, **Renamed-component migration.** When a component is renamed, its old
`dest` stops appearing in every subsequent manifest, so the record walk of Units
7-8 never revisits it and the file is stranded on disk forever. For a `bin`
component that is a live PATH collision, not just clutter. The installer
therefore reverses a known rename from the *prior* record, on the same
bytes-still-ours terms uninstall uses (R7.3): the old `dest` is removed only
when its SHA-256 still equals the `installed-hash` recorded for it, so a file
the user replaced is kept and reported.

The concrete case is the switch binary, installed as `gvproxy` before this
release and as `gvproxy-min` after it — the `bin` prefix is on `PATH` and
podman/crc ship their own `gvproxy` there, so the two cannot share a name.

Three rules make the migration safe:

- **Skip when the manifest still ships the old component.** Channels advance
  independently, so a post-rename installer *will* be pointed at a pre-rename
  manifest. There the file on disk is the one this very run installed, and
  deleting it would leave the host with no switch binary at all, on every run.
  The migration therefore runs only when this run's records contain no row for
  the old component name.
- **Report a refusal.** A hash mismatch means the user replaced the file; it is
  kept and named.
- **Retry a failure.** If removal fails (a read-only or root-owned `bin`), the
  row is carried into this run's record so the next run tries again — without
  it the migration gets exactly one attempt, because the record it reads is
  replaced immediately afterwards.

**R6.2**, If the resolved `bin` directory is not on `$PATH` **in the
installing session**, the installer prints an advisory: the Unit 9 rc hook only
takes effect in new shells, so the advisory tells the user to restart their
shell or export `PATH` now. The installer never *silently* edits an rc file,
the only rc edit it makes is Unit 9's announced, marker-fenced block (R9.2).

**Proof artifacts**:

- **Test**: After a successful install into temp prefixes, `<state>/installed`
  exists and lists the installed components with their destinations and hashes.
- **Test**: With the `bin` prefix absent from `PATH`, the advisory is printed;
  with it present, it is not.
- **Test** (R6.1a): a record naming the old component at a path whose bytes
  still match the recorded hash has that file removed on the next install, the
  removal is announced, and a further rerun says nothing (the row is gone).
- **Test** (R6.1a): a record naming the old component whose file the user has
  since replaced keeps the file, byte-for-byte, and reports that it was kept.
- **Test** (R6.1a): when the manifest for *this* run still ships the old
  component, the file it just installed survives and no removal is announced —
  the case that would otherwise leave the host with no switch binary.

### Unit 9 - Shell integration: PATH, shell-init files, completions

The goal: after one install and one new shell, `min` is on `PATH` and
tab-completes, in bash, zsh, and fish. Everything this unit writes is either an
install-record row (so Units 7-8 remove it for free) or a marker-fenced rc
block (so uninstall can strip it precisely).

**R9.1**, After the component loop, the installer **generates** (never
downloads) one init file per shell family under `<data>/shell-init/`:
`bash.sh`, `zsh.sh`, and `fish.fish`. Each file:

- embeds the `bin` directory as resolved **at install time**
  (`${MINIMAL_BIN:-$HOME/.local/bin}`), and
- guards at shell startup: only if the dir exists and is not already in
  `PATH` is it prepended (`case ":$PATH:"` for POSIX shells,
  `fish_add_path --prepend` for fish), so sourcing is idempotent and becomes a
  no-op once the user manages `PATH` themselves.

`zsh.sh` also adds the zsh completions dir (R9.3) to `fpath` and runs
`compinit`, and then **self-heals a lying dump**: `compinit` trusts its cached
`.zcompdump` whenever the dump's (zsh version, completion-file count) header
matches, a check that misses real changes (one completions dir replacing
another with the same file count). If `min` is still unregistered after
`compinit` while the `_min` file exists, `zsh.sh` deletes
`${ZDOTDIR:-$HOME}/.zcompdump` and reruns `compinit`; the file-exists guard
keeps a home without generated completions from rebuilding the dump on every
startup. All three files are regenerated on every run and appended to the
install record (R6.1) with the on-disk digest in **both** hash columns (no
manifest hash exists for generated content), so reruns replace them and
uninstall removes them like any component.

**R9.2**, The installer hooks the rc file of the user's login shell
(`basename "$SHELL"`) with a block sourcing the matching init file, fenced by
the exact markers `# >>> minimal >>>` / `# <<< minimal <<<`:

| shell   | rc file(s)                                                        |
|---------|-------------------------------------------------------------------|
| `bash`  | every existing one of `~/.bashrc`, `~/.bash_profile`; neither exists → create `~/.bashrc` |
| `zsh`   | `${ZDOTDIR:-$HOME}/.zshrc`, created if missing                     |
| `fish`  | `${XDG_CONFIG_HOME:-~/.config}/fish/config.fish`, created if missing |
| other   | `~/.profile` (the POSIX login rc), with the `bash.sh` (POSIX) init |

The markers are the installer's to **own**, not merely to detect: a file whose
marker block already sources the current init file is never touched again
(reruns add nothing), but a marker block with any other content is *stale*,
notably the pre-rewrite installer's, which used the same markers around a line
sourcing `~/.minimal/shim/shell-init/…`, and is replaced (stripped via the
R9.4 filter, then re-appended), or PATH and completions silently break on every
upgraded machine. Either edit is always announced, never silent, and the result
always carries exactly one marker block. The sourced line itself is guarded
(`[ -f … ] && . …` / `if test -f …`), so an rc file that outlives an uninstall
stays harmless.

A *malformed* block, a start marker with no matching end marker, i.e. a hand
edit, is never repaired by force: stripping it would truncate everything from
the marker to end-of-file, and appending after it would set up exactly that
truncation for a later strip. The file is left byte-for-byte untouched and the
installer warns, naming the file and printing the line to add by hand.

The hook is **best-effort and non-fatal**: by the time it runs, the binaries
are already correctly installed, so an rc file that cannot be appended (or a
config dir that cannot be created) must not turn the run into a failure. The
installer prints a warning naming the file (`failed to hook minimal shell
support (… is not writable)`) plus the exact line to add by hand, continues,
and still exits 0, and the R6.2 `PATH` advisory still fires.

**R9.3**, Tab completions are generated by **running the just-installed
binary**, `<bin>/min completions <shell>`, so they always match the installed
version, and are written atomically (temp sibling + `mv`) to each shell's
user-level completion dir:

| shell  | completion file                                                        |
|--------|------------------------------------------------------------------------|
| bash   | `${XDG_DATA_HOME:-~/.local/share}/bash-completion/completions/min`     |
| zsh    | `${XDG_DATA_HOME:-~/.local/share}/zsh/completions/_min` (on `fpath` via `zsh.sh`) |
| fish   | `${XDG_CONFIG_HOME:-~/.config}/fish/completions/min.fish`              |

All three are written regardless of `$SHELL` (covers shell switching), each
recorded in the install record like the init files. The whole step is
**best-effort, warning-not-error**: the binaries are already correctly
installed, and completions regenerate on the next run. Specifically:

- an unwritable completion dir (these are shared, user-owned locations that can
  pre-exist unwritable, e.g. a root-owned `~/.config/fish/completions`) is
  probed before generating and skipped with a warning naming the dir;
- failure to execute the binary (or empty output) warns and moves on;
- if `<bin>/min` was not part of the manifest, the step is skipped with a
  notice;
- the shell's own redirection errors are suppressed (writes run in a subshell
  with stderr nulled, a command-level `2>/dev/null` cannot catch them), so the
  user sees the installer's warning, never a raw `Permission denied` line.

Writing the zsh completion file also **drops a pre-existing
`${ZDOTDIR:-$HOME}/.zcompdump`** (announced, best-effort like the rest of the
step): the dump is a pure, regenerable cache, and its staleness check cannot
see `_min` change when the completion-file count stays equal, the upgrade
from the pre-rewrite installer hits exactly that, leaving `min` completion
dead in every new shell until an unrelated `fpath` change. Dropping the cache
forces a real rescan on the next zsh startup (the `zsh.sh` self-heal in R9.1
is the belt-and-braces for dumps that go stale later).

**R9.4**, Uninstall (Units 7-8) undoes shell integration completely:

- the generated init and completion files are ordinary record rows, removed by
  the hash-verified walk (R7.3);
- the marker-fenced block is stripped from every rc file the installer may
  have edited (all candidates from the R9.2 table are tried, `$SHELL` may have
  changed since install; a file without markers is never rewritten), via an
  awk filter to a temp sibling + atomic `mv` (`sed -i` is not portable); a file
  whose start marker lacks its end marker is kept untouched with a warning
  (the filter would otherwise drop everything from the marker to end-of-file),
  and the walk continues to the remaining candidates;
- the emptied `shell-init` and completion dirs (and their possibly
  installer-created parents) are pruned with the same `rmdir`-only discipline
  as R8.1: they are shared locations, never `rm -rf`ed;
- `${ZDOTDIR:-$HOME}/.zcompdump` is dropped (announced), but **only when the
  record shows zsh completions were installed**: the dump is the user's cache,
  and left behind it keeps a `min` registration whose function file is gone,
  so the first `min <tab>` in every new zsh fails with `function definition
  file not found`;
- `--dry-run` composes: it announces the would-be rc strip and removals and
  touches nothing.

**Proof artifacts**:

- **Test**: after an install with `SHELL=/bin/bash`, the three init files exist
  under `<data>/shell-init/`, embed the resolved bin dir, and are listed in the
  install record; sourcing `bash.sh` under plain `sh` prepends the bin dir to
  `PATH` exactly once (a second source does not duplicate it).
- **Test**: a fresh home gets `~/.bashrc` created with exactly one marker-fenced
  block; a rerun adds no second block; with both `~/.bashrc` and
  `~/.bash_profile` pre-existing, both are hooked and user content is preserved.
- **Test**: `SHELL=…/zsh` hooks (and creates) `.zshrc`; `…/fish` hooks
  `config.fish`; an unrecognized shell falls back to `~/.profile`.
- **Test**: an rc file carrying the pre-rewrite installer's marker block
  (sourcing `~/.minimal/shim/shell-init/…`) has it replaced, the run announces
  the replacement, exactly one marker block remains, it sources the current
  init file, no shim reference survives, and user content on both sides of the
  old block is preserved; a rerun then rewrites nothing. A pre-existing
  `.zcompdump` is dropped by that upgrade (announced), and the rerun, with no
  dump present, announces no drop.
- **Test**: the generated `zsh.sh` carries the compinit self-heal (checks
  `_comps[min]` against the `_min` file).
- **Test**: an rc file with a start marker but no end marker is left untouched
  by both install and uninstall, each warns naming the file, appends nothing,
  preserves the content after the stray marker, and exits 0.
- **Test**: with a read-only `~/.bashrc`, the install still exits 0, prints the
  `failed to hook minimal shell support` warning and the manual line, leaves
  the rc file untouched, and still prints the R6.2 PATH advisory.
- **Test**: the bash/zsh/fish completion files exist at their R9.3 paths with
  content produced by the installed binary; a manifest without the `min`
  component skips completions non-fatally, and an unrunnable binary degrades to
  a warning with exit 0.
- **Test**: with one completion dir pre-existing unwritable, the install exits
  0, warns naming that dir, still installs the other shells' completions, and
  leaks no raw shell `Permission denied` error into the output.
- **Test**: `--uninstall` removes the generated files, strips the rc block
  while preserving the user's own rc content, prunes the emptied
  completion/shell-init dirs, and drops the `.zcompdump` cache; `--dry-run`
  announces the strip and the dump drop without editing either. A data-only
  install (no zsh completions in the record) leaves the user's `.zcompdump`
  untouched on uninstall.

### Unit 10 - Presentation

`curl … | sh` is the product's first impression, and it lands on everything
from a modern terminal to a CI log with no terminal at all. This unit fixes
what the run looks like and, more importantly, what it must **not** emit when
nobody is watching. Only R10.1 is a contract; the rest is the shape the
implementation currently takes, recorded so a rewrite does not have to
rediscover it.

**R10.1**, **Degradation.** Presentation degrades along two independent axes,
each probed once at startup:

- *attributes* (bold, dim, and the in-place row rewrite) are emitted **only**
  when stderr is a terminal, `NO_COLOR` is unset, and `TERM` is not `dumb`;
- *glyphs* (the `▸` marker, `→` arrow, `·` separator, and the mark) are emitted
  only under a UTF-8 locale (`LC_ALL`/`LC_CTYPE`/`LANG`), with ASCII
  stand-ins otherwise. This axis is independent of the first: UTF-8 in a
  redirected log is still fine.

`MINIMAL_INSTALL_PLAIN=1` forces both off. It follows that a run whose stderr
is redirected emits **no escape sequence of any kind** — the property that
keeps CI logs and any future output parsing clean, and the one thing here
worth a regression test.

Attributes only, never color: the installer is monochrome, like the CLI's
prompt theme (`crates/minimal/src/theme.rs`) and the website.

**R10.2**, **Component table.** The component loop prints one row per
component: the component name in a fixed column, a verb (`downloading`,
`installed`, `current`, `linked`, `kept`, `removed`, …), and an optional
detail (a size, a `$HOME`-relative path). On a terminal the in-progress row is
rewritten in place, so a slow download narrates itself and still leaves one
line behind; otherwise the two halves are consecutive lines, which is what a
log wants. Anything printed while a row is open (a warning, the R5.5 prompt, a
fatal error) closes that row first, so no message lands mid-line. Uninstall
prints the same table.

**R10.3**, **The mark.** A first install — no prior install record (R6.1) —
opens with the Minimal mark, character-for-character the one in the README's
session demo (`docs/public/loadout-demo.cast`). Terminal-only, UTF-8 only, and
never on an upgrade: a mark in a log file, or on the fifth rerun of the week,
is litter.

**R10.4**, **The closing card.** Every **successful install** ends on a card
naming the first commands to run. It is the last output of the run, after every
bookkeeping note (install record, shell integration, the R6.2 PATH advisory,
the AppArmor advisory), because a finished installer that ends on a filesystem
path leaves a new user with no next step. When the resolved `bin` directory is
not on `$PATH` in this session, the R6.2 advisory is carried **inside** the
card, above the commands: the rc hook only takes effect in new shells, so
those commands would not resolve in this one, and saying so is part of the
next step rather than a footnote after it. No card on a failed install, and
none in uninstall mode.

**Proof artifacts**:

- **Test** (R10.1): the harness captures every run to a file, so no run's
  output may contain an ESC byte; asserted on a full install.
- **Test** (R10.4): a fresh install and an up-to-date rerun both end on the
  card, it names `min session activate --attach .`, and it is still the parting
  block when the AppArmor advisory is the last note before it.
- **Test** (R10.4): a failed install (checksum mismatch) prints no card.
- **Not automated**: the terminal-only behaviors — attributes, the in-place row
  rewrite, and the mark (R10.2/R10.3) — are unreachable from the harness, whose
  output is always redirected. They are verified by eye against a mock bucket
  before release, not by CI.

## Non-Goals

- **Uninstall.** ~~The install record (R6.1) is written to enable it later; the
  uninstall command itself is out of scope.~~ Now specified below, see
  [Uninstaller](#uninstaller). The install record (R6.1) is the sole authority
  for what to remove.
- **Multi-file / archive components.** v1 handles `kind = file` single files
  and `kind = symlink` links (R5.6) only. The `kind` column reserves room for
  archive kinds without a format break.
- **Signing/verification beyond TLS + SHA-256.** See Security Considerations for
  the future `minisign` path.
- **Windows.** POSIX-sh targets macOS and Linux only.

## Design Considerations

**Why POSIX `sh`, not bash.** macOS ships bash 3.2 (frozen over GPLv3) and
Debian/Ubuntu's `/bin/sh` is `dash`; users are told to pipe to either `bash` or
`sh`. Targeting strict POSIX `sh`, single `=` in `[ ]`, `printf` over
`echo -e`, `case` over `[[ =~ ]]`, no arrays, is the only way one script runs
across all of them. Correctness is enforced in CI (see Verification).

**Why a flat table, not JSON/YAML.** The installer must parse the manifest with
tooling that is always present. `jq` is not installed by default on macOS or
minimal Linux images, so a JSON manifest creates a bootstrap problem;
grep/sed JSON parsing is fragile. A whitespace-delimited table is what `awk`
parses natively with zero dependencies. YAML has no portable CLI parser at all.

**Why not a `source`-able manifest.** Sourcing a fetched `KEY=value` file is
remote code execution, anyone who can write the bucket runs code as the
installer. The manifest is strictly *data*; prefix tokens are mapped through a
`case`, never expanded.

**On-disk hash as the skip oracle.** Comparing the manifest hash against the
actual destination file (R5.1) is more reliable than trusting a recorded state
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
  (incompatible BSD/GNU flags), and GNU `date -d` are not used anywhere. Plain
  flagless `readlink` (used only to verify `symlink` rows, R5.6) is fine: it is
  present on macOS/BSD, GNU coreutils, and busybox, only the `-f` canonicalize
  flag is the portability trap.
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
  The manifest is treated as data only, no field is ever `eval`ed or expanded.
- **No privilege escalation.** The installer never invokes `sudo` and writes only
  to user-owned directories.
- **Future hardening (out of scope).** To defend against a compromised bucket
  (beyond TLS), the manifest can be signed with `minisign`/`signify` and the
  public key embedded in the script. Deferred until it is in the threat model.

## Verification

1. **Static**: `shellcheck --shell=sh` passes on the installer with no warnings.
2. **Dash conformance**: the installer's test harness runs the script under
   `dash` (and, where available, macOS `/bin/sh`), not just `bash`, in CI.
3. **Unit tests** (Units 1-6, 9, 10) pass against fixture pointer files, manifests,
   and a stubbed bucket/downloader, asserting: downloader/hasher/platform
   selection; target and version validation; field extraction; prefix resolution
   and traversal rejection; skip-on-rerun and checksum-mismatch handling; install
   record and PATH advisory; shell-init generation, rc hooking, and completion
   installation (the `min` CLI fixture is a runnable script, so completion
   generation exercises the real execute-the-binary path); and that a redirected
   run emits no terminal escapes and ends on the closing card (Unit 10).
4. **End-to-end**: against a real (or local mock) bucket, `curl … | sh` installs
   the current `stable` binaries into temp prefixes; a second run performs zero
   downloads; corrupting one on-disk binary makes the next run re-fetch only that
   component.

---

# Uninstaller

## Context

The installer places files (R5) and, after each successful run, records exactly
what it placed: `<state>/installed` holds one **tab-delimited** row per installed
component variant, `component<TAB>dest<TAB>manifest-hash<TAB>installed-hash`, where
`dest` is the **absolute** on-disk path and `installed-hash` is the SHA-256 of the
bytes actually written there (R6.1). On macOS that hash is the *post-signing*
digest of an ad-hoc-signed `bin` file, which deliberately diverges from the
manifest `sha256` (see R5.1 and `install.sh`'s signing note). Uninstall reads only
`dest` and `installed-hash`; the `manifest-hash` column is for the installer's
rerun skip check (R5.1) and is unused here.

That record is a complete, self-contained inventory of the installer's
footprint, downloaded components and the generated shell-init/completion files
alike (Unit 9 records what it writes). An uninstaller does not need the network,
the bucket, the manifest, or even to know which version is installed: it walks
the record and undoes it, then strips the marker-fenced rc block (R9.4), the one
piece of footprint an rc file carries instead of the record. This
mirrors the installer's guiding principle, **the recorded/on-disk hash is the
oracle**, applied in reverse: only remove a file the installer wrote and that is
still byte-for-byte what it wrote.

## Introduction/Overview

Uninstall is a **mode of the same `install.sh` script**, entered with
`--uninstall` as the first argument, so there is one published URL and one script
to maintain and the two modes share environment probing (SHA-256 tool, prefix
resolution) and the path-safety discipline. It is offline: no downloader is
required or invoked.

```sh
curl --proto '=https' --tlsv1.2 -fsSL <URL>/install.sh | sh -s -- --uninstall
# or, if the script is already on disk:
sh install.sh --uninstall [--dry-run] [--force] [--purge]
```

For each recorded component the uninstaller re-hashes the file at `dest` and,
**only if it matches the recorded `installed-hash`**, removes it; a file that is
missing is counted and skipped, and a file whose bytes have changed is left in
place (the user edited or replaced it) unless `--force` is given. It then removes
the record itself and prunes now-empty `minimal`-owned directories. The operation
is idempotent: a second `--uninstall` finds no record and is a clean no-op.

## Goals

1. A single `… | sh -s -- --uninstall` removes every file the installer placed
   for this host, using only the local install record, no network, no bucket,
   no manifest.
2. It never deletes a file the installer did not write, and never a file the user
   has since modified or replaced (unless `--force`).
3. It is idempotent and safe to interrupt: a partial or repeated run never errors
   out and never removes something outside the recorded footprint.
4. `--dry-run` shows precisely what would be removed without touching anything.

## User Stories

- **As a user who wants minimal gone**, I run the documented `--uninstall` line
  and every binary and data file the installer placed is removed, with a summary
  of what went and what was kept.
- **As a user who hand-patched a binary**, I run `--uninstall` and my modified
  file is reported as *kept* (its hash no longer matches the record), not silently
  deleted.
- **As a user reclaiming disk**, I add `--purge` to also delete the `minimal`
  data/state/cache trees, not just the recorded files.

## Demoable Units of Work

### Unit 7 - Uninstall dispatch and record walk

**R7.1**, When the first argument is `--uninstall`, the script enters uninstall
mode **before** target validation (R2.1), `--uninstall` otherwise passes the
target charset and would be fetched as a bogus target. In this mode the downloader
probe (R1.1) is skipped/made lazy: an uninstall must succeed on a host with no
`curl`/`wget`. The SHA-256 tool (R1.2), platform probe (R1.3), and prefix
resolution (R4.1) are still required. `--uninstall` is mutually exclusive with a
target argument.

**R7.2**, The record is located at `<state>/installed` via the same
`resolve_prefix state` used to write it (R6.1), so an `XDG_STATE_HOME` set at
uninstall time resolves identically. If the record is absent, the uninstaller
prints "nothing to uninstall (no install record at …)" and exits **0**, absence
is success, not an error.

**R7.3**, Each record row is parsed with tab as the field separator
(`awk -F'\t'` / `read -r … <TAB>`), never default whitespace splitting, because a
`dest` under a `$HOME` containing spaces is legal. Taking `dest` and
`installed-hash` from each `(component, dest, manifest-hash, installed-hash)` row:

- `dest` **absent** → counted as *already removed*, skipped.
- `dest` is **not a regular file** (a symlink or directory now occupies the
  path) → left in place with a warning; a `file` row only ever wrote a regular
  file, so something else owns this path.
- `dest` present, a regular file, and `sha256(dest) == installed-hash` → removed.
- `dest` present but `sha256(dest) != installed-hash` → the file was modified or
  replaced since install; **left in place** with a warning by default, removed
  only under `--force`.

A row whose hash columns carry `link:<target>` (R5.6) is a symlink the
installer created, and the regular-file rules above invert for it: `dest` is
removed when it is still a symlink whose `readlink` equals `<target>` (removal
is of the link itself, never what it points at); a symlink pointing elsewhere
was retargeted by the user, kept unless `--force`; and anything that is not a
symlink is foreign and always kept.

**R7.4**, The comparison is against the recorded `installed-hash`, **not** the
manifest `sha256` (which the uninstaller does not have offline). This is what
lets a macOS ad-hoc-signed `bin` file, whose on-disk bytes diverge from the
manifest, still match and be recognized as ours.

**Proof artifacts**:

- **Test**: After an install into temp prefixes, `--uninstall` removes every
  recorded file and reports the count; the destinations no longer exist.
- **Test**: A recorded file whose bytes are altered before `--uninstall` is
  **kept** (reported as modified) and removed only when `--force` is added.
- **Test**: A record listing a `dest` that has already been deleted causes
  `--uninstall` to exit 0, counting it as already-removed, with no error.
- **Test**: A recorded symlink is removed by `--uninstall`; one retargeted
  since install is kept and removed only under `--force`; a regular file now
  occupying the recorded path is kept even with `--force`.

### Unit 8 - Record teardown, directory pruning, and purge

**R8.1**, After the walk, the record file is removed **only if the footprint is
fully gone**, every recorded file removed or already absent. If anything was
kept (a modified file under R7.3, or a foreign path), the record is **retained**
so a later `--force` or manual cleanup still has the inventory to work from;
re-running is idempotent because already-removed rows re-classify as
already-absent. Teardown happens after the walk (not before) for the same reason:
an interrupted run leaves the inventory intact for the retry. Then each
`minimal`-owned directory that the installer may have created is removed **only
if empty**, via `rmdir` (never `rm -rf`): the `data`, `state`, and `cache`
prefixes resolve to `.../minimal` subdirectories the installer owns, and the
`bin` prefix (`~/.local/bin`) is shared with other tools so it is `rmdir`ed only
when empty and otherwise left untouched. Pruning failures (a non-empty dir) are
ignored, not fatal.

**R8.2**, `--purge` also removes the `minimal`-owned trees in full,
the resolved `data`, `state`, and `cache` directories and everything under them
(build cache included), because those live at fixed `.../minimal` paths the tool
owns exclusively. `--purge` never touches the shared `bin` directory beyond the
empty-`rmdir` of R8.1, and never removes individual files outside those
`minimal`-owned roots.

**R8.3**, `--dry-run` (accepted in uninstall mode) prints each planned removal
and prune, prefixed to make it unmistakable, and touches nothing, no file
removed, record left intact. It composes with `--force`/`--purge` to preview
their effect.

**R8.4**, The run prints a summary: counts of *removed*, *already-absent*,
*kept (modified)*, and *kept (not a regular file)*, plus which directories were
pruned. A run that kept files because they were modified still exits **0** (it did
what was asked); only an unexpected internal failure is non-zero.

**Proof artifacts**:

- **Test**: After `--uninstall`, `<state>/installed` is gone and an emptied
  `data`/`state` dir is `rmdir`ed, while a `bin` dir still holding an unrelated
  file is left in place.
- **Test**: `--dry-run` against a populated record removes nothing and leaves the
  record; a subsequent plain `--uninstall` then removes everything.
- **Test**: With a stray build artifact under the `cache` prefix, plain
  `--uninstall` leaves the cache tree; `--purge` removes it.

## Non-Goals (uninstaller)

- **Reconstructing the footprint from the manifest.** The local record is the
  only authority. If it is missing, uninstall is a no-op, the uninstaller never
  fetches a manifest and deletes by guessing which paths *would have* been
  written, which could clobber unrelated files at those paths.
- ~~Removing PATH edits.~~ Superseded by Unit 9: the installer hooks rc files
  with a marker-fenced block (R9.2), and uninstall strips exactly that block
  from every candidate rc file (R9.4). User content around the markers is never
  touched.
- **Cross-prefix drift recovery.** If `XDG_*`/`MINIMAL_BIN` differ between install
  and uninstall, the record's **absolute** `dest` paths are still removed
  correctly, but directory pruning (R8.1) targets the *currently* resolved
  prefixes; a stale, differently-resolved empty dir may remain. Surfacing that is
  out of scope.

## Design Considerations (uninstaller)

**Why a mode of `install.sh`, not a separate script.** One published URL, one
script to keep POSIX-clean and shellcheck-green, and direct reuse of
`resolve_prefix`, the SHA-256 wrapper, and the path-safety `case`s. The cost is a
small dispatch at the top of `main`; the alternative, a second script, would
duplicate all of environment probing and drift out of sync.

**Hash-verify before delete.** The symmetric counterpart to the install skip
oracle (R5.1). Removing only files whose current bytes equal what we recorded
writing means a user who replaced a binary with their own build, or whose file
was touched by another tool, never loses data to `--uninstall`. `--force` exists
for the "I know, remove it anyway" case.

**Record deleted last.** Files are removed first, the record last, so an
interrupted run can be re-run: rows already removed re-classify as
*already-absent* (R7.3) and the run completes. Deleting the record first would
strand any not-yet-removed files with no inventory to find them by.

**`rmdir`, never `rm -rf`, for shared paths.** `~/.local/bin` holds other tools'
binaries; an empty-only `rmdir` can never take them. Full-tree deletion is gated
behind explicit `--purge` and confined to the `.../minimal` roots the tool owns.

## Security Considerations (uninstaller)

- **Trust boundary is the local record.** The record lives in the user's own
  `state` dir and lists absolute paths the installer itself wrote through the
  validated `resolve_prefix` + subpath checks (R4). The uninstaller does not
  re-derive paths from any network input. As defense in depth it still refuses to
  remove a `file`-row `dest` that is not a regular file (R7.3), so a symlink
  swapped in at a recorded path is not followed into deleting something else;
  for `link:` rows, removal targets the link itself, `rm` never follows it,
  and only when it still points at the recorded target.
- **No privilege escalation.** Like the installer, uninstall runs as the user and
  writes only under user-owned prefixes; it never invokes `sudo`.
- **`--force`/`--purge` are opt-in.** The destructive behaviors (removing modified
  files; deleting whole `minimal` trees) require an explicit flag; the default is
  the conservative, hash-verified removal of the exact recorded footprint.

## Verification (uninstaller)

1. **Static/conformance**: the same `shellcheck --shell=sh` and `dash` CI gates
   cover the added uninstall path.
2. **Unit tests** (Units 7-8): dispatch and record-absent no-op; hash-verified
   removal; modified-file keep vs `--force`; already-absent idempotency;
   non-regular-file refusal; record teardown and empty-dir pruning; `--dry-run`
   removing nothing; `--purge` clearing the owned trees; rc-block stripping and
   shell-integration teardown (R9.4).
3. **End-to-end**: `install` into temp prefixes, then `--uninstall` leaves the
   prefixes free of every recorded file and removes the record; a second
   `--uninstall` is a clean no-op exiting 0.
