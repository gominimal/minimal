#!/bin/sh
#
# install.sh — the minimal curl|sh fallback installer.
#
# A single POSIX-sh script served for `curl … | sh`. It resolves a target
# (default `stable`) to a version via a pointer file, fetches that version's
# components manifest, and for each component that applies to the host OS/arch
# it verifies whether the correct file is already installed (by hashing the
# on-disk file) and, if not, downloads, checksum-verifies, and atomically
# installs it. Reruns re-download only components whose hash changed.
#
# See docs/specs/07-spec-installer/07-spec-installer.md.
#
# Usage:
#   curl --proto '=https' --tlsv1.2 -fsSL <URL>/install.sh | sh
#   curl … | sh -s -- unstable          # pick a non-default target
#
# The script targets strict POSIX `sh` (not bash): it runs identically under
# dash, macOS's frozen bash 3.2, busybox, and zsh-invoked-sh. It depends only on
# tooling present by default on every target: a downloader (curl or wget), a
# SHA-256 tool (sha256sum, shasum, or openssl), and awk/uname/mkdir/mv/chmod.

set -eu

# --- Configuration ---------------------------------------------------------

# Bucket root. Hardcoded, overridable for staging/tests. Must be HTTPS: the
# downloader wrappers enforce a TLS 1.2 floor and refuse redirect downgrades.
BUCKET="${MINIMAL_OVERRIDE_INSTALLER_BUCKET:-https://storage.googleapis.com/minimal-one}"

# Manifest column layout this installer understands. The manifest carries a
# `# format:` header (spec R2.4); a mismatch is a hard error, not a misparse.
SUPPORTED_FORMAT=1

# --- Output helpers --------------------------------------------------------

# All diagnostics go to stderr so a future machine-readable stdout stays clean.
say() { printf '%s\n' "$*" >&2; }
die() { printf 'install: %s\n' "$*" >&2; exit 1; }

# --- Unit 1: environment probing (downloader, hasher, platform) ------------

# R1.1 — prefer curl, else wget. Both enforce HTTPS + TLS 1.2 and refuse a
# redirect that would downgrade the scheme.
DL_TOOL=
if command -v curl >/dev/null 2>&1; then
    DL_TOOL=curl
elif command -v wget >/dev/null 2>&1; then
    DL_TOOL=wget
else
    die "need a downloader: neither curl nor wget found on PATH"
fi

# Download $1 (url) to $2 (path). Fails non-zero on any HTTP/transport error.
fetch() {
    case "$DL_TOOL" in
        curl) curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL "$1" -o "$2" ;;
        wget) wget --https-only --secure-protocol=TLSv1_2 -qO "$2" "$1" ;;
    esac
}

# R1.2 — prefer sha256sum, else `shasum -a 256`, else `openssl dgst -sha256`.
# Each wrapper prints the bare lowercase hex digest, nothing else.
SHA_TOOL=
if command -v sha256sum >/dev/null 2>&1; then
    SHA_TOOL=sha256sum
elif command -v shasum >/dev/null 2>&1; then
    SHA_TOOL=shasum
elif command -v openssl >/dev/null 2>&1; then
    SHA_TOOL=openssl
else
    die "need a SHA-256 tool: none of sha256sum, shasum, openssl found on PATH"
fi

# Emit the lowercase hex digest of file $1 on stdout.
sha256() {
    case "$SHA_TOOL" in
        sha256sum) sha256sum "$1" | awk '{print $1}' ;;
        shasum)    shasum -a 256 "$1" | awk '{print $1}' ;;
        openssl)   openssl dgst -sha256 "$1" | awk '{print $NF}' ;;
    esac
}

# R1.3 — normalize OS/arch so one CPU has one name across platforms. R1.4 — tool
# discovery uses `command -v`, never `which` (see above).
os=
case "$(uname -s)" in
    Linux)  os=linux ;;
    Darwin) os=darwin ;;
    *)      die "unsupported OS: $(uname -s) (installer covers Linux and macOS)" ;;
esac

arch=
case "$(uname -m)" in
    amd64|x86_64)  arch=amd64 ;;
    arm64|aarch64) arch=arm64 ;;
    *)             die "unsupported architecture: $(uname -m)" ;;
esac

[ -n "${HOME:-}" ] || die "HOME is not set; cannot resolve install prefixes"

# --- Unit 4: destination prefix resolution ---------------------------------

# R4.1 — map a prefix token to an absolute directory through a fixed case.
# The manifest string is NEVER shell-expanded or eval'ed; an unknown token is a
# hard error. Note the XDG variable names and that ~/.local/bin has no XDG var
# (hence MINIMAL_BIN).
resolve_prefix() {
    case "$1" in
        bin)   printf '%s\n' "${MINIMAL_BIN:-$HOME/.local/bin}" ;;
        data)  printf '%s\n' "${XDG_DATA_HOME:-$HOME/.local/share}/minimal" ;;
        state) printf '%s\n' "${XDG_STATE_HOME:-$HOME/.local/state}/minimal" ;;
        cache) printf '%s\n' "${XDG_CACHE_HOME:-$HOME/.cache}/minimal" ;;
        *)     die "unknown dest prefix token: $1" ;;
    esac
}

# --- Unit 2: target -> version -> manifest resolution ----------------------

# R2.1 — optional first argument, the target, defaulting to `stable`. The
# default applies only when no argument is given (`${1-…}`, not `${1:-…}`): an
# explicitly-passed empty string is a malformed target and must be rejected, not
# silently turned into `stable`. Validated against the safe charset before use.
# The charset forbids `/`, so a value is always a single path segment; `.` and
# `..` are rejected outright because curl normalizes `$BUCKET/..` back past the
# bucket prefix (RFC 3986 dot-segment removal) before the request is sent.
target="${1-stable}"
case "$target" in
    ''|.|..|*[!A-Za-z0-9._-]*) die "invalid target '$target' (allowed: A-Za-z0-9._-, not '.'/'..')" ;;
esac

# A trap-cleaned temp dir for the pointer and manifest. The BSD/GNU mktemp
# template split is bridged the portable way.
tmpdir="$(mktemp -d 2>/dev/null || mktemp -d -t minimal)" || die "mktemp failed"
trap 'rm -rf "$tmpdir"' EXIT

# R2.2 — resolve the target to a version via the pointer file. Command
# substitution strips the trailing newline; the charset check catches any
# internal whitespace or smuggled path segment.
fetch "$BUCKET/$target" "$tmpdir/pointer" \
    || die "could not fetch target pointer '$target' from $BUCKET/$target"
VERSION="$(cat "$tmpdir/pointer")"
# Same guard as the target: reject `.`/`..` so a compromised pointer cannot make
# `versions/$VERSION/components` normalize outside the versioned prefix.
case "$VERSION" in
    ''|.|..|*[!A-Za-z0-9._-]*) die "target '$target' resolved to a malformed version" ;;
esac
say "install: target '$target' -> version $VERSION"

# R2.3 — fetch that version's immutable components manifest.
manifest="$tmpdir/components"
fetch "$BUCKET/versions/$VERSION/components" "$manifest" \
    || die "could not fetch components manifest for version $VERSION"

# R2.4 — refuse a manifest whose format this installer does not understand.
fmt="$(awk '/^#[ \t]*format:/ {print $3; exit}' "$manifest")"
[ -n "$fmt" ] || die "manifest has no '# format:' header"
[ "$fmt" = "$SUPPORTED_FORMAT" ] \
    || die "unsupported manifest format '$fmt' (this installer supports $SUPPORTED_FORMAT); upgrade the installer"

# --- Units 3+5: field extraction, skip/download/verify/install -------------

# R3.1/R3.2/R3.3 — select every data row that applies to this host by EXACT
# field equality on awk-split columns. Comment and blank lines are dropped.
# The rows are written to a file and consumed by a `while read` fed via redirection
# so the loop body runs in this shell: its `die` exits the whole script and its counters persist.
applicable="$tmpdir/applicable"
awk -v o="$os" -v a="$arch" \
    '!/^#/ && NF && $2==o && $3==a {print}' "$manifest" >"$applicable"
[ -s "$applicable" ] || die "manifest lists no components for $os/$arch at version $VERSION"

records="$tmpdir/installed"
: >"$records"
installed=0 skipped=0

# The prior run's install record (R6.1) maps each component to the hash of the
# file it actually placed on disk. On macOS a `bin` file is ad-hoc code-signed
# after download (see below), so its installed bytes — and hash — differ from
# the manifest `sha256`; this lets a signed component be recognized as already
# installed without re-downloading. It is only a positive-match optimization: a
# deleted or tampered file matches neither hash and is reinstalled, so the
# on-disk file remains the source of truth (R5.1). Read before the new record is
# written into place at the end of the run.
state_dir="$(resolve_prefix state)"
prev_record="$state_dir/installed"
prev_installed_hash() {
    [ -f "$prev_record" ] || return 0
    # Records are tab-delimited; split on tab so a dest containing spaces (e.g. a
    # $HOME with a space) still parses.
    awk -F'\t' -v c="$1" '$1==c {print $3; exit}' "$prev_record"
}

# No field ever contains whitespace (R3.2), so default IFS splitting is exact.
# The os/arch/version columns are consumed into `_` (already matched in awk, or
# informational); comp/want/kind/dest/src are what drive the install.
while read -r comp _ _ _ want kind dest src; do
    # v1 handles single files only; an unknown kind is a hard error, not a
    # silent skip (the column reserves room for archive kinds later).
    [ "$kind" = file ] || die "component $comp has unsupported kind '$kind'"

    # dest is `<prefix-token>/<subpath>`. Require both halves.
    case "$dest" in
        */*) ;;
        *)   die "component $comp has malformed dest '$dest' (no subpath)" ;;
    esac
    prefix="${dest%%/*}"
    subpath="${dest#*/}"

    # R4.2 — reject an absolute subpath or any `..` component before it is used
    # to build a path, closing the traversal vector.
    case "$subpath" in
        ''|/*|..|../*|*/..|*/../*) die "component $comp has unsafe dest subpath '$subpath'" ;;
    esac

    dir="$(resolve_prefix "$prefix")"
    target_file="$dir/$subpath"

    # R5.1 — the on-disk file is the skip oracle. It is up to date if its hash
    # matches the manifest `sha256` OR (for a macOS `bin` file we signed last
    # run) the installed hash recorded then, since signing diverges the bytes.
    if [ -f "$target_file" ]; then
        on_disk="$(sha256 "$target_file")"
        if [ "$on_disk" = "$want" ] || [ "$on_disk" = "$(prev_installed_hash "$comp")" ]; then
            say "  $comp: up to date"
            skipped=$((skipped + 1))
            printf '%s\t%s\t%s\n' "$comp" "$target_file" "$on_disk" >>"$records"
            continue
        fi
    fi

    # R4.3/R5.2 — create the destination dir, then download to a temp sibling
    # IN that dir so the final rename is a same-filesystem atomic swap.
    mkdir -p "$dir"
    tmp="$target_file.tmp.$$"
    say "  $comp: downloading"
    fetch "$BUCKET/$src" "$tmp" || { rm -f "$tmp"; die "download failed: $comp ($src)"; }

    # R5.3 — verify the DOWNLOAD against the manifest before any local
    # post-processing modifies it; a mismatch removes the temp file and aborts,
    # so a truncated/corrupt artifact is never placed.
    got="$(sha256 "$tmp")"
    [ "$got" = "$want" ] || { rm -f "$tmp"; die "checksum mismatch for $comp (want $want, got $got)"; }

    # R5.4 — bin components appear executable at their final path atomically:
    # chmod the temp file, then rename.
    [ "$prefix" = bin ] && chmod +x "$tmp"

    # macOS: make a freshly-downloaded bin executable actually runnable before it
    # is placed. Strip the Gatekeeper quarantine attribute (metadata, so it never
    # affected the hash above; a no-op if absent — hence the swallowed error),
    # then ad-hoc self-sign: arm64 macOS refuses to exec an unsigned or
    # transfer-invalidated Mach-O, and our release binaries are not yet signed
    # with a developer identity. Signing rewrites the Mach-O, so the installed
    # bytes deliberately diverge from the manifest hash — the skip oracle and the
    # installed-hash record both account for this.
    if [ "$os" = darwin ] && [ "$prefix" = bin ]; then
        xattr -d com.apple.quarantine "$tmp" 2>/dev/null || true
        codesign --sign - --force "$tmp" || { rm -f "$tmp"; die "codesign failed: $comp"; }
    fi

    mv -f "$tmp" "$target_file"
    installed=$((installed + 1))
    # Record the hash of what is actually on disk now (== manifest hash except
    # for a signed macOS bin file), so a later run recognizes it (R5.1/R6.1).
    printf '%s\t%s\t%s\n' "$comp" "$target_file" "$(sha256 "$target_file")" >>"$records"
done <"$applicable"

# --- Unit 6: install record and PATH advisory ------------------------------

# R6.1 — persist the resolved (component, dest, installed-hash) rows for this
# platform, replacing the prior record read during the loop. Enables a future
# uninstall and surfaces prefix drift across XDG changes.
mkdir -p "$state_dir"
mv -f "$records" "$prev_record"

say "install: $installed installed, $skipped up to date -> record at $prev_record"

# R6.2 — if the bin prefix is not on PATH, advise the user; never edit an rc file.
bindir="$(resolve_prefix bin)"
case ":${PATH:-}:" in
    *":$bindir:"*) ;;
    *) say ""
       say "note: $bindir is not on your PATH."
       say "  add it, e.g.:  export PATH=\"$bindir:\$PATH\"" ;;
esac
