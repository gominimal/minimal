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
#   curl … | sh -s -- --force-stop      # stop live sessions without asking
#   curl … | sh -s -- --uninstall       # remove what a prior run installed
#
# An upgrade must stop the running daemon before it swaps its binaries.
# When that daemon has active sessions the installer asks on the terminal before
# ending them; --force-stop (or a non-empty MINIMAL_INSTALL_FORCE_STOP) skips the
# question, for scripted upgrades that must not block.
#
# Uninstall walks the local install record (no network) and removes each file
# whose on-disk bytes still match what the installer recorded writing; it accepts
# --force (remove modified files too), --purge (also delete the minimal data/
# state/cache trees), and --dry-run.
#
# After the files are placed, the installer wires up shell integration:
# it generates per-shell init files that prepend the bin dir to PATH, installs
# tab completions for `min` by running the freshly-installed binary, and adds a
# marker-fenced source line to the current shell's rc file. Uninstall undoes all
# of it (the generated files are ordinary install-record rows; the rc block is
# stripped by its markers).
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
# `# format:` header; a mismatch is a hard error, not a misparse.
SUPPORTED_FORMAT=1

# --- Output helpers --------------------------------------------------------

# All diagnostics go to stderr so a future machine-readable stdout stays clean.
#
# A component row is written in two halves on a terminal (the verb first, the
# finished row rewritten over it), so anything that prints in between has to
# close the open row first or its message lands mid-line. Every path out of
# this script prints through say/die, so closing there covers all of them.
row_open=0
end_row() { [ "$row_open" -eq 0 ] || { row_open=0; printf '\n' >&2; }; }
say() { end_row; printf '%s\n' "$*" >&2; }
die() { end_row; printf 'install: %s\n' "$*" >&2; exit 1; }

# --- Presentation ----------------------------------------------------------

# `curl … | sh` lands on everything from a modern terminal to a CI log with no
# terminal at all, so presentation degrades along two independent axes:
#
#   attr  — bold/dim SGR attributes. Needs stderr to be a terminal, NO_COLOR
#           unset or empty (no-color.org: only a non-empty value suppresses),
#           and a TERM that is not `dumb`. Also gates the two effects that
#           only make sense live: the in-place row rewrite and the mark.
#   glyph — the ▸ marker and → arrow (the marker matches `min`'s prompt theme
#           and the `min dash` cursor). Needs a UTF-8 locale; ASCII otherwise.
#           Independent of attr: UTF-8 in a redirected log is still fine.
#
# Deliberately monochrome — no color accents anywhere — because that is what
# the product and the website are (crates/minimal/src/theme.rs).
# MINIMAL_INSTALL_PLAIN=1 forces both axes off.
attr=0
glyph=0
if [ -z "${MINIMAL_INSTALL_PLAIN:-}" ]; then
    if [ -t 2 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != dumb ]; then
        attr=1
    fi
    case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in
        *UTF-8*|*utf-8*|*UTF8*|*utf8*) glyph=1 ;;
    esac
fi

if [ "$attr" -eq 1 ]; then
    b="$(printf '\033[1m')"
    dim="$(printf '\033[2m')"
    rst="$(printf '\033[0m')"
else
    b='' dim='' rst=''
fi

if [ "$glyph" -eq 1 ]; then
    mark='▸' arrow='→' sep='·'
else
    mark='>' arrow='->' sep='-'
fi

# One table row: the component in a fixed dim column, its verb, and an
# optional dim detail (a size, a path). `row_wait` writes the in-progress half
# and `row` finishes it — on a terminal by rewriting the same line, so a slow
# download narrates itself and still leaves exactly one clean line behind;
# everywhere else the two halves are ordinary consecutive lines, which is what
# a CI log wants anyway.
row_wait() {
    printf '  %s%-18s%s %s' "$dim" "$1" "$rst" "$2" >&2
    if [ "$attr" -eq 1 ]; then
        row_open=1
    else
        printf '\n' >&2
    fi
}
row() {
    if [ "$row_open" -eq 1 ]; then
        row_open=0
        printf '\r\033[K' >&2
    fi
    if [ -n "${3:-}" ]; then
        printf '  %s%-18s%s %-12s %s%s%s\n' "$dim" "$1" "$rst" "$2" "$dim" "$3" "$rst" >&2
    else
        printf '  %s%-18s%s %s\n' "$dim" "$1" "$rst" "$2" >&2
    fi
}

# Byte count -> one short human string. Integer arithmetic only (POSIX sh has
# no floats), so the MB tenth is computed by scaling before dividing.
human_size() {
    _hs="$1"
    if [ "$_hs" -ge 1048576 ]; then
        printf '%s.%s MB\n' "$((_hs / 1048576))" "$(((_hs % 1048576) * 10 / 1048576))"
    elif [ "$_hs" -ge 1024 ]; then
        printf '%s KB\n' "$((_hs / 1024))"
    else
        printf '%s B\n' "$_hs"
    fi
}

# $HOME-relative display path: the card and the table are meant to be read, and
# an absolute /Users/... prefix on every line is noise.
tilde() {
    case "$1" in
        "$HOME"/*) printf '~%s\n' "${1#"$HOME"}" ;;
        *)         printf '%s\n' "$1" ;;
    esac
}

# The mark, character-for-character the one in the README's session demo
# (docs/public/loadout-demo.cast): the three strokes of
# docs/public/minimal-mark-dark.svg in block glyphs, over the `minimal ·` line
# the same demo prints. One rendering of the mark in the terminal, not two.
#
# Terminal-only (attr), because a mark in a log file is litter, and only on a
# first install (see first_run below). The cast paints it 256-color 215; here
# it is bold and otherwise unpainted, like everything else the installer and
# the CLI print (crates/minimal/src/theme.rs). Without UTF-8 the blocks would
# render as mojibake, so that host gets the wordmark line alone.
wordmark() {
    [ "$attr" -eq 1 ] || return 0
    printf '\n' >&2
    if [ "$glyph" -eq 1 ]; then
        printf '%s%s\n%s\n%s%s\n\n' "$b" \
            '     ████  ████▄' \
            '  ▄▄▄ ▀███▄ ▀███▄' \
            '  ▀███  ▀███  ▀███' "$rst" >&2
    fi
    printf '  %sminimal%s %s%s Build Software You Can Trust%s\n' \
        "$b" "$rst" "$dim" "$sep" "$rst" >&2
}

# --- Mode dispatch: install (default) vs uninstall -------------------------

# `--uninstall` as the FIRST argument switches to uninstall mode; it is parsed
# here, before the target charset check, because `--uninstall` otherwise
# validates as a target and would be fetched as one. Uninstall is offline and
# takes its own flags; install mode's sole positional is the target, left in `$@`
# for target resolution below. The two modes are mutually exclusive.
MODE=install
uninstall_force=0
uninstall_purge=0
dry_run=0
# Install mode's escape hatch for the active-sessions prompt, settable by
# flag or environment because `curl … | sh` makes argv awkward. Deliberately NOT
# named --force: that flag already means "remove modified files" in uninstall.
force_stop=0
if [ -n "${MINIMAL_INSTALL_FORCE_STOP:-}" ]; then
    force_stop=1
fi
if [ "${1-}" = "--uninstall" ]; then
    MODE=uninstall
    shift
    while [ $# -gt 0 ]; do
        case "$1" in
            --force)      uninstall_force=1 ;;
            --purge)      uninstall_purge=1 ;;
            -n|--dry-run) dry_run=1 ;;
            *)            die "unknown uninstall option '$1' (allowed: --force, --purge, --dry-run)" ;;
        esac
        shift
    done
else
    # Install mode's only option. Filter it out of "$@" wherever it appears (by
    # rotating the kept arguments to the end) so the sole positional — the
    # target — is still $1 for target resolution, whichever side of the
    # flag it was on.
    argn=$#
    while [ "$argn" -gt 0 ]; do
        case "$1" in
            --force-stop) force_stop=1 ;;
            *)            set -- "$@" "$1" ;;
        esac
        shift
        argn=$((argn - 1))
    done
fi

# --- Environment probing (downloader, hasher, platform) --------------------

# Prefer curl, else wget. Both enforce HTTPS + TLS 1.2 and refuse a
# redirect that would downgrade the scheme. Uninstall never fetches, so a
# missing downloader is fatal only in install mode.
DL_TOOL=
if command -v curl >/dev/null 2>&1; then
    DL_TOOL=curl
elif command -v wget >/dev/null 2>&1; then
    DL_TOOL=wget
elif [ "$MODE" = install ]; then
    die "need a downloader: neither curl nor wget found on PATH"
fi

# Download $1 (url) to $2 (path). Fails non-zero on any HTTP/transport error.
fetch() {
    case "$DL_TOOL" in
        curl) curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL "$1" -o "$2" ;;
        wget) wget --https-only --secure-protocol=TLSv1_2 -qO "$2" "$1" ;;
    esac
}

# Prefer sha256sum, else `shasum -a 256`, else `openssl dgst -sha256`.
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

# Normalize OS/arch so one CPU has one name across platforms. Tool discovery
# uses `command -v`, never `which` (see above).
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

# --- Destination prefix resolution -----------------------------------------

# Map a prefix token to an absolute directory through a fixed case.
# The manifest string is NEVER shell-expanded or eval'ed; an unknown token is a
# hard error. Note the XDG variable names and that ~/.local/bin has no XDG var
# (hence MINIMAL_BIN).
resolve_prefix() {
    case "$1" in
        bin)   printf '%s\n' "${MINIMAL_BIN:-$HOME/.local/bin}" ;;
        lib)   printf '%s\n' "${XDG_LIB_HOME:-$HOME/.local/lib}" ;;
        data)  printf '%s\n' "${XDG_DATA_HOME:-$HOME/.local/share}/minimal" ;;
        state) printf '%s\n' "${XDG_STATE_HOME:-$HOME/.local/state}/minimal" ;;
        cache) printf '%s\n' "${XDG_CACHE_HOME:-$HOME/.cache}/minimal" ;;
        *)     die "unknown dest prefix token: $1" ;;
    esac
}

# The bin prefix, resolved once. Needed early: the pre-upgrade daemon stop
# runs the `min` already installed there, before the component loop
# replaces it.
bindir="$(resolve_prefix bin)"

# The prior run's install record maps each component to the hash of the
# file it placed on disk. Its path is needed early too: its absence is what
# makes this a first install rather than an upgrade, which is the one run that
# gets the mark. The on-disk files — not this record — remain the skip oracle
#: a deleted or tampered file matches nothing and is reinstalled.
state_dir="$(resolve_prefix state)"
prev_record="$state_dir/installed"
first_run=0
[ -f "$prev_record" ] || first_run=1

# Whole-second wall clock for the closing card. `date +%s` is not in POSIX but
# is in every shipped date (GNU, BSD, busybox); a host without it just loses
# the elapsed line.
t0="$(date +%s 2>/dev/null || echo 0)"

# --- Shared shell-integration paths and markers ----------------------------

# Where the generated (not downloaded) shell-integration files live. Init
# scripts sit under the minimal-owned data prefix; completions go to each
# shell's standard user-level lookup dir. Shared by install (write/record) and
# uninstall (strip/prune). The rc files themselves are the user's; the
# installer only ever appends/removes one marker-fenced block.
init_dir="$(resolve_prefix data)/shell-init"
bash_comp_dir="${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions"
zsh_comp_dir="${XDG_DATA_HOME:-$HOME/.local/share}/zsh/completions"
fish_comp_dir="${XDG_CONFIG_HOME:-$HOME/.config}/fish/completions"
fish_config="${XDG_CONFIG_HOME:-$HOME/.config}/fish/config.fish"
zshrc="${ZDOTDIR:-$HOME}/.zshrc"
# zsh's compinit caches completion registrations here, and its staleness check
# is only (zsh version, completion-file count) — it cannot see `_min` appear,
# change, or vanish when the count happens to stay equal. The dump is a pure,
# regenerable cache: both install and uninstall drop it when they change the
# zsh completions, forcing a real rescan on the next zsh startup.
zcompdump="${ZDOTDIR:-$HOME}/.zcompdump"

marker_start='# >>> minimal >>>'
marker_end='# <<< minimal <<<'

# Remove the marker-fenced block from rc file $1. Rewrites via a temp
# sibling + atomic mv — `sed -i` is not portable across BSD/GNU. A file without
# the start marker is never rewritten (or even opened for write).
strip_rc_block() {
    [ -f "$1" ] || return 0
    grep -q '>>> minimal >>>' "$1" 2>/dev/null || return 0
    # Refuse a file whose start marker has no matching end marker (hand edits
    # happen): the filter below would otherwise silently drop everything from
    # that marker to EOF — the strip must never cost the user their rc tail.
    # Distinct exit code so add_rc_block can tell "markers are broken" from
    # "file not writable". Checked before the dry-run branch so a dry run
    # predicts the real outcome.
    if ! awk -v s="$marker_start" -v e="$marker_end" \
            '$0==s {open=1} $0==e {open=0} END {exit open}' "$1"; then
        say "  warning: unterminated minimal block in $1, left untouched"
        return 2
    fi
    if [ "$dry_run" -eq 1 ]; then
        say "  would remove shell-init block from $(tilde "$1")"
        return 0
    fi
    _tmp="$1.tmp.$$"
    awk -v s="$marker_start" -v e="$marker_end" \
        '$0==s {skip=1; next} $0==e {skip=0; next} !skip' "$1" >"$_tmp" \
        || { rm -f "$_tmp"; die "failed to rewrite $1"; }
    mv -f "$_tmp" "$1"
    say "  removed shell-init block from $(tilde "$1")"
}

# Offer to also remove the *system* AppArmor profile on uninstall. That profile
# (packaging/apparmor/minimald) is installed separately, with root, by
# install-apparmor-profile.sh; it outlives minimald, leaving an inert label
# bound to a now-absent binary path under /etc/apparmor.d. Removing it needs
# root — which this installer never assumes — so on an interactive terminal we
# prompt and, on yes, elevate via the shipped loader's own --uninstall (run here,
# before the record walk deletes that loader). Piped (curl|sh), non-interactive,
# or dry-run: advise the root command instead, which stays valid after the walk.
# Gated on the profile actually being present, so macOS and never-set-up hosts
# see nothing. The apparmor.d path is overridable for install_test.sh.
maybe_remove_apparmor_profile() {
    _aa_dir="${MINIMAL_OVERRIDE_APPARMOR_DIR:-/etc/apparmor.d}"
    _aa_profile="$_aa_dir/minimald"
    [ -e "$_aa_profile" ] || return 0
    _aa_tunable="$_aa_dir/tunables/minimald"

    if [ "$dry_run" -eq 1 ]; then
        say "  would offer to remove the system AppArmor profile $_aa_profile"
        return 0
    fi

    # Prompt only when stdin is a terminal. Under `curl … | sh -s -- --uninstall`
    # stdin is the script pipe, not a tty, so advise rather than consume it.
    if [ -t 0 ]; then
        _aa_loader="$(resolve_prefix data)/apparmor/install-apparmor-profile.sh"
        printf 'Also remove the system AppArmor profile %s (needs root)? [y/N] ' \
            "$_aa_profile" >&2
        _aa_ans=
        read -r _aa_ans || _aa_ans=
        case "$_aa_ans" in
            [Yy]*)
                if [ -f "$_aa_loader" ] && command -v sudo >/dev/null 2>&1 \
                    && sudo bash "$_aa_loader" --uninstall; then
                    return 0
                fi
                say "  warning: could not remove it automatically; do it manually (root):"
                say "      sudo apparmor_parser -R \"$_aa_profile\" && sudo rm -f \"$_aa_profile\" \"$_aa_tunable\""
                return 0
                ;;
            *) return 0 ;;
        esac
    fi

    say ""
    say "note: the system AppArmor profile is still loaded at $_aa_profile."
    say "  it was installed separately with root; remove it too with:"
    say "      sudo apparmor_parser -R \"$_aa_profile\" && sudo rm -f \"$_aa_profile\" \"$_aa_tunable\""
}

# --- Uninstall (walk the install record and undo it) -----------------------

# Offline teardown driven solely by the local install record. The record
# is a tab-delimited table of `component<TAB>dest<TAB>manifest-hash<TAB>installed-hash`
# rows, where `dest` is absolute and `installed-hash` is the SHA-256 of the bytes
# actually written. Uninstall keys off `installed-hash`; the manifest-hash column
# is unused here (it equals installed-hash for records written by this installer,
# but may differ in records written by older signing installers). A file is removed
# only if it is still byte-for-byte what we recorded writing, so a
# user's edited or replaced file is kept unless --force. Runs entirely on local
# state: no network, manifest, or bucket.
do_uninstall() {
    state_dir="$(resolve_prefix state)"
    record="$state_dir/installed"

    # No record means nothing to undo (or it is already gone). Absence is
    # success, so a second --uninstall is a clean no-op.
    if [ ! -f "$record" ]; then
        say "uninstall: nothing to uninstall (no install record at $(tilde "$record"))"
        return 0
    fi
    say ""
    [ "$dry_run" -eq 1 ] && say "uninstall: dry run — nothing will be removed"

    # Before the walk (which deletes the shipped loader), offer to tear down the
    # separately-installed system AppArmor profile too.
    maybe_remove_apparmor_profile

    # Tab, computed once, so rows are split on tab alone: a dest under a
    # $HOME containing spaces must still parse as one field.
    tab="$(printf '\t')"
    removed=0 absent=0 kept_modified=0 kept_foreign=0 had_zsh_completions=0

    # `comp` is informational here and the manifest-hash column (`_`) is unused;
    # `dest`/`want` (the installed hash) drive removal. Read from the record via
    # redirection so the loop body runs in this shell (counters persist).
    while IFS="$tab" read -r comp dest _ want; do
        [ -n "$dest" ] || continue

        # A completions-zsh row (whatever the file's fate below) means a
        # compinit dump may hold a `min` registration; noted for the cache
        # drop after the walk.
        [ "$comp" = completions-zsh ] && had_zsh_completions=1

        # Already gone (not even a dangling symlink) — count and continue, which
        # is what makes an interrupted run re-runnable.
        if [ ! -e "$dest" ] && [ ! -L "$dest" ]; then
            row "$comp" "already gone"
            absent=$((absent + 1))
            continue
        fi

        # A `link:<target>` row is a symlink the installer created; the
        # regular-file rules below don't apply. It is still ours while the
        # path is a symlink pointing at the recorded target — `rm` removes the
        # link itself, never what it points at. A retargeted link is the
        # user's edit (kept unless --force); a non-symlink is foreign, always
        # kept.
        case "$want" in
            link:*)
                if [ ! -L "$dest" ]; then
                    row "$comp" kept "$(tilde "$dest") is not a symlink the installer wrote"
                    kept_foreign=$((kept_foreign + 1))
                elif [ "$(readlink "$dest")" != "${want#link:}" ] && [ "$uninstall_force" -eq 0 ]; then
                    row "$comp" kept "retargeted since install; pass --force to remove"
                    kept_modified=$((kept_modified + 1))
                elif [ "$dry_run" -eq 1 ]; then
                    row "$comp" "would remove" "$(tilde "$dest")"
                    removed=$((removed + 1))
                else
                    rm -f "$dest" || die "failed to remove $dest"
                    row "$comp" removed "$(tilde "$dest")"
                    removed=$((removed + 1))
                fi
                continue
                ;;
        esac

        # A `file` row only ever wrote a regular file. A symlink or directory
        # now at this path is something else — never follow it into a delete.
        if [ -L "$dest" ] || [ ! -f "$dest" ]; then
            row "$comp" kept "$(tilde "$dest") is not a regular file the installer wrote"
            kept_foreign=$((kept_foreign + 1))
            continue
        fi

        # Remove only if the on-disk bytes still equal the recorded
        # installed-hash, unless --force.
        if [ "$(sha256 "$dest")" != "$want" ] && [ "$uninstall_force" -eq 0 ]; then
            row "$comp" kept "modified since install; pass --force to remove"
            kept_modified=$((kept_modified + 1))
            continue
        fi

        if [ "$dry_run" -eq 1 ]; then
            row "$comp" "would remove" "$(tilde "$dest")"
        else
            rm -f "$dest" || die "failed to remove $dest"
            row "$comp" removed "$(tilde "$dest")"
        fi
        removed=$((removed + 1))
    done <"$record"

    # Strip the marker-fenced shell-init block from every rc file the
    # installer may have edited (which shell's rc got it depends on $SHELL at
    # install time, so try them all — a file without markers is untouched).
    # The generated init/completion files themselves are ordinary record rows,
    # already handled by the walk above.
    kept_rc=0
    for _rc in "$HOME/.bashrc" "$HOME/.bash_profile" "$zshrc" "$fish_config" "$HOME/.profile"; do
        # An unterminated block returns non-zero (file kept, warning printed);
        # that must not abort the walk over the remaining rc candidates, but it
        # does mean a block survives, which the record teardown below must see.
        strip_rc_block "$_rc" || kept_rc=1
    done

    # The `min` registration also lives on inside zsh's compinit dump
    # (see zcompdump above); left behind, the first `min <tab>` in every new
    # zsh fails with "function definition file not found". Dropped only when
    # the record shows zsh completions were installed: the dump belongs to
    # the user, and an install that never touched zsh completions has no
    # business clearing their cache.
    if [ "$had_zsh_completions" -eq 1 ] && [ -f "$zcompdump" ]; then
        if [ "$dry_run" -eq 1 ]; then
            say "  would remove compinit dump cache $(tilde "$zcompdump")"
        elif rm -f "$zcompdump" 2>/dev/null; then
            say "  removed compinit dump cache $(tilde "$zcompdump")"
        else
            say "  warning: could not remove compinit dump cache $(tilde "$zcompdump")"
        fi
    fi

    # Teardown LAST, after the walk and the shell teardown above. The record is
    # the only inventory a later run has, and `--uninstall` treats its absence as
    # "nothing to undo", so dropping it early strands whatever the run failed to
    # remove: an unremoved rc block (or a kept component) would become
    # uninstallable. Remove it only once the footprint is fully gone; otherwise
    # retain it so a later `--force`/manual cleanup still has something to work
    # from. Re-running is idempotent: already-removed rows re-classify as
    # already-gone.
    if [ "$kept_modified" -ne 0 ] || [ "$kept_foreign" -ne 0 ]; then
        say "  kept install record $(tilde "$record") (unremoved entries remain)"
    elif [ "$kept_rc" -ne 0 ]; then
        say "  kept install record $(tilde "$record") (shell-init block remains)"
    elif [ "$dry_run" -eq 1 ]; then
        say "  would remove install record $(tilde "$record")"
    else
        rm -f "$record"
    fi

    # --purge additionally deletes the minimal-owned trees wholesale (build
    # cache included); they live at fixed .../minimal paths the tool owns. It
    # never removes files outside those roots.
    if [ "$uninstall_purge" -eq 1 ]; then
        for p in data state cache; do
            d="$(resolve_prefix "$p")"
            [ -d "$d" ] || continue
            if [ "$dry_run" -eq 1 ]; then
                say "  would purge $d"
            else
                rm -rf "$d"
            fi
        done
    fi

    # Prune now-empty minimal-owned dirs with rmdir only (never rm -rf):
    # the shared bin/lib dirs are removed only if empty, and a non-empty dir fails
    # rmdir harmlessly. --purge (above) already cleared the data/state/cache trees.
    # lib (~/.local/lib) is shared like bin, so it is only ever rmdir'd-if-empty,
    # never purged.
    if [ "$dry_run" -eq 0 ]; then
        # Shell-integration dirs first: the init dir must empty out
        # before the data prefix can, and the completion dirs (plus their
        # parents, which the installer may have created) are shared with other
        # tools so, like bin, they are only ever rmdir'd-if-empty.
        for d in "$init_dir" \
                 "$(resolve_prefix data)/apparmor/tunables" \
                 "$(resolve_prefix data)/apparmor" \
                 "$bash_comp_dir" "${bash_comp_dir%/*}" \
                 "$zsh_comp_dir" "${zsh_comp_dir%/*}" \
                 "$fish_comp_dir"; do
            if [ -d "$d" ]; then
                rmdir "$d" 2>/dev/null || true
            fi
        done
        for p in bin lib data state cache; do
            d="$(resolve_prefix "$p")"
            if [ -d "$d" ]; then
                rmdir "$d" 2>/dev/null || true
            fi
        done
    fi

    # A run that merely kept modified files still did what was asked; only
    # an unexpected internal failure (via set -e / die) is non-zero.
    say ""
    say "uninstall: $removed removed, $absent already gone, $kept_modified kept (modified), $kept_foreign kept (foreign)"
    [ "$dry_run" -eq 1 ] && say "uninstall: dry run — nothing was actually removed"
    return 0
}

# Dispatch uninstall before any target/manifest work. resolve_prefix and
# the SHA/platform probes above are all it needs; it never resolves a target.
if [ "$MODE" = uninstall ]; then
    do_uninstall
    exit 0
fi

# --- Target -> version -> manifest resolution ------------------------------

# The target. A non-empty MINIMAL_INSTALL_TARGET_OVERRIDE (injected by
# the download endpoint for a pinned target) wins outright; otherwise it is the
# optional first argument, defaulting to `stable`. The default applies only when
# no argument is given (`${1-…}`, not `${1:-…}`): an explicitly-passed empty
# string is a malformed target and must be rejected, not silently turned into
# `stable`. Validated against the safe charset before use. The charset forbids
# `/`, so a value is always a single path segment; `.` and `..` are rejected
# outright because curl normalizes `$BUCKET/..` back past the bucket prefix
# (RFC 3986 dot-segment removal) before the request is sent.
target="${MINIMAL_INSTALL_TARGET_OVERRIDE:-${1-stable}}"
case "$target" in
    ''|.|..|*[!A-Za-z0-9._-]*) die "invalid target '$target' (allowed: A-Za-z0-9._-, not '.'/'..')" ;;
esac

# A trap-cleaned temp dir for the pointer and manifest. The BSD/GNU mktemp
# template split is bridged the portable way.
tmpdir="$(mktemp -d 2>/dev/null || mktemp -d -t minimal)" || die "mktemp failed"
trap 'rm -rf "$tmpdir"' EXIT

# Resolve the target to a version via the pointer file. Command
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
# The mark waits for a resolved version: a run that cannot even reach the
# bucket should print an error, not a logo.
if [ "$first_run" -eq 1 ]; then
    wordmark
fi
say ""
say "$mark target '$target' $arrow $b$VERSION$rst"
say ""

# Fetch that version's immutable components manifest.
manifest="$tmpdir/components"
fetch "$BUCKET/versions/$VERSION/components" "$manifest" \
    || die "could not fetch components manifest for version $VERSION"

# Refuse a manifest whose format this installer does not understand.
fmt="$(awk '/^#[ \t]*format:/ {print $3; exit}' "$manifest")"
[ -n "$fmt" ] || die "manifest has no '# format:' header"
[ "$fmt" = "$SUPPORTED_FORMAT" ] \
    || die "unsupported manifest format '$fmt' (this installer supports $SUPPORTED_FORMAT); upgrade the installer"

# --- Field extraction, skip/download/verify/install ------------------------

# Select every data row that applies to this host by EXACT
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

# Swapping binaries under a running daemon wedges it: the daemon keeps
# serving from the old image while the new `min` talks to it. Stop it first,
# using the `min` ALREADY on disk — that one matches the daemon it started, and
# it is about to be overwritten. Deliberately best-effort and silent: nothing
# installed yet, no daemon running, or a `min` too old to have `stop` all mean
# "nothing to stop", and none of them should fail an install whose binaries are
# otherwise fine. `min stop` only connects (it never autospawns), so with no
# daemon up this is a failed connect and nothing more.
#
# The graceful `min stop` goes first because it already refuses while sessions
# are live, printing exactly this message — the one signal that an upgrade is
# about to destroy someone's work, and worth a question. Matched literally
# rather than on exit status: a bare non-zero also means no daemon, a failed
# connect, or a transport drop on an otherwise successful stop, and none of
# those may turn every upgrade into a prompt.
#
# Every `min` below reads from /dev/null: this runs inside the component loop,
# whose stdin is the applicable-manifest file, and a child that ever read stdin
# would eat the rows still to be installed.
sessions_live_msg='daemon has active sessions'

# Ask, on the CONTROLLING TERMINAL, whether to end the live sessions. Under
# `curl … | sh` stdin is the script pipe, so reading the answer from it would
# consume the script; /dev/tty is the only sound source (overridable so the
# test harness can drive both answers). No terminal to ask on — CI, a
# non-interactive shell — means nobody can consent: say so and let the caller
# abort, rather than hang or silently destroy work. Returns non-zero when the
# upgrade must not proceed.
confirm_force_stop() {
    _tty="${MINIMAL_OVERRIDE_TTY:-/dev/tty}"
    say ""
    say "warning: the running daemon has active sessions:"
    "$bindir/min" ls >&2 </dev/null || true
    say ""
    if ! (exec <"$_tty") 2>/dev/null; then
        say "there is no terminal to confirm on; rerun with --force-stop"
        say "(or MINIMAL_INSTALL_FORCE_STOP=1) to stop those sessions anyway."
        return 1
    fi
    printf 'Stopping the daemon ends them. Continue? [y/N] ' >&2
    _ans=
    read -r _ans <"$_tty" || _ans=
    case "$_ans" in
        [Yy]*) return 0 ;;
        *)     return 1 ;;
    esac
}

daemon_stop_tried=0
stop_running_daemon() {
    [ "$daemon_stop_tried" -eq 0 ] || return 0
    daemon_stop_tried=1
    [ -x "$bindir/min" ] || return 0

    if [ "$force_stop" -eq 0 ]; then
        # Stopped gracefully (or there was nothing to stop): done, no --force.
        if _stop_out="$("$bindir/min" stop 2>&1 </dev/null)"; then
            return 0
        fi
        case "$_stop_out" in
            *"$sessions_live_msg"*) confirm_force_stop || return 1 ;;
        esac
        # Any other failure falls through to the force stop, silent as before.
    fi
    "$bindir/min" stop --force >/dev/null 2>&1 </dev/null || true
}

# No field ever contains whitespace, so default IFS splitting is exact.
# The os/arch/version columns are consumed into `_` (already matched in awk, or
# informational); comp/want/kind/dest/src are what drive the install.
while read -r comp _ _ _ want kind dest src; do
    # `file` and `symlink` are the kinds this installer understands; an
    # unknown kind is a hard error, not a silent skip (the column reserves
    # room for archive kinds later).
    case "$kind" in
        file|symlink) ;;
        *) die "component $comp has unsupported kind '$kind'" ;;
    esac

    # dest is `<prefix-token>/<subpath>`. Require both halves.
    case "$dest" in
        */*) ;;
        *)   die "component $comp has malformed dest '$dest' (no subpath)" ;;
    esac
    prefix="${dest%%/*}"
    subpath="${dest#*/}"

    # Reject an absolute subpath or any `..` component before it is used
    # to build a path, closing the traversal vector.
    case "$subpath" in
        ''|/*|..|../*|*/..|*/../*) die "component $comp has unsafe dest subpath '$subpath'" ;;
    esac

    dir="$(resolve_prefix "$prefix")"
    target_file="$dir/$subpath"

    # A symlink component: `src` is the LINK TARGET rather than a bucket
    # path, resolved by the OS relative to the link's own directory. It gets
    # the same traversal discipline as the dest subpath, so a manifest can only
    # point a link within its own prefix. Nothing is downloaded either way.
    if [ "$kind" = symlink ]; then
        case "$src" in
            ''|/*|..|../*|*/..|*/../*) die "component $comp has unsafe symlink target '$src'" ;;
        esac
        if [ -L "$target_file" ] && [ "$(readlink "$target_file")" = "$src" ]; then
            row "$comp" current
            skipped=$((skipped + 1))
        else
            # Atomic like a file component: create the link as a temp sibling
            # and rename it
            # over whatever holds the path now — notably a stale regular file
            # from a release that shipped this component as a copy.
            mkdir -p "$dir"
            tmp="$target_file.tmp.$$"
            ln -s "$src" "$tmp" || { rm -f "$tmp"; die "failed to create symlink for $comp"; }
            mv -f "$tmp" "$target_file"
            row "$comp" linked "$arrow $src"
            installed=$((installed + 1))
        fi
        # No artifact hashes exist for a link; both hash columns carry the
        # link target instead (`link:` cannot collide with a hex digest), so
        # --uninstall can verify the link is still ours.
        printf '%s\t%s\t%s\t%s\n' "$comp" "$target_file" "link:$src" "link:$src" >>"$records"
        continue
    fi

    # The on-disk file is the skip oracle: it is up to date when its hash
    # equals the manifest `sha256`. A changed manifest hash (a new release) fails
    # this check and is re-downloaded.
    if [ -f "$target_file" ]; then
        on_disk="$(sha256 "$target_file")"
        if [ "$on_disk" = "$want" ]; then
            row "$comp" current
            skipped=$((skipped + 1))
            printf '%s\t%s\t%s\t%s\n' "$comp" "$target_file" "$want" "$on_disk" >>"$records"
            continue
        fi
    fi

    # Create the destination dir, then download to a temp sibling
    # IN that dir so the final rename is a same-filesystem atomic swap. Create
    # the target file's PARENT (not just the prefix root): a component whose
    # subpath nests dirs (e.g. apparmor/tunables/minimald) needs them made first.
    mkdir -p "${target_file%/*}"
    tmp="$target_file.tmp.$$"
    row_wait "$comp" downloading
    fetch "$BUCKET/$src" "$tmp" || { rm -f "$tmp"; die "download failed: $comp ($src)"; }

    # Verify the DOWNLOAD against the manifest before any local
    # post-processing modifies it; a mismatch removes the temp file and aborts,
    # so a truncated/corrupt artifact is never placed.
    got="$(sha256 "$tmp")"
    [ "$got" = "$want" ] || { rm -f "$tmp"; die "checksum mismatch for $comp (want $want, got $got)"; }

    # Bin components appear executable at their final path atomically:
    # chmod the temp file, then rename.
    [ "$prefix" = bin ] && chmod +x "$tmp"

    # macOS: strip the Gatekeeper quarantine attribute from a freshly-downloaded
    # Mach-O (a bin executable or the shipped lib dylib) so it runs without a
    # Gatekeeper prompt.
    if [ "$os" = darwin ] && { [ "$prefix" = bin ] || [ "$prefix" = lib ]; }; then
        xattr -d com.apple.quarantine "$tmp" 2>/dev/null || true
    fi

    # Last moment before the first live file is swapped, so a run where
    # every component is up to date (or one that dies fetching/verifying) never
    # touches a healthy daemon. The guard inside makes this a no-op after the
    # first replaced component. Only executable images wedge a running daemon
    # (bin, and lib — minvmd's @rpath dylib); replacing a data file (e.g. a
    # re-shipped apparmor text) must not kill live sessions.
    # A declined (or unconfirmable) stop aborts here, still before the first
    # rename: the downloaded temp file is dropped, no record is written, and
    # the daemon and its sessions are left exactly as they were. The message
    # claims only what the abort point guarantees — the stop runs before the
    # FIRST bin/lib swap, so no executable has been replaced, but a `data` row
    # earlier in the manifest may already have been.
    case "$prefix" in
        bin|lib)
            stop_running_daemon || {
                rm -f "$tmp"
                die "aborted: no executables were replaced, the daemon is still running"
            }
            ;;
    esac

    mv -f "$tmp" "$target_file"
    row "$comp" installed "$(human_size "$(wc -c <"$target_file" | tr -d ' ')")"
    installed=$((installed + 1))
    # Record the manifest hash paired with the on-disk hash, so a later
    # run and `--uninstall` know what this run placed. The
    #
    # paired-column format is retained for compatibility with records
    # written by earlier installer versions.
    printf '%s\t%s\t%s\t%s\n' "$comp" "$target_file" "$want" "$(sha256 "$target_file")" >>"$records"
done <"$applicable"

# --- Generated shell-init files and completions ----------------------------

# Append a generated file to this run's install record so a later run and
# `--uninstall` treat it exactly like a downloaded component. No
# manifest hash exists for generated content, so both hash columns carry the
# on-disk digest.
record_generated() {
    _h="$(sha256 "$2")"
    printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$_h" "$_h" >>"$records"
}

# Per-shell init files, regenerated on every run. Each embeds the bin
# dir as resolved NOW and guards at shell startup (dir exists, not already on
# PATH), so sourcing is idempotent and a no-op once the user manages PATH
# themselves. Only shell-runtime variables are escaped in the heredocs; the
# unescaped $bindir/$zsh_comp_dir/$fish_comp_dir expand at generation time.
mkdir -p "$init_dir"

cat >"$init_dir/bash.sh" <<EOF
# minimal shell init for bash
# Completions are auto-loaded from $bash_comp_dir/

if [ -d "$bindir" ]; then
    case ":\${PATH}:" in
        *":$bindir:"*) ;;
        *) export PATH="$bindir:\$PATH" ;;
    esac
fi
EOF
record_generated shell-init-bash "$init_dir/bash.sh"

cat >"$init_dir/zsh.sh" <<EOF
# minimal shell init for zsh
# Adds the completions dir to fpath before compinit.

if [ -d "$bindir" ]; then
    case ":\${PATH}:" in
        *":$bindir:"*) ;;
        *) export PATH="$bindir:\$PATH" ;;
    esac
fi

# Completions
if [ -d "$zsh_comp_dir" ]; then
    fpath=("$zsh_comp_dir" \$fpath)
    autoload -Uz compinit
    compinit
    # compinit trusts a cached dump whenever its (zsh version, completion-file
    # count) header matches — a check that misses real changes, e.g. one
    # completions dir replacing another with the same file count. If min is
    # still unregistered while its completion file exists, the dump lied:
    # drop it and scan for real. The file-exists guard keeps this from
    # rebuilding the dump on every startup when completions were never
    # generated.
    if [ -f "$zsh_comp_dir/_min" ] && [ -z "\${_comps[min]:-}" ]; then
        rm -f "\${ZDOTDIR:-\$HOME}/.zcompdump"
        compinit
    fi
fi
EOF
record_generated shell-init-zsh "$init_dir/zsh.sh"

cat >"$init_dir/fish.fish" <<EOF
# minimal shell init for fish
# Completions are auto-loaded from $fish_comp_dir/

if test -d "$bindir"
    fish_add_path --prepend "$bindir"
end
EOF
record_generated shell-init-fish "$init_dir/fish.fish"

# Tab completions, installed by the just-installed binary itself
# (`min completions install <shell>`), so they always match the installed
# version and the bookkeeping — target dir per shell, atomic write,
# unwritable-dir tolerance, zsh zcompdump invalidation — has exactly one
# implementation, reachable by everyone rather than only by `curl | sh` users.
# The binary prints every path it wrote on stdout, one per line; that is the
# contract, and those paths are what this records. A failure here is a warning,
# not an error: the binaries are already correctly installed, and completions
# regenerate on the next run.
gen_completions() {
    _out="$tmpdir/completions.out"
    _err="$tmpdir/completions.err"
    # One shell per call, so each record row still names the shell it belongs
    # to (uninstall walks those rows). The binary exits 0 even when it skipped
    # a shell with a warning, so a non-zero status means the binary itself is
    # unusable — the one case where its stderr is dropped rather than relayed,
    # since an unrunnable `min` produces the shell's noise, not a warning.
    if ! "$bindir/min" completions install "$1" >"$_out" 2>"$_err"; then
        say "  completions: warning: could not generate $1 completions (non-fatal)"
        return 0
    fi
    # Its warnings (an unwritable dir) and notices (a dropped compinit dump)
    # arrive on stderr, re-emitted here so they read like the rest of the
    # installer's output.
    while IFS= read -r _line; do
        say "  completions: $_line"
    done <"$_err"
    while IFS= read -r _path; do
        [ -f "$_path" ] || continue
        record_generated "completions-$1" "$_path"
    done <"$_out"
}

if [ -x "$bindir/min" ]; then
    # One open row across all three shells: each shell's own warnings (an
    # unwritable dir) close it and print above, so the finished row still
    # lands last and still reads as one line.
    row_wait completions generating
    gen_completions bash
    gen_completions zsh
    gen_completions fish
    row completions installed "bash zsh fish"
else
    row completions skipped "$(tilde "$bindir")/min not present"
fi

# --- Install record and PATH advisory --------------------------------------

# Migration: the switch binary used to install as `bin/gvproxy` and now installs
# as `bin/gvproxy-min` (the bin prefix is on PATH, and podman/crc ship their own
# `gvproxy` there). The renamed component is a *new* row, so the old file is no
# longer referenced by any manifest and the record walk would never revisit it —
# it would sit on PATH forever, which is the collision the rename exists to
# remove. Undo it here on the same terms as uninstall: remove it only when its
# bytes are still exactly what we recorded writing, so a user who replaced that
# path with their own gvproxy keeps it.
remove_renamed_gvproxy() {
    [ -f "$prev_record" ] || return 0
    _tab="$(printf '\t')"
    # Only a RENAME justifies deleting the old path. If the manifest this run
    # installed still ships a `gvproxy` component, the file on disk is the one
    # we just placed — deleting it would leave the host with no switch binary
    # at all, on every run. Channels advance independently, so a post-rename
    # installer WILL be pointed at a pre-rename manifest.
    if cut -f1 "$records" | grep -qx gvproxy; then
        return 0
    fi
    while IFS="$_tab" read -r _comp _dest _ _want; do
        [ "$_comp" = gvproxy ] || continue
        [ -n "$_dest" ] || continue
        [ -f "$_dest" ] || continue
        # A symlink row, or one we did not write, is not ours to remove.
        [ -L "$_dest" ] && continue
        case "$_want" in link:*) continue ;; esac
        # No dry-run branch: --dry-run is an uninstall-only option, and
        # uninstall is dispatched long before this runs.
        if [ "$(sha256 "$_dest")" != "$_want" ]; then
            say "  gvproxy: kept $_dest (modified since install; now shipped as gvproxy-min)"
        elif rm -f "$_dest"; then
            say "  gvproxy: removed $_dest (renamed to gvproxy-min)"
        else
            # Carry the row into this run's record so the next run retries.
            # Without it the migration gets exactly one attempt — the record is
            # replaced below — and a stale gvproxy would sit on PATH forever,
            # which is the collision the rename exists to remove.
            say "  gvproxy: could not remove $_dest; will retry on the next install"
            printf '%s\t%s\t%s\t%s\n' "$_comp" "$_dest" "$_want" "$_want" >>"$records"
        fi
    done <"$prev_record"
}
remove_renamed_gvproxy

# Persist the resolved (component, dest, installed-hash) rows for this
# platform, replacing the prior record read during the loop. Enables a future
# uninstall and surfaces prefix drift across XDG changes.
mkdir -p "$state_dir"
mv -f "$records" "$prev_record"

# --- Hook the current shell's rc file --------------------------------------

# Append one marker-fenced block sourcing the matching init file to the
# rc of the user's login shell ($SHELL). The markers are ours to own: a block
# already sourcing the current init file is left alone (reruns add nothing),
# but a marker block with any other content is stale — e.g. the pre-rewrite
# installer's, sourcing ~/.minimal/shim/shell-init — and is replaced, or PATH
# and completions silently break on upgraded machines. The markers are also
# what --uninstall strips (strip_rc_block).
add_rc_block() {
    _verb=added
    _hook_ok=1
    if grep -q '>>> minimal >>>' "$1" 2>/dev/null; then
        if grep -qxF "$2" "$1" 2>/dev/null; then
            return 0
        fi
        # Subshell: strip_rc_block dies on a failed rewrite, which must stay
        # non-fatal (and quiet) here; only the subshell exits. Exit 2 means an
        # unterminated marker block: never append after a stray start marker —
        # a later strip would then eat everything between it and our end
        # marker, the exact truncation the strip guard exists to prevent.
        _strip_rc=0
        ( strip_rc_block "$1" ) >/dev/null 2>&1 || _strip_rc=$?
        if [ "$_strip_rc" -eq 2 ]; then
            say "  warning: cannot hook minimal shell support: unterminated minimal block in $1"
            say "  fix or remove its '# >>> minimal >>>' block, or add this line yourself:"
            say "      $2"
            return 0
        fi
        [ "$_strip_rc" -eq 0 ] || _hook_ok=0
        _verb=replaced
    fi
    # Non-fatal: by this point the binaries are correctly installed, so an
    # unwritable rc file must not turn a successful install into a failure.
    # Warn, tell the user what to add by hand, and keep going (the PATH
    # advisory below still fires).
    # The subshell wrapper (not just 2>/dev/null on the command) is what keeps
    # a redirection failure quiet: that error is printed by the shell itself,
    # before the command-level stderr redirect is in effect.
    if [ "$_hook_ok" -eq 1 ]; then
        ( mkdir -p "${1%/*}" \
            && printf '\n%s\n%s\n%s\n' "$marker_start" "$2" "$marker_end" >>"$1" ) 2>/dev/null \
            || _hook_ok=0
    fi
    if [ "$_hook_ok" -eq 0 ]; then
        say "  warning: failed to hook minimal shell support ($1 is not writable)"
        say "  to enable it yourself, add this line to your shell rc:"
        say "      $2"
        return 0
    fi
    row shell-init "$_verb" "$(tilde "$1")"
}

posix_line="[ -f \"$init_dir/bash.sh\" ] && . \"$init_dir/bash.sh\""
shell_name="${SHELL:-/bin/sh}"
shell_name="${shell_name##*/}"
case "$shell_name" in
    bash)
        # Append to whichever bash rc files exist (a login-shell-only
        # .bash_profile must also see PATH); with neither present, create
        # .bashrc so a fresh machine still gets wired up.
        if [ -f "$HOME/.bashrc" ] || [ -f "$HOME/.bash_profile" ]; then
            for _rc in "$HOME/.bashrc" "$HOME/.bash_profile"; do
                if [ -f "$_rc" ]; then
                    add_rc_block "$_rc" "$posix_line"
                fi
            done
        else
            add_rc_block "$HOME/.bashrc" "$posix_line"
        fi
        ;;
    zsh)
        add_rc_block "$zshrc" "[ -f \"$init_dir/zsh.sh\" ] && . \"$init_dir/zsh.sh\""
        ;;
    fish)
        add_rc_block "$fish_config" "if test -f \"$init_dir/fish.fish\"; source \"$init_dir/fish.fish\"; end"
        ;;
    *)
        # Unknown or unset shell: .profile is the POSIX login-shell rc.
        add_rc_block "$HOME/.profile" "$posix_line"
        ;;
esac

# The run's own receipt, closing the component table: what changed, what did
# not, and how long it took. The record path stays on it — dim, but present:
# it is the first thing a support answer asks for.
elapsed=
if [ "$t0" -gt 0 ]; then
    t1="$(date +%s 2>/dev/null || echo 0)"
    if [ "$t1" -gt "$t0" ]; then
        elapsed=" $sep $((t1 - t0))s"
    fi
fi
say ""
say "  $b$installed installed$rst $sep $skipped current$elapsed"
say "  ${dim}record: $(tilde "$prev_record")$rst"

# --- Linux host advisory: unprivileged user namespaces ---------------------

# Ubuntu 24.04+ defaults kernel.apparmor_restrict_unprivileged_userns=1, under
# which minimald cannot create the user namespace every session sandbox needs —
# sessions then die at uid_map with an opaque EPERM, far from here. Detect the
# restriction at install time (Linux only) and point at the AppArmor loader we
# just shipped. Advice only: installing the profile needs root, and this
# installer never elevates. Silent on hosts that do not need it, AND on a host
# already remediated — but "remediated" depends on the bin prefix: the stock
# tunable attaches only /usr/bin, /usr/local/bin, and ~/.local/bin, so for a
# custom MINIMAL_BIN the advised command carries --path, and a loaded profile
# counts as remediation only if the tunables actually name this binary
# (otherwise sessions still die and a reinstall must keep saying so). The
# sysctl and apparmor.d paths are overridable for install_test.sh.
userns_sysctl="${MINIMAL_OVERRIDE_USERNS_SYSCTL:-/proc/sys/kernel/apparmor_restrict_unprivileged_userns}"
apparmor_dir="${MINIMAL_OVERRIDE_APPARMOR_DIR:-/etc/apparmor.d}"
if [ "$os" = linux ] && [ -r "$userns_sysctl" ] \
    && [ "$(cat "$userns_sysctl" 2>/dev/null)" = 1 ]; then
    apparmor_loader="$(resolve_prefix data)/apparmor/install-apparmor-profile.sh"
    aa_loader_args=""
    aa_remediated=0
    case "$bindir" in
        /usr/bin|/usr/local/bin|"$HOME/.local/bin")
            [ -e "$apparmor_dir/minimald" ] && aa_remediated=1
            ;;
        *)
            aa_loader_args=" --path \"$bindir/minimald\""
            if [ -e "$apparmor_dir/minimald" ] \
                && grep -rqs "$bindir/minimald" "$apparmor_dir/tunables" 2>/dev/null; then
                aa_remediated=1
            fi
            ;;
    esac
    if [ "$aa_remediated" -eq 0 ] && [ -f "$apparmor_loader" ]; then
        say ""
        say "note: this host restricts unprivileged user namespaces (Ubuntu 24.04+);"
        say "  minimald's session sandbox cannot start until you install its AppArmor"
        say "  profile — a one-time step that needs root:"
        say "      sudo bash \"$apparmor_loader\"$aa_loader_args"
        say "  details: https://docs.minimal.dev/reference/linux-host-setup"
    fi
fi

# --- The closing card ------------------------------------------------------

# The last thing a `curl … | sh` user sees. It ends on what to run rather than
# on a filesystem path, and it carries the PATH advisory when it applies:
# the rc hook above only takes effect in NEW shells, so in this one the two
# commands below would not resolve, and saying so is part of the next step
# rather than a footnote after it.
say ""
say "  ${b}Minimal $VERSION is ready.$rst"
say ""
case ":${PATH:-}:" in
    *":$bindir:"*) ;;
    *) say "  $(tilde "$bindir") is not on your PATH in this shell yet."
       say "  Start a new shell, or run:"
       say "      export PATH=\"$bindir:\$PATH\""
       say "" ;;
esac
say "  $mark ${b}min init$rst                          ${dim}declare this project's environment$rst"
say "  $mark ${b}min session activate --attach .$rst   ${dim}build the sandbox and step inside$rst"
say ""
say "  ${dim}docs.minimal.dev   $sep   discord.com/invite/qgX8sm6X7G$rst"
say ""
