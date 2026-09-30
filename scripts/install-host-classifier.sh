#!/usr/bin/env bash
# Install (or remove) the cgroup tree minimald and its session boxes are
# placed in: the classifier tree at /sys/fs/cgroup/minimald.slice, with a
# `daemon` leaf and a `boxes/` cohort delegated to the account minimald runs
# as. Every host-address box runs in a leaf of its own for its whole life
# (NET-079); that stays true only while the tree above its cohort is
# root-owned and cgroup2 is mounted `nsdelegate`, which makes a box's cgroup
# namespace a delegation boundary its own migrations cannot cross. The
# daemon cannot build the tree itself: its uid has no write access above
# `boxes/`, which is the point of the barrier.
#
# Usage:
#   sudo scripts/install-host-classifier.sh [--user NAME] [--root DIR]
#   sudo scripts/install-host-classifier.sh --uninstall
#        scripts/install-host-classifier.sh --check      # unprivileged
#
# --user delegates to that account (default: the one running sudo). --root
# installs the tree somewhere other than the conventional cgroup2 mount,
# for a host that mounts cgroup2 elsewhere or a test rehearsing against a
# stand-in tree.
set -euo pipefail

# Mirrors sandbox2::classifier's constants (crates/sandbox2/src/lib.rs): the
# tree this script lays out is the one the daemon looks for at startup.
readonly DEFAULT_TREE_ROOT=/sys/fs/cgroup/minimald.slice
readonly DAEMON_LEAF=daemon
readonly BOXES_DIR=boxes

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
note() { printf '%s\n' "$*"; }

# Rehearsal posture (set iff the stand-in mountinfo below is in play): the
# caller created the stand-in tree, so the one fact it cannot represent is
# the root-owned barrier above the delegated leaves — the tree root
# necessarily carries the caller's uid.
readonly rehearsal=${MINIMAL_OVERRIDE_CGROUP_MOUNTINFO:+1}

mode=install
user=
tree_root=$DEFAULT_TREE_ROOT
# The parse loop consumes $@; keep the original invocation for the sudo hint
# below, or a copy-pasted retry silently drops --user/--uninstall.
original_args=("$@")

while [ $# -gt 0 ]; do
    case "$1" in
        --user)
            [ $# -ge 2 ] || die "--user needs an account name"
            user=$2
            shift 2
            ;;
        --root)
            [ $# -ge 2 ] || die "--root needs a directory"
            tree_root=$2
            shift 2
            ;;
        --uninstall) mode=uninstall; shift ;;
        --check)     mode=check; shift ;;
        -h|--help)   sed -n '2,20p' "$0" | sed 's/^# \?//'; exit 0 ;;
        *)           die "unknown argument: $1 (see --help)" ;;
    esac
done

# The account the tree is delegated to, and the one whose boxes it is:
# --user wins, else the account that ran sudo, else there is no default worth
# guessing — delegating to root would hand every box a way to write the tree.
resolve_owner() {
    if [ -n "$user" ]; then
        owner_uid="$(id -u "$user")" || die "no such account: $user"
        owner_gid="$(id -g "$user")" || die "no such account: $user"
    elif [ -n "${SUDO_UID:-}" ] && [ -n "${SUDO_GID:-}" ]; then
        owner_uid=$SUDO_UID
        owner_gid=$SUDO_GID
    else
        die "which account should the tree be delegated to? pass --user NAME"
    fi
    # Delegating to root would hand every box — which runs as the daemon's
    # uid — the account that owns the tree, and so every sibling leaf in it.
    if [ "$owner_uid" -eq 0 ]; then
        die "delegating to root is the same as not delegating: pass --user NAME for the account minimald runs as"
    fi
}

# The mount table this run reads: the real one, or the stand-in the rehearsal
# posture names. install.sh's own test seam is the precedent (its
# MINIMAL_OVERRIDE_* knobs), and the rehearsal changes nothing about what runs
# — only that the uid-0 assertion below is lifted, because the whole point is
# that an unprivileged caller can rehearse inside a directory it owns.
readonly MOUNTINFO=${MINIMAL_OVERRIDE_CGROUP_MOUNTINFO:-/proc/self/mountinfo}

# covering_mount <tree-root> — the cgroup2 mount that carries the tree root:
# the one whose mountpoint is the deepest prefix of it (a host may mount the
# hierarchy anywhere). Prints "<mountpoint> <nsdelegate 0|1> <namespace
# root>"; exits non-zero when no cgroup2 mount covers the path at all.
covering_mount() {
    awk -v target="$1" '
        {
            sep = 0
            for (i = 1; i <= NF; i++) { if ($i == "-") { sep = i; break } }
            if (!sep || NF < sep + 3) next
            if ($(sep + 1) != "cgroup2") next
            mp = $5
            if (target != mp && substr(target, 1, length(mp) + 1) != mp "/") next
            # Deeper prefixes win: /sys/fs/cgroup beats /sys/fs.
            if (length(mp) <= length(best)) next
            best = mp
            nsroot = $4
            nsdel = 0
            n = split($(sep + 3), opt, ",")
            for (j = 1; j <= n; j++) { if (opt[j] == "nsdelegate") nsdel = 1 }
        }
        END { if (best == "") exit 1; print best, nsdel, nsroot }
    ' "$MOUNTINFO"
}

# verify_mount — the two facts every leaf-bearing box's confinement rests on:
# the tree root sits on a cgroup2 mount, and that mount carries nsdelegate
# (without it, a cgroup namespace is not a delegation boundary, and a box
# could migrate out of its leaf). Refuses a mount rooted elsewhere than "/":
# that is another cgroup namespace's view, and the tree would be created
# inside it instead of on the host.
verify_mount() {
    [ -r "$MOUNTINFO" ] || die "cannot read the mount table at $MOUNTINFO"
    covering="$(covering_mount "$tree_root")" ||
        die "no cgroup2 mount covers $tree_root; the unified hierarchy must be mounted there"
    read -r covering_point nsdel nsroot <<<"$covering"
    [ "$nsroot" = / ] ||
        die "$covering_point is the view of another cgroup namespace (its root is $nsroot); install from the host's initial namespace"
    [ "$nsdel" = 1 ] ||
        die "cgroup2 at $covering_point is not mounted with nsdelegate; without it a box could migrate out of its leaf. Remount it, e.g.: mount -o remount,nosuid,nodev,noexec,nsdelegate $covering_point"
    note "cgroup2 mounted at $covering_point, nsdelegate"
}

# stat_uid_gid <path> — "<uid> <gid>", GNU or BSD syntax (macOS ships the
# latter; this script runs on both).
stat_uid_gid() {
    out="$(stat -c '%u %g' "$1" 2>/dev/null || true)"
    if [ -n "$out" ]; then printf '%s\n' "$out"; return 0; fi
    stat -f '%u %g' "$1"
}

# do_check — an unprivileged rehearsal of the install's assertions, the
# answer to "why is my box unenforced?": every fact it prints is one an
# install would have enforced. Exits 0 when the tree is in place and
# delegated to the expected account, 1 otherwise.
do_check() {
    problems=0
    problem() { printf 'error: %s\n' "$*" >&2; problems=$((problems + 1)); }

    resolve_owner
    # The fix for a missing tree is the install, not a re-check: hint the
    # caller's own invocation with --check dropped, keeping whatever --root
    # and --user they asked about.
    hint_args=()
    for a in "${original_args[@]}"; do [ "$a" = --check ] || hint_args+=("$a"); done
    hint="sudo $0${hint_args[0]+ }${hint_args[*]-}"
    if covering="$(covering_mount "$tree_root")"; then
        read -r covering_point nsdel nsroot <<<"$covering"
        if [ "$nsroot" != / ]; then
            problem "$covering_point is the view of another cgroup namespace (root $nsroot)"
        fi
        if [ "$nsdel" != 1 ]; then
            problem "cgroup2 at $covering_point is not mounted with nsdelegate; a box could migrate out of its leaf"
        fi
    else
        problem "no cgroup2 mount covers $tree_root"
        covering_point="(unmounted)"
    fi
    note "mount:    $covering_point (cgroup2, nsdelegate ${nsdel:-0})"

    for leaf in "" "/$DAEMON_LEAF" "/$BOXES_DIR"; do
        path="$tree_root$leaf"
        if [ ! -d "$path" ]; then
            problem "$path does not exist (install it: $hint)"
            continue
        fi
        actual="$(stat_uid_gid "$path")"
        if [ -z "$leaf" ]; then
            # The tree root must NOT be delegated: a box runs as the daemon's
            # uid, so a root owned by that account hands it every sibling
            # leaf. Not asseverable in the rehearsal posture (see `rehearsal`).
            if [ "$rehearsal" != 1 ] && [ "$actual" = "$owner_uid $owner_gid" ]; then
                problem "$path is delegated to the daemon's account ($actual); the tree above the leaves must stay root-owned, or a box running as that uid could reach a sibling leaf"
            fi
        elif [ "$actual" != "$owner_uid $owner_gid" ]; then
            problem "$path is owned by $actual, not $owner_uid $owner_gid (the daemon's account)"
        fi
    done
    [ "$problems" -eq 0 ] || die "$problems problem(s): the tree is not installed as minimald needs it"
    note "tree:     $tree_root"
    note "delegated: $owner_uid:$owner_gid ($DAEMON_LEAF and $BOXES_DIR, the tree above them root-owned)"
    note "each session box will run in a leaf of its own; minimald's launch log names it"
}

if [ "$mode" = check ]; then
    do_check
    exit 0
fi

# The root check is the one thing the rehearsal posture lifts; everything
# else runs unchanged.
if [ "$rehearsal" != 1 ]; then
    [ "$(id -u)" -eq 0 ] || die "must run as root (try: sudo $0${original_args[0]+ }${original_args[*]-})"
fi

if [ "$mode" = uninstall ]; then
    # rmdir, never rm: on the real filesystem these are cgroups, and the
    # kernel refuses to remove one that still holds a process — which is
    # exactly the guard wanted here (stop minimald first).
    rmdir "$tree_root/$DAEMON_LEAF" 2>/dev/null || true
    rmdir "$tree_root/$BOXES_DIR" 2>/dev/null || true
    if rmdir "$tree_root" 2>/dev/null; then
        note "removed the classifier tree at $tree_root"
        exit 0
    fi
    die "could not remove $tree_root: a live leaf or process still holds it (stop minimald and its sessions first)"
fi

verify_mount
resolve_owner

install -d "$tree_root" ||
    die "cannot create $tree_root (is cgroup2 mounted there, and this account allowed to?)"
install -d "$tree_root/$DAEMON_LEAF" "$tree_root/$BOXES_DIR"

# Delegate the two leaves and nothing above them: the daemon must be able to
# create a leaf per box and to move processes in and out — `daemon/` is
# delegated too because the box processes it moves *out of* start there — but
# the tree root stays root-owned, or the barrier that stops a box reaching a
# sibling leaf by uid alone would be gone.
chown -R "$owner_uid:$owner_gid" "$tree_root/$DAEMON_LEAF" "$tree_root/$BOXES_DIR"

note "installed the classifier tree at $tree_root"
note "  $DAEMON_LEAF/  the daemon itself, entered at startup"
note "  $BOXES_DIR/   one leaf per session box, created before its spawn and removed once reaped"
note "delegated to $owner_uid:$owner_gid; the tree above them stays root-owned"
note "minimald's next start places each box in its leaf; its launch log names the leaf each box entered"
