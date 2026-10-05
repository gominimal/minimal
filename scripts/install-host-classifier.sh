#!/usr/bin/env bash
# Install (or remove) the cgroup tree minimald and its session boxes are
# placed in: the classifier tree at /sys/fs/cgroup/minimald.slice,
# delegated to the account minimald runs as. Delegation follows the cgroup
# v2 contract — a delegated cgroup is its directory plus its cgroup.procs,
# cgroup.threads and cgroup.subtree_control — because a migration into a
# leaf is refused unless the mover can write the common ancestor's
# cgroup.procs, and the common ancestor of the daemon's leaf and of every
# box leaf is the slice itself. Everything above the slice — the cgroup2
# mount root, and the hierarchy root above that — stays root-owned, so the
# daemon's first hop into the slice is a migration only root can make:
# that hop is --pid. Every host-address box then runs in a leaf of its own
# for its whole life (NET-079); that stays true only while cgroup2 is
# mounted `nsdelegate`, which makes a box's cgroup namespace a delegation
# boundary its own migrations cannot cross. The daemon cannot build the
# tree itself: its uid has no write access above the slice, which is the
# point of the barrier.
#
# Usage:
#   sudo scripts/install-host-classifier.sh [--user NAME] [--root DIR]
#         [--answerer-address ADDR] [--answerer-port PORT]
#         [--no-resolver-carve-out] [--ct-mark-mask 0x30000000]
#         --cohort-address ADDR --node-plane-address ADDR
#   sudo scripts/install-host-classifier.sh --pid PID
#   sudo scripts/install-host-classifier.sh --uninstall
#        scripts/install-host-classifier.sh --check           # unprivileged
#        scripts/install-host-classifier.sh --print-ruleset   # unprivileged
#
# --user delegates to that account (default: the one running sudo). --root
# installs the tree somewhere other than the conventional cgroup2 mount,
# for a host that mounts cgroup2 elsewhere or a test rehearsing against a
# stand-in tree. --pid places the running daemon in the slice's daemon
# leaf: the one migration the delegated account cannot make itself,
# because the common ancestor of the cgroup the daemon starts in and the
# slice is the root-owned hierarchy root.
#
# The install also lays out the cohort's two subtrees, boxes/deny and
# boxes/allow — a box's declaration, not its session name, decides which
# one it lives in — and loads the one nftables inet table that decides a
# deny-all box's connections, as a single `nft -f` transaction. Its output
# chain matches a box's own cgroup before any source translation and
# refuses every connection a box in boxes/deny opens except the one to the
# zone answerer (--answerer-address, --answerer-port; the box's resolver,
# refused actively and never silently dropped), while the reply leg of a
# connection someone else opened to the box — the hostname proxy's to its
# loopback listener — is admitted: a box answering a connection it did not
# open is not egress the box originates. Its dstnat chain retargets
# the deny subtree's DNS-port lookups on the answerer's address onto the
# answerer's own port, so the one destination the deny rule admits is also
# the one a deny-all box's lookups reach. Its classify chain runs at
# output, at the mangle priority — the last place the kernel admits a
# socket-cgroup match, which is why the classification lives there and
# not at postrouting — and classes only a connection that is new: the
# boxes subtree is marked with the cohort bit of the connection mark's
# mask, the slice's remaining flows with the node bit, guarded so a
# flow the boxes rule already classed is never re-decided, and writing
# only the mask's two bits, so bits another component already classes
# with survive untouched. Its postrouting chain translates by that
# mark, giving the boxes cohort and the rest of the slice their two
# source identities (--cohort-address and --node-plane-address, both
# required: they are this host's to know, and a table that refuses a
# deny-all box's connections while its cohort keeps the host's own
# source identity is half of the classification), each with a `lo`
# guard so a packet to the answerer is never rewritten. Rules are keyed
# on the cgroups' paths and the connection mark alone — never a uid or
# pid, which a box could change about itself — and nothing is per-box:
# no rule is added or removed at box launch or stop. The mask's two
# bits default to 0x30000000, above the ranges a host's other
# components commonly class with; --ct-mark-mask overrides them (it
# must name exactly two contiguous bits), the ruleset this host already
# carries is scanned for a ct-mark user of those bits and the install
# refuses over one, and the chosen mask is recorded beside the marker
# minimald probes, so the daemon and this step read one value. That
# marker is removed before the transaction and written only after it
# succeeds, so a re-install that fails leaves the host honestly
# reported as deciding nothing per box, never looking decided over a
# table that is not the one this step rendered.
set -euo pipefail

# Mirrors sandbox2::classifier's constants (crates/sandbox2/src/lib.rs): the
# tree this script lays out is the one the daemon looks for at startup.
readonly DEFAULT_TREE_ROOT=/sys/fs/cgroup/minimald.slice
readonly DAEMON_LEAF=daemon
readonly BOXES_DIR=boxes
readonly DENY_DIR=deny
readonly ALLOW_DIR=allow
# The name the loaded table and its presence marker share: the daemon probes
# $tree_root/$TABLE_MARKER (read-only, no CAP_NET_ADMIN) because listing the
# table itself needs the very capability that loaded it.
readonly TABLE_MARKER=classifier-table
readonly TABLE_NAME=minimal_class
# The ct-mark bits the classify chain writes and the postrouting chain
# translates by. Two contiguous bits, overridable with --ct-mark-mask; the
# default sits above the ranges a host's other components commonly class
# with (Tailscale's 0x00ff0000, kube-proxy's 0x4000 and 0x8000), and the
# scan below refuses to install over a ruleset whose ct-mark use overlaps
# whichever two bits were chosen. The chosen value is recorded beside the
# marker, in a cgroup named with this prefix plus the value — a name the
# daemon's probe (crates/minimald/src/net/classifier.rs) spells the same
# way, so the two read one fact — and an uninstall and a check read it
# back by prefix, never by the default value.
readonly MASK_RECORD_PREFIX=ct-mark-mask-
readonly DEFAULT_CT_MARK_MASK=0x30000000

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
note() { printf '%s\n' "$*"; }

# sha256_of <text> — the digest of exactly the bytes handed to it: the hex
# field alone, because sha256sum spells its output "<hex>  -" and shasum
# "<hex> -". shasum is the macOS spelling of the same sum, so a rehearsal
# on a Mac digests like an install on a Linux host; neither being there is
# this step's own failure to name, before anything loads.
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sum="$(printf '%s' "$1" | sha256sum)"
    elif command -v shasum >/dev/null 2>&1; then
        sum="$(printf '%s' "$1" | shasum -a 256)"
    else
        die "cannot digest the ruleset: this step needs sha256sum (or shasum) to name the sha256 of the bytes it loads"
    fi
    printf '%s' "${sum%% *}"
}

# Rehearsal posture (set iff the stand-in mountinfo below is in play): the
# caller created the stand-in tree, so the one fact it cannot represent is
# the root-owned barrier above the delegated leaves — the tree root
# necessarily carries the caller's uid.
readonly rehearsal=${MINIMAL_OVERRIDE_CGROUP_MOUNTINFO:+1}

mode=install
user=
pid=
tree_root=$DEFAULT_TREE_ROOT
# The one destination a deny-all box's connections are admitted to: the
# zone answerer the daemon serves, at its own loopback address. The port
# mirrors the daemon's ANSWERER_PORT; --answerer-address/--answerer-port
# exist because a daemon may serve the answerer elsewhere (NET-079's
# carve-out is by address and port, never loopback-wide).
answerer_address=127.0.0.1
answerer_port=7656
# --no-resolver-carve-out renders neither the answerer's admission in
# deny_out nor the dstnat retarget: a VM-backed guest has no resolver a
# deny-all box may be admitted to (its node DNS layer applies no per-box
# name rule to host-address boxes), so its DNS is refused like any other
# destination until gominimal/inbox#897 gives it one.
resolver_carve_out=1
answerer_given=
# The cohort's and the node plane's source identities (NET-078). They are
# this host's to know, not the script's to guess: each SNAT rule is rendered
# only when its address was given, and the two go together — half a
# classification is one identity wearing two names.
cohort_address=
node_plane_address=
# The two ct-mark bits the classify chain classifies with (see the
# constants above); require_mask checks the value and derives every
# spelling the ruleset renders from it.
ct_mark_mask=$DEFAULT_CT_MARK_MASK
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
        --answerer-address)
            [ $# -ge 2 ] || die "--answerer-address needs an address"
            answerer_address=$2
            answerer_given=1
            shift 2
            ;;
        --answerer-port)
            [ $# -ge 2 ] || die "--answerer-port needs a port"
            case "$2" in ''|*[!0-9]*)
                die "--answerer-port needs a numeric port, got: $2" ;;
            esac
            answerer_port=$2
            answerer_given=1
            shift 2
            ;;
        --cohort-address)
            [ $# -ge 2 ] || die "--cohort-address needs an address"
            cohort_address=$2
            shift 2
            ;;
        --node-plane-address)
            [ $# -ge 2 ] || die "--node-plane-address needs an address"
            node_plane_address=$2
            shift 2
            ;;
        --ct-mark-mask)
            [ $# -ge 2 ] || die "--ct-mark-mask needs a mask"
            ct_mark_mask=$2
            shift 2
            ;;
        --no-resolver-carve-out) resolver_carve_out=; shift ;;
        --uninstall) mode=uninstall; shift ;;
        --check)     mode=check; shift ;;
        --print-ruleset) mode=print_ruleset; shift ;;
        --pid)
            [ $# -ge 2 ] || die "--pid needs a process id"
            case "$2" in ''|*[!0-9]*)
                die "--pid needs a numeric process id, got: $2" ;;
            esac
            pid=$2
            mode=place
            shift 2
            ;;
        # The header above this line is the usage. Two explicit strips, not
        # 's/^# \?//': \? is a GNU sed extension BSD sed does not know, and this
        # script's own tests run on macOS's /bin/sh too.
        -h|--help)   sed -n '2,77p' "$0" | sed -e 's/^# //' -e 's/^#//'; exit 0 ;;
        *)           die "unknown argument: $1 (see --help)" ;;
    esac
done

# A render without the carve-out has no answerer to name, so a call that
# names one asked for two renders at once.
if [ -z "$resolver_carve_out" ] && [ -n "$answerer_given" ]; then
    die "--no-resolver-carve-out renders no answerer: drop --answerer-address and --answerer-port"
fi

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
    # and --user they asked about. The two source identities the install
    # refuses to run without (see require_identities) are appended for
    # whichever this check was not told — the hint must be the command an
    # install would accept, so copy-pasting it lands on the refusal the
    # install makes of a half-told classification, never a refusal of the
    # hint's own shape.
    hint_args=()
    for a in "${original_args[@]}"; do [ "$a" = --check ] || hint_args+=("$a"); done
    [ -n "$cohort_address" ] ||
        hint_args+=(--cohort-address "<cohort address>")
    [ -n "$node_plane_address" ] ||
        hint_args+=(--node-plane-address "<node-plane address>")
    hint="sudo $0${hint_args[0]+ }${hint_args[*]-}"
    if covering="$(covering_mount "$tree_root")"; then
        read -r covering_point nsdel nsroot <<<"$covering"
        if [ "$nsroot" != / ]; then
            problem "$covering_point is the view of another cgroup namespace (root $nsroot)"
        fi
        if [ "$nsdel" != 1 ]; then
            problem "cgroup2 at $covering_point is not mounted with nsdelegate; a box could migrate out of its leaf"
        fi
        # The mount root — the parent of the slice, up to the hierarchy root —
        # must NOT be delegated: a box runs as the daemon's uid, so a mount
        # root owned by that account is every cgroup on the host. Not
        # assertable in the rehearsal posture (see `rehearsal`): the stand-in
        # mount root necessarily carries the caller's uid.
        if [ "$rehearsal" != 1 ] && [ "$covering_point" != / ]; then
            actual="$(stat_uid_gid "$covering_point")"
            if [ "$actual" = "$owner_uid $owner_gid" ]; then
                problem "$covering_point is delegated to the daemon's account ($actual); everything above the slice must stay root-owned, or a box running as that uid could reach past the slice"
            fi
        fi
    else
        problem "no cgroup2 mount covers $tree_root"
        covering_point="(unmounted)"
    fi
    note "mount:    $covering_point (cgroup2, nsdelegate ${nsdel:-0})"

    # The slice itself is delegated — a migration between two of its leaves
    # is a write to the slice's own cgroup.procs — so every cgroup this
    # script lays out must carry the whole v2 contract: the directory plus
    # cgroup.procs, cgroup.threads and cgroup.subtree_control. The two
    # subtrees under the cohort are part of what the daemon's placement
    # needs: a box's leaf is one level below the cohort now, in the subtree
    # its declaration picked.
    for cgroup in \
        "" "/$DAEMON_LEAF" "/$BOXES_DIR" \
        "/$BOXES_DIR/$DENY_DIR" "/$BOXES_DIR/$ALLOW_DIR"
    do
        path="$tree_root$cgroup"
        if [ ! -d "$path" ]; then
            problem "$path does not exist (install it: $hint)"
            continue
        fi
        actual="$(stat_uid_gid "$path")"
        [ "$actual" = "$owner_uid $owner_gid" ] ||
            problem "$path is owned by $actual, not $owner_uid $owner_gid (the daemon's account)"
        for file in cgroup.procs cgroup.threads cgroup.subtree_control; do
            if [ ! -e "$path/$file" ]; then
                problem "$path/$file is missing: a delegated cgroup is its directory plus cgroup.procs, cgroup.threads and cgroup.subtree_control"
                continue
            fi
            owner="$(stat_uid_gid "$path/$file")"
            [ "$owner" = "$owner_uid $owner_gid" ] ||
                problem "$path/$file is owned by $owner, not $owner_uid $owner_gid; without that write the daemon cannot migrate a process across this boundary"
        done
    done
    # The packet-filter table's presence marker: the daemon probes it
    # read-only at start, because listing the table needs the capability
    # that loaded it. Its absence is the one fact this rehearsal can see of
    # the step's second half, so it is reported, not assumed. The ct-mark
    # mask recorded beside it is the other half of the same fact: a marker
    # with no mask recorded is a step that did not finish, which is the
    # state the daemon reads as the step not installed.
    recorded="$(recorded_ct_mark_masks "$tree_root")"
    if [ ! -d "$tree_root/$TABLE_MARKER" ]; then
        problem "$tree_root/$TABLE_MARKER is missing: the table's presence marker, written by an install whose nft transaction succeeded (install it: $hint)"
    elif [ -z "$recorded" ]; then
        problem "$tree_root/$MASK_RECORD_PREFIX<mask> is missing: the ct-mark mask the loaded table classifies with, written beside the marker by the install that wrote it (re-install it: $hint)"
    fi
    [ "$problems" -eq 0 ] || die "$problems problem(s): the tree is not installed as minimald needs it"
    note "tree:     $tree_root"
    note "delegated: $owner_uid:$owner_gid — the slice, $DAEMON_LEAF, $BOXES_DIR and its $DENY_DIR and $ALLOW_DIR subtrees, each with its cgroup.procs, cgroup.threads and cgroup.subtree_control"
    note "table:    $tree_root/$TABLE_MARKER (the loaded table's marker; minimald records a per-box verdict only while it is there)"
    note "ct-mark:  ${recorded:-<none recorded>} (the mask the table classifies cohort and node plane with, recorded beside the marker)"
    note "the cgroup2 mount above the slice stays root-owned"
    note "each session box will run in a leaf of its own; minimald's launch log names it"
}

# place_daemon — the one migration the delegated account cannot make itself.
# The daemon starts wherever its starter left it (user.slice, usually), so
# the common ancestor of that cgroup and the slice is the hierarchy root,
# which is root-owned by design: the barrier that stops a box climbing out
# is the same fact that stops the daemon climbing in. Only root can write
# the daemon's pid into its leaf — hence this mode, and hence a daemon
# started by a Delegate=yes systemd unit needing neither.
place_daemon() {
    verify_mount
    procs="$tree_root/$DAEMON_LEAF/cgroup.procs"
    if [ ! -e "$procs" ]; then
        die "$tree_root/$DAEMON_LEAF is not installed (run: sudo $0 --user <the account minimald runs as>)"
    fi
    kill -0 "$pid" 2>/dev/null ||
        die "no process $pid: pass the pid of the running minimald (its startup line names the tree it is outside)"
    printf '%s\n' "$pid" >"$procs" ||
        die "cannot place $pid in $procs (is $pid a process root may move, and is it the running minimald?)"
    note "placed $pid in $tree_root/$DAEMON_LEAF"
    note "the running minimald is inside the slice now: the placement probe runs per launch, so the next box it launches is placed in a leaf of its own"
    note "a plain restart loses this placement — a new minimald starts in its starter's cgroup unless a Delegate=yes unit starts it in the slice, so pass --pid again afterwards"
}

# The cgroups' paths as the packet filter spells them: relative to the
# cgroup2 hierarchy's root, which is where nft's socket match resolves
# them from. The tree root minus its covering mountpoint (and the "/" the
# subtraction leaves behind) is that spelling, because verify_mount above
# refused every other namespace's view — and a tree root that *is* the
# mount root has no path of its own to be keyed on.
compute_cgroup_paths() {
    rel=${tree_root#"$covering_point"}
    rel=${rel#/}
    [ -n "$rel" ] ||
        die "$tree_root is the cgroup2 mount root itself; the classifier needs a slice below the mount root to key its rules on"
    deny_path="$rel/$BOXES_DIR/$DENY_DIR"
    boxes_path="$rel/$BOXES_DIR"
}

# cgroup_level <path> — the nft socket match compares that many leading
# components of the socket's cgroup path, so the level is the path's own
# depth, derived rather than hardcoded: a --root deeper in the hierarchy
# shifts every rule with it.
cgroup_level() {
    awk -v p="$1" 'BEGIN { printf "%d\n", split(p, a, "/") }'
}

# render_ruleset — the one table this step owns, on stdout, as one `nft -f`
# reads it. Every rule is keyed on a cgroup path alone — never a uid, pid or
# mark, which a box could change about itself — and nothing is per-box, so
# nothing is edited at box launch or stop: a box's declaration picks its
# subtree, the subtree carries the verdict, and the launch only places the
# box in the leaf it already owns.
#
# The prelude is the replace itself: `nft -f` applies a batch whole or not
# at all, so declaring this table empty, deleting it, and re-declaring it
# in the same file is one transaction that replaces whatever a previous
# run left — never an add-to-it that could leave half a table deciding
# things — and leaves the previous table standing when it dies.
#
# The dstnat chain (priority dstnat, before the filter output chain)
# retargets the deny subtree's DNS-port lookups on the answerer's address
# onto the answerer's own port: a deny-all box resolves through the
# answerer (NET-079) by asking DNS's port like any resolver would, and the
# one destination its deny rule admits is the one its lookups reach.
#
# The filter output chain runs before the postrouting chain (priority
# srcnat), so a connection refused on the box's own cgroup is refused
# before any source translation: the deny is decided inside the box host,
# on the declaration, not on the identity the packet would leave with. In
# deny_out, replies are admitted first — and only replies: a connection
# someone else opened to the box, the hostname proxy's to its loopback
# listener among them, has its answer leg in the reply direction, so
# admitting that one direction is what lets a deny-all box serve what
# reaches it, while a flow the box itself originates is original-direction
# and still meets the refusal — egress the box originates is what the deny
# denies, not the box answering a connection it did not open. The refusal
# is active — reject, never a silent drop — and each one logs,
# rate-limited, so a diagnostics bundle's daemon log tail carries the
# refused connections themselves.
#
# The classify chain is where a flow is classed, at the mangle priority —
# ahead of the dstnat and filter chains, and the last place the kernel
# admits a socket-cgroup match at all, which is why the classification
# lives at output while the translation at postrouting reads its result:
# the kernel refuses a socket match in a postrouting chain, so a rule
# keyed on one there has never been loadable. Only a connection that is
# new is classed (one already classed is never re-decided); the boxes
# subtree takes the cohort bit and the slice's remaining flows the node
# bit, the second guarded by the mask so the boxes rule's mark is final —
# every box leaf is inside the slice too, and the slice's rule must not
# re-class what the boxes rule already decided. Both rules write the
# mask's two bits and no others (`mark and ~mask or bit`), so bits another
# component of this host classes with survive classification untouched.
#
# The postrouting chain translates by the mark, not the socket, with a
# `lo` guard on each SNAT: a packet to the answerer never leaves the host,
# so translating its source would rewrite the reply the conntrack entry
# already knows.
render_ruleset() {
    carve_out_rule=
    dstnat_chain=
    if [ -n "$resolver_carve_out" ]; then
        carve_out_rule="
        ip daddr $answerer_address udp dport $answerer_port accept"
        dstnat_chain="
    chain dstnat {
        type nat hook output priority dstnat; policy accept;
        socket cgroupv2 level $(cgroup_level "$deny_path") \"$deny_path\" ip daddr $answerer_address udp dport 53 dnat ip to $answerer_address:$answerer_port
    }"
    fi
    cat <<RULES
add table inet $TABLE_NAME
delete table inet $TABLE_NAME

table inet $TABLE_NAME {
    chain output {
        type filter hook output priority filter; policy accept;
        socket cgroupv2 level $(cgroup_level "$deny_path") "$deny_path" jump deny_out
    }
    chain deny_out {
        ct state established,related ct direction reply accept$carve_out_rule
        limit rate 1/second burst 4 packets log prefix "minimal-classifier: refused " level warn
        reject with icmpx admin-prohibited
    }$dstnat_chain
    chain classify {
        type filter hook output priority mangle; policy accept;
        ct state new socket cgroupv2 level $(cgroup_level "$boxes_path") "$boxes_path" ct mark set ct mark and $clear_hex or $cohort_hex
        ct state new ct mark and $mask_hex == 0 socket cgroupv2 level $(cgroup_level "$rel") "$rel" ct mark set ct mark and $clear_hex or $node_hex
    }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ct mark and $mask_hex == $cohort_hex oifname != "lo" snat ip to $cohort_address
        ct mark and $mask_hex == $node_hex oifname != "lo" snat ip to $node_plane_address
    }
}
RULES
}

# require_identities — the cohort's and the node plane's source identities
# are this host's to know, not the script's to guess, and not optional to the
# classification: a table that refuses a deny-all box's connections while its
# cohort leaves with the host's own source identity is half of NET-078
# wearing the other half's name, so an install refuses to render half of
# it. They go together or the install does not run.
require_identities() {
    if [ -z "$cohort_address" ] || [ -z "$node_plane_address" ]; then
        die "the install needs both source identities: pass --cohort-address ADDR (what the boxes cohort leaves as) and --node-plane-address ADDR (what the rest of the slice leaves as)"
    fi
}

# require_mask — the two ct-mark bits this install classifies with, checked
# and derived before anything renders: exactly two contiguous set bits
# inside the 32 the kernel gives a connection mark, and nothing else. One
# bit is no classification, three is a spelling mistake, and a bit above
# the 31st is not a mark the kernel can hold; each is refused with the
# reason, before a cgroup is made or a rule is written. The lowest bit
# classifies the boxes cohort, the other the rest of the slice, and every
# spelling the ruleset renders — the mask, its complement (what the
# classify chain clears), both bits — is derived from the one value, so
# they cannot drift into a rule that clears or compares bits it never set.
require_mask() {
    case "$ct_mark_mask" in
        0x*) ;;
        *)   die "--ct-mark-mask needs a 0x-prefixed hexadecimal value, got: $ct_mark_mask" ;;
    esac
    digits=${ct_mark_mask#0x}
    case "$digits" in
        ''|*[!0-9a-fA-F]*)
            die "--ct-mark-mask needs a hexadecimal value, got: $ct_mark_mask" ;;
    esac
    # Bash arithmetic is 64-bit signed, so a value with bits above the 32nd
    # parses rather than wrapping — which is exactly what must be refused
    # here, not silently classified with.
    mask_value=$((16#$(printf '%s' "$digits" | tr 'A-F' 'a-f')))
    if [ "$mask_value" -le 0 ] || [ "$mask_value" -gt $((0xffffffff)) ]; then
        die "--ct-mark-mask must name bits inside the 32 a connection mark holds, got: $ct_mark_mask"
    fi
    # Exactly two contiguous set bits: the mask is 3 shifted left by some k
    # in 0..30. Anything else — one bit, three or more, or two that are not
    # adjacent — is not a pair of identities and is refused.
    contiguous=
    k=0
    while [ "$k" -le 30 ]; do
        if [ "$mask_value" -eq $((3 << k)) ]; then
            contiguous=1
            break
        fi
        k=$((k + 1))
    done
    [ -n "$contiguous" ] ||
        die "--ct-mark-mask must name exactly two contiguous set bits (e.g. $DEFAULT_CT_MARK_MASK), got: $ct_mark_mask"
    cohort_bit=$((mask_value & -mask_value))
    node_bit=$((mask_value ^ cohort_bit))
    clear_mask=$((0xffffffff ^ mask_value))
    # Eight digits every time, so the value the record's name carries is the
    # value the ruleset renders — `printf %x` would drop leading zeros, and a
    # mask spelled two ways is a mask a reader has to compare by value
    # instead of by name.
    mask_hex=0x$(printf '%08x' "$mask_value")
    cohort_hex=0x$(printf '%08x' "$cohort_bit")
    node_hex=0x$(printf '%08x' "$node_bit")
    clear_hex=0x$(printf '%08x' "$clear_mask")
}

# ct_mark_conflicts_in — the lines of an nftables or iptables-save listing,
# read on stdin, whose ct-mark use touches either of the mask's two bits —
# this step's own table's rules excepted, because a re-install replaces
# that whole table rather than sharing bits with it. One awk, POSIX on
# purpose (this script runs on BSD awk too): it has no strtonum and no
# bitwise operators, so hexadecimal values are parsed by hand and each bit
# is tested with a division and a remainder. The 0x spellings both listings
# print are found lexically; the decimal spellings iptables' mark options
# use are read from the value that follows each one, split on the "/" of a
# value/mask pair — a mask naming a bit is a use of it, never mind which
# side of the pair it is on.
ct_mark_conflicts_in() {
    awk -v a="$cohort_bit" -v b="$node_bit" -v own="$TABLE_NAME" '
        function bit(v, x) { return int(v / x) % 2 == 1 }
        function hex(s,  i, d, v) {
            v = 0
            for (i = 1; i <= length(s); i++) {
                d = index("0123456789abcdef", tolower(substr(s, i, 1))) - 1
                if (d < 0) return -1
                v = v * 16 + d
            }
            return v
        }
        # A table header names whose rules follow: everything until the next
        # header belongs to it, and this step replacing its own table is not
        # a host it must refuse to install over.
        $1 == "table" { own_table = ($3 == own); next }
        own_table { next }
        /ct mark|CONNMARK|connmark/ {
            line = $0
            hit = 0
            rest = line
            while (match(rest, /0[xX][0-9a-fA-F]+/)) {
                v = hex(substr(rest, RSTART + 2, RLENGTH - 2))
                if (v >= 0 && (bit(v, a) || bit(v, b))) hit = 1
                rest = substr(rest, RSTART + RLENGTH)
            }
            for (i = 1; i < NF; i++) {
                if ($i ~ /^--(set-mark|set-xmark|or-mark|and-mark|xor-mark|save-mark|restore-mark|mask|mark)$/) {
                    split($(i + 1), parts, "/")
                    for (p in parts) {
                        if (parts[p] ~ /^0[xX]/ || parts[p] !~ /^[0-9]+$/) continue
                        if (bit(parts[p] + 0, a) || bit(parts[p] + 0, b)) hit = 1
                    }
                }
            }
            if (hit) print line
        }
    '
}

# scan_ct_mark_conflicts — before loading, the ruleset this host already
# carries is read for any ct-mark use that touches the bits this install
# classifies with. The connection mark is a shared namespace: a component
# already writing one of these bits would be overwritten by the classify
# chain and would overwrite it back, and each side silently corrupts the
# other's classification — so the install refuses, naming the rule and the
# override, rather than loading a table over a conflict its own scan
# shows. `nft list ruleset` must succeed: a ruleset this step cannot read
# is a host it refuses to guess about, and that listing also carries every
# rule the nft backend of iptables holds. iptables-save is read where it
# exists, for legacy rules that bypass nft's own view, and skipped where it
# cannot be read, because a failure to read a *second* listing is no
# conflict — the first one already had to be legible.
scan_ct_mark_conflicts() {
    if ! listing="$(nft list ruleset 2>/dev/null)"; then
        die "cannot read this host's ruleset with \`nft list ruleset\` to check the ct-mark bits $mask_hex: refusing to load a classification over a ruleset this step cannot see"
    fi
    conflicting="$(printf '%s\n' "$listing" | ct_mark_conflicts_in)"
    if command -v iptables-save >/dev/null 2>&1 &&
        legacy="$(iptables-save 2>/dev/null)" && [ -n "$legacy" ]
    then
        conflicting="$conflicting$(printf '%s\n' "$legacy" | ct_mark_conflicts_in)"
    fi
    if [ -n "$conflicting" ]; then
        printf 'error: this host already uses the ct-mark bits %s this install classifies with:\n%s\n' "$mask_hex" "$conflicting" >&2
        die "refusing to install over another ct-mark user: pass --ct-mark-mask <two contiguous bits nothing else classes with> and this step classifies with those instead"
    fi
}

# recorded_ct_mark_masks <tree-root> — the ct-mark masks an install
# recorded beside the marker, one per line: the record is a cgroup named
# "$MASK_RECORD_PREFIX<0x mask>", so the name carries the value, and a
# reader never has to guess the default. Uninstall and --check read it
# here, and the daemon's probe reads the same names its own way.
recorded_ct_mark_masks() {
    for record in "$1"/"$MASK_RECORD_PREFIX"*; do
        [ -d "$record" ] || continue
        printf '%s\n' "${record#"$1/$MASK_RECORD_PREFIX"}"
    done
}

if [ "$mode" = check ]; then
    do_check
    exit 0
fi

# --print-ruleset: the table this step would load, on stdout, and nothing
# else — no root, no tree, no table, no marker. It is how the daemon's own
# tests read the rule set they assert against, so what they pin is what a
# host actually loads, not a second spelling of it kept in step.
if [ "$mode" = print_ruleset ]; then
    verify_mount >/dev/null
    require_identities
    require_mask
    compute_cgroup_paths
    render_ruleset
    exit 0
fi

# The root check is the one thing the rehearsal posture lifts; everything
# else runs unchanged.
if [ "$rehearsal" != 1 ]; then
    [ "$(id -u)" -eq 0 ] || die "must run as root (try: sudo $0${original_args[0]+ }${original_args[*]-})"
fi

if [ "$mode" = place ]; then
    place_daemon
    exit 0
fi

if [ "$mode" = uninstall ]; then
    # The table first: it is this step's own artifact and it outlives the
    # cgroups it is keyed on — a table left loaded over a removed tree
    # decides nothing while still looking installed. rmdir, never rm, for
    # everything else: on the real filesystem these are cgroups, and the
    # kernel refuses to remove one that still holds a process — which is
    # exactly the guard wanted here (stop minimald first).
    if command -v nft >/dev/null 2>&1 &&
        nft list table inet "$TABLE_NAME" >/dev/null 2>&1
    then
        nft delete table inet "$TABLE_NAME" ||
            die "cannot remove the classifier table inet $TABLE_NAME (is another nft call holding it?)"
        note "removed the classifier table inet $TABLE_NAME"
    fi
    rmdir "$tree_root/$DAEMON_LEAF" 2>/dev/null || true
    rmdir "$tree_root/$TABLE_MARKER" 2>/dev/null || true
    # The mask records go with the marker they were written beside, read
    # back by prefix so whatever mask an install chose comes away with its
    # install, never a record left vouching for a table that is gone.
    for record in "$tree_root"/"$MASK_RECORD_PREFIX"*; do
        [ -d "$record" ] || continue
        rmdir "$record" 2>/dev/null || true
    done
    rmdir "$tree_root/$BOXES_DIR/$DENY_DIR" 2>/dev/null || true
    rmdir "$tree_root/$BOXES_DIR/$ALLOW_DIR" 2>/dev/null || true
    rmdir "$tree_root/$BOXES_DIR" 2>/dev/null || true
    if rmdir "$tree_root" 2>/dev/null; then
        note "removed the classifier tree at $tree_root"
        exit 0
    fi
    die "could not remove $tree_root: a live leaf or process still holds it (stop minimald and its sessions first)"
fi

verify_mount
resolve_owner
require_identities
require_mask
command -v nft >/dev/null 2>&1 ||
    die "nft is this step's dependency: install it (e.g. apt install nftables) and run this step again"
# The bits this install classifies with are nobody else's: whatever ruleset
# the host carries is scanned for a ct-mark user of them, ours excepted,
# and a conflict is refused, named, with the override — never installed
# over, because a silent overwrite would corrupt both sides' facts. The
# scan runs before anything is laid out, so a refused install touches
# nothing on the host.
scan_ct_mark_conflicts

# mkdir, not install -d: on a cgroup2 mount mkdir is the operation itself (the
# hierarchy decides its own permissions, there is no mode to set), and it is
# the one form every host this script runs on guarantees — BSD install -d is a
# different tool with its own default mode.
mkdir -p "$tree_root" ||
    die "cannot create $tree_root (is cgroup2 mounted there, and this account allowed to?)"
mkdir -p "$tree_root/$DAEMON_LEAF" "$tree_root/$BOXES_DIR"
mkdir "$tree_root/$BOXES_DIR/$DENY_DIR" 2>/dev/null ||
    [ -d "$tree_root/$BOXES_DIR/$DENY_DIR" ] ||
    die "cannot create $tree_root/$BOXES_DIR/$DENY_DIR"
mkdir "$tree_root/$BOXES_DIR/$ALLOW_DIR" 2>/dev/null ||
    [ -d "$tree_root/$BOXES_DIR/$ALLOW_DIR" ] ||
    die "cannot create $tree_root/$BOXES_DIR/$ALLOW_DIR"

# Delegate each cgroup this script lays out — the slice first, because a
# migration between two of its leaves is a write to the slice's own
# cgroup.procs — as the v2 contract spells it: the directory plus
# cgroup.procs, cgroup.threads and cgroup.subtree_control. Ownership of a
# directory alone is not delegation: the daemon's migrations are writes to
# the common ancestor's cgroup.procs, and enabling controllers in the
# leaves below is a write to subtree_control. Nothing above the slice is
# touched — the mount root stays root-owned, which is the barrier.
for cgroup in \
    "" "/$DAEMON_LEAF" "/$BOXES_DIR" \
    "/$BOXES_DIR/$DENY_DIR" "/$BOXES_DIR/$ALLOW_DIR"
do
    dir="$tree_root$cgroup"
    for file in cgroup.procs cgroup.threads cgroup.subtree_control; do
        # On a cgroup2 mount the kernel makes these at mkdir; only a
        # rehearsal's stand-in tree has no kernel to make them, so make
        # the file that stands in for one there.
        [ -e "$dir/$file" ] || : >"$dir/$file"
        chown "$owner_uid:$owner_gid" "$dir/$file"
    done
    chown "$owner_uid:$owner_gid" "$dir"
done

# The cgroups' paths the ruleset is keyed on, as the covering mount spells
# them (see compute_cgroup_paths).
compute_cgroup_paths

# The one nftables transaction. `nft -f` applies a batch whole or not at
# all, so the ruleset above carries its own prelude — declare this table,
# delete it, then the definition — and the load replaces whatever a previous
# run left in one move. nft resolves the cgroups' paths against the
# hierarchy at load, so a transaction naming a cgroup this step did not make
# dies whole.
# The marker goes before the load, not after a failed one: it is the one
# fact the daemon reads, and a marker that outlives a failed re-install
# would vouch for a table this step did not render — the previous one —
# while the host reports a verdict decided on it. Failing to remove it is
# failing closed: die before touching the table, so no marker ever
# survives a load that did not succeed.
if [ -e "$tree_root/$TABLE_MARKER" ] && ! rmdir "$tree_root/$TABLE_MARKER" 2>/dev/null; then
    die "cannot remove the presence marker at $tree_root/$TABLE_MARKER: a re-install must leave no marker over a table it did not load (is something squatting on its name?)"
fi
# The mask records follow the marker's discipline for its own reason: two
# records would be two masks, and a daemon that cannot tell which one the
# loaded table classifies with reads the step as not installed — so a
# re-install that cannot remove the records it is about to replace dies
# before touching the table, exactly as it does for the marker.
for stale_record in "$tree_root"/"$MASK_RECORD_PREFIX"*; do
    [ -d "$stale_record" ] || continue
    rmdir "$stale_record" 2>/dev/null ||
        die "cannot remove the previous ct-mark mask record at $stale_record: a re-install must leave no record beside a table it did not load"
done
# Render into a variable first, so nothing that touches a disk can sit between
# rendering and loading. The captured text is byte for byte what render_ruleset
# wrote: `read -d ''` with an empty delimiter reads without a terminator, so
# every trailing newline survives (a command substitution would strip them and
# the digest below would then cover different bytes than nft received).
IFS= read -r -d '' ruleset < <(render_ruleset) || true
ruleset_sha256="$(sha256_of "$ruleset")"
printf '%s' "$ruleset" | nft -f - || die "nft refused the classifier table: the previous table, if any, is untouched and neither the marker nor its ct-mark mask record was written, so minimald reports no per-box verdict until this step succeeds (nft's own error is above)"
note "loaded the classifier table inet $TABLE_NAME: sha256 $ruleset_sha256, over exactly the bytes piped to nft"

# The presence marker the daemon probes at start, and the ct-mark mask
# recorded beside it: on real cgroupfs a plain file cannot exist, so each
# is a cgroup of its own — ones that hold no process and are never
# delegated, because only this step writes them. Both are removed before
# the transaction above and written again only after it succeeded, so a
# daemon that finds the marker knows the table it vouches for is the one
# this step rendered, and the mask the marker's table classifies with is
# the one this step chose — not a default the daemon would have to guess
# at. The record is written first and the marker last, so the marker is
# the commit point: it is never there without the mask beside it, and a
# daemon that reads it also reads the one value the table classifies by.
mask_record="$tree_root/$MASK_RECORD_PREFIX$mask_hex"
mkdir "$mask_record" 2>/dev/null ||
    [ -d "$mask_record" ] ||
    die "cannot record the table's ct-mark mask at $mask_record"
mkdir "$tree_root/$TABLE_MARKER" 2>/dev/null ||
    [ -d "$tree_root/$TABLE_MARKER" ] ||
    die "cannot create the table's presence marker at $tree_root/$TABLE_MARKER"

note "installed the classifier tree at $tree_root"
note "  $DAEMON_LEAF/            the daemon itself, entered at startup or placed with --pid"
note "  $BOXES_DIR/$DENY_DIR/    the boxes that admit no destination, resolved through the answerer"
note "  $BOXES_DIR/$ALLOW_DIR/   every other box"
note "delegated to $owner_uid:$owner_gid per the v2 contract: each directory plus its cgroup.procs, cgroup.threads and cgroup.subtree_control"
note "loaded the classifier table inet $TABLE_NAME: $deny_path is refused everything but the answerer at $answerer_address:$answerer_port (its DNS-port lookups retargeted there), and the refusal is active, never a silent drop"
note "the boxes cohort leaves as $cohort_address; everything else in the slice as $node_plane_address"
note "classified the cohort and the node plane on the ct-mark bits $mask_hex: the ruleset this host carried used neither, and a re-install rescans before it loads"
note "wrote the table's presence marker at $tree_root/$TABLE_MARKER with the ct-mark mask $mask_hex recorded beside it: minimald records a per-box verdict only while both are there"
note "the cgroup2 mount above the slice stays root-owned"
note "place the running daemon next: sudo $0 --pid <pid of minimald> (or start it from a Delegate=yes unit)"
note "once minimald is in the slice, each box it launches runs in a leaf of its own; its launch log names the leaf each box entered"
