---
id: "TBD"
title: "S1: nested userns re-verification from THIS tree's minimald image (CF Container)"
status: in-progress
date: 2026-07-25
budget_hours: 4
actual_hours: 1
progress: "probe primitive-set GROUNDED in sandbox2 new_container: correction — add CGROUP unshare + /dev(devfs)+/tmp(tmpfs) mounts to the probe, drop UTS assertion (not explicitly unshared), skip NET (host-net-only cloud target). Live in-CF probe still pending a deploy."
related:
  - "plan: /home/.claude/plans/look-at-the-lessons-silly-stallman.md (Phase 0, S1)"
  - "sibling: norrietaylor/minimal-sessions docs/spikes/2026-05-16-nested-userns-cf-container.md"
  - "branch: fix/sandbox2-mountinfo-locked-flags (S3 — the remount-RO fix this spike exercises)"
  - "crates/sandbox2/src/lib.rs (hakoniwa/userns primitive layer)"
tags:
  - cloudflare
  - remote-provider
  - sandbox2
  - userns
  - de-risk
---

# Question

Does `minimald`'s `sandbox2`/hakoniwa primitive layer run **nested and natively**
inside a Cloudflare Container built from **this** repository (not the sibling's
image)? Specifically, inside a deployed CF Container running our amd64 static-musl
`minimald`:

1. Do `unshare(USER|MNT|PID|UTS)`, `mount -t tmpfs`, `mount -t proc`, and
   `pivot_root` all succeed unprivileged?
2. What is `max_user_namespaces`, and does the CF controller run as uid 0 as the
   sibling observed?
3. Does a real `min run`-equivalent sandbox spin-up (not just a primitive probe)
   complete end-to-end?

# Hypothesis

Yes — the sibling proved it for their image (`max_user_namespaces=1845`;
`unshare`/tmpfs/`pivot_root`/proc all pass), and nothing in our sandbox2 stack
diverges at the primitive level. Native-in-container is confirmed; **no nested
VM** is needed (and libkrun/KVM is unavailable regardless).

# Method

1. Build an amd64 static-musl `minimald` from this tree and package the CF
   container image (see the S3 branch / the planned CI lane for the image build).
2. Deploy one CF Container (`standard-3`/`standard-4`) and exec into it.
3. Run the primitive probe over the set **this tree actually requests** (corrected
   from `USER|MNT|PID|UTS` — see Findings § "Code-level grounding"): assert
   `unshare(USER|MNT|PID|`**`CGROUP`**`)` + `devfsmount /dev` + `tmpfsmount /tmp` +
   `proc` mount + rootfs `pivot_root` succeed; skip NETWORK (host-net-only cloud
   target); capture `/proc/sys/user/max_user_namespaces`, `id`, and the
   AppArmor/seccomp posture.
4. Run a real sandboxed task (`min run <trivial task>`-equivalent) nested inside
   and confirm it composes its rootfs and executes.

# Gate

**PASS** ⇒ every primitive passes AND the real sandbox spin-up completes ⇒
native-in-container confirmed for this tree; unblocks P1 provider plumbing.
**FAIL** ⇒ capture exactly which primitive/step fails and the kernel error; a
primitive-level failure is a hard architecture blocker — STOP and re-plan (there
is no VM fallback on CF).

# Findings

## Code-level grounding of the probe (2026-07-25, local — no deploy)

The primitive list in the Method above was a generic guess; the actual primitive set
`sandbox2` requests is now read off the tree (`crates/sandbox2/src/lib.rs`
`new_container`, lines 490–534), so the CF probe covers **exactly our syscalls**:

- **Namespaces unshared:** USER + MNT + PID come from hakoniwa's rootless
  `Container::new().rootfs()` default; **CGROUP is explicitly unshared** (line 497,
  with `Runctl::IgnoreCgroupSetupFailed` at 498 — cgroup *setup* failure is tolerated
  and degrades accounting only, not security); **NETWORK is unshared only for
  NoNet/OwnIp** (line 526) and **fails closed** if unavailable (lines 527–533).
  - **Correction to the stub's `USER|MNT|PID|UTS` list:** add **CGROUP** to the probe;
    UTS is not explicitly unshared here (confirm whether hakoniwa unshares it by
    default rather than asserting it). NETWORK is **out of scope for the CF probe** —
    cloud sessions are **host-net only** (no in-container iptables, per the plan), so
    `isolate=false` and the netns unshare + its fail-closed path are never exercised
    in CF. Probe in host-net mode.
- **Mount primitives (beyond the S3 bind path):** `devfsmount("/dev")` (line 495),
  `tmpfsmount("/tmp")` (line 496), and the composed-rootfs `pivot_root` (inside
  hakoniwa's `rootfs()`). The probe should assert `/dev` + `/tmp` mounts and the
  rootfs pivot all succeed nested, in addition to `unshare` + `proc`.
- **The S3 remount path is the per-bind mount:** `MountOptions::BIND | NOSUID
  [| RDONLY | REC] | locked_mount_flags(path)` (lines 460–467) — this is precisely
  the `bind+remount-RO` path S3 fixes, so S1's real-task step exercises the S3 change
  end-to-end (as the coupling note below already says).

Net: nothing in our config diverges from the sibling's proven primitive set at a
level that would change the verdict, **except** that our probe must additionally
cover the CGROUP namespace and the `/dev`+`/tmp` mounts, and can **skip** the netns
path entirely for the host-net cloud target.

## Live probe results

_TBD — fill on execution. Record the probe table (primitive → OK/FAIL) covering
USER/MNT/PID/**CGROUP** unshare + `/dev`(devfs) + `/tmp`(tmpfs) + rootfs `pivot_root`
+ `proc` mount, plus `max_user_namespaces`, uid, AppArmor/seccomp state, and the
real-task (S3-exercising) outcome._

# Conclusion

_TBD — one line: native-in-container confirmed / blocked, with the deciding
evidence._

# Action items

_TBD._

# Residual Risks / Live Trial Needed

- Requires a live CF Containers deployment (Workers Paid) — cannot be run from the
  local dev sandbox.
- Couples to S3: the real-task path exercises the `bind+remount-RO` fix; run S1
  against an image that includes the S3 mountinfo-locked-flags change.

# Artifacts

_TBD — image ref/digest, `wrangler` config, probe script, raw logs._
