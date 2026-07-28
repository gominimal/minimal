---
id: spec-ssh-host-key-in-beacon
title: "feat(minvmd): include SSH host public key in the ready beacon"
kind: spec
status: shipped
tracking-issue: 467
supersedes:
---

# feat(minvmd): include SSH host public key in the ready beacon

## Context

`minimald` ships as the initramfs `/init` in the minvmd microVM. On boot it
emits a one-shot `READY\n` marker over vsock port 7350 to signal the VM is up.
The host (`minvmd boot` and `minvmd run`) receives this marker and signals boot
completion to its caller.

The native (non-VM) `minimald` path already writes the SSH host key to a
per-instance `known_hosts` file on startup (`minimald/src/main.rs:377–382`,
via `russh::keys::known_hosts::learn_known_hosts_path`). In the VM path the
equivalent write happens inside the VM into `/run/minimal/…` (a tmpfs the host
SSH client never sees), so the first SSH connection to a fresh VM triggers a
host-key warning or interactive TOFU prompt.

(informed by #409, the KVM READY marker implementation that established the
current one-line beacon protocol and the boot.rs / run.rs duplication)

## Introduction/Overview

Extend the ready-beacon wire format from one line (`READY\n`) to two lines
(`READY\n<openssh-pubkey>\n`). `minimald` (the guest pid-1) already holds the
SSH host private key at the moment it emits the beacon; the public key is cheap
to serialize in OpenSSH authorized_keys format. `minvmd` reads the second line,
parses it as an SSH public key, and writes it to
`$XDG_STATE_HOME/minimal/providers/local-minvmd0/known_hosts` on the host so the
SSH client finds it before the first connection attempt.

## Goals

1. Fresh VM sessions connect with no host-key warning and no interactive TOFU
   prompt.
2. A malformed or absent key in the beacon does not fail the VM boot.
3. The change is backward-compatible: a `minvmd` that does not read the second
   line continues to work with an older guest.

## User Stories

- **As a developer**, when I connect to a minvmd microVM session for the first
  time, I want the SSH connection to succeed cleanly without a host-key warning.

## Demoable Units of Work

### Unit 1 - Beacon enrichment (minimald, guest side)

**R1.1**, The beacon emission is extended from one line to two: `READY\n`
followed by the SSH host public key in OpenSSH authorized_keys format on a
second line, terminated by `\n`.

**R1.2**, In the vsock boot path, the beacon emitter receives the SSH host
public key already loaded from the host configuration; no redundant key load
is introduced.

**Proof artifacts**:

- **Test**: A unit test in `minimald` constructs a mock in-memory writer, calls
  `emit_ready_marker(&pubkey)` with a generated Ed25519 key, and asserts that
  the written bytes equal `b"READY\n"` followed by the key in OpenSSH format
  followed by `b"\n"`. This test does not pass against the current
  single-line implementation.

### Unit 2 - Key reception and known_hosts write (minvmd, host side)

**R2.1**, Both `minvmd boot` and the `minvmd run` supervisor read a second
line from the beacon connection immediately after validating `READY`.

**R2.2**, If the second beacon line contains a valid SSH public key, `minvmd`
records it in `known_hosts` at
`$XDG_STATE_HOME/minimal/providers/local-minvmd0/known_hosts` for hostname `local-minvmd0`
at port 22, using the same known-hosts API path already used by the native
(non-VM) `minimald` flow.

**R2.3**, If the second line is absent, empty, or fails to parse as an SSH
public key, `minvmd` logs a warning and proceeds; the boot is not aborted.

**R2.4**, The `providers/local-minvmd0/` directory hierarchy is created before
writing `known_hosts`.

**R2.5**, `russh` is promoted from `[dev-dependencies]` to `[dependencies]`
in `minvmd/Cargo.toml` so the production code can call
`russh::keys::known_hosts::learn_known_hosts_path`.

**Proof artifacts**:

- **Test**: An integration test in `minvmd` creates a mock marker Unix socket,
  writes `READY\n<valid-ed25519-pubkey>\n` to it, exercises the READY-marker
  read path, and asserts the expected `known_hosts` entry is present in a temp
  directory. This test cannot pass against the current single-line reader.
- **File**: After `minvmd run` completes boot against a real guest,
  `$XDG_STATE_HOME/minimal/providers/local-minvmd0/known_hosts` exists and contains
  a valid entry for `local-minvmd0` at port 22 matching the VM's SSH host key.

## Non-Goals

- Changing the vsock port or creating a new side-channel for the key exchange.
- Writing `known_hosts` for instance numbers other than 0 (VMs always boot as
  instance 0 per the hardcoded `is_minimal_microvm()` config).
- Rotating or re-verifying the key across reboots (`learn_known_hosts_path`
  is idempotent for the same key and updates the entry on key change).
- Updating `MinimalClientHandler::check_server_key` in `minimal/src/client.rs`
  (the internal RPC client already accepts any key unconditionally; this spec
  targets user-facing SSH warnings on first connect).

## Design Considerations

**Why extend the beacon protocol instead of a file channel?**
The marker Unix socket is the only reliable synchronization point between guest
and host at boot time; it is already used for the `READY` signal and is kept
alive for the duration of the read. A file-based channel would require a shared
filesystem or a new vsock port; both add complexity. A second line on the
existing connection is the simplest extension that fits the established pattern.

**Hostname and port in `known_hosts`**
`minimald` uses `"local-{instance_num}"` as the SSH hostname (from `ssh_args()`
at `minimald/src/main.rs:109`). In the VM case `instance_num` is always 0
(hardcoded in `is_minimal_microvm()`). `minvmd` therefore hard-codes `"local-minvmd0"`
and port `22` in the `learn_known_hosts_path` call, matching the native path.

**Non-fatal key parse**
A failed parse must not prevent the VM from booting. The SSH server is up
regardless; the only consequence of a missing `known_hosts` entry is the first
manual SSH connection prompts TOFU. Keeping the boot non-fatal is the safer
default and preserves backward compatibility with an older guest that sends only
one line.

**Known_hosts path on the host**
The path is `$XDG_STATE_HOME/minimal/providers/local-minvmd0/known_hosts`, derived the
same way `minimald`'s native path is derived. `minvmd` already uses
`dirs::state_dir()` for its own state (`$XDG_STATE_HOME/minimal/minvmd/`), so
the derivation is consistent and needs no new configuration.

**READY marker duplication**
The READY marker read logic is duplicated between `boot.rs::run_boot` and
`run.rs::run_foreground`. Both functions must be updated; factoring the read into
a shared helper in `cmd/mod.rs` is advisable to keep the two in sync.

## Repository Standards

Single-PR path: no separate architecture record; see Design notes above; the
implementation plan is in the tracking issue comment (ADR 0024).

## Open Questions

None. The prior art (`learn_known_hosts_path` call at
`minimald/src/main.rs:377–382`) settles the API, hostname, and port. The beacon
extension is additive and backward-compatible.

## Technical Considerations

- `russh::keys::known_hosts::learn_known_hosts_path` is idempotent: repeated
  calls with the same key produce no duplicate entries; a key rotation (new VM,
  new key) updates the entry in place.
- `PublicKey::to_openssh()` serializes to the standard OpenSSH authorized_keys
  line format (e.g. `ssh-ed25519 AAAA…`), which `PublicKey::from_openssh()`
  can round-trip.
- The `dirs::state_dir()` call in `minvmd` uses the same XDG variable as
  `minimald`, so the path is consistent across both processes on the same host.

## Security Considerations

- The host key is delivered over the marker Unix socket, which is created with a
  PID+nonce path (`/tmp/minvmd-marker-<pid>-<nonce>.sock`) and used once. The
  socket's lifetime is the boot window (≤5 s); there is no persistent exposure.
- The `learn_known_hosts_path` call uses TOFU semantics: the first key for
  `local-minvmd0:22` is accepted; a later differing key from the same hostname is
  treated as a possible MITM by the SSH client. Because the marker socket
  includes a random nonce and the VM is a locally controlled environment, this
  is an acceptable trust model.

## Verification

1. `cargo test -p minimald`, the `emit_ready_marker` unit test (R1.1) passes.
2. `cargo test -p minvmd`, the READY-marker integration test (R2.1–R2.4)
   passes; the expected key entry is present in the temp `known_hosts`.
3. End-to-end: `minvmd run` followed by a fresh SSH connect with
   `ssh -o UserKnownHostsFile=<path> local-minvmd0` succeeds with no host-key prompt.
