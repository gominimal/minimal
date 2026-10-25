# Split-user VMM: provider directory and socket ownership

Status: proposed. The architecture ruling is pending. This document records
the model that it asks the architecture to rule on, and the fallback.

## Question

The plan moves gvproxy and the VMM child (`minvmd __krun-vmm`) to a
dedicated unprivileged user. The `minvmd run` supervisor, `min` and the
Box Egress Proxy (`bep serve`) stay with the login user. Each provider
directory socket and file must stay reachable by the processes that open it.

Today one user owns the provider directory. `sock::prepare_socket_dir`
creates it with mode 0700. `sock::restrict_owned_dir` tightens it back to
0700, and `sock::verify_provider_dir_ownership` refuses any other owner or
mode. Every socket gets 0600 through `sock::enforce_socket_permissions`. A
second user can then open nothing in the directory.

The provider directory is `<state dir>/providers/local-minvmd0/` for the
default VM (`state::provider_dir`).

## Names in this document

- `<login>`: the user who runs `min`. The supervisor, `bep serve` and
  `min` run as this user.
- `minimal-vmm`: the dedicated unprivileged user. On macOS the name is
  `_minimal-vmm`, following the platform convention for service accounts.
- `minimal-vmm` (group): a group whose members are `minimal-vmm` and
  `<login>`. It is the primary group of the `minimal-vmm` user.

## What each process does today

This list comes from `sock.rs`, `vm.rs`, `image.rs`, `volume.rs`,
`cmd/vmm_child.rs`, `cmd/run.rs`, `net.rs`, `net/shuttle.rs`, `timekeep.rs`,
`control.rs`, `guest_telemetry.rs` and `crates/bep/src/listener.rs`.

- `vm.rs` `apply` (in the VMM child) calls `prepare_socket_dir` on the
  `ssh.sock` path. It removes a stale `ssh.sock` and registers it with
  `krun_add_vsock_port2(listen = true)`. libkrun binds the socket, so the VMM
  child creates it. The child registers `gvproxy-gate.sock` with
  `listen = false`, so libkrun connects to it.
- `cmd/vmm_child.rs` also calls `prepare_socket_dir` on `timekeep.sock`.
  libkrun binds it (`listen = true`), and the timekeep thread in the same
  child connects to it.
- `cmd/vmm_child.rs` creates `boot.log` with `File::create`, unless
  `MINVMD_BOOT_LOG` names another path. It creates `data-vol.raw` with
  `volume::ensure_sparse_raw`, unless `MINVMD_DATA_VOLUME_PATH` names another
  path. libkrun opens the volume read-write as the guest data disk.
- `cmd/vmm_child.rs` connects (through libkrun, `listen = false`) to the
  marker socket, `guest-control.sock` and `guest-telemetry.sock`. The
  supervisor binds all three before it spawns the child.
- `image.rs` resolves the kernel, rootfs and initramfs under the data
  directory (`~/.local/share/minimal`), not under the provider directory.
  The VMM child only reads them.
- `cmd/run.rs` binds the marker socket at
  `/tmp/minvmd-marker-<pid>-<nonce>.sock`. It is outside the provider
  directory, but the VMM child opens it, so the model lists it.
- `cmd/run.rs` runs `enforce_socket_permissions` on `ssh.sock` after the VM
  is up. That is a `chmod` from the supervisor.
- `net.rs` writes `gvproxy.yaml` and spawns gvproxy with
  `-listen unix://<provider dir>/gvproxy-switch.sock`. gvproxy creates the
  switch socket, and the egress gate in the supervisor connects to it.
- `net/egress_gate.rs` binds `gvproxy-gate.sock` in the supervisor.
- `control.rs` binds `control.sock` and `guest-control.sock`.
  `guest_telemetry.rs` binds `guest-telemetry.sock`. Each one calls
  `restrict_owned_dir`, `verify_provider_dir_ownership` and
  `enforce_socket_permissions`.
- `crates/bep/src/listener.rs` binds `gvproxy-bep.sock` with
  `bind_owner_only` (0600). It admits a peer only when the peer uid equals
  its own uid. The peer is `switch::bep_host`, which runs inside the
  supervisor, not inside gvproxy.
- `min` connects to `ssh.sock` and `control.sock`. `min diag` reads
  `boot.log` and reads the size of `data-vol.raw` (`diag/collect.rs`).
- On a failed boot the supervisor can remove a blank `data-vol.raw`
  (`cmd/mod.rs`, R2.5 disposition). That needs write access to the
  directory, not to the file.

## Facts the model depends on

1. To create or unlink an entry, a process needs write and search access to
   the directory.
2. On Linux, `connect(2)` to a unix socket needs write permission on the
   socket file. Before T38 relies on it, it must confirm that macOS checks the
   same bit.
3. Only the owner of a file (or root) can `chmod` it. The supervisor's
   `chmod` of `ssh.sock` fails with `EPERM` when `minimal-vmm` owns the
   socket. The VMM child must set the mode of the sockets it creates.
4. libkrun binds a socket with the mode that the umask of the process gives.
   The VMM child sets its umask to `0007` before the first `add_vsock_port2`.
5. A directory with the setgid bit gives its group to every new entry. A
   3770 directory with group `minimal-vmm` gives every new socket and file the
   `minimal-vmm` group, whichever of the two users creates it.
6. A directory with the sticky bit lets a user unlink or rename an entry
   only when that user owns the entry or owns the directory. In a 3770
   directory that `<login>` owns, `minimal-vmm` can create entries, but it
   cannot unlink, rename or replace an entry that `<login>` owns. `<login>`
   can unlink any entry, because it owns the directory.
7. `bind(2)` fails with `EADDRINUSE` when any entry, a symlink included,
   already exists at the path. After a bind succeeds, the path is the
   socket that the caller bound.
8. `sudo` resets the environment and closes inherited descriptors above 2 by
   default. The VMM child reads `MINVMD_MARKER_SOCK`,
   `MINVMD_GUEST_REPORT_SOCK`, `MINVMD_GUEST_TELEMETRY_SOCK` and the state
   identity from its environment. It also inherits the alive lock descriptor
   (`alive_lock.inherit_into`). The drop-in must keep these, or the spawn must
   pass them as arguments.

## Ownership model

The hypothesis: a group that the two users share, a 3770 provider
directory (setgid and sticky), and 0660 on each socket that the other user opens. A socket or
file that only one user opens stays 0600. The uid change goes through a
sudoers drop-in that `min finalize-install` installs. The drop-in permits
`<login>` to run the `minvmd` and gvproxy binaries as `minimal-vmm`, and
nothing else.

Every row names the user that creates the entry, the mode it gets, and each
user that opens it.

| Path | Created by | Mode | Opened by |
|---|---|---|---|
| `<provider dir>/` | `<login>` (`prepare_socket_dir`, from the supervisor before the spawn) | 3770, group `minimal-vmm` | `<login>` (supervisor, `min`, `bep serve`), `minimal-vmm` (VMM child, gvproxy) |
| `ssh.sock` | `minimal-vmm` (VMM child, libkrun bind) | 0660 | `<login>` (`min`), `minimal-vmm` (libkrun bridge) |
| `timekeep.sock` | `minimal-vmm` (VMM child, libkrun bind) | 0600 | `minimal-vmm` (timekeep thread in the VMM child) |
| `gvproxy-gate.sock` | `<login>` (supervisor, egress gate) | 0660 | `minimal-vmm` (VMM child, libkrun shuttle) |
| `guest-control.sock` | `<login>` (supervisor, guest report door) | 0660 | `minimal-vmm` (VMM child, libkrun) |
| `guest-telemetry.sock` | `<login>` (supervisor, guest telemetry door) | 0660 | `minimal-vmm` (VMM child, libkrun) |
| `/tmp/minvmd-marker-<pid>-<nonce>.sock` | `<login>` (supervisor) | 0660, group `minimal-vmm` set with `fchown` before `listen` | `minimal-vmm` (VMM child, libkrun) |
| `boot.log` | `minimal-vmm` (VMM child) | 0640 | `minimal-vmm` (libkrun console), `<login>` (`min diag`) |
| `data-vol.raw` | `minimal-vmm` (VMM child, `ensure_sparse_raw`) | 0600 | `minimal-vmm` (libkrun data disk) |
| `gvproxy.yaml` | `<login>` (supervisor, `write_config`) | 0640 | `minimal-vmm` (gvproxy) |
| `gvproxy-switch.sock` | `minimal-vmm` (gvproxy `-listen`) | 0660 | `<login>` (supervisor, egress gate) |
| `gvproxy-bep.sock` | `<login>` (`bep serve`, `bind_owner_only`) | 0600 | `<login>` (supervisor, `switch::bep_host`) |
| `control.sock` | `<login>` (supervisor) | 0600 | `<login>` (`min`) |

Notes on the table:

- `data-vol.raw` stays 0600. `min diag` reads only its metadata, and that
  needs search access to the directory, not read access to the file. The
  supervisor checks only whether it exists, and it can unlink it through
  the directory.
- `timekeep.sock` stays 0600. Only the VMM child opens it.
- `gvproxy-bep.sock` and `control.sock` stay 0600, owned by `<login>`. The
  `minimal-vmm` user can search the directory but cannot connect to them.
  `control.sock` drives the daemon, and `gvproxy-bep.sock` substitutes
  credentials, so a compromised VMM must reach neither. The peer uid check in
  `listener.rs` stays as it is, because its peer runs in the supervisor.
- The directory has the sticky bit, so `minimal-vmm` cannot unlink or
  rename `control.sock`, `gvproxy-bep.sock` or any other entry that
  `<login>` owns (fact 6). Without the sticky bit, a compromised VMM can
  delete `control.sock` and bind its own socket at that path. Then `min`
  connects to the VMM's socket. The next section says how each process
  checks an entry before it uses it.
- The group gives `minimal-vmm` access to the 0660 sockets that `<login>`
  binds, and nothing more. The supervisor sets those modes with
  `enforce_socket_permissions` after each bind. The VMM child sets the mode
  of the sockets that it creates.

## How each process checks an entry before use

The sticky bit stops `minimal-vmm` from replacing an entry that `<login>`
owns. It does not stop `minimal-vmm` from creating an entry at a name that
does not exist yet. These rules close that gap.

- Bind: the supervisor and `bep serve` `lstat` the path before they bind.
  An entry that `<login>` owns is a stale socket from an earlier run, and
  they unlink it. An entry that another user owns, or a symlink, is a
  refusal: the process logs the path and the owner, and it does not start.
  When `minimal-vmm` creates the entry between the unlink and the bind, the
  bind fails with `EADDRINUSE` (fact 7), and that is a refusal too.
- Mode: the supervisor sets the mode of a socket that it binds with
  `fchmod` on the listening descriptor where the platform permits it.
  Otherwise it runs `chmod` on the path only after the bind succeeds. Fact 7
  and fact 6 together make sure that the path is still its own socket, so a
  planted symlink cannot redirect the `chmod`.
- Connect to a `<login>` socket: `min` (for `control.sock`) and the
  supervisor (for `gvproxy-bep.sock`) `lstat` the path before they connect.
  They require a socket that their own uid owns, and they refuse anything
  else. The sticky bit makes sure that `minimal-vmm` cannot swap the entry
  after the check. `control.rs` and `listener.rs` also keep their peer uid
  checks on the listening side.
- Connect to a `minimal-vmm` socket: `min` (for `ssh.sock`) and the
  supervisor (for `gvproxy-switch.sock`) `lstat` the path and require a
  socket that `minimal-vmm` owns. These sockets carry the VM's own traffic,
  so a compromised VMM gains nothing here that it does not already have.
- Supervisor files: the supervisor writes `gvproxy.yaml` with
  `O_CREAT | O_EXCL | O_NOFOLLOW` after it unlinks a stale copy, and it
  refuses an entry that another user owns. It removes a blank
  `data-vol.raw` with `unlink`, which never follows a symlink.
- Migration: a provider directory from before the split holds `ssh.sock`,
  `timekeep.sock` and `boot.log` owned by `<login>`. The VMM child cannot
  unlink them under the sticky bit. So the supervisor removes these three
  entries before it spawns the VMM child.

## What T38 changes

- `prepare_socket_dir` creates the directory 3770 with group `minimal-vmm`.
- `restrict_owned_dir` and `verify_provider_dir_ownership` accept 3770 with
  group `minimal-vmm`. They refuse a directory without the sticky bit, a
  directory that another uid owns, and a directory that is open to others.
- The bind, connect and file checks in the section before this one.
- `enforce_socket_permissions` and `verify_socket_permissions` take the
  mode from the table. The supervisor stops the `chmod` of `ssh.sock`. The
  VMM child sets it after libkrun binds it, and the supervisor only verifies
  it.
- The supervisor spawns the VMM child and gvproxy through `sudo -u
  minimal-vmm`. The drop-in keeps the environment variables and the alive
  lock descriptor that fact 8 names.

## Fallback: only gvproxy runs as `minimal-vmm`

If the architecture does not accept the shared group, the VMM child stays
with `<login>`. Then only three rows change from today:

| Path | Created by | Mode | Opened by |
|---|---|---|---|
| `<provider dir>/` | `<login>` (`prepare_socket_dir`) | 3770, group `minimal-vmm` | `<login>` (supervisor, `min`, `bep serve`), `minimal-vmm` (gvproxy) |
| `gvproxy.yaml` | `<login>` (supervisor) | 0640, group `minimal-vmm` | `minimal-vmm` (gvproxy) |
| `gvproxy-switch.sock` | `minimal-vmm` (gvproxy `-listen`) | 0660 | `<login>` (supervisor, egress gate) |

gvproxy creates its socket in the directory, so the directory needs 3770
with group `minimal-vmm` here too. The sticky bit and the checks before use
apply as in the shared group model. The other choice is a subdirectory that
`minimal-vmm` owns, for the switch socket only. Then the provider directory
needs only 0710 with group `minimal-vmm`, and `minimal-vmm` cannot write to
it. Every other entry keeps the owner and the mode it has today.

## Open items for the architecture ruling

- Accept or refuse the shared group model, or choose the fallback.
- Choose between the sticky bit and a separate directory that `minimal-vmm`
  cannot write for the sockets that `<login>` owns.
- Confirm that macOS checks socket write permission on `connect(2)`.
- The tree has no sudoers drop-in and no `min finalize-install` command
  today. The task that installs them (T19 in this plan) must land first.
