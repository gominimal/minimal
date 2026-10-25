# Split-user VMM: provider directory and socket ownership

Status: ruled. The architecture accepted the split-user model with a
separate directory for the VM user, not a shared sticky directory. The
provider directory stays writable only by `<login>`. Every entry that
`minimal-vmm` creates goes into `<provider dir>/vmm/`, which `minimal-vmm`
owns. Two open items remain at the end of this document.

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
- `minimal-vmm` (group): the primary group of the `minimal-vmm` user. It
  has exactly one login member, `<login>`. `min finalize-install` adds
  `<login>` and removes any other login member. A second login member can
  connect to the 0660 sockets of the first user's VM, so the group never
  has two.

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
- `cmd/run.rs` names the proxy socket with
  `switch_sock.with_file_name("gvproxy-bep.sock")`, beside the switch
  socket. `timekeep.rs` names `timekeep.sock` beside the `ssh.sock` path.
- `control.rs` `serve_connection` reads the peer uid of every connection,
  on the host door (`control.sock`) and on the guest door
  (`guest-control.sock`). It admits the supervisor's own uid, and root for
  the two answerer handover verbs only. It drops every other uid
  unanswered. `guest_telemetry.rs` `accept_loop` admits only the
  supervisor's own uid. `net/egress_gate.rs` and the marker socket in
  `cmd/run.rs` do no peer check.

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
5. Only root can give a file or a directory to another user. A user who is
   not root can change the group of its own entry only to a group that it is
   a member of. So `<login>` can set group `minimal-vmm` on its own sockets,
   but it cannot create a directory that `minimal-vmm` owns.
6. A socket path exists from `bind(2)`, not from `socket(2)`. An `fchown`
   or `fchmod` on the descriptor before the bind does not change the path.
   The owner sets the group and the mode with `chown` and `chmod` on the
   path after the bind.
7. `bind(2)` fails with `EADDRINUSE` when any entry, a symlink included,
   already exists at the path. After a bind succeeds, the path is the
   socket that the caller bound. Only a user that can write the directory
   can replace it after that.
8. `sudo` resets the environment and closes inherited descriptors above 2 by
   default. The VMM child reads `MINVMD_MARKER_SOCK`,
   `MINVMD_GUEST_REPORT_SOCK`, `MINVMD_GUEST_TELEMETRY_SOCK` and the state
   identity from its environment. It also inherits the alive lock descriptor
   (`alive_lock.inherit_into`). The drop-in must keep these, or the spawn must
   pass them as arguments.
9. `sudo -n` never prompts. When no rule admits the command without a
   password, it exits non-zero at once.

## Ownership model

The provider directory belongs to `<login>`, and `minimal-vmm` cannot write
to it. `minimal-vmm` creates its entries only in `<provider dir>/vmm/`, a
subdirectory that `minimal-vmm` owns and `<login>` cannot write to. So
gvproxy and `bep serve` share no writable directory. The two users share
the `minimal-vmm` group. A socket that the other user opens gets 0660 with
group `minimal-vmm`. A socket or file that only one user opens stays 0600.

The uid change goes through a sudoers drop-in that `min finalize-install`
installs. The drop-in is a `NOPASSWD` rule that lets `<login>` run as
`minimal-vmm` exactly two commands: the `minvmd __krun-vmm` spawn of the
VMM child and the gvproxy spawn. It permits nothing else. The supervisor
runs both spawns as `sudo -n -u minimal-vmm`, so `min session start` never
prompts for a password (fact 9).

When `sudo -n` fails, the drop-in or the `minimal-vmm` user is missing. Then
the supervisor refuses to start the VM, and `min` prints an error that names
`min finalize-install`. The supervisor never starts gvproxy or the VMM child
as `<login>` in place of `minimal-vmm`. The proposed text, which T38 pins in
a test:

```text
The VM did not start: this machine has no minimal-vmm user, or no sudo rule that lets min start the VM as that user.
Run `min finalize-install` to set them up.
```

Every row names the user that creates the entry, the mode it gets, and each
user that opens it. A path that starts with `vmm/` is in `<provider dir>/vmm/`.

| Path | Created by | Mode | Opened by |
|---|---|---|---|
| `<provider dir>/` | `<login>` (`prepare_socket_dir`, from the supervisor before the spawn) | 0710, group `minimal-vmm` | `<login>` (supervisor, `min`, `bep serve`), `minimal-vmm` (VMM child, gvproxy; search only) |
| `<provider dir>/vmm/` | `root` (`min finalize-install`, which gives it to `minimal-vmm`) | 0750, owner `minimal-vmm`, group `minimal-vmm` | `minimal-vmm` (VMM child, gvproxy), `<login>` (supervisor, `min`; read and search only) |
| `vmm/ssh.sock` | `minimal-vmm` (VMM child, libkrun bind) | 0660 | `<login>` (`min`), `minimal-vmm` (libkrun bridge) |
| `vmm/timekeep.sock` | `minimal-vmm` (VMM child, libkrun bind) | 0600 | `minimal-vmm` (timekeep thread in the VMM child) |
| `vmm/boot.log` | `minimal-vmm` (VMM child) | 0640 | `minimal-vmm` (libkrun console), `<login>` (`min diag`) |
| `vmm/data-vol.raw` | `minimal-vmm` (VMM child, `ensure_sparse_raw`) | 0600 | `minimal-vmm` (libkrun data disk) |
| `vmm/gvproxy-switch.sock` | `minimal-vmm` (gvproxy `-listen`) | 0660 | `<login>` (supervisor, egress gate) |
| `gvproxy-gate.sock` | `<login>` (supervisor, egress gate) | 0660, group `minimal-vmm` | `minimal-vmm` (VMM child, libkrun shuttle) |
| `guest-control.sock` | `<login>` (supervisor, guest report door) | 0660, group `minimal-vmm` | `minimal-vmm` (VMM child, libkrun) |
| `guest-telemetry.sock` | `<login>` (supervisor, guest telemetry door) | 0660, group `minimal-vmm` | `minimal-vmm` (VMM child, libkrun) |
| `/tmp/minvmd-marker-<pid>-<nonce>.sock` | `<login>` (supervisor) | 0660, group `minimal-vmm` set with `chown` on the path after `bind` | `minimal-vmm` (VMM child, libkrun) |
| `gvproxy.yaml` | `<login>` (supervisor, `write_config`) | 0640, group `minimal-vmm` | `minimal-vmm` (gvproxy) |
| `gvproxy-bep.sock` | `<login>` (`bep serve`, `bind_owner_only`) | 0600 | `<login>` (supervisor, `switch::bep_host`) |
| `control.sock` | `<login>` (supervisor) | 0600 | `<login>` (`min`) |

Notes on the table:

- `minimal-vmm` can search the provider directory, so it can reach the
  0660 sockets there by name. It cannot list, create, unlink or rename an
  entry there. So it cannot replace `control.sock`, `gvproxy-bep.sock`,
  `gvproxy.yaml` or a door socket with its own.
- `<login>` can read and search `vmm/`, but it cannot write there. So the
  supervisor cannot unlink `vmm/data-vol.raw` or a stale socket in `vmm/`.
  The VMM child removes its own stale sockets (`prepare_socket_dir` already
  does this). The removal of a blank data volume after a failed boot (R2.5
  disposition) moves into the VMM child.
- `data-vol.raw` stays 0600. `min diag` reads only its metadata, and that
  needs search access to `vmm/`, not read access to the file.
- `timekeep.sock` stays 0600. Only the VMM child opens it.
- `gvproxy-bep.sock` and `control.sock` stay 0600, owned by `<login>`. A
  compromised VMM must reach neither: `control.sock` drives the daemon, and
  `gvproxy-bep.sock` substitutes credentials.
- `gvproxy-bep.sock` stays in the provider directory. `cmd/run.rs` must
  stop naming it beside the switch socket, because that name now points
  into `vmm/`, where `bep serve` cannot bind. `timekeep.sock` moves with
  `ssh.sock`, because `timekeep.rs` names it beside that path.
- The provider directory is not setgid, so a socket that the supervisor
  binds gets the primary group of `<login>`. The supervisor sets group
  `minimal-vmm` and mode 0660 with `chown` and `chmod` on the path after
  the bind, and before it spawns the VMM child (fact 6). `minimal-vmm`
  cannot write the provider directory, and `/tmp` is sticky. So nobody else
  can replace the path between the bind and the `chown` (fact 7).

## Peer checks after the split

The 0660 mode lets `minimal-vmm` connect. Each listener then reads the peer
uid. This list states the peer that dials each socket and the uids that the
check admits.

- `control.sock` (host door): `min` dials it as `<login>`. `serve_connection`
  admits the supervisor's own uid, and root for the two answerer handover
  verbs. This does not change. `minimal-vmm` is refused.
- `guest-control.sock` (guest door): the VMM child dials it as
  `minimal-vmm`. On this door only, `serve_connection` admits the
  `minimal-vmm` uid, and the supervisor's own uid. The host door keeps its
  check. The door, not the peer, decides which verbs a connection can ask
  for, as `control.rs` does today.
- `guest-telemetry.sock`: the VMM child dials it as `minimal-vmm`.
  `accept_loop` admits the `minimal-vmm` uid and the supervisor's own uid.
- `gvproxy-gate.sock` and the marker socket: the VMM child dials them as
  `minimal-vmm`. They have no peer check today. The 0660 mode and the
  one-member group are the gate.
- `gvproxy-bep.sock` (the BEP socket): the supervisor dials it as
  `<login>`, through `switch::bep_host`. gvproxy never dials it. The
  `listener.rs` check admits only the uid of `bep serve`, which is
  `<login>`, and then requires the token. This does not change.
  `minimal-vmm` is refused by the 0600 mode and by the uid check.
- `vmm/gvproxy-switch.sock`: the supervisor dials it as `<login>`. gvproxy
  does no peer check.
- `vmm/ssh.sock`: `min` dials it as `<login>`. libkrun does no peer check.

The supervisor resolves the `minimal-vmm` uid once at start, with
`getpwnam`. It refuses to start when the user is missing, with the error in
the ownership model.

## How each process checks an entry before use

- Bind in the provider directory: the supervisor and `bep serve` `lstat`
  the path before they bind. An entry that `<login>` owns is a stale socket
  from an earlier run, and they unlink it. Only `<login>` can write the
  directory, so no entry there has another owner. An entry that another
  user owns, or a symlink, is a refusal: the process logs the path and the
  owner, and it does not start.
- Start: the supervisor checks that `vmm/` is a directory, not a symlink,
  owned by `minimal-vmm` with group `minimal-vmm` and mode 0750. Otherwise
  it refuses to start the VM with an error that names
  `min finalize-install`.
- Connect to a `minimal-vmm` socket: `min` (for `vmm/ssh.sock`) and the
  supervisor (for `vmm/gvproxy-switch.sock`) `lstat` the path and require a
  socket that `minimal-vmm` owns. These sockets carry the VM's own traffic,
  so a compromised VMM gains nothing here that it does not already have.
- Supervisor files: the supervisor writes `gvproxy.yaml` with
  `O_CREAT | O_EXCL | O_NOFOLLOW` after it unlinks a stale copy.
- Migration: a provider directory from before the split holds `ssh.sock`,
  `timekeep.sock`, `boot.log` and `data-vol.raw` owned by `<login>`. The
  supervisor removes the stale sockets and the old `boot.log`.
  `data-vol.raw` holds the user's data, and `<login>` cannot write `vmm/`.
  So `min finalize-install`, as root, moves it into `vmm/` and gives it to
  `minimal-vmm`.

## What T38 changes

- `prepare_socket_dir` creates the provider directory 0710 with group
  `minimal-vmm`. The VMM child calls it on `vmm/` and only verifies that
  directory, because it cannot create it.
- `restrict_owned_dir` and `verify_provider_dir_ownership` accept 0710 with
  group `minimal-vmm`. They refuse a provider directory that another uid
  owns, that the group can write, or that is open to others. A new check
  verifies `vmm/` as the section before this one says.
- `ssh.sock`, `timekeep.sock`, `boot.log`, `data-vol.raw` and
  `gvproxy-switch.sock` move to `vmm/`. `gvproxy-bep.sock` keeps its path in
  the provider directory.
- `enforce_socket_permissions` and `verify_socket_permissions` take the
  mode and the group from the table. The supervisor stops the `chmod` of
  `ssh.sock`. The VMM child sets it after libkrun binds it, and the
  supervisor only verifies it.
- The guest door and the telemetry door admit the `minimal-vmm` uid, as
  the peer checks section says.
- The supervisor spawns the VMM child and gvproxy through
  `sudo -n -u minimal-vmm`. The drop-in keeps the environment variables
  and the alive lock descriptor that fact 8 names. When `sudo -n` fails,
  the start refuses with the error in the ownership model.

## Fallback: only gvproxy runs as `minimal-vmm`

If T38 cannot move the VMM child, the VMM child stays with `<login>`, and
only gvproxy runs as `minimal-vmm`. The same subdirectory carries the model:
`vmm/` holds only the switch socket. These rows change from today:

| Path | Created by | Mode | Opened by |
|---|---|---|---|
| `<provider dir>/` | `<login>` (`prepare_socket_dir`) | 0710, group `minimal-vmm` | `<login>` (supervisor, `min`, `bep serve`), `minimal-vmm` (gvproxy; search only) |
| `<provider dir>/vmm/` | `root` (`min finalize-install`, which gives it to `minimal-vmm`) | 0750, owner `minimal-vmm`, group `minimal-vmm` | `minimal-vmm` (gvproxy), `<login>` (supervisor; read and search only) |
| `gvproxy.yaml` | `<login>` (supervisor) | 0640, group `minimal-vmm` | `minimal-vmm` (gvproxy) |
| `vmm/gvproxy-switch.sock` | `minimal-vmm` (gvproxy `-listen`) | 0660 | `<login>` (supervisor, egress gate) |

Every other entry keeps the owner, the mode and the path it has today.
`minimal-vmm` cannot write the provider directory here either. The drop-in
permits only the gvproxy spawn, and the `sudo -n` refusal is the same.

## Open items

- Confirm that macOS checks socket write permission on `connect(2)`.
- The tree has no sudoers drop-in and no `min finalize-install` command
  today. The task that installs them (T19 in this plan) must land first.
  That task must also create `<provider dir>/vmm/` and move a
  `data-vol.raw` from before the split, because only root can give a
  directory or a file to `minimal-vmm` (fact 5).
