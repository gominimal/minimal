# Split-user VMM: provider directory and socket ownership

Status: proposed. Arch reviews this document on
[pull request #2546](https://github.com/gominimal/minimal/pull/2546), and its
review comments there carry each ruling:

- The model with a separate directory for the VM user, and the file-mode
  condition, at `52231ae0`. The file modes, and the reason to keep gvproxy
  away from the VM user, at `e8be045a`. A third user, `minimal-gvproxy`, for
  gvproxy, and a gvproxy directory outside the provider directory, at
  `e8be045a`, confirmed at `391f1317`. These rulings are in the arch reviews
  of those commits on the pull request.
- The placement of the egress gate and `switch::bep_host` in an EGW process
  as `minimal-gvproxy`, at `4308298d`:
  [arch C1 on the placement](https://github.com/gominimal/minimal/pull/2546#discussion_r4369852941).
- The channel from the supervisor to the EGW process, and the token on it,
  at `c8ffab40`:
  [arch C1 on the channel](https://github.com/gominimal/minimal/pull/2546#discussion_r4369886051)
  and [arch C1 on the token](https://github.com/gominimal/minimal/pull/2546#discussion_r4369886053).
  The EGW behaviour before the first table and after the channel closes:
  [arch C2](https://github.com/gominimal/minimal/pull/2546#discussion_r4369886054).
  Arch ruled at `15b77c5b` that the channel, the token and the fail-closed
  EGW start conform.
- The bound on the wait for a withdrawal acknowledgement, and the citation
  of the networking design for default deny and fail closed:
  [arch C2](https://github.com/gominimal/minimal/pull/2546#discussion_r4369951621)
  and [arch C1](https://github.com/gominimal/minimal/pull/2546#discussion_r4369951620).
  Arch ruled at `a591a791` that the citation conforms.
- The stop of the EGW process as `minimal-gvproxy`, the observed exit
  before the withdrawal answer, and the fail-closed result when no exit
  comes:
  [arch C1 on the stop](https://github.com/gominimal/minimal/pull/2546#discussion_r4369987466)
  and [arch C1 on the test](https://github.com/gominimal/minimal/pull/2546#discussion_r4369987470).
  This revision answers those two conditions, and arch has not ruled on
  the answer yet.

The open items are at the end of this document.

## Question

The plan moves gvproxy and the VMM child (`minvmd __krun-vmm`) to a
dedicated unprivileged user. The `minvmd run` supervisor, `min` and the
Box Egress Proxy (`bep serve`) stay with the login user. Each provider
directory socket and file must stay reachable by the processes that open it.

Gatehouse section 6.10, line 831, separates "the BEP role and the
EGW/gvproxy role". The line gives the surface that parses guest frames to
the EGW process, not only to gvproxy.

This design uses three users. The VMM child runs as `minimal-vmm`.
gvproxy runs as `minimal-gvproxy`, a third user, apart from `<login>` and
from `minimal-vmm`. So the egress gate is the only path from the VMM to the
switch (fact 10), and gvproxy shares no writable state with `bep serve`.
The egress gate and `switch::bep_host` move out of the supervisor into an
EGW process, a `minvmd` process that runs as `minimal-gvproxy`. So the
surface that parses guest frames runs as a user apart from the BEP role, as
line 831 requires. The fallback at the end moves only gvproxy.

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
- The EGW process: the `minvmd` process that runs the egress gate
  (`net/egress_gate.rs`) and the `switch::bep_host` leg. It runs as
  `minimal-gvproxy`. Today both run inside the supervisor.
- `minimal-vmm`: the dedicated unprivileged user. On macOS the name is
  `_minimal-vmm`, following the platform convention for service accounts.
- `minimal-vmm` (group): the primary group of the `minimal-vmm` user. It
  has exactly one login member, `<login>`. `min finalize-install` adds
  `<login>` and removes any other login member. A second login member can
  connect to the 0660 sockets of the first user's VM, so the group never
  has two. `minimal-gvproxy` is never a member, so it gets no access to
  `vmm/`.
- `minimal-gvproxy`: the dedicated user for gvproxy. On macOS the name is
  `_minimal-gvproxy`. It is a different user from `<login>` and from
  `minimal-vmm`.
- `minimal-gvproxy` (group): the primary group of the `minimal-gvproxy`
  user. It has exactly one login member, `<login>`, and `minimal-vmm` is
  never a member. `min finalize-install` keeps it so, as for the
  `minimal-vmm` group.
- `<gvproxy dir>`: the directory where gvproxy binds its switch socket,
  `/var/lib/minimal/<login>/<vm>/gvproxy/` on Linux and
  `/var/db/minimal/<login>/<vm>/gvproxy/` on macOS. `<login>` is the login
  name and `<vm>` is the VM name (`local-minvmd0` for the default VM).
- `<gvproxy config dir>`: the directory that holds `gvproxy.yaml` and the
  BEP socket `gvproxy-bep.sock`, at `gvproxy-config/` beside
  `<gvproxy dir>`.
- `<gate dir>`: the directory where the EGW process binds the egress gate
  socket, at `gate/` beside `<gvproxy dir>`. It is setgid, so every entry
  in it gets group `minimal-vmm`.
- The directories above those three (`/var/lib/minimal/` and the `<login>`
  and `<vm>` levels) are owned by root with mode 0755. Only root can
  create, rename or replace an entry in them.

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
   Under umask `0007`, every regular file that the child creates without an
   explicit mode gets 0660. `File::create` and `volume::create_sparse_raw`
   set no mode. So the child sets the mode of each file itself, with
   `OpenOptions::mode`, and does not rely on the umask for a file.
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
   default. It passes descriptors 0, 1 and 2 to the command. With
   `use_pty` set, it puts a pseudo-terminal in place of them, so a rule
   that hands a pipe or a socket on descriptor 0 sets `!use_pty`. Today the
   VMM child reads `MINVMD_MARKER_SOCK`, `MINVMD_GUEST_REPORT_SOCK`,
   `MINVMD_GUEST_TELEMETRY_SOCK`, the image and volume overrides, the trace
   context and the state identity from its environment. It also inherits
   the alive lock descriptor (`alive_lock.inherit_into`). Under the split,
   the spawn passes these values on descriptor 0 (the section on per-run
   values). The alive lock descriptor needs `closefrom_override` in the
   rule, or the spawn passes the lock another way. T38 picks one and pins
   it in a test.
9. `sudo -n` never prompts. When no rule admits the command without a
   password, it exits non-zero at once.
10. gvproxy v0.8.9 only listens on its switch socket. `-listen` is its one
    endpoint that takes more than one client, and gvproxy has no mode that
    connects out to a socket that another process binds
    (`docs/spikes/2026-06-21-gvproxy-attachment.md`). The socket that gvproxy
    binds belongs to the uid of gvproxy. Any process with that uid can
    connect to it, whatever its mode. So the egress gate is the only path to
    the switch only when the VMM child and gvproxy run as different users.
11. gvproxy sets the mode of its switch socket through the umask of its
    process (`docs/spikes/2026-06-21-gvproxy-attachment.md`, line 126). The
    spike saw 0600 under the default umask. `sudo` combines the umask of
    the caller with the `umask` default of the rule (0022) unless the rule
    sets `umask_override`. Only the EGW process dials the switch socket, and
    it runs as the same user as gvproxy. So the gvproxy rule sets
    `umask=0077` with `umask_override`, and the socket gets 0600.
12. A socket or file gets the group of the directory on macOS, and the
    primary group of the process on Linux when the directory is not
    setgid. In a setgid directory on Linux it gets the group of the
    directory. In `<gvproxy dir>` both give group `minimal-gvproxy`. In the
    setgid `<gate dir>` both give group `minimal-vmm`, though the EGW
    process is not a member of that group.

## Ownership model

The provider directory belongs to `<login>`, and `minimal-vmm` cannot write
to it. `minimal-vmm` creates its entries only in `<provider dir>/vmm/`, a
subdirectory that `minimal-vmm` owns and `<login>` cannot write to. So
`<login>` and `minimal-vmm` share no writable directory. They share the
`minimal-vmm` group. A socket that the other user opens gets 0660 with
group `minimal-vmm`. A socket or file that only one user opens stays 0600.

gvproxy and the EGW process run as `minimal-gvproxy`, and their entries are
outside the provider directory. The provider directory is 0710 with group
`minimal-vmm`, so `minimal-gvproxy` cannot search it. gvproxy binds its
switch socket in `<gvproxy dir>`, which `minimal-gvproxy` owns and
`<login>` can only read and search. gvproxy reads `gvproxy.yaml` in
`<gvproxy config dir>`, which `<login>` owns and `minimal-gvproxy` can only
read and search. `bep serve` binds `gvproxy-bep.sock` in the same
directory, and the EGW process connects to it there. The EGW process binds
the gate socket in `<gate dir>`, which `minimal-gvproxy` owns with group
`minimal-vmm`. So `minimal-gvproxy` and `<login>` share no writable
directory or file, and `bep serve` shares no writable state with gvproxy
or the EGW process. `minimal-vmm` is not in the `minimal-gvproxy` group, so
it can open nothing in `<gvproxy dir>` or `<gvproxy config dir>`. It can
search `<gate dir>` through the `minimal-vmm` group. `minimal-gvproxy` is
not in the `minimal-vmm` group, so it cannot search `vmm/`.

The uid change goes through a sudoers drop-in that `min finalize-install`
installs. The drop-in has `NOPASSWD` rules that let `<login>` run exactly
the spawns that this model runs as another user. In this model there are
three spawns and two stop rules. `minvmd __krun-vmm`, the VMM child, runs
as `minimal-vmm`. gvproxy and the EGW process run as `minimal-gvproxy`.
Each stop rule runs a fixed `minvmd` subcommand, one as `minimal-gvproxy`
and one as `minimal-vmm` (the section on the stop of the EGW process). In
the fallback there is one spawn, gvproxy as `minimal-vmm`, and one stop
rule as `minimal-vmm`. These rules apply to each spawn and to each stop
rule:

- The rule names the binary by its absolute path. That path, and every
  directory above it, is owned by root and not writable by any other user.
  A binary path that `<login>` can write lets `<login>` run any code as
  `minimal-vmm`.
- The rule names every argument of the spawn as a literal. It has no
  wildcard, so it admits no other argument and no extra flag. Each
  argument is the same on every run of one VM, so the rule can name it
  (the section on per-run values).
- The rule keeps `env_reset`, and its `env_keep` list is empty. A value
  that changes between runs reaches the spawn on descriptor 0, never in the
  environment or the arguments (fact 8).
- The VMM child rule, the EGW rule and the stop rule set `!use_pty`, so
  descriptor 0 is the pipe or the socket that the supervisor hands over
  (fact 8).
- The gvproxy rule sets `umask=0077` and `umask_override` (fact 11).
- The EGW process gets the token of `gvproxy-bep.sock` on the supervisor
  channel, with the box table (the section on the supervisor channel). The
  token is never in the arguments, which any user can read, or in the
  environment.
- The drop-in permits nothing else.

The supervisor runs the spawns as `sudo -n -u minimal-vmm` and
`sudo -n -u minimal-gvproxy`, so `min session start` never prompts for a
password (fact 9).

When `sudo -n` fails, the drop-in or one of the two users is missing. Then
the supervisor refuses to start the VM, and `min` prints an error that names
`min finalize-install`. The supervisor never starts gvproxy or the VMM child
as `<login>` in place of its dedicated user. The proposed text, which T38
pins in a test:

```text
The VM did not start: this machine has no minimal-vmm or minimal-gvproxy user, or no sudo rule that lets min start the VM as those users.
Run `min finalize-install` to set them up.
```

Every row names the user that creates the entry, the mode it gets, and each
user that opens it. A path that starts with `vmm/` is in `<provider dir>/vmm/`.

| Path | Created by | Mode | Opened by |
|---|---|---|---|
| `<provider dir>/` | `<login>` (`prepare_socket_dir`, from the supervisor before the spawn) | 0710, group `minimal-vmm` | `<login>` (supervisor, `min`, `bep serve`), `minimal-vmm` (VMM child; search only) |
| `<provider dir>/vmm/` | `root` (`min finalize-install`, which gives it to `minimal-vmm`) | 0750, owner `minimal-vmm`, group `minimal-vmm` | `minimal-vmm` (VMM child), `<login>` (supervisor, `min`; read and search only) |
| `vmm/ssh.sock` | `minimal-vmm` (VMM child, libkrun bind) | 0660 | `<login>` (`min`), `minimal-vmm` (libkrun bridge) |
| `vmm/timekeep.sock` | `minimal-vmm` (VMM child, libkrun bind) | 0600 | `minimal-vmm` (timekeep thread in the VMM child) |
| `vmm/boot.log` | `minimal-vmm` (VMM child, `OpenOptions::mode(0o640)`) | 0640 | `minimal-vmm` (libkrun console), `<login>` (`min diag`) |
| `vmm/data-vol.raw` | `minimal-vmm` (VMM child, `ensure_sparse_raw` with `OpenOptions::mode(0o600)`) | 0600 | `minimal-vmm` (libkrun data disk) |
| `<gvproxy dir>/` | `root` (`min finalize-install`, which gives it to `minimal-gvproxy`) | 0750, owner `minimal-gvproxy`, group `minimal-gvproxy` | `minimal-gvproxy` (gvproxy, EGW process), `<login>` (supervisor; read and search only) |
| `<gvproxy dir>/gvproxy-switch.sock` | `minimal-gvproxy` (gvproxy `-listen`, spawn umask `0077`) | 0600 | `minimal-gvproxy` (EGW process, egress gate) |
| `<gate dir>/` | `root` (`min finalize-install`, which gives it to `minimal-gvproxy`) | 2710, owner `minimal-gvproxy`, group `minimal-vmm`, setgid | `minimal-gvproxy` (EGW process), `minimal-vmm` (VMM child; search only), `<login>` (supervisor; search only) |
| `<gate dir>/gvproxy-gate.sock` | `minimal-gvproxy` (EGW process, egress gate; `chmod` on the path after `bind`) | 0660, group `minimal-vmm` from the setgid `<gate dir>` | `minimal-vmm` (VMM child, libkrun shuttle) |
| `guest-control.sock` | `<login>` (supervisor, guest report door) | 0660, group `minimal-vmm` | `minimal-vmm` (VMM child, libkrun) |
| `guest-telemetry.sock` | `<login>` (supervisor, guest telemetry door) | 0660, group `minimal-vmm` | `minimal-vmm` (VMM child, libkrun) |
| `/tmp/minvmd-marker-<pid>-<nonce>.sock` | `<login>` (supervisor) | 0660, group `minimal-vmm` set with `chown` on the path after `bind` | `minimal-vmm` (VMM child, libkrun) |
| `<gvproxy config dir>/` | `root` (`min finalize-install`, which gives it to `<login>`) | 0750, owner `<login>`, group `minimal-gvproxy` | `<login>` (supervisor, `bep serve`), `minimal-gvproxy` (gvproxy, EGW process; read and search only) |
| `<gvproxy config dir>/gvproxy.yaml` | `<login>` (supervisor, `write_config`) | 0640, group `minimal-gvproxy` | `minimal-gvproxy` (gvproxy) |
| `<gvproxy config dir>/gvproxy-bep.sock` | `<login>` (`bep serve`; `chown` and `chmod` on the path after `bind`) | 0660, group `minimal-gvproxy` | `minimal-gvproxy` (EGW process, `switch::bep_host`) |
| `control.sock` | `<login>` (supervisor) | 0600 | `<login>` (`min`) |
| EGW channel (descriptor 0 of the EGW process) | `<login>` (supervisor, `socketpair(2)` before the EGW spawn) | 0777, as `fstat` reports a `socketpair` end on Linux; it has no path, so only the two descriptors reach it | `minimal-gvproxy` (EGW process, descriptor 0 through `sudo`), `<login>` (supervisor, the other end) |

Notes on the table:

- `minimal-vmm` can search the provider directory, so it can reach the
  0660 sockets there by name. It cannot list, create, unlink or rename an
  entry there. So it cannot replace `control.sock` or a door socket with
  its own.
- `<login>` can read and search `vmm/`, but it cannot write there. So the
  supervisor cannot unlink `vmm/data-vol.raw` or a stale socket in `vmm/`.
  The VMM child removes its own stale sockets (`prepare_socket_dir` already
  does this). The removal of a blank data volume after a failed boot (R2.5
  disposition) moves into the VMM child.
- `data-vol.raw` stays 0600. `min diag` reads only its metadata, and that
  needs search access to `vmm/`, not read access to the file.
- `timekeep.sock` stays 0600. Only the VMM child opens it.
- `control.sock` stays 0600, owned by `<login>`. A compromised VMM must not
  reach it, because it drives the daemon.
- `gvproxy-bep.sock` moves to `<gvproxy config dir>`, because the EGW
  process dials it as `minimal-gvproxy` and `minimal-gvproxy` cannot search
  the provider directory. `minimal-gvproxy` can search
  `<gvproxy config dir>` through its group. `minimal-vmm` is not in that
  group, so it cannot search the directory or connect to the socket. The
  socket substitutes credentials, so a compromised VMM must not reach it.
  Only `<login>` can write `<gvproxy config dir>`, so nobody else can
  replace the socket after the bind (fact 7). `<login>` is in the
  `minimal-gvproxy` group, so `bep serve` can set that group on its socket
  (fact 5).
- `gvproxy-switch.sock` moves to `<gvproxy dir>`. gvproxy binds it as
  `minimal-gvproxy`, and only the egress gate in the EGW process dials it,
  as the same user. The socket is 0600, so `<login>` cannot connect to it
  and `bep serve` has no path to the switch past the egress gate.
  `minimal-vmm` cannot search `<gvproxy dir>` or connect to the socket.
- `gvproxy-gate.sock` moves to `<gate dir>`. The EGW process binds it as
  `minimal-gvproxy`. The setgid `<gate dir>` gives it group `minimal-vmm`,
  and the EGW process sets 0660 with `chmod` on the path after the bind
  (fact 6). `minimal-vmm` can search `<gate dir>` and connect through that
  group, but it cannot write the directory, so it cannot replace the
  socket. `minimal-gvproxy` is not in the `minimal-vmm` group, so the group
  of `<gate dir>` gives it no access to `vmm/`.
- `gvproxy.yaml` moves to `<gvproxy config dir>`. gvproxy can read it but
  cannot change it. `minimal-vmm` cannot read it.
- Today `cmd/run.rs` names `gvproxy-bep.sock` beside the switch socket, and
  `net/shuttle.rs` `gate_sock_beside` names the gate socket beside the
  `ssh.sock` path. Both move, so T38 names each socket from its own
  directory. `timekeep.sock` moves with `ssh.sock`, because
  `timekeep.rs` names it beside that path.
- `<gvproxy dir>`, `<gvproxy config dir>`, `<gate dir>` and the directories
  above them are outside the state directory of `<login>`. Root creates
  them under root-owned parents, so no other user can replace a path while
  root works there.
- The provider directory is not setgid, so a socket that the supervisor
  binds gets the primary group of `<login>`. The supervisor sets group
  `minimal-vmm` and mode 0660 with `chown` and `chmod` on the path after
  the bind, and before it spawns the VMM child (fact 6). `minimal-vmm`
  cannot write the provider directory, and `/tmp` is sticky. So nobody else
  can replace the path between the bind and the `chown` (fact 7).

## The supervisor channel to the EGW process

Today the egress gate and `switch::bep_host` read the live `BoxTable`, the
row withdrawals, the `Attachments` and the token in the supervisor process.
In the EGW process they get these from the supervisor channel:

- Kind: a `socketpair(2)` of `AF_UNIX` `SOCK_STREAM` sockets, with
  length-framed messages. It has no path in any directory, so no other
  process can connect to it, and no file mode applies to it.
- Descriptor: the supervisor creates the pair before the EGW spawn. One end
  becomes descriptor 0 of the EGW process through
  `sudo -n -u minimal-gvproxy`, and the rule sets `!use_pty` (fact 8). The
  supervisor closes its copy of that end after the spawn, and keeps the
  other end.
- Creating user: `<login>` (the supervisor). Opening users:
  `minimal-gvproxy` (the EGW process) and `<login>` (the supervisor).
- Direction, supervisor to EGW: first the token, then the first complete
  table, then each change in the apply order of the control doors. The
  first complete table is every row of the `BoxTable` and every entry of
  the `Attachments`, and a last message that ends it. A change is a row
  registration, a row withdrawal or an attachment change, each with a
  sequence number.
- Direction, EGW to supervisor: only the sequence number of each change
  that the EGW process applied. The supervisor answers a withdrawal on its
  control door only after the EGW process acknowledges it, so a withdrawn
  row admits no frame after the answer. The supervisor closes the channel
  on any other message.
- Bound on the acknowledgement: the supervisor waits at most 5 seconds for
  the acknowledgement of a withdrawal. On timeout, it stops the EGW process
  and gvproxy with the stop sequence below. It answers the withdrawal as
  done only after it observes the exit of both. When no exit comes within
  the bound of the stop sequence, it answers the withdrawal as failed (the
  fail-closed result below). The control door does not wait without end.
- Peer check: the EGW process reads the peer credentials of descriptor 0
  (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS). For a `socketpair`
  end, they are the credentials of the process that created the pair. The
  EGW process requires a socket, and a peer uid equal to the `SUDO_UID`
  that `sudo` sets. Otherwise it exits non-zero before it binds the gate
  socket. The supervisor does no peer check, because no other process can
  hold an end of the pair.

Until the EGW process holds the first complete table, the egress gate drops
every frame, and it refuses every publish request. When it reads end of
file on the channel, or a message does not parse, the EGW process stops the gate, closes every
relay and exits non-zero. A supervisor that exits closes its end, so an EGW
process never outlives it.

### The stop of the EGW process

The EGW process runs as `minimal-gvproxy` behind `sudo`, so `<login>`
cannot signal it. Today `GvproxySupervisor::stop` sends SIGTERM and then
SIGKILL to the pid of its child. Under the split that child is `sudo`, and
the SIGKILL ends `sudo` only. The EGW process then keeps running, with the
last table it applied. So the supervisor never sends SIGKILL to the `sudo`
of a spawn as another user. The `Drop` of the handle, which sends SIGKILL
today, runs the stop rule in its place. These are the facts about `sudo` that the
stop sequence uses:

- With `!use_pty`, `sudo` forks the command and waits for it. The command
  runs in the process group of `sudo`. `sudo` exits after the command
  exits, with the status of the command. T38 pins in a test that the EGW
  process runs in the process group of its `sudo`.
- `sudo` relays to the command each signal that it can catch. That
  includes SIGTERM, SIGINT, SIGHUP, SIGQUIT, SIGUSR1 and SIGUSR2. It does
  not relay a signal from a process in the process group of the command.
- No process can catch SIGKILL or SIGSTOP, so `sudo` relays neither.

The supervisor spawns the `sudo` of the EGW process, of gvproxy and of the
VMM child, each in a new process group of its own (`process_group(0)`). So
the group id of each is the pid of its `sudo`. The supervisor is in a
different group, so `sudo` relays its SIGTERM. The pid of `sudo` stays
taken until the supervisor reaps it, so the group id cannot go to another
process before the reap.

The stop sequence, for the EGW process and for gvproxy:

1. The supervisor calls `shutdown(2)` with `SHUT_WR` on its end of the
   supervisor channel, and keeps that end open. The EGW process then
   reads end of file and exits. gvproxy has no channel.
2. The supervisor sends SIGTERM to `sudo`, and `sudo` relays it to the
   command. Then it waits for the exit for `term_timeout`
   (`DEFAULT_TERM_TIMEOUT`, 3 seconds).
3. When no exit comes, the supervisor runs the stop rule as the user of
   the command: `sudo -n -u minimal-gvproxy` with a fixed `minvmd`
   subcommand that T38 names. It hands the group id on descriptor 0. The
   subcommand sends SIGKILL to that process group with `killpg(2)`, and
   exits. As `minimal-gvproxy`, it can signal only the processes of
   `minimal-gvproxy`. The `sudo` of the group runs as root, so the
   SIGKILL does not reach it. The subcommand refuses a group id that
   holds no process of its user.
4. The supervisor waits at most 5 seconds after the stop rule for the
   exit.

The supervisor observes the exit of the EGW process when two things are
true. `waitpid(2)` reports the exit of its `sudo`, and the supervisor
reads end of file on its end of the channel. `sudo` exits only after the
command exits, and end of file comes only when no process holds the other
end. The supervisor can read that end of file because step 1 shuts down
only the write side of its end. It closes its end only after it observes
the exit, or after it gives the fail-closed result. For gvproxy, the exit
is the exit of its `sudo`.

Fail-closed result: when no exit comes within the 5 seconds after the
stop rule, the supervisor cannot prove that no gate runs. Then it does
these things:

- It answers the withdrawal on its control door as failed, never as done.
- It stops the VMM child. The VMM child is the only process that sends
  guest frames to the gate socket, so no guest frame then reaches the
  gate. The VMM child runs as `minimal-vmm` behind `sudo`, so the
  supervisor stops it with the same sequence and the stop rule as
  `minimal-vmm`. The VMM child has no channel, so step 1 does not apply.
- It refuses every later registration, and it exits non-zero after the
  VMM child exit. The guest has no egress until the next boot.

This follows the networking design: the EGW fails closed
([networking design section 4.3, line 85](https://github.com/gominimal/arch/blob/5c1201517ba07347344fb9725efb06ee39d5c03e/specs/networking/deployment-and-egress-gateway.md)).

### An unexpected exit of the EGW process

The supervisor handles that exit on the path that handles an unexpected
gvproxy exit today. `supervise_switch` in `net.rs` holds the child, and an
exit without a stop fires the exit notification. The `tokio::select!` in
`HostGvproxy::spawn_inner` then logs an error and drops the egress handles.
For an EGW exit, that arm also stops gvproxy. The guest then has no egress
until the next boot, as after an unexpected gvproxy exit today. The
networking design requires default deny and that the EGW fails closed
([networking design section 4.3, lines 83 and 85](https://github.com/gominimal/arch/blob/5c1201517ba07347344fb9725efb06ee39d5c03e/specs/networking/deployment-and-egress-gateway.md)).

## Values that change between runs

No sudoers rule has an argument that changes between runs, so no rule
needs a wildcard or a wrapper that checks its arguments:

- gvproxy: `GvproxyConfig::argv` gives `-config`, `-listen` and
  `-ssh-port -1`. The first two name `<gvproxy config dir>/gvproxy.yaml`
  and `unix://<gvproxy dir>/gvproxy-switch.sock`. Root creates those
  directories at fixed paths for each login and VM, so the rule names each
  argument as a literal. The subnet and the leases are in `gvproxy.yaml`,
  not in the arguments.
- The EGW process: the arguments are a fixed `minvmd` subcommand and the VM
  name. The EGW process finds the gate socket, the switch socket and
  `gvproxy-bep.sock` from the VM name. The token and the table come on the
  supervisor channel.
- The two stop rules: the arguments are a fixed `minvmd` subcommand and
  the VM name. The process group id changes between runs, so it comes on
  descriptor 0.
- The VMM child: the arguments are `__krun-vmm` and the VM name. Every
  other value that it reads from its environment today comes on
  descriptor 0, from a pipe, as one length-framed record. That includes the
  marker socket path with its pid and nonce, the door paths, the proxy
  port and the trace context. The child reads the record to its end and
  closes the pipe before it registers a vsock port.
- The VMM child accepts a marker path only in the form
  `/tmp/minvmd-marker-<pid>-<nonce>.sock`. Before it connects, it `lstat`s
  the path and requires a socket that the `SUDO_UID` user owns, with group
  `minimal-vmm` and mode 0660. Under the split it refuses a boot log or a
  data volume path outside `vmm/`.

`min finalize-install` writes one rule for each spawn of each VM, with the
literal arguments for that VM.

## What a compromised VMM can reach

A VMM child that the guest takes over runs as `minimal-vmm`.

- It can reach every entry in `vmm/`. These are its own sockets, its boot
  log and the data volume.
- It can connect to `<gate dir>/gvproxy-gate.sock`. The egress gate in the
  EGW process decides every frame that it sends, before the switch sees
  the frame.
- It can connect to `guest-control.sock` and `guest-telemetry.sock`. Those
  doors take only the guest verbs and the guest reports (peer checks
  below).
- It can connect to the marker socket.
- It cannot search `<gvproxy dir>` or connect to `gvproxy-switch.sock`.
  So it cannot send a frame past the egress gate.
- It cannot search `<gvproxy config dir>`. So it cannot connect to
  `gvproxy-bep.sock` or read `gvproxy.yaml`.
- It cannot connect to `control.sock`, and it cannot write `<gate dir>`.
- It cannot reach the supervisor channel, because the channel has no path.
- It cannot signal or trace the supervisor, `bep serve` or `min`, because
  they run as `<login>`. It cannot signal or trace gvproxy or the EGW
  process, because they run as `minimal-gvproxy`.

## What a compromised EGW process can reach

The egress gate and the `switch::bep_host` leg parse guest frames in the
EGW process, which runs as `minimal-gvproxy`. A guest frame that takes
over either one runs as `minimal-gvproxy`.

- It can reach every entry in `<gvproxy dir>` and `<gate dir>`, which
  `minimal-gvproxy` owns. So it can connect to the switch socket and serve
  the gate socket itself.
- It can signal or trace gvproxy, because gvproxy runs as the same user.
- It can connect to `gvproxy-bep.sock`, and it holds the token. That is the
  access that `switch::bep_host` has by design. `listener.rs` still checks
  the uid and the token on each connection.
- It can read `gvproxy.yaml`. It cannot change it, because `<login>` owns
  `<gvproxy config dir>`.
- It cannot trace or signal `bep serve`, the supervisor or `min`, because
  they run as `<login>`. It cannot trace or signal the VMM child, because
  the VMM child runs as `minimal-vmm`.
- It cannot write the provider directory. It cannot even search it,
  because the directory is 0710 with group `minimal-vmm`, and
  `minimal-gvproxy` is not in that group. So it cannot reach
  `control.sock`, the doors or `vmm/`.
- It cannot write `<gvproxy config dir>`, so it cannot replace
  `gvproxy-bep.sock` with its own.
- It can read every row that the supervisor channel carries. It can write
  only sequence numbers to the supervisor, which closes the channel on any
  other message. It cannot change a row in the supervisor.

So the frame-parsing surface and the forwarding state run as
`minimal-gvproxy`, and the access to the store providers stays with
`bep serve` as `<login>`. This is the placement that Gatehouse section
6.10 line 831 gives.

## What a compromised gvproxy can reach

A gvproxy that a guest frame takes over runs as `minimal-gvproxy`.

- It can reach every entry in `<gvproxy dir>` and `<gate dir>`, which
  `minimal-gvproxy` owns.
- It can signal or trace the EGW process, because the EGW process runs as
  the same user. So it can reach what the EGW process can reach (the
  section before this one).
- It can read `gvproxy.yaml`. It cannot change it, because `<login>` owns
  `<gvproxy config dir>`.
- It cannot search the provider directory, so it can reach no socket or
  file there: not `control.sock`, the doors or `vmm/`.
- It cannot signal or trace the supervisor, `bep serve`, `min` or the VMM
  child, because they run as other users.

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
- `<gate dir>/gvproxy-gate.sock` and the marker socket: the VMM child dials
  them as `minimal-vmm`. They have no peer check today. The 0660 mode and
  the one-login-member `minimal-vmm` group are the gate.
- `<gvproxy config dir>/gvproxy-bep.sock` (the BEP socket): the EGW process
  dials it as `minimal-gvproxy`, through `switch::bep_host`. gvproxy never
  dials it. The `listener.rs` check admits the `minimal-gvproxy` uid in
  place of its own uid, and then requires the token. It refuses every other
  uid. `minimal-vmm` is refused by the 0750 mode of
  `<gvproxy config dir>` and by the uid check.
- `<gvproxy dir>/gvproxy-switch.sock`: the egress gate in the EGW process
  dials it as `minimal-gvproxy`. gvproxy does no peer check. The 0600 mode
  refuses every other user, and the 0750 mode of `<gvproxy dir>` refuses
  `minimal-vmm` too.
- `vmm/ssh.sock`: `min` dials it as `<login>`. libkrun does no peer check.

The supervisor resolves the `minimal-vmm` uid once at start, with
`getpwnam`. It resolves the `minimal-gvproxy` uid the same way. `bep serve`
resolves the `minimal-gvproxy` uid the same way for its uid check. It refuses
to start when either user is missing, with the error in the ownership model.

## How each process checks an entry before use

- Bind in the provider directory or in `<gvproxy config dir>`: the
  supervisor and `bep serve` `lstat` the path before they bind. An entry that `<login>` owns is a stale socket
  from an earlier run, and they unlink it. Only `<login>` can write
  either directory, so no entry there has another owner. An entry that another
  user owns, or a symlink, is a refusal: the process logs the path and the
  owner, and it does not start.
- Start: the supervisor checks that `vmm/` is a directory, not a symlink,
  owned by `minimal-vmm` with group `minimal-vmm` and mode 0750. Otherwise
  it refuses to start the VM with an error that names
  `min finalize-install`.
- Connect to `vmm/ssh.sock`: `min` `lstat`s the path and requires a socket
  that `minimal-vmm` owns. A compromised VMM can serve this socket itself.
  It can then show `min` a false shell, but it cannot reach any socket that
  `<login>` owns through it.
- Start, gvproxy directories: the supervisor checks that `<gvproxy dir>`
  is a directory, not a symlink, owned by `minimal-gvproxy` with group
  `minimal-gvproxy` and mode 0750. It checks that `<gvproxy config dir>`
  is a directory, not a symlink, owned by `<login>` with group
  `minimal-gvproxy` and mode 0750. It checks that `<gate dir>` is a
  directory, not a symlink, owned by `minimal-gvproxy` with group
  `minimal-vmm`, the setgid bit and mode 2710. Otherwise it refuses to start
  the VM with an error that names `min finalize-install`.
- Connect to `gvproxy-switch.sock`: the EGW process `lstat`s the path and
  requires a socket that `minimal-gvproxy` owns, with mode 0600.
- Connect to `gvproxy-bep.sock`: the EGW process `lstat`s the path and
  requires a socket that `<login>` owns, with group `minimal-gvproxy` and
  mode 0660.
- Bind in `<gate dir>`: the EGW process `lstat`s the path before it binds.
  Only `minimal-gvproxy` can write `<gate dir>`, so an entry there is a
  stale gate socket from an earlier run, and it unlinks it. A symlink is a
  refusal, as in the provider directory.
- Start, VMM child files: after the VMM child creates `vmm/boot.log` and
  `vmm/data-vol.raw`, the supervisor `lstat`s each one. It refuses to start
  the VM when the file is not a regular file that `minimal-vmm` owns, or
  when its mode has a group or other write bit.
- Supervisor files: the supervisor writes `gvproxy.yaml` with
  `O_CREAT | O_EXCL | O_NOFOLLOW` and mode 0640 after it unlinks a stale
  copy. It sets group `minimal-gvproxy` with `fchown` on the descriptor.
- Migration: a provider directory from before the split holds `ssh.sock`,
  `timekeep.sock`, `boot.log`, `data-vol.raw`, `gvproxy-switch.sock`,
  `gvproxy-gate.sock`, `gvproxy-bep.sock` and `gvproxy.yaml` owned by
  `<login>`. The supervisor removes the stale
  sockets, the old `boot.log` and the old `gvproxy.yaml`. `data-vol.raw`
  holds the user's data, and `<login>` cannot write `vmm/`. So
  `min finalize-install`, as root, moves it into `vmm/` and gives it to
  `minimal-vmm`. The next section says how root does that safely.

## How `min finalize-install` works in the state directory

The provider directory sits in the state directory of `<login>`, and
`<login>` can write it. While root works there, `<login>` can replace
`vmm/`, `data-vol.raw` or a parent directory with a symlink or a hard link.
So root never uses a path in the state directory for a change. It works
from directory descriptors that it checked:

1. Root opens each component of the provider directory path from `/` with
   `openat(O_DIRECTORY | O_NOFOLLOW)`. It `fstat`s each descriptor. Every
   component must be owned by root or by `<login>`, and the last one must
   be owned by `<login>`. Otherwise root changes nothing and exits
   non-zero.
2. Root creates `vmm/` with `mkdirat` on the provider directory descriptor,
   mode 0700. It opens it with `openat(O_DIRECTORY | O_NOFOLLOW)` and
   `fstat`s it. It must be a directory owned by root. `<login>` cannot
   create a directory that root owns, so a swap fails this check. When
   `vmm/` already exists, root opens and checks it the same way, and
   requires owner `minimal-vmm` or root. Root then takes it back with
   `fchown` to root and `fchmod` 0700 on the descriptor, so that only root
   can write it until step 6.
3. Root opens `data-vol.raw` with `openat(O_RDONLY | O_NOFOLLOW |
   O_NONBLOCK)` on the provider directory descriptor and `fstat`s it. It
   must be a regular file, owned by `<login>`, with `st_nlink == 1`.
   Otherwise root leaves it where it is and exits non-zero.
4. Root moves it with `renameat` from the provider directory descriptor to
   the `vmm/` descriptor. It opens the moved entry with `O_NOFOLLOW` on the
   `vmm/` descriptor and `fstat`s it again. The device and inode must equal
   the ones from step 3, and `st_nlink` must be 1. Only root can write
   `vmm/` at this point, so the entry cannot change after the rename. When
   the check fails, root moves the entry back and exits non-zero.
5. Root gives the file to `minimal-vmm` with `fchown` and sets 0600 with
   `fchmod`, both on the descriptor from step 4.
6. Last, root gives `vmm/` to `minimal-vmm` with `fchown` and sets 0750
   with `fchmod`, both on the descriptor from step 2.

Root never calls `chown`, `chmod` or `rename` by path in the state
directory. A failed check leaves the data volume in place, and `min` keeps
refusing to start the VM until `min finalize-install` succeeds.

`<gvproxy dir>`, `<gvproxy config dir>` and `<gate dir>` are outside the
state directory. Root creates them, and the parents above them, under root-owned
parents (`mkdir` with mode 0700, then `chown` and `chmod` to the table
values). No other user can write those parents, so the paths cannot
change while root works there.

## What T38 changes

- `prepare_socket_dir` creates the provider directory 0710 with group
  `minimal-vmm`. The VMM child calls it on `vmm/` and only verifies that
  directory, because it cannot create it.
- `restrict_owned_dir` and `verify_provider_dir_ownership` accept 0710 with
  group `minimal-vmm`. They refuse a provider directory that another uid
  owns, that the group can write, or that is open to others. A new check
  verifies `vmm/` as the section before this one says.
- `ssh.sock`, `timekeep.sock`, `boot.log` and `data-vol.raw` move to
  `vmm/`. `gvproxy-switch.sock` moves to `<gvproxy dir>`. `gvproxy.yaml`
  moves to `<gvproxy config dir>` through `GvproxyConfig::with_config_path`.
  `gvproxy-bep.sock` moves to `<gvproxy config dir>`, and `cmd/run.rs`
  names it there, not beside the switch socket. `gvproxy-gate.sock` moves
  to `<gate dir>`, and the VMM child gets that path in place of
  `gate_sock_beside`.
- The egress gate (`net/egress_gate.rs`) and the `switch::bep_host` leg
  move out of the supervisor into the EGW process. The supervisor spawns it
  through `sudo -n -u minimal-gvproxy`, as a fixed `minvmd` subcommand
  that T38 names. The rule names the root-owned absolute path of `minvmd`
  and the literal arguments. The supervisor hands the EGW process the
  supervisor channel on descriptor 0. The EGW process binds the gate
  socket, sets 0660 on it, and dials the switch socket and
  `gvproxy-bep.sock`. Tests pin the 0660 mode and the `minimal-vmm` group
  of the gate socket, the dropped frames and refused publish requests
  before the first complete table, and the exit when the channel closes.
  A test holds back the acknowledgement of a withdrawal in a stub EGW
  process. The stub also ignores SIGTERM and the end of file on the
  channel. The test pins that after 5 seconds the supervisor runs the stop
  sequence. It pins that step 1 is a `shutdown(SHUT_WR)`: the stub reads
  end of file, and the supervisor end stays open until the supervisor
  reads end of file after the exit. It pins that the stop rule ends the
  stub with SIGKILL. It pins that the
  supervisor does not answer the withdrawal as done before it observes the
  exit of the stub and of gvproxy.
  A second test gives the stub a stop rule that sends no SIGKILL, so no
  exit comes. It pins the fail-closed result: the withdrawal answer is
  failed, the VMM child stops, a later registration is refused, and the
  supervisor exits non-zero.
- The supervisor spawns the `sudo` of the EGW process, of gvproxy and of
  the VMM child each in a new process group, and never sends SIGKILL to
  that `sudo`. The drop-in has the two stop rules. A test pins that the
  EGW process runs in the process group of its `sudo`.
- `bep serve` binds `gvproxy-bep.sock` with group `minimal-gvproxy` and
  mode 0660, in place of `bind_owner_only`. The `listener.rs` peer check
  admits the `minimal-gvproxy` uid in place of its own uid, and keeps the
  token check.
- The VMM child creates `vmm/boot.log` with `OpenOptions::mode(0o640)`, in
  place of the `File::create` in `cmd/vmm_child.rs`. It creates
  `vmm/data-vol.raw` with `OpenOptions::mode(0o600)` in
  `volume::create_sparse_raw`. The supervisor verifies both modes. It
  refuses to start the VM when either file has a group or other write bit
  (fact 4). The two users then share no writable file.
- The supervisor spawns gvproxy through `sudo -n -u minimal-gvproxy`. The
  rule names the root-owned absolute path of gvproxy and its fixed
  arguments, and sets `umask=0077` with `umask_override`. A test pins the
  0600 mode of the switch socket.
  `gvproxy.yaml` gets 0640 with group `minimal-gvproxy`.
- `enforce_socket_permissions` and `verify_socket_permissions` take the
  mode and the group from the table. The supervisor stops the `chmod` of
  `ssh.sock`. The VMM child sets it after libkrun binds it, and the
  supervisor only verifies it.
- The guest door and the telemetry door admit the `minimal-vmm` uid, as
  the peer checks section says.
- T38 can claim conformance with Gatehouse section 6.10 line 831 for this
  model, because the EGW process and `bep serve` run as different users.
  The fallback does not conform.
- The supervisor spawns the VMM child through `sudo -n -u minimal-vmm`.
  The drop-in names the root-owned absolute path of `minvmd` and the
  literal arguments of the spawn. It keeps `env_reset` with an empty
  `env_keep` list, and the child reads its per-run values on descriptor 0.
  When `sudo -n` fails, the start refuses with the error in the ownership
  model.

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
| `gvproxy-gate.sock` | `<login>` (supervisor, egress gate) | 0600 | `<login>` (VMM child, libkrun shuttle) |
| `gvproxy-bep.sock` | `<login>` (`bep serve`, `bind_owner_only`) | 0600 | `<login>` (supervisor, `switch::bep_host`) |

Today `net.rs` names the gate socket, and `cmd/run.rs` names
`gvproxy-bep.sock`, beside the switch socket. In the fallback the switch
socket is in `vmm/`, which `<login>` cannot write. So T38 names both
sockets from the provider directory, and they keep the path, the owner and
the mode they have today. Every other entry keeps the owner, the mode and
the path it has today.
`minimal-vmm` cannot write the provider directory here either. The drop-in
permits only the gvproxy spawn and the stop rule as `minimal-vmm`, with
the same rules for the path, the
arguments and the environment. The `sudo -n` refusal is the same.

In the fallback the egress gate and `switch::bep_host` stay in the
supervisor as `<login>`, the user of `bep serve`. So the fallback does not
meet the placement that Gatehouse section 6.10 line 831 gives.

The fallback does not protect the egress gate from the VMM. The VMM child
runs as `<login>`, the same user as the supervisor, so it can connect to
the 0660 switch socket and send frames past the gate, as it can today.
The fallback protects `<login>` from a compromised gvproxy, and nothing
more.

## Open items

Arch decided the switch socket at `e8be045a`: gvproxy runs as a third
user, `minimal-gvproxy`, with its switch socket in `<gvproxy dir>`. Arch
ruled the placement at `4308298d`: the egress gate and `switch::bep_host`
run in the EGW process as `minimal-gvproxy`. These items stay open:

- Confirm that macOS checks socket write permission on `connect(2)`.
- Confirm that gvproxy removes a stale switch socket before it binds
  `-listen`. `<login>` cannot write `<gvproxy dir>`, so the supervisor
  cannot remove it. If gvproxy does not, T38 adds a fixed cleanup spawn as
  `minimal-gvproxy` to the drop-in.
- A named VM needs its own `vmm/`, `<gvproxy dir>`,
  `<gvproxy config dir>` and `<gate dir>`, and only root can create them.
  The gvproxy, EGW process and VMM child arguments name the VM, so
  `min finalize-install` writes literal rules for each VM. T19 decides
  whether `min finalize-install` takes the VM name.
- Confirm that macOS `LOCAL_PEERCRED` reports the creating process for a
  `socketpair` end. If it does not, T38 picks another peer check for the
  supervisor channel and records it in this document.
- The tree has no sudoers drop-in and no `min finalize-install` command
  today. The task that installs them (T19 in this plan) must land first.
  That task must create the `minimal-vmm` and `minimal-gvproxy` users and
  groups, `<provider dir>/vmm/`, `<gvproxy dir>`, `<gvproxy config dir>`
  and `<gate dir>`. It must also move a `data-vol.raw` from before
  the split, as the section on `min finalize-install` says, because only
  root can give a directory or a file to another user (fact 5).
