---
description: Install Minimal on Linux (x86_64/aarch64) or macOS (Apple Silicon).
---

# Install Minimal

## Linux

### Requirements

- **x86_64** or **aarch64** architecture
- Kernel 5.10 or later with unprivileged user namespaces enabled. Ubuntu 24.04
  and later restrict them by default. The
  [Linux host setup guide](../reference/linux-host-setup.md) has the fix.

### Install

```shell
curl --proto "=https" --tlsv1.2 -fsSL https://go.minimal.dev/stable | sh
```

### Check the install

```shell
min --version
```

If installed correctly, it prints the version.

## macOS

On macOS, Minimal boots a lightweight Linux microVM via libkrun on Apple's Hypervisor.framework.

### Requirements

- **Apple Silicon** (M1 or later). Intel Macs are not supported

### Install

Copy and paste the following into your terminal:

```shell
curl --proto "=https" --tlsv1.2 -fsSL https://go.minimal.dev/stable | sh
```

### Check the install

```shell
min --version
```

If installed correctly, it prints the version.

## Upgrade

Re-run the install command for your platform. The installer checks each
installed component against the current release and re-downloads only the ones
that changed, swapping them into place atomically.

Note: upgrading restarts the Minimal daemon, which interrupts any sessions that
are currently active. When sessions are running, the installer lists them and
asks on your terminal before ending them. If you answer no, nothing changes.
A scripted upgrade can skip the question. Set `MINIMAL_INSTALL_FORCE_STOP=1`,
or give the installer the flag:

```shell
curl --proto "=https" --tlsv1.2 -fsSL https://go.minimal.dev/stable | sh -s -- --force-stop
```

### Upgrade from 0.7 to 0.8

0.8 changes how Minimal stores your boxes. 0.7 cannot read the box state that
0.8 writes. To go back to 0.7 with your boxes after the upgrade, you need a
copy of the state from before it. The installer makes that copy for you when
it upgrades a 0.7 install. The next section says when to make it by hand.

What changes in 0.8:

- Every session and task is a box. A box stays after it stops or ends, until
  `min box rm` or `min box prune` removes it.
- The old session verbs, bare `min stop` and `min task run --path` are gone.
  Use the `min box` verbs, `min host stop <HOST>` and `-C <DIR>`. Run
  `min box --help` to see the verbs.
- A box without a name that you chose takes `<project>` for the default entry,
  or `<project>-<entry>` for another entry. When a box already has that name,
  the new box takes the name with `-<n>` added.
- Minimal keeps a name that you choose with `--name` or with an entry's
  `[box] name` exactly as you wrote it. When any box on the host has that
  name, in any state, the command refuses and creates nothing.
- One table, `env_vars`, sets environment variables in `minimal.toml` and in
  loadout files. A session, task or defaults table, or a loadout file, that
  still sets `vars` or `vars_lenient` fails with exit code 3. The message
  names the file and the key. Rename `vars` to `env_vars`. Move each
  `vars_lenient` entry into `env_vars` as `NAME = "value"`. A name in
  `env_vars` holds only letters, digits and `_`, and does not start with a
  digit. Minimal refuses any other name.
- `min init` writes the session entry as `[sessions.default]`, which holds the
  session's packages, and writes no `[boxes]` or `[defaults]` table.

#### Copy your box state by hand

When the installer upgrades a 0.7 install, it copies the box state next to the
state directory. The closing card names the copy. Make the copy by hand only
in these cases:

- You want the copy in another place.
- The installer stopped because the disk did not have enough free space. Then
  the copy must go to another disk that has enough free space. On Linux, a
  copy on the same disk needs the same space that the installer did not find.

After a copy by hand, run the installer with `--skip-state-archive`.

Minimal keeps its box state in `~/.local/state/minimal`, or in
`$XDG_STATE_HOME/minimal` when `XDG_STATE_HOME` is an absolute path. On macOS,
that directory holds the data volume of the virtual machine, a large sparse
file. The copy commands below keep it sparse.

1. Stop the 0.7 daemon, so that nothing writes to the state while you copy
   it. When sessions are active, `min stop` refuses, and `min stop --force`
   stops the daemon anyway:

   ```shell
   min stop
   ```

2. Set `state` to the state directory, and `copy` to a path that does not
   exist yet. A `copy` that exists already gets the state inside it, not in
   its place:

   ```shell
   case "${XDG_STATE_HOME:-}" in
       /*) state="$XDG_STATE_HOME/minimal" ;;
       *)  state="$HOME/.local/state/minimal" ;;
   esac
   source="$(cd -P "$state" && pwd -P)"
   copy="$HOME/minimal-state-0.7"
   test -n "$source" && test ! -e "$copy" && echo "ready to copy $source to $copy"
   ```

   `source` is the real directory, also when `state` is a symbolic link to
   another disk. When the command prints nothing, `state` does not exist or
   `copy` exists already. Correct the one that is wrong before you go on. For
   another disk, set `copy` to a path on that disk.

3. Copy what the state directory holds.

   On macOS:

   ```shell
   mkdir "$copy" && cp -Rc "$source/." "$copy/"
   ```

   On Linux:

   ```shell
   mkdir "$copy" && cp -a --sparse=always "$source/." "$copy/"
   ```

   Run the install command only when the copy command exits with no error.

4. Run the install command for your platform, with `--skip-state-archive`:

   ```shell
   curl --proto "=https" --tlsv1.2 -fsSL https://go.minimal.dev/stable | sh -s -- --skip-state-archive
   ```

#### Go back to 0.7

A 0.7 daemon that meets 0.8 state can fail to start, or start without the boxes
that 0.8 changed. In the other direction, a 0.8 release that meets box state
from a newer release stops and changes nothing, and its message says so. The
boxes that you made on 0.8 are lost when you go back.

1. Skip this step when the installer made the copy. That copy is beside the
   state directory already. For a copy that you made by hand, copy it into a
   new directory beside the state directory. Set `state` and `copy` as in the
   copy steps above, then:

   On macOS:

   ```shell
   mkdir "$state.0.7.hand" && cp -Rc "$copy/." "$state.0.7.hand/" && echo ready
   ```

   On Linux:

   ```shell
   mkdir "$state.0.7.hand" && cp -a --sparse=always "$copy/." "$state.0.7.hand/" && echo ready
   ```

   When the command does not print `ready`, `$state.0.7.hand` exists already,
   or the copy stopped partway. For a name that exists, choose another name
   that starts with `$state.0.7.`, and run it again. When the disk is short
   of space, move other files that you do not need off that disk, and run it
   again. Do not delete the 0.8 state or the copy to make space. To stay on
   0.8 instead, stop here.

2. Run the install command for the 0.7 release that you had. Replace
   `<0.7.x>` with the version that `min --version` printed before the upgrade:

   ```shell
   curl --proto "=https" --tlsv1.2 -fsSL https://go.minimal.dev/stable | sh -s -- --version <0.7.x>
   ```

   Over 0.8 state, the installer stops before it downloads or changes
   anything. It prints the commands for this machine. They stop the 0.8
   hosts. Then one line renames the 0.8 state aside, and renames the newest
   copy beside it into its place. When more than one copy is there, the
   installer says how many others there are.

3. Run the stop commands that the installer printed. Then run its last line,
   the one that renames the 0.8 state aside and renames the copy into its
   place. Do not run the shorter `mv` line before it, because that line only
   moves the 0.8 state aside. Then run the install command from step 2 again.

## Uninstall

```shell
curl --proto "=https" --tlsv1.2 -fsSL https://go.minimal.dev/stable | sh -s -- --uninstall
```

This removes every file a previous install placed, including the shell
integration. It accepts these flags:

- `--force` also removes files that you changed.
- `--purge` also deletes the data, state and cache directories of Minimal.
- `--dry-run` shows what the command removes, and removes nothing.
