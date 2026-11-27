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
copy of the state from before it. Make that copy before you run the install
command.

What changes in 0.8:

- Every session and task is a box. A box stays after it stops or ends, until
  `min box rm` removes it.
- The old session verbs, bare `min stop` and `min task run --path` are gone.
  Use the `min box` verbs, `min host stop <HOST>` and `-C <DIR>`. Run
  `min box --help` to see the verbs.
- A box without a name that you chose takes `<project>` for the default entry,
  or `<project>-<entry>` for another entry. When a box already has that name,
  the new box takes the name with `-<n>` added.
- Minimal keeps a name that you choose with `--name` or with an entry's
  `[box] name` exactly as you wrote it. When any box on the host has that name, in any state, the command
  refuses and creates nothing.
- One table, `env_vars`, sets environment variables in `minimal.toml` and in
  loadout files. A file that still sets `vars` or `vars_lenient` fails
  with exit code 3, and the message names the file and the key. Rename the key
  to `env_vars`.
- `min init` writes the session entry as `[sessions.default]`, which holds the
  session's packages, and writes no `[boxes]` or `[defaults]` table.

#### Copy your box state before you upgrade

When the installer upgrades a 0.7 install, it makes this copy itself, next to
the state directory. It names the copy when it finishes. Make the copy by hand
only when you want it in another place. Make it by hand also when the
installer stops because the disk is short of free space. Then run the
installer with `--skip-state-archive`.

Minimal keeps its box state in `${XDG_STATE_HOME:-$HOME/.local/state}/minimal`.
On macOS, that directory holds the data volume of the virtual machine, a
large sparse file. The copy commands below keep it sparse.

1. Stop the 0.7 daemon, so that nothing writes to the state while you copy
   it. When sessions are active, `min stop` refuses, and `min stop --force`
   stops the daemon anyway:

   ```shell
   min stop
   ```

2. Copy the state directory.

   On macOS:

   ```shell
   cp -Rc "${XDG_STATE_HOME:-$HOME/.local/state}/minimal" "$HOME/minimal-state-0.7"
   ```

   On Linux:

   ```shell
   cp -a --sparse=always "${XDG_STATE_HOME:-$HOME/.local/state}/minimal" "$HOME/minimal-state-0.7"
   ```

3. Run the install command for your platform.

#### Go back to 0.7

A 0.7 daemon that meets 0.8 state can fail to start, or start without the boxes
that 0.8 changed. To go back, put your copy back in place first. The boxes that
you made on 0.8 are lost.

1. Stop the 0.8 hosts. Run `min host list` to see their names, then stop each
   one. This command stops the VM host on macOS:

   ```shell
   min host stop local-minvmd0
   ```

2. Move the 0.8 state aside, and put the copy back. Replace `<copy>` with the
   copy's path: the one the installer named, or the one you made by hand:

   ```shell
   mv "${XDG_STATE_HOME:-$HOME/.local/state}/minimal" "$HOME/minimal-state-0.8"
   mv "<copy>" "${XDG_STATE_HOME:-$HOME/.local/state}/minimal"
   ```

3. Install the 0.7 release that you had. This command installs 0.7.3:

   ```shell
   curl --proto "=https" --tlsv1.2 -fsSL https://go.minimal.dev/stable | sh -s -- --version 0.7.3
   ```

## Uninstall

```shell
curl --proto "=https" --tlsv1.2 -fsSL https://go.minimal.dev/stable | sh -s -- --uninstall
```

This removes every file a previous install placed, including the shell
integration. It accepts these flags:

- `--force` also removes files that you changed.
- `--purge` also deletes the data, state and cache directories of Minimal.
- `--dry-run` shows what the command removes, and removes nothing.
