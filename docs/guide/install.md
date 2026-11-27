---
description: Install Minimal on Linux (x86_64/aarch64) or macOS (Apple Silicon).
---

# Install Minimal

## Linux

### Requirements

- **x86_64** or **aarch64** architecture
- Kernel 5.10 or later with unprivileged user namespaces enabled. Ubuntu 24.04
  and later restrict them by default; see the
  [Linux host setup guide](../reference/linux-host-setup.md) for the fix.

### Install

```shell
curl --proto "=https" --tlsv1.2 -fsSL https://go.minimal.dev/stable | sh
```

### Verify

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

### Verify

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
asks on your terminal before ending them; declining leaves everything as it was.
For a scripted upgrade that must not stop to ask, set
`MINIMAL_INSTALL_FORCE_STOP=1`, or pass the flag through the shell:

```shell
curl --proto "=https" --tlsv1.2 -fsSL https://go.minimal.dev/stable | sh -s -- --force-stop
```

### Upgrade from 0.7 to 0.8

0.8 changes how Minimal stores your boxes. 0.7 cannot read the box state that
0.8 writes, so after the upgrade you cannot go back to 0.7 with your boxes
unless you made a copy of the state first. Make that copy before you run the
install command.

What changes in 0.8:

- Every session and task is a box. A box stays after it stops or ends, until
  `min box rm` removes it.
- The old session verbs, bare `min stop` and `min task run --path` are gone.
  Use the `min box` verbs, `min host stop <HOST>` and `-C <DIR>`. Run
  `min box --help` to see the verbs.
- A box without a name that you chose takes `<project>` for the default entry,
  or `<project>-<entry>` for another entry. When a box already has that name,
  the new box takes the name with `-<n>` added.
- A name that you choose with `--name` or with an entry's `[box] name` is kept
  exactly. When any box on the host has that name, in any state, the command
  refuses and creates nothing.
- Environment variables are set in one table, `env_vars`, in `minimal.toml`
  and in loadout files. A file that still sets `vars` or `vars_lenient` fails
  with exit code 3, and the message names the file and the key. Rename the key
  to `env_vars`.
- `min init` writes the session entry as `[sessions.default]`, which holds the
  session's packages, and writes no `[boxes]` or `[defaults]` table.

#### Copy your box state before you upgrade

When the installer upgrades a 0.7 install, it makes this copy itself, next to
the state directory, and names the copy when it finishes. Make the copy by hand,
as below, only when you want it somewhere else, or when the installer stops
because there is not enough free space. Then run the installer with
`--skip-state-archive`.

Minimal keeps its box state in `${XDG_STATE_HOME:-$HOME/.local/state}/minimal`.
On macOS, that directory holds the virtual machine's data volume, a large
sparse file. The copy commands below keep it sparse.

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
   one, for example:

   ```shell
   min host stop local-minvmd0
   ```

2. Move the 0.8 state aside, and put the copy back. Replace `<copy>` with the
   copy's path: the one the installer named, or the one you made by hand:

   ```shell
   mv "${XDG_STATE_HOME:-$HOME/.local/state}/minimal" "$HOME/minimal-state-0.8"
   mv "<copy>" "${XDG_STATE_HOME:-$HOME/.local/state}/minimal"
   ```

3. Install the 0.7 release that you had, for example 0.7.3:

   ```shell
   curl --proto "=https" --tlsv1.2 -fsSL https://go.minimal.dev/stable | sh -s -- --version 0.7.3
   ```

## Uninstall

```shell
curl --proto "=https" --tlsv1.2 -fsSL https://go.minimal.dev/stable | sh -s -- --uninstall
```

This removes every file a previous install placed, including the shell
integration. It accepts `--force` (also remove files you modified), `--purge`
(also delete Minimal's data, state, and cache directories), and `--dry-run`
(show what would be removed).
