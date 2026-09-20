---
title: minvmd daemon
description: "Ops reference for the minvmd VM daemon: boots and supervises the Linux microVM that hosts minimald."
---

# `minvmd` - VM daemon

`minvmd` is the host daemon that brings up a Linux microVM via libkrun
(macOS/HVF or Linux/KVM) and supervises the
[minimald](./cli-minimald.md) instance running inside it. On macOS it is
the only session backend; on Linux it is selected with `min --provider local-minvmd`
(see [min](./cli-min.md)).

Generated from `--help` at `3a05252c`.

## Global flags

| Flag | Description |
|------|-------------|
| `--minimal-state-dir <PATH>` | Override the state dir base (default: `$XDG_STATE_HOME/minimal`). Runtime files live under `<dir>/providers/local-minvmd0/` |

## Commands

Two commands bring the VM up. `run` (alias `start`) is the
lifecycle-managed supervisor: it drives the daemon's state transitions and
supports `--detach` for background operation, so it is the usual entry
point. `boot` is a lower-level bring-up that skips lifecycle state, used
mainly for diagnostics.

### `boot`

```
minvmd boot [--foreground]
```

Boots the microVM and waits until the guest is up. `--foreground` stays
in the foreground until the VMM child exits.

### `run` (alias: `start`)

```
minvmd run [--detach] [--timeout <SECONDS>]
```

Starts the microVM supervisor (foreground by default).

| Flag | Description |
|------|-------------|
| `--detach` | Spawn the supervisor in the background and return once the host UDS is accepting connections |
| `--timeout <SECONDS>` | Timeout in seconds to wait for the host UDS when using `--detach` (default: `8`) |

### `status`

```
minvmd status [--json]
```

Prints daemon status. Exit code: `0` if running, `1` if stopped, `2` on
lock contention. `--json` prints status as a JSON object.

### `config show`

```
minvmd config show [--json]
```

Prints the effective per-VM resource configuration and each value's
source. `--json` prints it as a JSON object.

### `config set`

```
minvmd config set [--vcpus <N>] [--ram-mib <N>]
```

Validates and persists resource parameters, applied on the next boot.

| Flag | Description |
|------|-------------|
| `--vcpus <N>` | Number of virtual CPUs |
| `--ram-mib <N>` | Guest RAM in MiB |

### `stop`

```
minvmd stop
```

Stops the running daemon gracefully.

### `completions`

```
minvmd completions <SHELL>
```

Generates a shell tab-completion script. Supported shells include `bash`, `zsh`,
`elvish`, `fish`, `powershell`.

## Host processes and users

`minvmd run` supervises three host processes for the VM's lifetime, each its
own process with its own files, and none sharing writable state with another:

| Process | Runs as | Writable state |
|---------|---------|----------------|
| box egress proxy (`bep`) | the operator's login user | `<state>/bep/` (audit log, box attachments) |
| gvproxy switch (`gvproxy-min`) | the dedicated VM user | the switch socket and `gvproxy.yaml` in the provider dir |
| the VM (`minvmd __krun-vmm`) | the dedicated VM user | the data volume and boot log in the provider dir |

The proxy runs as the operator because the keychain items it redeems are the
operator's. The switch and the VM run as one dedicated unprivileged account,
`_minimalvm` by default, which the installer does not create (creating an
account needs root, and the installer never elevates); it reports whether the
account is present and prints the one-time command when it is not:

```
# macOS: a role account (name starts with `_`, uid in 200–400)
sudo sysadminctl -addUser _minimalvm -fullName "Minimal VM" -roleAccount -UID 399
# Linux
sudo useradd --system --no-create-home --shell /usr/sbin/nologin _minimalvm
```

The users are decided once per boot and logged once. Each spawn line
(`gvproxy switch spawned`, `box egress proxy spawned`, `VMM child spawned`)
names the user its process runs as, so a support bundle's process tree and the
daemon log agree. Every spawn sets its process's uid and gid explicitly, the
operator's real uid included: a supervisor started with the privilege to
switch (effective uid 0, real uid the operator's) never passes root on to the
proxy, nor to the switch and the VM when they fall back. The switch and the
VM fall back to the operator's login user, with the reason in the log, when:

- the supervisor holds no privilege to switch users, i.e. its effective uid is
  not 0 (`Unprivileged`), which is checked first;
- `MINVMD_VM_USER` is set empty (`OptedOut`, an explicit choice);
- the account does not exist on this host (`NoSuchUser`);
- the account is the operator's own (`IsOperator`).

The first case is every unprivileged `minvmd run` today, so on a host where
nothing starts the supervisor with that privilege all three processes run as
the operator; that and the opt-out are logged at info, the other two at warn,
since a privileged supervisor that still cannot switch was set up to. The
dedicated user takes effect as soon as the supervisor is started with the
privilege.

When it does, the supervisor hands the dedicated user the files the switch
and the VM write before spawning them (`VM files handed to the dedicated
user` in the log): the provider dir, where the switch binds its socket and
the VM binds the bridge; the data volume and boot log a previous boot left;
the READY-marker socket the VM dials; and the daemon log files under
`<state>/logs/`, which the VM's own tracing appends to. After the boot it
hands the bridge socket (`ssh.sock`) back to the operator, whose `min` CLI is
what connects to it, before tightening it to 0600. Ownership is all that
changes, so the account must also be able to reach these paths on its own:
read the kernel, rootfs and initramfs images, and traverse the state dir —
on a host whose home directories are 0750, the operator's `~/.local/state`
is out of its reach until that is opened up.

| Variable | Description |
|----------|-------------|
| `MINVMD_VM_USER` | The dedicated user for the switch and the VM (default `_minimalvm`). Empty keeps them on the operator's login user. |

