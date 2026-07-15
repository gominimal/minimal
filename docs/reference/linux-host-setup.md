---
description: Preparing a Linux host to run minimald — the unprivileged user namespace the session sandbox needs, and the AppArmor profile that grants it on Ubuntu 24.04+.
---

# Linux host setup

`minimald` runs every session and task inside a sandbox (hakoniwa), and every
sandbox is an **unprivileged user namespace**: the daemon forks, the child calls
`unshare(CLONE_NEWUSER)` and writes `/proc/self/uid_map`. No `setcap`, no root,
no setuid helper — but the host has to permit unprivileged user namespaces.

Most distributions do. **Ubuntu 24.04 and later do not**, by default.

## The symptom

Ubuntu 24.04 ships `kernel.apparmor_restrict_unprivileged_userns=1`, which stops
an unconfined program from creating a user namespace. The sandbox child dies
writing its uid map before it runs anything, so *no* session can start:

```
DIAG hakoniwa container/process exited non-zero code=125 exit_code=None
  reason=write("/proc/self/uid_map", ..) => Operation not permitted (os error 1)
```

`minimal attach` shows this as a session that closes immediately. The daemon
also preflights this at startup: on a host that will refuse the namespace it
logs a `sessions will fail to start` warning naming the restriction and this
fix, so check the daemon log first. Confirm the host is the cause — this needs
no minimal code at all:

```console
$ cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns
1
$ unshare --user --map-root-user id
unshare: write failed /proc/self/uid_map: Operation not permitted
```

## The fix: install minimald's AppArmor profile

Ubuntu's intended accommodation is a profile that grants the binary the `userns`
permission — the same thing the distro ships for `rootlesskit`, `runc`, and
`podman`. minimal ships one in `packaging/apparmor/`:

```console
$ sudo scripts/install-apparmor-profile.sh
loaded the minimald AppArmor profile (/etc/apparmor.d/minimald)
```

That is all. Sessions work; nothing else on the host gains the ability to create
user namespaces.

If you installed minimal with the `curl … | sh` installer rather than from a
checkout, the same loader ships alongside the binaries — run it with root:

```console
$ sudo bash ~/.local/share/minimal/apparmor/install-apparmor-profile.sh
loaded the minimald AppArmor profile (/etc/apparmor.d/minimald)
```

The installer prints this exact hint on its own when it detects the restriction
on the host, so you do not have to know to look for it.

The profile **confines nothing** — it is declared `flags=(unconfined)`, so it
does not restrict what minimald may do. It exists only to give minimald a named
AppArmor label, because on Ubuntu only a *labelled* program can be granted
`userns`. Installing it neither sandboxes minimald nor weakens the host.

It attaches to minimald at the paths it is normally installed to — `/usr/bin`,
`/usr/local/bin`, and `~/.local/bin` (where [the installer](/reference/cli) puts
it). A binary somewhere else — a dev build in `target/debug`, or a custom
`MINIMAL_BIN` — needs that path named explicitly, because AppArmor matches
profiles by executable path:

```console
$ sudo scripts/install-apparmor-profile.sh --path "$PWD/target/debug/minimald"
```

Re-run the installer after moving or reinstalling the binary. To remove the
profile: `sudo scripts/install-apparmor-profile.sh --uninstall` (from a
checkout) or `sudo bash ~/.local/share/minimal/apparmor/install-apparmor-profile.sh --uninstall`
(curl-installed). `minimal`'s own uninstaller
(`curl … | sh -s -- --uninstall`) also offers to remove this system profile —
prompting on a terminal, or printing the root command otherwise.

## Alternative: lift the restriction host-wide

If you cannot install a profile, turn the restriction off:

```console
$ sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0   # until reboot
```

Persist it in `/etc/sysctl.d/`. Note this re-enables unprivileged user
namespaces for **every** program on the host, not just minimald, which is what
the profile exists to avoid. It is what CI does, for a throwaway runner.

## Other deployment models

Only the host-native daemon (**DM2**) is affected. When minimald runs inside a
minimal-managed microVM (**DM1** on macOS, **DM3** on Linux/KVM) the sandbox's
user namespace is created in the guest, whose kernel carries no such
restriction — the host's setting is irrelevant.
