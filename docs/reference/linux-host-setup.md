---
title: Linux host setup
description: "Preparing a Linux host to run minimald: the unprivileged user namespace the session sandbox needs, and the sysctls and AppArmor profile that grant it on Ubuntu 24.04+."
---

# Linux host setup

`minimald` and `mip` run every session and task inside their own
sandbox composed of an unprivileged user namespace and other Linux
namespaces, similar to how containers are sandboxed on
Kubernetes. Root/sudo access is not needed to create these sandboxes;
however, some Linux distributions require enabling unprivileged user
namespace creation.

Most distributions allow this by default. **Ubuntu 24.04
and later require the small configuration change described
below.**

## The symptom

Ubuntu 24.04 ships `kernel.apparmor_restrict_unprivileged_userns=1`, which stops
an unconfined program from creating a user namespace. The sandbox child dies
writing its uid map before it runs anything, so *no* session can start:

```
DIAG hakoniwa container/process exited non-zero code=125 exit_code=None
  reason=write("/proc/self/uid_map", ..) => Operation not permitted (os error 1)
```

On such a host `min session activate` fails before any session exists.
The daemon checks the namespace on every create and refuses with the
cause and its fix, which `min` prints as its error. `mip` prints the
same cause and the fix for its own binary when a task starts. Make sure
that the host is the cause with stock tools, no Minimal involved:

```console
$ cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns
1
$ unshare --user --map-root-user id
unshare: write failed /proc/self/uid_map: Operation not permitted
```

## The fix, by cause

The refusal names one of two causes. Each has its own fix. Minimal
does not suggest `kernel.apparmor_restrict_unprivileged_userns=0`: that
sysctl turns the protection off for every program on the host.

### Ubuntu restricts unprivileged user namespaces

This is the AppArmor restriction above. An AppArmor profile that grants
`userns` to one binary lifts it for that binary alone, and the profile
attaches by binary path.

For `minimald`, installed with the `curl … | sh` installer, finish the
install. The step loads the profile for the installed daemon:

```console
$ min finalize-install --show
$ min finalize-install
```

The profile takes effect when the daemon next starts. Run `min stop`,
then your command again. To remove the profile run:

```console
$ min finalize-install --undo
```

For a `minimald` built from source, run the loader from the checkout
with the binary's path:

```console
$ sudo scripts/install-apparmor-profile.sh --path "$PWD/target/debug/minimald"
```

For `mip`, which builds every task in the same kind of sandbox, attach
the profile to the `mip` binary with `--path`. `min finalize-install`
covers the daemon alone. The installer places the loader under the
Minimal data directory:

```console
$ sudo bash ~/.local/share/minimal/apparmor/install-apparmor-profile.sh --path "$(command -v mip)"
```

From a checkout, the same loader is `scripts/install-apparmor-profile.sh`,
and one run can take several `--path` flags:

```console
$ sudo scripts/install-apparmor-profile.sh --path "$PWD/target/debug/minimald" --path "$PWD/target/debug/mip"
```

To remove a profile the loader installed:

```console
$ sudo scripts/install-apparmor-profile.sh --uninstall   # from a checkout
```

### User namespaces switched off

Separately from the AppArmor restriction, no program can create a user
namespace on a kernel built without `CONFIG_USER_NS`, or on a host with
`user.max_user_namespaces` set to `0`. No profile lifts this. The daemon
reads the sysctl on every create, so the first command below clears the
refusal at once. The second keeps it across reboots:

```console
$ sudo sysctl -w user.max_user_namespaces=15000
$ sudo sh -c "echo 'user.max_user_namespaces=15000' > /etc/sysctl.d/60-minimal-userns.conf"
```

On a kernel built without `CONFIG_USER_NS`, use a kernel with user
namespaces enabled. Debian-derived kernels that carry
`kernel.unprivileged_userns_clone` also need it set to `1`.
