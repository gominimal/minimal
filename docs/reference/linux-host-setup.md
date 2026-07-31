---
title: Linux host setup
description: "Preparing a Linux host to run minimald: the unprivileged user namespace the session sandbox needs, and the sysctls and AppArmor profile that grant it on Ubuntu 24.04+."
---

# Linux host setup

`minimald` runs every session and task inside its own sandbox
composed of an unprivileged user namespace and other Linux
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

`min session attach` shows this as a session that closes
immediately. The `minimald` daemon also checks this at startup: on a
host that will refuse the namespace it logs a `sessions will fail to
start` warning naming the restriction and this fix, so check the
daemon log first. Confirm the host is the cause using stock tools,
no Minimal involved:

```console
$ cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns
1
$ unshare --user --map-root-user id
unshare: write failed /proc/self/uid_map: Operation not permitted
```

## Option 1: enable unprivileged user namespace creation host-wide

The following disables the restriction for every program on the host until the next reboot:

```console
$ sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```

To persist this change across reboots, create a file in `/etc/sysctl.d/`:

```console
$ sudo sh -c "echo 'kernel.apparmor_restrict_unprivileged_userns=0' > /etc/sysctl.d/enable-user-ns.conf"
```

## Option 2: install minimald's AppArmor profile

If you installed Minimal with the `curl … | sh` installer, you can
grant user namespace creation to minimald alone instead of
system-wide:

```console
$ sudo bash ~/.local/share/minimal/apparmor/install-apparmor-profile.sh
loaded the minimald AppArmor profile (/etc/apparmor.d/minimald)
```

The only change to your system is allowing minimald to create user
namespaces. To remove the profile run:

```console
$ sudo bash ~/.local/share/minimal/apparmor/install-apparmor-profile.sh --uninstall
```

If you built minimald from source on an Ubuntu system, run
the following script in the source directory to allow it to create
user namespaces:

```console
$ sudo scripts/install-apparmor-profile.sh --path "$PWD/target/debug/minimald"
```

To remove the AppArmor profile:

```console
$ sudo scripts/install-apparmor-profile.sh --uninstall   # from a checkout
```

## User namespaces disabled entirely

Separately from the AppArmor restriction, user namespaces cannot be
created at all on a kernel built without `CONFIG_USER_NS`, on a host
with `user.max_user_namespaces` set to `0`, or on Debian-derived
kernels that ship `kernel.unprivileged_userns_clone` with it set to
`0`. The daemon's startup logs report this as its own error. The fix
matches the cause: use a kernel with user namespaces enabled, raise
`user.max_user_namespaces` via sysctl, or set
`kernel.unprivileged_userns_clone=1`.
