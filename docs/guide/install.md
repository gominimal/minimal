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

## Uninstall

```shell
curl --proto "=https" --tlsv1.2 -fsSL https://go.minimal.dev/stable | sh -s -- --uninstall
```

This removes every file a previous install placed, including the shell
integration. It accepts `--force` (also remove files you modified), `--purge`
(also delete Minimal's data, state, and cache directories), and `--dry-run`
(show what would be removed).
