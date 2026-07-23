---
description: Install Minimal on Linux (x86_64/aarch64) or macOS (Apple Silicon).
---

# Install Minimal

## Linux

### Requirements

- **x86_64** or **aarch64** architecture
- Kernel support for user namespaces (most modern distributions)

### Install

```shell
curl --proto "=https" --tlsv1.2 -fsSL https://go.minimal.dev/stable | sh
```

### Verify

```shell
min --version
```

If installed correctly, it will provide you with the version.

## macOS

On macOS, Minimal boots a lightweight Linux microVM via libkrun on Apple's Hypervisor.framework.

### Requirements

- **macOS Tahoe 26.2** or later
- **Apple Silicon** (M1, M2, M3, M4). Intel Macs are not supported

### Install

Copy and paste the following into your terminal:

```shell
curl --proto "=https" --tlsv1.2 -fsSL https://go.minimal.dev/stable | sh
```

### Verify

```shell
min --version
```

If installed correctly, it will provide you with the version.
