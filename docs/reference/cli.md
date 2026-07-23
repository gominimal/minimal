---
title: CLI Reference
description: Overview of the Minimal command-line binaries (min, mip, minimald, and minvmd) and where each is documented.
---

# CLI Reference

Minimal's primary command-line tool is **`min`**, the session CLI: it creates,
attaches to, and manages sandboxed development sessions. `min` talks to the
`minimald` host daemon, which creates and supervises sessions. On macOS (and
optionally on Linux), `minimald` runs inside a Linux microVM managed by the
`minvmd` daemon.

Underneath, Minimal has a declarative package/build engine that evaluates
`minimal.toml` plus Nickel files, builds packages in clean rooms, runs tasks in
sandboxes, and manages a content-addressed artifact cache. Most users interact
with it only through `min` and their `minimal.toml`. Advanced users on Linux can
drive it directly with the **`mip`** CLI.

## Binaries

| Binary | Role | Reference |
|--------|------|-----------|
| `min` | Session CLI: create, attach to, and manage sandboxed dev sessions | [min](./cli-min.md) |
| `mip` | Package/build CLI (advanced, Linux-only): build packages, run tasks, manage the cache directly | [mip](./cli-mip.md) |
| `minimald` | Host daemon: serves sessions to `min` over SSH-on-UDS | [minimald](./cli-minimald.md) |
| `minvmd` | VM daemon: boots the Linux microVM that hosts `minimald` | [minvmd](./cli-minvmd.md) |

## Platform availability

- **Linux**: installs ship `min`, `mip`, and `minimald`. `minimald` runs
  natively by default; `min --minvmd` routes sessions through the `minvmd`
  microVM instead, which needs a separately obtained `minvmd` binary (a
  prebuilt Linux amd64 `minvmd` is attached to each GitHub Release; arm64
  must build from source).
- **macOS**: installs ship `min` and `minvmd` only. `minimald` always runs
  inside the microVM, and the package/build plane runs there with it;
  there is no native macOS `mip`.
- `mip run` (and its `shell`/`build`/`test` shorthands) executes tasks in
  Linux sandboxes and is available on Linux only.

## In-sandbox helper commands

Task sandboxes expose a small set of helper commands (`add`, `search`,
`check`, `run`) for use from inside a running sandbox. Those are
documented separately in [sandbox operations](./sandbox-operations.md).
