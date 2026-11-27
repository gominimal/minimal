---
title: CLI Reference
description: Overview of the Minimal command-line binaries (min, mip, minimald, and minvmd), with the page that documents each one.
---

# CLI Reference

Minimal's main command-line tool is **`min`**, the session CLI. You use it to
create sandboxed development boxes, attach to them and manage them. `min`
talks to the `minimald` host daemon, which creates and supervises the boxes.
On macOS, `minimald` always runs inside a Linux microVM that the `minvmd`
daemon boots. On Linux, the provider decides whether it runs on the host or
in that microVM, as [Platform availability](#platform-availability) says.

Under `min` is a declarative package and build engine. It evaluates
`minimal.toml` and the project's Nickel files, and it builds packages in
clean rooms. It also runs tasks in sandboxes and keeps a content-addressed
artifact cache. Most users reach the engine only through `min` and their
`minimal.toml`. On Linux, you can also drive it directly with the **`mip`**
CLI.

## Binaries

| Binary | Role | Reference |
|--------|------|-----------|
| `min` | Session CLI: create and attach to sandboxed dev boxes, and manage them | [min](./cli-min.md) |
| `mip` | Package and build CLI (advanced, Linux only): build packages and run tasks directly, without the daemon | [mip](./cli-mip.md) |
| `minimald` | Host daemon: serves boxes to `min` over SSH on a Unix domain socket | [minimald](./cli-minimald.md) |
| `minvmd` | VM daemon: boots the Linux microVM that hosts `minimald` | [minvmd](./cli-minvmd.md) |

## Command naming convention {#command-naming-convention}

A command has the form **`<noun> <verb>`**: `min box start`,
`min session start`, `min loadout list`, `mip package build`. The noun names
the thing that the command acts on. The verb names the action.

The convention has these rules:

1. **A noun for a kind of thing accepts the singular and the plural.** In
   `min`, `--help` shows both forms of each such noun, as in `box`/`boxes`
   and `host`/`hosts`. In `mip`, `package` also accepts `packages` and `pkg`, which
   `--help` does not show.
2. **A verb means the same thing under every noun.** `list` lists and
   `stop` stops, so you can guess `<noun> list` for any noun that lists.
3. **New surface gets a noun.** Use an existing noun when one fits. A new
   kind of thing gets a new noun. Do not add a bare verb at the top level
   for it.

### Documented exceptions

These top-level forms are intentional exceptions to the convention.

| Form | What it does, and why it stays |
|------|--------------|
| `min` | In a terminal, attaches to the session box for the current directory. With no such box, it attaches to the only session box, or opens a picker when there are more. With no session box at all, it starts one from the current directory and attaches. Without a terminal, prints a read-only state report on stderr. [`min`](./cli-min.md) describes how it picks the box. `min --help` prints the help. |
| `min ls` | The most-used command keeps its bare form, with the `--raw` and `--json` flags that scripts read. It is not an alias of `min session list`, which is `min box list` limited to session boxes. |
| `min init`, `min add`, `min update` | Pass through to the `mip` commands of the same name. The same spelling in the two CLIs is more useful than the noun form. |
| `min login` | The same as `min auth login`. |
| `min bug` | The same as `min diag collect`. It keeps its name because bug reports ask for it. |

## Platform availability

- **Linux**: the installer puts `min`, `mip`, `minimald` and `minvmd` on the
  host, on amd64 and arm64. The provider decides where `minimald` runs, and so where
  your boxes are. `--provider local` or `--provider local-minvmd` chooses
  it, then the `MIN_PROVIDER` variable, then the `provider` key in
  `config.toml`. With none of these, `min` uses `local-minvmd` when
  `/dev/kvm` opens for you and answers the KVM API version request, and
  `local` otherwise. [Choosing the provider on
  Linux](./cli-min.md#choosing-the-provider-on-linux) gives the details.
- **macOS**: the installer puts `min` and `minvmd` on the host, without `mip`
  or a native `minimald`. `minimald` always runs inside the microVM, and the
  package and build engine runs there with it.
- `mip run` runs tasks in Linux sandboxes, so it is on Linux only.

## In-sandbox helper commands

Inside a box, `/usr/bin/min` is a helper with its own small set of commands,
not the session CLI. Run `min` with no arguments inside the box to list
them. [Sandbox operations](./sandbox-operations.md) describes each one.
