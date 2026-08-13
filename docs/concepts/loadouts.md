---
description: Loadouts are per-developer, session-level bundles of packages, vars, file patches, and lifecycle hooks that layer your personal environment on top of a project's shared config.
---

# Loadouts

A **loadout** is your personal layer on a session. The project's
[`minimal.toml`](../reference/minimal-dot-toml.md) describes what every
contributor's [session](./sessions.md) needs to build and run the code. A
loadout describes what *you* want on top of that: your editor, your terminal
multiplexer, your shell prompt, your dotfiles. When you activate a session,
the loadout is layered in, so the environment comes up matching your muscle
memory without changing anything the rest of the team sees.

Loadouts are deliberately per-developer. They live in your user config
directory, not in the repository, and they never travel with the project.
Two people working in the same codebase can activate the same session
definition and still get their own editors, aliases, and prompts.

## How a loadout differs from `minimal.toml`

It helps to keep the two roles straight:

- The project's `minimal.toml` is **shared and checked in**. It is the
  contract for the codebase: the packages a build needs, the tasks everyone
  runs, the session baseline the project expects. Changing it changes the
  environment for every contributor.
- A loadout is **personal and local**. It is never committed to the project
  and never affects another developer. Deleting all your loadouts changes
  nothing about how the project builds or what its sessions require.

Both feed the same session, and the daemon merges them into one final
configuration when the session comes up. The project contribution and every
applied loadout compose together as peers: there is no override precedence,
so a loadout adds to the project rather than silently replacing parts of it.
If two contributors disagree on the same value, activation fails with a
conflict. (For the exact merge and conflict rules, see the
[loadout reference](../reference/loadouts.md).)

One boundary worth stating up front: loadouts apply to **sessions**
(`min session activate`). They do not apply to task sandboxes, which carry their own
packages and environment through the task schema.

## Where loadouts live

Each loadout is a single TOML file in your user config directory:

```
~/.config/minimal/loadouts/<name>.toml
```

On Linux this is `$XDG_CONFIG_HOME/minimal/loadouts` (falling back to
`~/.config/minimal/loadouts` when `XDG_CONFIG_HOME` is unset). macOS uses the
same `~/.config` location for consistency with Minimal's state and cache
directories. The global `--config-dir` flag overrides the base directory when
you need a non-default location.

The filename stem is the loadout's identifier. A file named `dev.toml`
defines the loadout `dev`, and its `name` field inside the file must match
that stem. The directory is not created for you: make it and drop
`<name>.toml` files in to get started.

## What a loadout carries

A loadout can contribute four kinds of things to a session, and all four take
effect inside the session when it is activated.

### Packages

A list of package names brought into the session alongside the project's
baseline packages. This is how you land your editor and tools in the sandbox
without asking the project to depend on them:

```toml
packages = ["helix", "zellij"]
```

Packages compose as a set across all contributors, so listing something the
project already provides is harmless: duplicates are deduplicated.

### Vars

Environment variables set in the session. A value can be a literal, or it can
inherit from the host environment of the `min` process, optionally with a
fallback:

```toml
[vars]
EDITOR = "hx"
VISUAL = "hx"
```

Vars are the main lever for interactive setup, because the shell you get from
`min session attach` sources no rc files. Your prompt (`PS1`), a one-time banner, and
similar touches all travel through `[vars]` rather than through a `.bashrc`
patch. The [reference](../reference/loadouts.md) walks through the prompt and
banner patterns in detail.

### File patches

Patches copy files from your host into the session, which is how your
dotfiles arrive. Each entry pairs a host `source` (a path, a glob, or a list
of them) with a `dest` inside the session:

```toml
patches = [
    { dest = ".config/helix/config.toml", source = "~/dotfiles/helix/config.toml" },
    { dest = ".config/zellij/",           source = "~/dotfiles/zellij/**/*.kdl" },
]
```

A source that does not exist on your host is skipped with a warning rather
than failing activation, so you can opportunistically patch a dotfile tree
that may not be present on every machine.

### Lifecycle hooks

Hooks run inside your session, with its packages, variables, files, and
network. Your own loadouts' hooks run without ceremony; a *project's* hooks
require you to allow-list that project in your
[user policy](../reference/user-policy.md) first, because a hook is arbitrary
code the project asked to run on your machine. `min session activate
--no-hooks` turns them off for a session entirely.

Hooks are scripts declared to run at session transition points: `on_activate`
when the session comes up, `on_destroy` when it is torn down, `on_attach`
when you connect to it, and `on_detach` when you disconnect. Declare them to
warm a cache, fetch grammars, or clean up when you step away:

```toml
[[lifecycle_hooks]]
on_activate = { type = "inline", value = "hx --grammar fetch >/dev/null 2>&1 || true" }
```

Hooks from every applied loadout concatenate in declaration order.

### A complete example

Putting the pieces together, a loadout that sets up the helix editor and the
zellij multiplexer with your dotfiles looks like this:

```toml
name        = "dev"
description = "helix + zellij with my dotfiles"
packages    = ["helix", "zellij"]

patches = [
    { dest = ".config/helix/config.toml", source = "~/dotfiles/helix/config.toml" },
    { dest = ".config/zellij/",           source = "~/dotfiles/zellij/**/*.kdl" },
]

[vars]
EDITOR = "hx"

[[lifecycle_hooks]]
on_activate = { type = "inline", value = "hx --grammar fetch >/dev/null 2>&1 || true" }
```

Saved as `~/.config/minimal/loadouts/dev.toml`, it is ready to apply.

## Applying a loadout

Name a loadout when you activate a session with `--loadout`, which is
repeatable to stack several at once:

```console
$ min session activate --loadout dev
$ min session activate --loadout dev --loadout scratch
```

Loadouts are read and composed on the client, before the CLI contacts the
daemon, so a missing or malformed loadout file fails the activation loudly and
immediately rather than producing a silently-empty session. When loadouts are
applied, the CLI prints `Applying loadouts: <names>` to stderr.

Applying a loadout is also the moment its contents are captured: files are
read once, inherited vars are resolved against your current host environment,
and the composed result is what the session runs with. Editing a loadout file
does not retroactively change sessions that already exist, so destroy and
re-activate to pick up an edit.

To activate with no loadouts at all, including skipping the defaults described
below, pass `--no-loadouts` (which conflicts with `--loadout`):

```console
$ min session activate --no-loadouts
```

## Auto-applying with `default_loadouts`

Typing `--loadout dev` on every activation gets old. Set the loadouts you
almost always want in the client config at `~/.config/minimal/config.toml`,
under a `[loadouts]` section:

```toml
[loadouts]
default_loadouts = ["dev", "fish"]
```

With this in place, a plain `min session activate` applies `dev` and `fish`
automatically. The defaults are a convenience layer, and the activation flags
take precedence over them:

1. `--no-loadouts` applies nothing, regardless of the config.
2. One or more `--loadout NAME` applies exactly those, and the config's
   `default_loadouts` are ignored for that activation.
3. Neither flag applies the `default_loadouts` list, which may be empty.

So the defaults are your baseline, `--loadout` is an explicit override for a
one-off session, and `--no-loadouts` is the clean-room escape hatch.

## Listing your loadouts

To see which loadouts you have and what each contributes, run:

```console
$ min loadout ls
```

`ls` is an alias for `min loadout list`. It enumerates every `*.toml` file in
your loadouts directory, one row per file, with the name, description, and a
per-kind summary of what it contributes:

```
  NAME   DESCRIPTION                     CONTRIBUTES
* dev    helix + zellij with my dotfiles 2 pkg / 2 var / 2 patch / 1 hook
  extra                                  1 pkg / 0 var / 0 patch / 0 hook

* default (from `[loadouts].default_loadouts`)
```

Loadouts named in `default_loadouts` are marked with a leading `*`, so the
listing doubles as a quick check of what a plain `min session activate` will pull in.
A malformed file is listed with its parse error so you can fix it in place
rather than hunting for which file is broken. Pass `--dir <DIR>` to list a
loadouts directory other than the default.

## Where to go next

- The [loadout reference](../reference/loadouts.md) has the full TOML schema
  for every field (`name`, `packages`, `[vars]`, `patches`,
  `[[lifecycle_hooks]]`, and the rest), the client config keys, and the exact
  composition and conflict rules.
- [Sessions](./sessions.md) explains the session model that loadouts layer
  onto: activation, attaching, and teardown.
