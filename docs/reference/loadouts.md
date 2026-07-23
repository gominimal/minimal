---
title: Loadouts
description: Per-developer loadout reference: the loadout TOML schema, config-directory layout, min CLI flags, client config, and how loadouts compose into sessions.
---

# Loadouts

A loadout is a per-developer bundle of packages, environment variables, file
patches, and lifecycle hooks that the [`min` session CLI](./cli-min.md) layers
into the sessions it activates. The project's
[`minimal.toml`](./minimal-dot-toml.md) describes what every contributor's
session needs; a loadout carries what *you* want on top (your editor,
terminal multiplexer, shell config, and dotfiles) so each development
environment comes up matching your muscle memory.

Loadouts apply to sessions (`min activate`); they are not used by task
sandboxes ([`mip run`](./cli-mip.md)), which have their own
`packages`/`env_vars`/`patches` schema described in [Tasks](./tasks.md).

> **Current limitations**: of the four things a loadout can contribute,
> **packages** and **vars** take effect inside the session today. **Patches**
> and **lifecycle hooks** are parsed, validated, and composed into the
> session's configuration, but the session launcher does not yet apply them
> inside the sandbox; the daemon holds them with the session and logs each
> one as deferred. The schema below documents all four so files written
> now stay valid as the remaining plumbing lands.

## Where loadouts live

Each loadout is a single TOML file at:

```
<config>/minimal/loadouts/<name>.toml
```

`<config>` is the platform user config directory: `$XDG_CONFIG_HOME` on Linux
(or `$HOME/.config` when unset); macOS also uses `$HOME/.config` for
consistency with Minimal's state and cache dirs, not
`~/Library/Application Support`. The global
[`--config-dir`](./cli-min.md#global-flags) flag overrides the base, and
`min dirs` prints the resolved loadouts directory.

The filename stem **is** the loadout's identifier:

- It must match the `name` field declared inside the file, or loading fails
  with a `NameMismatch` error naming both the file stem and the declared
  `name`.
- Names are trimmed and must be non-empty, with no `/`, `\`, or NUL
  characters.

The directory is not created automatically; create it and drop
`<name>.toml` files there to get started.

## Example

A loadout that brings in the helix editor and zellij multiplexer, wired up
with the user's dotfiles:

```toml
name        = "dev"
description = "helix + zellij with my dotfiles"
packages    = ["helix", "zellij"]

patches = [
    # Helix: single config files plus a themes directory.
    { dest = "~/.config/helix/config.toml", source = "~/dotfiles/helix/config.toml" },
    { dest = "~/.config/helix/languages.toml", source = "~/dotfiles/helix/languages.toml" },
    { dest = "~/.config/helix/themes/", source = "~/dotfiles/helix/themes/**/*.toml" },

    # Zellij: single config file plus a layouts directory.
    { dest = "~/.config/zellij/config.kdl", source = "~/dotfiles/zellij/config.kdl" },
    { dest = "~/.config/zellij/layouts/", source = "~/dotfiles/zellij/layouts/**/*.kdl" },
]

[vars]
EDITOR    = "hx"
VISUAL    = "hx"
TERM      = { inherit = true, default = "xterm-256color" }
COLORTERM = { inherit = true }

# Warm helix's tree-sitter grammar cache the first time the session
# comes up. Best-effort; failures don't tank activation.
[[lifecycle_hooks]]
on_activate = { type = "inline", value = "hx --grammar fetch >/dev/null 2>&1 || true" }
```

Saved as `<config>/minimal/loadouts/dev.toml`, this is applied with
`min activate --loadout dev`, or automatically via
[`default_loadouts`](#client-config).

## Loadout schema

### `name` - The loadout's identifier

_Required_

Must match the filename stem. Shown in selection and error messages.

```toml
name = "dev"
```

### `description` - Describe the loadout

_Optional_

Free-form text, shown alongside the name in `min loadout list`.

```toml
description = "Editor + terminal multiplexer"
```

### `packages` - Packages to bring into the session

_Optional_

Package names installed into the session, in addition to the session's
baseline packages and anything the project contributes. Duplicates across
contributors are deduplicated.

```toml
packages = ["helix", "zellij"]
```

Names are not checked at activation: an unknown package composes cleanly
and fails later, when the session sandbox first spawns, with
`no such package: <name>`.

### `[vars]` - Environment variables

_Optional_

Variables set in the session environment. Names must be POSIX-shaped
(`[A-Z_][A-Z0-9_]*`); for other names, see
[`[[vars_lenient]]`](#vars_lenient). Each value takes one of three forms:

```toml
[vars]
EDITOR = "hx"                                # literal value
TERM   = { inherit = true, default = "xterm-256color" }  # inherit, with fallback
COLORTERM = { inherit = true }               # inherit from the host env
```

- A **literal** string sets the variable to that value.
- `{ inherit = true }` passes the variable through from the environment of
  the `min` process on the host. If the host doesn't have it set, the
  variable is dropped from the session (with a warning) rather than failing
  activation, so opportunistically inheriting things like `TERM` is safe.
- `{ inherit = true, default = "..." }` inherits, falling back to `default`
  when the host doesn't have the variable set.

`inherit = false` is rejected; omit the variable instead.

### `[[vars_lenient]]` - Environment variables with non-POSIX names {#vars_lenient}

_Optional_

An explicit opt-in for the rare variable whose name is not POSIX-shaped.
Anything the Linux kernel accepts is allowed (no `=`, no NUL). Values use
the same three forms as `[vars]`.

```toml
[[vars_lenient]]
name  = "weird-thing"
value = "x"
```

### `patches` - Files copied from the host into the session

_Optional_

Each row names a `source` on the host and a `dest` inside the session
sandbox, with an optional `description`.

```toml
patches = [
    { dest = "~/.psqlrc", source = "~/dotfiles/psqlrc" },
    { dest = "certs/",    source = ["~/ca/root.pem", "~/ca/dev.pem"] },
    { dest = "~/.config/nvim/", source = "~/dotfiles/nvim/**/*.lua" },
]
```

**`source`** is a host path or glob pattern, or a list of them (a list
fans out into one patch per pattern, sharing the `dest`):

- A leading `~` or `$HOME` expands to the host home directory. Other
  `$NAME` / `${NAME}` references resolve against the session's
  already-resolved variables (declared in `[vars]`); referencing an
  undefined name is an error. `$$` is a literal `$`.
- After expansion the path must be absolute; anchor home-relative sources
  with `~/` or `$HOME/`.
- Glob patterns must have a literal directory prefix to walk from:
  `~/dotfiles/**/*.lua` is fine, a bare `**/*.pem` is rejected.
- `..` components are rejected wherever they appear.
- A source path that does not exist on the host is dropped with a warning
  at activation rather than failing it, so opportunistically patching a
  dotfile tree the host may not have is safe. Other enumeration failures
  (permission denied, unreadable entries) still fail the composition.

**`dest`** is interpreted relative to the sandbox user's home directory; a
leading `~/` refers to that same home. Absolute paths and `..` components
are rejected. For a single-file source, `dest` is the destination file
path; for multi-file sources (lists, globs), `dest` is the destination
directory.

By default the walker does not follow symlinks while enumerating glob
matches; see [`follow_symlinks`](#follow_symlinks) and the
[client config](#client-config).

### `[[lifecycle_hooks]]` - Scripts at session transition points

_Optional_

Each hook groups up to three scripts (`on_activate`, `on_destroy`, and
`on_failure`), and at least one must be present. An optional `description`
labels the hook. Scripts are either inline or a path to a file:

```toml
[[lifecycle_hooks]]
description = "warm caches"
on_activate = { type = "inline",   value = "cargo fetch || true" }
on_failure  = { type = "external", value = "./cleanup.sh" }
```

External script paths must be relative (absolute paths are rejected at
parse time) and are anchored to the configuration directory the file was
loaded from. Hooks from multiple contributors concatenate and run in
declaration order.

### `follow_symlinks` - Symlink handling for patch sources {#follow_symlinks}

_Optional_

Overrides the client-wide `[loadouts].follow_symlinks` setting (see
[client config](#client-config)) for this loadout's patches only. When
unset, the client-wide setting applies.

```toml
follow_symlinks = true
```

## Selecting loadouts at activation

[`min activate`](./cli-min.md#activate) decides which loadouts to apply
from two flags:

| Flag | Description |
|------|-------------|
| `--loadout <NAME>` | Apply `<config>/minimal/loadouts/<NAME>.toml`. Repeatable. If given, the config file's `default_loadouts` are ignored |
| `--no-loadouts` | Apply no loadouts at all. Conflicts with `--loadout` |

Resolution order:

1. `--no-loadouts`: nothing is applied, regardless of configuration.
2. One or more `--loadout NAME`: exactly the named loadouts are applied.
3. Neither flag: the `[loadouts].default_loadouts` list from the
   [client config](#client-config) is applied (which may be empty).

Loadouts are resolved and composed **before** the CLI contacts the daemon:
a missing or malformed loadout file fails the activation loudly on the
client rather than producing a silently-empty session. When loadouts are
applied, the CLI prints `Applying loadouts: <names>` to stderr.

Activation is also when loadout contents are captured: the files are read
once, inherited vars are resolved against the host environment, and the
composed result is what the session runs with. Editing a loadout file
does not change sessions that already exist; destroy and re-activate to
pick up the edit.

## Client config {#client-config}

Client-wide loadout preferences live in `<config>/minimal/config.toml`,
under a `[loadouts]` section:

```toml
[loadouts]
default_loadouts = ["helix", "fish"]
follow_symlinks  = false
```

| Key | Default | Description |
|-----|---------|-------------|
| `default_loadouts` | `[]` | Loadouts (by filename stem) applied to each new session when no `--loadout`/`--no-loadouts` flag is given |
| `follow_symlinks` | `false` | Follow symlinks while enumerating loadout patch sources. Turn on when your dotfile tree is a symlink farm (stow, chezmoi) and you want the walk to descend through the links |

A missing file is equivalent to the defaults; unknown keys are rejected so
a typo (`[loadout]` for `[loadouts]`) fails loudly.

## Listing loadouts

[`min loadout list`](./cli-min.md#loadout-list-alias-ls) (alias:
`min loadout ls`) enumerates every `*.toml` file in the loadouts
directory, one row per file:

```
  NAME   DESCRIPTION                     CONTRIBUTES
* dev    helix + zellij with my dotfiles 2 pkg / 4 var / 5 patch / 1 hook
  extra                                  1 pkg / 0 var / 0 patch / 0 hook

* default (from `[loadouts].default_loadouts`)
```

- Loadouts named in `default_loadouts` are marked with a leading `*`.
- Malformed entries are listed with their parse error so they can be fixed
  in place; a `default_loadouts` entry with no matching file produces a
  warning.
- `--dir <DIR>` overrides the loadouts directory.

## Composition, conflicts, and policy

At activation, the client composes the selected loadouts into a single
contribution and ships it to the daemon, where it is merged with the
project's contribution (the `[session]` block of the project's
`minimal.toml`, plus per-package contributions) into the session's final
configuration. Merge semantics across all contributors:

- **Packages** deduplicate: set semantics, there is no value to disagree
  on.
- **Vars** with the same name and the same resolved value deduplicate.
  The same name with *different* values is a hard conflict that fails the
  composition; there is no override precedence between loadouts and the
  project. The error's hint applies: add the name to your policy's
  `ignore` list to drop all contributors of that variable.
- **Patches** with the same destination and different sources are likewise
  a conflict.
- **Lifecycle hooks** concatenate and run in declaration order.

Two loadouts with the same name cannot be applied together.

Loadout contributions are gated by the user's policy
(`<config>/minimal/user_policy.toml`): items you declare yourself
automatically pass the `allow` check, but the policy's `deny` and `ignore`
rules still apply: a loadout patch matching a `deny` pattern fails the
composition on the client, before the daemon is involved. A missing policy
file means an empty policy; a fresh install activates fine without it.

## Vars in the attach shell

The interactive shell minted by [`min attach`](./cli-min.md#attach) is
`bash --noprofile -l`, a login shell that sources **no** startup files
(not `/etc/profile`, `~/.bash_profile`, or `~/.bashrc`), so rc-file
patches cannot influence it. Interactive setup travels through the
environment instead, i.e. through `[vars]`:

- **Prompt**: the session launcher seeds a baseline environment
  (currently a stock `PS1`) before merging in the composed vars, and a
  composed var overwrites a baseline entry with the same name. Setting
  `PS1` in `[vars]` therefore replaces the stock prompt. This baseline is
  a layer *beneath* composition, not a contributor: the no-override
  conflict rule above arbitrates between contributors and does not apply
  to the launcher's defaults.
- **Banner / MOTD**: bash evaluates `PROMPT_COMMAND` from the
  environment before the first interactive prompt, so a once-only banner
  can ship as a payload var plus a self-unsetting trigger:

  ```toml
  [vars]
  PROMPT_COMMAND = 'eval "$MINIMAL_MOTD"; unset PROMPT_COMMAND MINIMAL_MOTD'
  MINIMAL_MOTD   = '''
  [ -t 1 ] && printf '%s\n' '' '  Welcome to the dev session.' ''
  '''
  ```

  The trigger unsets both variables, so the banner prints exactly once
  and never runs for non-interactive commands; the `[ -t 1 ]` guard keeps
  redirected output clean. Multi-line literal values survive composition
  intact.
