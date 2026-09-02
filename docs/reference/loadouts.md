---
title: Loadouts
description: "Per-developer loadout reference: the loadout TOML schema, config-directory layout, min CLI flags, client config, and how loadouts compose into sessions."
---

# Loadouts

A loadout is a per-developer bundle of packages, environment variables, file
patches, and lifecycle hooks that the [`min` session CLI](./cli-min.md) layers
into the sessions it activates. The project's
[`minimal.toml`](./minimal-dot-toml.md) describes what every contributor's
session needs; a loadout carries what *you* want on top (your editor,
terminal multiplexer, shell config, and dotfiles) so each development
environment comes up matching your muscle memory.

Loadouts apply to sessions (`min session activate`); they are not used by task
sandboxes, which have their own `packages`/`env_vars`/`patches` schema
described in [Tasks](./tasks.md).

## Where loadouts live

Each loadout is a single TOML file at:

```
<config>/minimal/loadouts/<name>.toml
```

`<config>` is the platform user config directory: `$XDG_CONFIG_HOME` on Linux
(or `$HOME/.config` when unset); macOS also uses `$HOME/.config` for
consistency with Minimal's state and cache dirs. The global
[`--config-dir`](./cli-min.md#global-flags) flag overrides the base, and
`min dirs` prints the resolved loadouts directory.

The filename stem **is** the loadout's identifier:

- Nothing inside the file names it, so renaming the file renames the
  loadout.
- Names are trimmed and must be non-empty, with no `/`, `\`, or NUL
  characters.
- A file that still carries the old `name` field loads anyway, with a
  warning that the field is no longer required. If the declared name
  disagrees with the filename, the warning says so and the filename wins;
  the declared name is discarded.

The directory is not created automatically; create it and drop
`<name>.toml` files there to get started.

## Example

A loadout that brings in the helix editor and zellij multiplexer, wired up
with the user's dotfiles:

```toml
description = "helix + zellij with my dotfiles"
packages    = ["helix", "zellij"]

patches = [
    # Helix: single config files plus a themes directory.
    { dest = ".config/helix/config.toml", source = "~/dotfiles/helix/config.toml" },
    { dest = ".config/helix/languages.toml", source = "~/dotfiles/helix/languages.toml" },
    { dest = ".config/helix/themes/", source = "~/dotfiles/helix/themes/**/*.toml" },

    # Zellij: single config file plus a layouts directory.
    { dest = ".config/zellij/config.kdl", source = "~/dotfiles/zellij/config.kdl" },
    { dest = ".config/zellij/layouts/", source = "~/dotfiles/zellij/layouts/**/*.kdl" },
]

[vars]
EDITOR    = "hx"
VISUAL    = "hx"

# Declared to warm helix's tree-sitter grammar cache when the session
# comes up. Best-effort; failures don't tank activation.
[[lifecycle_hooks]]
on_activate = { type = "inline", value = "hx --grammar fetch >/dev/null 2>&1 || true" }
```

Saved as `<config>/minimal/loadouts/dev.toml`, this is applied with
`min session activate --loadout dev`, or automatically via
[`default_loadouts`](#client-config).

## Loadout schema

### `name` - The loadout's identifier

_Not a field. Comes from the filename_

A loadout is identified by its filename stem — `dev.toml` is the loadout
`dev` — which is what selection and error messages show.

The field itself is obsolete. A file that still declares one loads with a
warning that it is no longer required, and the filename is used regardless:

```toml
# Delete this line; the file is already named `dev.toml`.
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
and fails later, when the session first spawns, with
`no such package: <name>`.

### `[vars]` - Environment variables

_Optional_

Variables set in the session environment. Names must be POSIX-shaped
(`[A-Z_][A-Z0-9_]*`); for other names, see
[`[[vars_lenient]]`](#vars_lenient). Each value takes one of three forms:

```toml
[vars]
EDITOR = "hx"                                # literal value
PAGER   = { inherit = true, default = "less" }  # inherit, with fallback
MUXER = { inherit = true }               # inherit from the host env
```

- A **literal** string sets the variable to that value.
- `{ inherit = true }` passes the variable through from the environment of
  the `min` process on the host. If the host does not have it set, the
  variable is dropped from the session (with a warning) rather than failing
  activation, so opportunistically inheriting things like `COLORTERM` is
  safe. `TERM` is not worth inheriting: the daemon sets it from the terminal
  you attach from and keeps it current, above anything a loadout composes —
  see [The attached terminal](#attached-terminal).
- `{ inherit = true, default = "..." }` inherits, falling back to `default`
  when the host does not have the variable set.

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

### `patches` - Files copied from the host into the session {#patches}

_Optional_

Each row names a `source` on the host and a `dest` inside the session,
with an optional `description`.

```toml
patches = [
    { dest = ".psqlrc", source = "~/dotfiles/psqlrc" },
    { dest = "certs/",    source = "~/ca/*.pem" },
    { dest = ".config/nvim/", source = "~/dotfiles/nvim/**/*.lua" },
]
```

**`source`** is a host path or glob pattern, or a list of them (a list
fans out into one independent patch per entry, each sharing the `dest` --
so list entries only make sense with per-entry dests or glob entries):

- A leading `~` expands to the host home directory. `$NAME` / `${NAME}`
  references (including `$HOME`) resolve against the session's
  already-resolved variables (declared in `[vars]`); referencing an
  undefined name is an error. `$$` is a literal `$`.
- `$LOADOUT_ROOT` expands to the loadout's own directory, for files you
  ship beside the loadout itself — see
  [`$LOADOUT_ROOT`](#loadout_root) below.
- After expansion the path must be absolute; anchor home-relative sources
  with `~/`.
- Glob patterns must have a literal directory prefix to walk from:
  `~/dotfiles/**/*.lua` is fine, a bare `**/*.pem` is rejected.
- `..` components are rejected wherever they appear.
- A source path that does not exist on the host is dropped with a warning
  at activation rather than failing it, so opportunistically patching a
  dotfile tree the host may not have is safe. Other enumeration failures
  (permission denied, unreadable entries) still fail the composition.

**`dest`** is interpreted relative to the session user's home directory.
Absolute paths and `..` components are rejected. For a literal (non-glob)
source, `dest` is used verbatim as the destination file path; for glob
sources, `dest` is the destination directory and each match's path under
the walk root is appended to it.

By default the walker does not follow symlinks while enumerating glob
matches; see [`follow_symlinks`](#follow_symlinks) and the
[client config](#client-config).

**Permissions** carry across. A patched file lands with the source file's
own permission bits, so a script stays executable and a `0600` key stays
readable only by you. Two qualifications:

- Preservation is exact, which cuts both ways: a read-only source (a
  `0444` file, or a dotfile symlinked into a read-only store) lands
  read-only, and editing it in the session takes a `chmod` first.
- `setuid`, `setgid`, and the sticky bit are dropped; the nine standard
  permission bits are what survives.

Ownership is not carried and cannot be: every file in the session belongs
to the session user, whatever it was owned by on your host.

#### `$LOADOUT_ROOT` - Files shipped with the loadout {#loadout_root}

Not every file a loadout patches in belongs in your dotfiles. For the ones
that exist only to serve this loadout, keep them beside it and name them
with `$LOADOUT_ROOT`, which expands to a directory named after the loadout
next to its `.toml` -- the same directory its
[external hook scripts](#lifecycle_hooks) resolve against:

```
<config>/minimal/loadouts/
├── dev.toml
└── dev/
    ├── config.toml
    └── themes/
        └── nord.toml
```

```toml
patches = [
    { dest = ".config/helix/config.toml", source = "$LOADOUT_ROOT/config.toml" },
    { dest = ".config/helix/themes/",     source = "$LOADOUT_ROOT/themes/**/*.toml" },
]
```

It resolves against the loadouts directory actually in use, so a
`--config-dir` or `$XDG_CONFIG_HOME` that moves your config takes the
loadout's files with it -- which a hard-coded `~/.config/minimal/loadouts/dev/`
would not.

Details worth knowing:

- The reference is **only** available in the `source` of a patch a loadout
  declared. In a [user policy](./user-policy.md) pattern, or in a patch a
  project declared, it fails the activation rather than resolving to some
  other declarer's directory. `dest` is a path inside the session, so it has
  no use for it either.
- The name is **reserved** here: a loadout that also declares a
  `LOADOUT_ROOT` variable still patches from its own directory. The variable
  reaches the session normally -- only patch sources ignore it.
- `$LOADOUT_ROOT` alone names a directory, and a patch source matches files,
  so it patches in nothing. Write `$LOADOUT_ROOT/**/*` to take the whole
  tree.
- The directory is optional. A loadout that never references it does not
  need one, and -- like any other source -- a path that isn't there is
  skipped with a warning rather than failing the activation.

### `[[lifecycle_hooks]]` - Scripts at session transition points {#lifecycle_hooks}

_Optional_

Each hook groups up to four scripts — `on_activate` when the session is
created, `on_destroy` when it is destroyed, `on_attach` when you connect,
and `on_detach` when you disconnect — and at least one must be present. An
optional `description` labels the hook. Scripts are either inline or a path
to a file:

```toml
[[lifecycle_hooks]]
description = "warm caches"
on_activate = { type = "inline",   value = "cargo fetch || true" }
on_detach   = { type = "external", value = "./cleanup.sh", timeout = 120 }
```

Each script may set a `timeout` in whole seconds, defaulting to 60 and
capped at 300; a script that exceeds the cap is rejected when the file is
parsed.

Scripts run under POSIX `sh` unless they open with a shebang, in which case
they run under what it names — so a hook can be written in whatever you
already think in:

```toml
[[lifecycle_hooks]]
on_activate = { type = "inline", value = "#!/usr/bin/env fish\nset -gx ...\n" }
on_detach   = { type = "external", value = "./teardown.py" }   # #!/usr/bin/env python3
```

The interpreter must be present *in the session*, and it is handed the
script on standard input rather than as a file. That covers every shell and
scripting language in common use; it does not cover one that insists on a
file argument (`awk -f`). The shebang is parsed the way the kernel parses
one — the interpreter is the first word, everything after it is a single
argument (so `#!/usr/bin/env -S python3 -u` works, `-S` and all), and there
is no quoting, so an interpreter path cannot contain spaces. Give an
absolute path or a bare command for `env` to find: a relative path would
resolve against the daemon, not the session. Default to POSIX `sh` where you
can — it is the one interpreter a session is guaranteed to have.

External script paths must be relative (absolute paths and `..` components
are rejected at parse time). A loadout's scripts are anchored at a directory
beside the loadout file, named after the loadout — so `dev.toml`'s scripts
live in `dev/`:

```
<config>/minimal/loadouts/
├── dev.toml
└── dev/
    ├── activate.sh
    └── teardown.sh
```

This is the same directory [`$LOADOUT_ROOT`](#loadout_root) names, so a
loadout's scripts and the files it patches in live together.

A script must resolve to a regular file inside that directory. Symlinks are
rejected rather than followed, at every path component — a symlink is the one
way a path that passes every other check could still reach outside the
anchor. All of this is checked on your machine before a session is created,
so a mistyped path fails immediately and names the file.

Hooks from multiple contributors concatenate in declaration order, and run in
that order for the setup transitions (`on_activate`, `on_attach`) and in
reverse for the teardown ones (`on_destroy`, `on_detach`) — so a project sets
up before your loadouts and tears down after them.

They execute inside the running session, sharing its packages, variables,
files, and network. `on_attach` runs on the terminal you are attached to, so
its output reaches you and `[ -t 1 ]` is true. The other three have no
terminal and their output is captured into the daemon log — `on_detach`
included, because the shell it would have run on is often the very thing
that just went away (leaving a session by exiting its shell is a detach).

On top of the session's own variables, each hook is given a few describing
the run it is part of:

| Variable | Value |
|---|---|
| `MINIMAL_SESSION_ID` | The session's id. |
| `MINIMAL_SESSION_NAME` | Its display name. |
| `MINIMAL_HOOK_EVENT` | The transition: `on_activate`, `on_destroy`, `on_attach`, or `on_detach`. |
| `MINIMAL_HOOK_SOURCE_KIND` | `loadout` or `project` — for branching. |
| `MINIMAL_HOOK_SOURCE_NAME` | The loadout's name, or the project's path as you refer to it on your own machine (not the daemon's copy of the tree). |
| `MINIMAL_HOOK_INDEX` / `MINIMAL_HOOK_COUNT` | Position within this transition's run, 1-based — for logging, e.g. `[2/3]`. |

Each teardown transition runs all of its hooks under a **single shared time
budget** rather than giving each one its own timeout — `on_detach` and
`on_destroy` get a budget each, not one between them. A session has to stay
destroyable, and per-script caps alone would let enough hooks add up to hold
one open. A hook that runs into the end of the budget is cut short and says
so, and one the budget leaves no room for at all is reported as not run —
either way the log distinguishes it from a hook that exhausted its own
`timeout`, and teardown continues.

A failing `on_activate` **fails the activation** — the session does not become
attachable, and the error names the hook and what it printed. The other three
never block their transition: a failing attach, detach, or destroy hook is
logged and the session carries on. A session must always be attachable and
always destroyable.

`on_failure` was an earlier spelling that never executed; it has been
removed. A hook file that still declares it is rejected with an error
pointing at `on_destroy`.

### `follow_symlinks` - Symlink handling for patch sources {#follow_symlinks}

_Optional_

Overrides the client-wide `[loadouts].follow_symlinks` setting (see
[client config](#client-config)) for this loadout's patches only. When
unset, the client-wide setting applies.

```toml
follow_symlinks = true
```

## Selecting loadouts at activation

[`min session activate`](./cli-min.md#session-activate) decides which loadouts to apply
from two flags:

| Flag | Description |
|------|-------------|
| `--loadout <NAME>` | Apply `<config>/minimal/loadouts/<NAME>.toml`. Repeatable. If given, the config file's `default_loadouts` are ignored |
| `--no-loadouts` | Apply no loadouts at all. Conflicts with `--loadout` |

Resolution order:

1. `--no-loadouts`: nothing is applied, regardless of configuration.
2. One or more `--loadout NAME`: exactly the named loadouts are applied.
3. Neither flag: the `[loadouts].default_loadouts` list from the
   [client config](#client-config) is applied.
4. Neither flag and an empty `default_loadouts`: the
   [built-in `default` loadout](#built-in-default-loadout) is applied,
   unless a user `default.toml` shadows it.

Loadouts are resolved and composed **before** the CLI contacts the daemon:
a missing or malformed loadout file fails the activation loudly on the
client rather than producing a silently-empty session. When loadouts are
applied, the CLI prints `Applying loadouts: <names>` to stderr.

Activation is also when loadout contents are captured: the files are read
once, inherited vars are resolved against the host environment, and the
composed result is what the session runs with. Editing a loadout file
does not change sessions that already exist; destroy and re-activate to
pick up the edit.

## Built-in default loadout {#built-in-default-loadout}

When a session is activated with no loadout flags and an empty
`default_loadouts`, a built-in `default` loadout applies so a fresh box
comes up oriented rather than in a bare shell. It contributes **no
packages** — only a shaped `PS1` and a once-only banner (the minimal
mark, the [orientation lines](#orientation-banner) naming the session
and its loadouts, plus a pointer to `min add`), shipped through the
[MOTD recipe](#vars-in-the-attach-shell). The banner is TTY-gated, prints
exactly once per session, and renders without color.

It is the lowest-precedence source: `--no-loadouts`, `--loadout`, and a
non-empty `default_loadouts` all take priority, and a user
`default.toml` in the loadouts directory shadows it entirely (the file
is applied in its place). `min loadout list` shows it as a
`default (built-in)` row unless that user file is present.

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

### Session keys {#session-keys}

The detach chord is configurable. The leader key (the chord that enters
command mode) and its command-mode subcommand keys live under a
`[session-keys]` section in the same `config.toml`.

`[session-keys]` is client configuration, not a loadout: unlike everything a
loadout composes, it is never baked into the session on activation. It is
read fresh on every attach and negotiated per SSH channel, so each client —
and each machine attaching to a session it didn't create — brings its own
chord. The section is documented here only because that is where
`config.toml` is described.

```toml
[session-keys]
leader = "ctrl-]"
bell_on_leader = false

[session-keys.subcommands]
detach = "d"
forward = "ctrl-]"
```

| Key | Default | Description |
|-----|---------|-------------|
| `leader` | `ctrl-]` | The chord that enters command mode, as a logical key name (`"ctrl-]"`, `"ctrl-^"`, `"d"`, …). Rejected loudly at load if termios-special (`ctrl-c`, `ctrl-w`, `ctrl-\`, … — consumed by the line discipline before the app) or wrapping-ambiguous (`ctrl-i` = TAB, `ctrl-m` = CR, …) |
| `bell_on_leader` | `false` | Ring the terminal bell (BEL `0x07`) on entering command mode. The terminal renders it per its own bell config; minimal picks no modality |
| `subcommands.detach` | `d` | The command-mode key that detaches the channel |
| `subcommands.forward` | `ctrl-]` | The command-mode key that verbatim-forwards a leader byte down the PTY (for nested sessions). Defaults to the resolved `leader`, so a double-press forwards |

Key names take one of two forms: `ctrl-<glyph>`, where the glyph is a single
ASCII character in `@`..`~` (so `ctrl-2` and `ctrl-?` are rejected), or a
single printable ASCII glyph such as `d`. Only `ctrl-` is configurable;
`alt-`, `shift-`, `meta-`, and `super-` are rejected. The `ctrl-` prefix is
case-insensitive and `ctrl-` letters normalise to lowercase, since `Ctrl+a`
and `Ctrl+A` send the same control code. Plain glyphs are case-sensitive.

The leader is negotiated with the daemon per attach channel — sent as env
vars alongside `MINIMAL_SESSION_ID` — so two clients with different configs on
the same session each get their own chord. The daemon re-validates the leader
as a silent backstop: a chord it rejects is logged and only that field falls
back to the default — your valid `detach`/`forward` remaps survive — never
garbling the screen. As with `[loadouts]`, every field
defaults and unknown keys are rejected, so an old config keeps parsing.

Two caveats on that per-channel model:

- **The banner's detach hint is mint-scoped.** The orientation banner prints
  `MINIMAL_DETACH_HINT`, seeded from the channel that minted the shell. A
  second client attaching with a remapped chord gets a *working* chord, but
  the banner still advertises the minting channel's; trust your config over
  the banner in that case.
- **Bindings must not shadow each other.** A `detach` that equals the
  `leader` or the `forward` key makes that other binding unreachable and is
  rejected at load; the daemon's backstop reverts just the detach field.

## Listing loadouts

[`min loadout list`](./cli-min.md#loadout-list-alias-ls) (alias:
`min loadout ls`) enumerates every `*.toml` file in the loadouts
directory, one row per file:

```
  NAME                DESCRIPTION                           CONTRIBUTES
* dev                 helix + zellij with my dotfiles       2 pkg / 4 var / 5 patch
  extra                                                     1 pkg / 0 var / 0 patch
  default (built-in)  orientation banner and shaped prompt  0 pkg / 3 var / 0 patch

  default (built-in) applied when no loadouts are configured

* default (from `[loadouts].default_loadouts`)
```

The two trailing lines are the legend `min loadout list` prints below the
table: the first appears only when the built-in `default` is shown, the
second only when `default_loadouts` is non-empty.

- Loadouts named in `default_loadouts` are marked with a leading `*`.
- The [built-in `default` loadout](#built-in-default-loadout) is listed as a
  `default (built-in)` row unless a user `default.toml` shadows it.
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
- **Lifecycle hooks** concatenate in declaration order; setup transitions
  run in that order and teardown transitions in reverse.

Two loadouts with the same name cannot be applied together.

Loadout contributions are gated by the user's policy
(`<config>/minimal/user_policy.toml`): items you declare yourself
automatically pass the `allow` check, but the policy's `deny` and `ignore`
rules still apply: a loadout patch matching a `deny` pattern fails the
composition on the client, before the daemon is involved. A missing policy
file means an empty policy; a fresh install activates fine without it.

## Vars in the attach shell

The interactive shell minted by [`min session attach`](./cli-min.md#session-attach)
is bash unless a loadout says otherwise — see
[`SHELL`](#session-shell) below. bash is started as
`bash --noprofile --rcfile <daemon rc> -i`: it sources **none** of your
startup files (not `/etc/profile`, `~/.bash_profile`, or `~/.bashrc`), so
rc-file patches cannot influence it — the only rc it reads is the daemon's
own, which installs the [attached terminal](#attached-terminal) hook and
nothing else. Interactive setup travels through the environment instead,
i.e. through `[vars]`:

- **Prompt**: the session launcher seeds a baseline environment
  (a stock `PS1`, plus the [orientation banner](#orientation-banner)
  vars below) before merging in the composed vars, and a composed var
  overwrites a baseline entry with the same name. Setting `PS1` in
  `[vars]` therefore replaces the stock prompt. This baseline is
  a layer *beneath* composition, not a contributor: the no-override
  conflict rule above arbitrates between contributors and does not apply
  to the launcher's defaults.
- **Banner / MOTD**: bash evaluates `PROMPT_COMMAND` from the
  environment before the first interactive prompt, so a once-only banner
  can ship as a payload var plus a trigger that clears its own payload:

  ```toml
  [vars]
  PROMPT_COMMAND = 'if [ -n "${MINIMAL_MOTD:-}" ]; then eval "$MINIMAL_MOTD"; unset MINIMAL_MOTD; fi; if [ -r "${MINIMAL_ATTACH_ENV:-}" ]; then . "$MINIMAL_ATTACH_ENV"; fi'
  MINIMAL_MOTD   = '''
  [ -t 1 ] && printf '%s\n' '' '  Welcome to the dev session.' ''
  '''
  ```

  The trigger clears `MINIMAL_MOTD`, so the banner prints exactly once
  and never runs for non-interactive commands; the `[ -t 1 ]` guard keeps
  redirected output clean. Multi-line literal values survive composition
  intact.

  Replacing `PROMPT_COMMAND` costs you nothing but the banner: the
  [attached terminal's](#attached-terminal) `TERM` is refreshed by a hook
  the daemon installs, not by this variable.

### `SHELL` - Which shell an attach starts {#session-shell}

Set `SHELL` in `[vars]` to be dropped into that shell instead of bash:

```toml
packages = ["fish"]

[vars]
SHELL = "/usr/bin/fish"
```

Only the file name is read, so a value carried over from your host
(`/opt/homebrew/bin/fish`, a Nix store path) still works — the path
itself names a filesystem the session does not have. Five shells are
supported, each because the session can install it *and* the daemon ships
it an [attached terminal](#attached-terminal) hook:

| `SHELL` | Package to install |
|---|---|
| `bash` | `bash` (always present) |
| `sh` | `bash` — it ships `sh` as a POSIX-mode symlink, so this needs nothing |
| `zsh` | `zsh` |
| `fish` | `fish` |
| `nu` | `nushell` |

Anything else starts bash and prints one line saying why. A shell from
that table which the session hasn't installed is named along with the
package that would supply it; a `SHELL` naming anything else is told
which five shells there are to choose from. Nothing fails either way.

This is the loadout's `SHELL`, not the `$SHELL` of the terminal you ran
`min` from: a session is a declared environment, and the shell it hands
you is part of the declaration.

Three things worth knowing:

- **bash is unchanged**, rc suppression included. Every other shell reads
  its own startup files from the session home — which is where
  [patches](#patches) land, so a patched-in `config.fish` or `.zshrc`
  applies. That asymmetry is deliberate: bash's behaviour predates this
  and stays as it was.
- **The shell is chosen once**, at the attach that mints the session
  shell, and that shell outlives later attaches. Changing `SHELL`
  afterwards takes a new session.
- **The stock prompt follows where it can.** The session default `PS1`
  is written in bash's syntax, so zsh is given the same prompt in zsh's
  syntax instead of printing `\u@\h` at you; fish and nushell build
  their prompts from their own config and ignore `PS1` entirely. A `PS1`
  you set in `[vars]` always wins, in whatever syntax you wrote it.
- **The banner does not follow.** The orientation banner rides
  `PROMPT_COMMAND`, which is bash's; a fish or nushell session simply
  doesn't print it. `TERM` refresh *does* work in all five — that is what
  the daemon's hooks are for.

### The attached terminal {#attached-terminal}

A session shell is spawned once and outlives the terminals that attach to
it, so `TERM` — a fact about *the terminal currently attached* — cannot
live in its environment alone. The shell may have been minted for a
different terminal, or for no terminal at all: a lifecycle hook or an exec
brings the sandbox up the same way an attach does.

**Nothing is required of a loadout or a project for this to work.** The
daemon publishes the current terminal's facts on every attach, and installs
the hook that re-reads them into every session rootfs, for every shell it
supports. This is deliberately not carried by a `[vars]` entry: an
environment variable is composed, so a loadout could replace it — and the
MOTD recipe above unsets `PROMPT_COMMAND` outright — which would leave the
session's `TERM` depending on whether an author knew to preserve it.

The published files, rewritten on each attach (edits to them are lost):

| Var | File | Read by |
|---|---|---|
| `MINIMAL_ATTACH_ENV` | `~/.local/state/minimal/attach-env.sh` | bash, zsh — POSIX `export TERM='…'` |
| `MINIMAL_ATTACH_ENV_FISH` | `~/.local/state/minimal/attach-env.fish` | fish — `set -gx TERM '…'` |
| `MINIMAL_ATTACH_ENV_JSON` | `~/.local/state/minimal/attach-env.json` | nushell — data, not a script |

`ENV` is also set, to a daemon-owned file that sources the POSIX form at
shell startup — see [Other POSIX shells](#attached-terminal-posix).

The variables are there for anything you want to script against. The hooks
themselves do not read them: each hard-codes the path, so a composition
that happens to set a variable of that name cannot redirect the refresh.

The hooks live at each shell's own vendor/system integration point, inside
the rootfs rather than the session home — so a loadout patch cannot collide
with one:

| Shell | Hook location | At the prompt | Before a command |
|---|---|---|---|
| bash | the rc the session shell is started with (`--rcfile`) | — | `DEBUG` trap |
| zsh | `/etc/zsh/zshrc` | `precmd` | `preexec` |
| fish | `/usr/share/fish/vendor_conf.d/` | `fish_prompt` event | `fish_preexec` event |
| nushell | `/usr/share/nushell/vendor/autoload/` | `pre_prompt` | `pre_execution` |

Two hooks, because they answer different questions. The prompt one keeps a
shell that is sitting idle current. The pre-execution one matters when you
re-attach: the prompt on your screen was drawn *before* you detached, and
it has already fired its prompt hook — so without a hook that runs before
the command, the first thing you type at that restored prompt would still
see the terminal you had last time, and only the *next* prompt would catch
up. bash's `DEBUG` trap covers both cases on its own.

bash uses a trap rather than `PROMPT_COMMAND` for the same reason the
mechanism is not a var at all: `PROMPT_COMMAND` is composed, and the MOTD
recipe unsets it. A trap is shell state, which nothing in a composition can
reach.

#### Other POSIX shells {#attached-terminal-posix}

A plain `sh`, dash, the BusyBox or BSD ashes, ksh and mksh get a weaker
guarantee, and the limit is POSIX's rather than ours. The one hook POSIX
defines is `$ENV`: an interactive shell expands it and sources that file at
**startup**. The daemon points `ENV` at a file of its own
(`/usr/share/minimal/attach-env-posix.sh`) which sources the published
POSIX form, so any such shell starts with the terminal that is current at
that moment — including one started from a parent whose own value was
stale.

What these shells cannot do is *refresh*. POSIX has no per-prompt or
per-command hook, and none can be built: `PS1` expansion cannot change the
shell's own environment, because a command substitution runs in a subshell
and `${var:=word}` assigns only when the variable is unset. So a `sh` you
left running across a re-attach keeps the terminal it started with. Two
ways out, either of which is a one-liner:

```sh
. "$MINIMAL_ATTACH_ENV"   # re-sync this shell
exec sh                   # or just start a new one
```

ksh93 is the exception in this family — its `PS1.get` discipline function
is a genuine per-prompt hook — but the daemon does not install one, so ksh93
behaves like the rest here.

Anything the daemon itself runs inside the session — an exec, a lifecycle
hook — gets the current terminal's facts applied directly, above the
composed vars, without any of this.

### Orientation banner {#orientation-banner}

Unless a loadout overrides it, the first interactive prompt of an
attached session prints a two-line orientation banner:

```
minimal · session api-server-4f2a · loadout default (built-in)
detach: ctrl-] then d · no minimal.toml here — min init to add one
```

The second line drops the `min init` pointer when the session workspace
carries a `minimal.toml` (either layout, `minimal.toml` or
`.minimal/minimal.toml`) — the template tests the workspace root
(`/workbench`) in-shell at the moment it prints, so the clause reflects
the session's actual filesystem: it stays correct when an activation
skipped the file upload, and disappears after an in-session `min init`
once a fresh shell launches. The banner is TTY-gated, prints exactly
once, and is plain text (`NO_COLOR`-safe).

It ships as a *static template* in the launcher baseline (the MOTD
recipe above), interpolated by the shell at print time from two env
vars every session carries:

| Var | Value |
|-----|-------|
| `MINIMAL_SESSION_NAME` | The session's name |
| `MINIMAL_LOADOUTS` | Display list of the active loadouts: comma-joined names, `default (built-in)` for the zero-config fallback, `none` with `--no-loadouts` |

Both are seeded daemon-side in the launcher baseline; the loadout list
travels from the client as a first-class field on the composition
(control-plane data, never a session var), so user vars and user policy
cannot collide with either.

Because the trigger lives in the baseline layer, a loadout that sets its
own `PROMPT_COMMAND` replaces the banner cleanly — and can interpolate
the same `$MINIMAL_*` vars in its own MOTD, as the built-in `default`
loadout does for its orientation lines. It carries no obligation beyond
the banner — the [attached terminal's](#attached-terminal) `TERM` is kept
current by a daemon-installed shell hook that no composition can reach.
