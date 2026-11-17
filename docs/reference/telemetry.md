---
title: Telemetry
description: "The daily update check in min 0.7: what it sends, when, the notice it prints, how to see the request, where its state lives, and how to turn it off."
---

# Telemetry

On the 0.7 release line, the only thing `min` sends on its own is the daily
[update check](#update-check). It tells you when your channel has a newer
release, and it counts installs. It is **on** by default until 1.0, and any
one of the [switches](#turning-the-check-off) turns it off.

This release line has no other telemetry. `min`, `minimald` and `minvmd`
export no traces, logs or metrics and keep no telemetry spool. Setting
`MINIMAL_TELEMETRY` to `0`, `false`, `no` or `off` (any case) turns the update
check off; any other value, `1` included, changes nothing.

## Update check

Once a day, a `min` command makes one request to
`https://update.minimal.dev/v1/<channel>/<key>` and caches the answer. When
the channel has moved on, one line on stderr names the channel's current
release and points here for the update steps. It prints once per new
release, not every day:

```
min 0.7.5: the stable channel is now at 0.7.6. How to update: https://docs.minimal.dev/reference/telemetry#update-check
```

"Moved on" means only that the channel's pointer is no longer the release
you installed. `min` does not compare version numbers, so the line also
prints when the channel moves to a new minor release, such as 0.8.0.

The line goes to stderr only when stderr is a terminal, and it waits for a
short command whose output leaves it in view: `min ls`, `min stop`,
`min dirs`, `min init`, `min add`, `min update`, `min login`, `min loadout`,
`min net`, `min bug` or `min diag`. Other commands never print it, among
them those that take the terminal (bare `min`,
`min session attach`, `min task run`, `min dash`, `min proxy`), so if you
only use those, the line is not shown. `min version` and shell completion
never take part in the check.

stdout, the exit code and the command's timing are never touched. The
request is made by a detached `min update-check --background` with a
2 second budget and no retry, and the command that spawned it does not wait.
An endpoint that is down, slow, or answers 404 produces nothing.

### How to update

An install made by the installer updates by running the installer again for
your channel. It replaces the binaries in place and keeps your loadouts and
settings. It also restarts the Minimal daemon, which ends any active
sessions: when sessions are running, it lists them and asks on your terminal
first ([Upgrade](../guide/install.md#upgrade) has the details):

```shell
curl --proto "=https" --tlsv1.2 -fsSL https://go.minimal.dev/stable | sh
```

Use `unstable` or `nightly` in place of `stable` for those channels. An
install made with `--version` is pinned and gets no notice; run the
installer with the version you want. An install from a package manager
updates through that package manager. `min update` does not update `min`
itself: it re-pins the project's `[upstream]` in `minimal.toml`.

### What is sent

The request carries six fields, and a `User-Agent: min` header that is the
same for every install:

| field | value |
|---|---|
| channel | `stable`, `unstable` or `nightly`; `pinned` for an install made with `--version`; `source` for a binary that no install record describes (a development build, a package without an install record, or a copy of `min` other than the one the installer put in place). Only a channel install is ever notified |
| key | the channel pointer this build was installed from, written by the installer to `<state>/minimal/install.toml`; for a build without one, the commit hash in `min version`, or the version of a tagged release |
| os, arch | `linux`/`macos`, `x86_64`/`aarch64` |
| install | `installer`, or the package that shipped `<prefix>/share/minimal/install.toml` |
| id | a random UUID minted on the first run, stored in `<state>/minimal/update-check.json`; delete the file to rotate it |

The endpoint also sees the country and network (ASN) of the request, as any
web request shows, and does not store the address. The service source is
`workers/update-check/` in the gominimal/webapp repository.

### When it is sent

- At most once every 24 hours.
- Never by an install's first `min` command: that command only mints the
  install id. The request waits for a later command.
- With a terminal, the first short command (the rule above: `min ls`, not
  bare `min`) prints a one-line disclosure of what is sent and how to turn
  it off, and sends nothing that time. Until that line has been shown,
  commands with a terminal send nothing.
- Without a terminal (a script's or an agent's commands), the install is
  counted from its second command. The installer's closing card carries the
  same disclosure for every install, `--version` ones included, so such an
  install has read it there. An install from a package manager sees the
  terminal line instead of the card.
- Never by the installer's own `min` calls: they run before its closing card
  discloses the check.

### Seeing the request

`min update-check --dry-run` prints the exact request that would be made,
whether the check is on, and the switch that stops it if one is set. It
sends nothing:

```shell
min update-check --dry-run
```

`min update-check` with no flag makes the request now and prints the answer,
for example `the stable channel is at 0.7.6. You have 0.7.5.`

### Where its state lives

Everything the check keeps is in the state directory, `<state>/minimal`,
where `<state>` is `$XDG_STATE_HOME` when it is set to an absolute path, and
`~/.local/state` otherwise. `min dirs` prints it as the State dir.

| file | what it holds |
|---|---|
| `update-check.json` | the install id, when the last check ran, the last answer, and whether the disclosure and the notice for that answer were shown |
| `install.toml` | written by the installer: the channel, the method, the release it installed (the key) and the path of the `min` it describes |
| `update-check.lock` | present while a check is running; one left by a check that died is taken over after an hour |

Uninstalling with the installer's `--uninstall` removes `install.toml`;
`--purge` also removes the state directory, and with it the install id.

## Turning the check off

Any one of these turns it off:

| switch | where |
|---|---|
| `[telemetry]` `enabled = false` | `config.toml` in the config directory (`min dirs` prints its path), or `/etc/minimal/config.toml` for every user of the machine; either turns it off |
| `MINIMAL_TELEMETRY=0` | environment; `false`, `no` and `off`, in any case, also count. Any other value changes nothing |
| `DO_NOT_TRACK=1` | environment, the [Console Do Not Track](https://consoledonottrack.com/) convention: any non-empty value, `0` and `false` included |
| `CI` set | environment, any non-empty value: a CI job that installs `min` is not an install to count |
| `OTEL_SDK_DISABLED=true` | environment, `true` in any case; other values change nothing |
| `--minimal-dir` | for that command: an alternate state directory is not counted |

In `config.toml` the table is:

```toml
[telemetry]
enabled = false
```

On this release line nothing but the update check reads
`/etc/minimal/config.toml`, and only its `[telemetry]` table matters. The
file is still parsed whole, so a table this release does not know (one
written for a newer release) makes it unparseable here, which turns the
check off. A `config.toml` that exists but does not parse, yours or the
organization's, turns the check off until it is fixed, and so does a config
directory that cannot be found (no `HOME`, no `XDG_CONFIG_HOME`).

A `min` release from before the update check refuses a `config.toml` that
has a `[telemetry]` table. If you switch between such a release and this
one, turn the check off with `MINIMAL_TELEMETRY=0` or `DO_NOT_TRACK=1`
instead.

`min update-check --dry-run` names the switch that is in effect. With the
check off, no install id is minted, nothing is sent, and no line is printed.

At 1.0 the default flips to off.
