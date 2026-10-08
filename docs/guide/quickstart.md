---
description: "Quickstart: go from a fresh install to a coding agent working in a sandboxed session on your repository in about three minutes."
---

# Quickstart

This page goes from nothing installed to a coding agent working in an isolated
session on your repository. You need a git repository and one of the
[supported platforms](./install.md): macOS on Apple Silicon, or Linux on
x86_64 or aarch64. You do not need an account or a token.

## 1. Install

```shell
curl --proto "=https" --tlsv1.2 -fsSL https://go.minimal.dev/stable | sh
```

The installer puts `min` on your `PATH` and sets up shell completions. Open a
new shell, then check that it worked:

```shell
min --version
```

On Ubuntu 24.04 and later, unprivileged user namespaces are off by default.
If your first session fails to start there, follow the
[Linux host setup guide](../reference/linux-host-setup.md).

## 2. Describe the session

From the root of your repository, generate a `minimal.toml`:

```shell
cd ~/projects/my-app
min init
```

`min init` detects your stack and proposes a config. It asks before it writes
anything. Then add the tools you want inside the session. This adds git and
Claude Code:

```shell
min add --session git claude-code
```

Every package name resolves against the
[Minimal Public Registry](https://github.com/gominimal/pkgs). Commit
`minimal.toml` so teammates and agents get the same session you do.

## 3. Enter the session

```shell
min session activate --attach
```

Minimal fetches the declared packages and copies your project into a fresh
sandbox. Then it opens a shell inside that sandbox. The first activation
downloads packages and can take a few minutes. Later activations are faster.
On macOS the sandbox is a lightweight Linux microVM. On Linux it is a user
namespace.

Inside, your project files and the declared tools are all there is. Nothing
you do changes the host checkout.

## 4. Run an agent

```shell
claude
```

The agent sees only the project copy and the tools you declared. It has no
SSH keys, no cloud credentials, and no access to the rest of your home
directory. If it needs another tool, it can run `min add <package>` from
inside the session.

To give a session a credential on purpose, see
[Passing through host credentials](./agents.md#passing-through-host-credentials).

## 5. Bring the work back

Commit inside the session, then type `exit` to detach. The session keeps
running. From your host checkout, pull the commits out over the `min://` git
remote:

```shell
git pull min://<session> <branch>
```

`min ls` prints the session's name.

## Manage sessions

```shell
min ls                        # list sessions
min session attach            # reattach to this directory's session
min dash                      # browse every session in a terminal UI
min session destroy <session> # end a session
```

## Next steps

- [Set up a project](./setup.md): what each table in `minimal.toml` does.
- [Dev shell](./dev-shell.md): host file patches, environment variables, and
  hooks that run when a session starts.
- [Agent shell](./agents.md): running agents with scoped credentials.
- [Loadouts](../concepts/loadouts.md): bring your editor and dotfiles into
  every session without changing the project config.
- [`min` CLI reference](../reference/cli-min.md): every command and flag.
