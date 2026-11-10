---
description: "Install Minimal and run Claude Code in an isolated box, in six commands."
---

# Quickstart

Run a coding agent in an isolated [box](../reference/glossary.md#box) on your own machine. The agent sees your project and the tools you declare, and nothing else from your host.

## 1. Install

```shell
curl --proto "=https" --tlsv1.2 -fsSL 'https://go.minimal.dev/stable' | sh
```

This puts `min` on your `PATH`. Minimal runs on macOS (Apple Silicon) and on Ubuntu or Debian Linux.

## 2. Set up your project

```shell
cd my-project
min init
```

`min init` detects your [stack](../reference/glossary.md#stack) and writes a [`minimal.toml`](../reference/glossary.md#minimaltoml). It asks before it writes.

## 3. Add the agent

```shell
min add --session claude
```

This adds the `claude` [package](../reference/glossary.md#package) to the project's sessions. It holds Claude Code and its Minimal plugin.

## 4. Start a box

```shell
min session start
```

Minimal creates a box of the [`session`](../reference/glossary.md#session) type from your project and attaches your terminal to its shell. The packages from step 3 are on its `PATH`.

## 5. Run the agent

```shell
claude
```

Type `exit` to leave the shell.

## 6. Come back, or clean up

```shell
min box list            # list this project's boxes and their state
min box attach          # attach to this project's box again
min box rm <box>        # remove a box (add --force if it is running)
```

## Next

- [Give the agent credentials and more tools](./agents.md)
- [Bring your editor and dotfiles](../concepts/loadouts.md)
- [Glossary](../reference/glossary.md)
