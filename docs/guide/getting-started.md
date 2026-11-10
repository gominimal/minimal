---
description: "Install Minimal and run Claude Code in an isolated box, in six commands."
---

# Quickstart

Run a coding agent in an isolated box on your own machine. The agent sees your project and the tools you declare, and nothing else from your host.

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

`min init` detects your stack and writes a `minimal.toml`. It asks before it writes.

## 3. Add the agent

```shell
min add --session claude
```

The `claude` package is Claude Code plus the Minimal plugin for it.

## 4. Start a box

```shell
min session activate --attach .
```

Minimal fetches the packages, copies your project into a new box and opens a shell inside it.

## 5. Run the agent

```shell
claude
```

Type `exit` to leave the shell. The box keeps running.

## 6. Come back, or clean up

```shell
min ls                       # list your boxes
min session attach           # open a shell in this project's box again
min session destroy <name>   # remove a box
```

## Next

- [Give the agent credentials and more tools](./agents.md)
- [Bring your editor and dotfiles](../concepts/loadouts.md)
- [Glossary](../reference/glossary.md)
