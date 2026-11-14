---
title: Glossary
description: "The words Minimal uses for its parts. Every page uses these words, and no others, for the same thing."
---

# Glossary

These terms come from Minimal's design of record. Each one names one thing. Other pages link here instead of defining a term again.

## Boxes

### Box

A box is an isolated Linux runtime that holds the packages its spec declares. Each box has one Box Type. On macOS, and under `--provider local-minvmd` on Linux, the box runs inside a microVM. You manage boxes with the `min box` commands. `min session start` creates a box of the `session` type.

### Box Type

A Box Type sets defaults and limits for a box. A type can narrow what a box can do. It never grants more. Minimal includes the `session` and `task` types.

### session

The `session` Box Type is for long-lived boxes with an interactive shell that you can attach to again. A session box runs until its shell exits or you stop it. Your loadouts apply to it.

### task

The `task` Box Type is for boxes that run one command to completion and exit. The command's input, output and exit code pass through, so `min task run` works in scripts and pipelines.

### exec

An exec is a command that you run inside a box that is already running, with `min box exec`. It runs inside that box's isolation.

### Box Spec

A Box Spec describes one box in full, including its type, packages, files and network access. Minimal builds it from `minimal.toml`, the Box Type, your loadouts and the flags you pass. `min box spec` prints it.

### network mode

The network mode decides how a box reaches the network. `none` gives it no network. `host_ip` shares the host's network. `own_ip` gives the box its own address, with egress closed unless you allow it.

## Configuration

### `minimal.toml`

`minimal.toml` sits at your project root and lists the boxes the project uses, with shared defaults. Commit it so every developer and agent gets the same boxes.

### entry

An entry is a table in `minimal.toml`, such as `[tasks.test]`, that becomes one Box Spec. You run an entry by its name.

### loadout

A loadout holds your own packages, config files and hooks. It lives in `~/.config/minimal/loadouts/`, outside the project. A loadout personalizes your boxes without changing the project's `minimal.toml`.

### stack

A stack is the tool set for a language, such as `rust` or `pnpm`. `[stack]` in `minimal.toml` selects it.

## Packages and supply chain

### package

A package is software that Minimal builds from a Package Build Spec, or fetches by its content hash.

### Package Build Spec

A Package Build Spec says how to build one package. It lists the sources and their hashes, the build tools and the runtime dependencies.

### Minimal Registry

A Minimal Registry is a git repository of Package Build Specs and stacks. `[upstream]` in `minimal.toml` pins one commit of it, which pins every package version. The Minimal Public Registry is [gominimal/pkgs](https://github.com/gominimal/pkgs).

## Hosts

### Box Host

A Box Host is a running `minimald` that creates and runs boxes.

### Box Provider

A Box Provider gives `min` a Box Host. With `local`, `minimald` runs on your Linux machine. With `local-minvmd`, `minimald` runs inside a microVM. macOS uses `local-minvmd` only.
