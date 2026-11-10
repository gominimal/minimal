---
title: Glossary
description: "The words these docs use, one line each. Every page uses these words and no others for the same thing."
---

# Glossary

| Word | Meaning |
|------|---------|
| **box** | An isolated place where you and your agent work on one project. It has only the tools your `minimal.toml` and your loadouts declare. You manage boxes with the `min session` commands. |
| **sandbox** | The operating-system isolation that a box runs in. On macOS, and on Linux with `--provider local-minvmd`, that is a microVM. Otherwise it is a Linux user namespace. |
| **`minimal.toml`** | The file at the root of your repository that declares the project's packages, stack and tasks. Commit it. |
| **package** | A tool that Minimal builds or fetches by content hash, such as `git` or `claude`. Packages come from the upstream. |
| **upstream** | The package registry a project reads from, pinned to one commit by `[upstream]` in `minimal.toml`. |
| **stack** | How a project builds, such as `rust` or `pnpm`, set by `[stack]` in `minimal.toml`. |
| **task** | A command declared in `minimal.toml` that runs once in its own sandbox and exits, such as a build or a test run. |
| **loadout** | Your own tools and dotfiles, kept outside the project, which Minimal adds to every box you create. |
| **provider** | The daemon that hosts your boxes: `local-minimald` or `local-minvmd`. |
