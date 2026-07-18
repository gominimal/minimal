<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/public/minimal-mark-light.svg">
    <img src="docs/public/minimal-mark-dark.svg" alt="Minimal logo" width="120">
  </picture>
</p>

# Minimal

[![CI](https://github.com/gominimal/minimal/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/gominimal/minimal/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Minimal provides VM-based development sandboxes and a secure package manager for the dev tools used inside them.

New here? Welcome! [Installation](#installation) and [Getting Started](#getting-started) will have you working in a sandbox in a few minutes, and we'd love to hear how it goes — questions and ideas are always welcome in [Discussions](https://github.com/gominimal/minimal/discussions).

## Contents

- [Features](#features)
- [Supported Platforms](#supported-platforms)
- [Installation](#installation)
- [Getting Started](#getting-started)
  - [Create a new project with Minimal](#create-a-new-project-with-minimal)
  - [Work on an existing project in a Minimal sandbox](#work-on-an-existing-project-in-a-minimal-sandbox)
  - [Add a Minimal Loadout with your preferred tools and configurations](#add-a-minimal-loadout-with-your-preferred-tools-and-configurations)
- [Tech Stack](#tech-stack)
- [Documentation](#documentation)
- [Building and Testing](#building-and-testing)
- [Contributing](#contributing)
  - [Contributor License Agreement](#contributor-license-agreement)
- [Code of Conduct](#code-of-conduct)
- [Security](#security)
- [License](#license)

## Features

Minimal repeatably creates Linux, terminal-based development sandboxes populated with exactly the toolsets and agents you need, as specified in your `minimal.toml` blueprint.

The tool executables (compilers, agents, shells, etc.) available in these sandboxes come from Minimal's [curated package registry](https://github.com/gominimal/pkgs/), which is refreshed daily. Simply add a `minimal.toml` to your project's git repo and all your teammates will have identical development environments that isolate AI agents from their laptops. Updating the shared `minimal.toml` to reference the freshest tool versions is just a `min update` away. No more outdated wiki pages for dev-env setup, and no more version drift across your team.

Per-developer [Loadouts](#add-a-minimal-loadout-with-your-preferred-tools-and-configurations) can be included in each development environment, so everyone can work efficiently using the editors, terminal multiplexers, and configs that match their hard-earned muscle memory.

## Supported Platforms

Minimal works on:

- macOS on ARM64 (Apple Silicon)
- Ubuntu and Debian Linux on ARM64 and x86_64, with a Linux kernel >= 5.10. Rootless user-namespace creation must be enabled for non-VM usage.

Not on one of these platforms yet? Tell us what you'd like to see supported in [Discussions](https://github.com/gominimal/minimal/discussions) — it helps us prioritize.

## Installation

To get started, install Minimal with the following shell command (a stable channel is coming soon):

```shell
curl --proto "=https" --tlsv1.2 -fsSL 'https://go.minimal.dev/unstable' | sh
```

This installs Minimal on your system, adds `min` to your PATH, and sets up shell completions for bash, fish, and zsh.

Minimal can be uninstalled with:

```shell
curl --proto "=https" --tlsv1.2 -fsSL 'https://go.minimal.dev/unstable' | sh -s -- --uninstall
```

## Getting Started

The examples below walk through the two most common workflows: starting a brand-new project inside a sandbox, and joining an existing project that already has a `minimal.toml`.

### Create a new project with Minimal

In this example we'll create a new git repo from within a Minimal sandbox, using tools from the [Minimal Public Registry](https://github.com/gominimal/pkgs/). It assumes Claude Code has been granted access to your GitHub repos (via the Claude GitHub App) so it can push changes on your behalf.

```shell
mkdir -p ~/projects/foo
cd ~/projects/foo

# create and update a minimal.toml file
min init
min add --session git gh claude-code

# start and enter a sandbox, which copies up the CWD file tree into the sandbox
min activate --attach .

git init

# develop specs, generate & test code, push to git, etc.
# agents can add tools from the Minimal Public Registry dynamically with "min add"
claude

exit
```

Prefer not to install the Claude GitHub App? The next example uses a fine-grained GitHub personal access token (PAT) stored in the macOS keychain instead. To create a fine-grained PAT (e.g. scoped to a specific repo), go to <https://github.com/settings/personal-access-tokens>.

Once you have created the PAT, copied it into your keychain (e.g. `security add-generic-password -s "PAT-foo-repo" -a "my-mac-user-name" -w`), and created the new, empty GitHub repo, the following shows how to populate that repo from within a sandbox:

```shell
mkdir -p ~/projects/foo
cd ~/projects/foo

# create and update a minimal.toml file
min init
min add --session git gh claude-code mermaid-cli kittyview less emacs

# copy the GitHub PAT to your clipboard from your macOS keychain
security find-generic-password -w -s "PAT-foo-repo" -a "my-mac-user-name" | pbcopy

# start and enter a sandbox, which copies up the CWD file tree into the sandbox
min activate --attach .

read -sp "paste GH PAT now:" GH_TOKEN && export GH_TOKEN

git init

claude --dangerously-skip-permissions
# develop specs, generate code, etc.

git add -A
git commit -m "initial checkin"

git remote add origin https://github.com/<your-owner>/<your-repo>.git
git branch -M main
git push -u origin main

exit
```

### Work on an existing project in a Minimal sandbox

In this example we'll work on an existing git repo that already has a `minimal.toml`, where Claude Code has been granted access to our GitHub repos.

```shell
cd ~/projects/foo

# get the latest files on the current branch - we need the minimal.toml
git pull

# don't copy any files up; we'll git pull inside the sandbox
min activate --attach --sync none .

# tell claude to pull https://github.com/<your-owner>/<your-repo>.git
# then add new features, fix bugs, etc.
# then ask claude to create a PR
claude

exit
```

### Add a Minimal Loadout with your preferred tools and configurations

TBD

## Tech Stack

Sandboxes: a pure Rust client, daemon, and VM manager. The sandbox VM is powered by [libkrun](https://github.com/libkrun/libkrun), a custom Linux kernel image, and an Alpine Linux rootfs.

[Packages](https://github.com/gominimal/pkgs/): glibc-based packages built frequently on Minimal's build servers from their canonical sources (GNU, GitHub, GitLab, etc.).

## Documentation

- [Architecture overview](docs/architecture.md) — how the crates fit together
- [CLI reference](docs/reference/cli.md) — every `min` command
- [`minimal.toml` reference](docs/reference/minimal-dot-toml.md) — the project blueprint format
- [Linux host setup](docs/reference/linux-host-setup.md) — kernel and namespace requirements
- More guides live in [docs/](docs/)

## Building and Testing

Minimal is a Rust workspace. From a checkout:

```shell
cargo build            # debug build (faster to build)
cargo build --release  # optimized build (slower to build, faster to run)
cargo test             # run the test suite
```

Binaries land at `target/debug/{min,mip,minimald,minvmd}` (or
`target/release/`). Building the entire package registry is heavy — 8 cores
and at least 16 GB of RAM are recommended.

### Ubuntu 24.04+ hosts

Sessions run in an unprivileged user namespace, which Ubuntu 24.04 blocks by
default (`kernel.apparmor_restrict_unprivileged_userns=1`) — every session dies
at `uid_map` with `Operation not permitted`. Install the AppArmor profile that
grants `minimald` the `userns` permission:

```shell
$> sudo scripts/install-apparmor-profile.sh              # installed binary
$> sudo scripts/install-apparmor-profile.sh --path "$PWD/target/debug/minimald"   # dev build
```

Installed via `curl … | sh` instead of a checkout? The installer ships this
loader and prints a hint when the host needs it; run
`sudo bash ~/.local/share/minimal/apparmor/install-apparmor-profile.sh`.

See [docs/reference/linux-host-setup.md](docs/reference/linux-host-setup.md).

## Contributing

We'd love your help, and you don't need to be a Rust expert to pitch in — bug reports, docs fixes, and feature ideas are all valued contributions. Please [open an Issue](https://github.com/gominimal/minimal/issues/new/choose) (or start a [Discussion](https://github.com/gominimal/minimal/discussions/new/choose) if it's large in scope) to outline the improvements you're seeking.

If you want to contribute code, docs, etc., please head over to [CONTRIBUTING.md](./CONTRIBUTING.md) for the development workflow and what we look for in a contribution.

### Contributor License Agreement

Before we can merge your first pull request, you'll need to accept our **Individual Contributor License Agreement (ICLA)**. This is a one-time, ~30 second step: [CLA Assistant](https://cla-assistant.io/) will post a link on your PR, you click through, sign in with GitHub, and you're done — you're then covered for all future contributions to this repository.

If you're contributing on your employer's time, or with code your employer might own, your employer will also need a **Corporate CLA (CCLA)** on file listing you as an authorized contributor. See [CONTRIBUTING.md](./CONTRIBUTING.md) for details, or email **security@minimal.dev** if you need help getting one set up.

Full text: [ICLA](./legal/ICLA.md) · [CCLA](./legal/CCLA.md)

## Code of Conduct

We want everyone to feel welcome here, whatever your background or experience level. This project follows the [Contributor Covenant](./CODE_OF_CONDUCT.md); by participating — contributing code, filing issues, or joining discussions — you agree to uphold it.

## Security

If you believe you've found a security vulnerability, please email **security@minimal.dev** instead of opening a public issue. We appreciate responsible disclosure and will get back to you quickly.

## License

This project is licensed under the [Apache License Version 2.0](LICENSE) — see the [LICENSE](LICENSE) file for details.
