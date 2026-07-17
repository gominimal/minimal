# Minimal

Minimal provides VM-based development sandboxes and a secure package manager the for dev tools used in those sandboxes.

# Features
Minimal can repeatably create a Linux, terminal-baseed development environment sandboxes populated with exactly the toolsets and agents you need as specified in your minimal.toml blueprint.

The tool executables (compilers, agents, shells, etc.) available in these sandboxes come from Minimal's [curated package registry](https://github.com/gominimal/pkgs/) which is refreshed daily. Simply add a minimal.toml to your project's git repo and all your teammates will have identical development environemnts that isolate AI agents from their laptops. Updating the shared minimal.toml to reference the freshest tool versions is just a `min update` away.  No more outdated wiki pages for dev-env setup and version drift across your team.

Per-developer "Loadouts" can be included in each development environment so everyone can work efficiently by using the editors, terminal multiplexers and their configs that match their hard-earned muscle memory.

## Contents


## Tech Stack

Sandboxes: pure Rust client, daemon and VM manager. The sandbox VM is powered by [libkrun](https://github.com/libkrun/libkrun), a custom Linux kernel image and an Alpine Linux rootfs

[Packages](https://github.com/gominimal/pkgs/): glibc-based packages built frequently on Minimal's build servers from their cannonical sources (GNU, Github, Gitlab, etc.)

## Supported Platforms

Minimal works on:
- MacOS / ARM64 (Apple Silicon)
- Ubuntu and Debian Linux, ARM64 and X86_64, with a Linux kernel >= 5.10. Rootless user-namespace creation must be enabled for non-VM usage.

## Installation

 To get started, install it with the following shell command (stable is coming soon):

```shell
curl --proto "=https" --tlsv1.2 -fsSL 'https://go.minimal.dev/unstable' | sh
```

This should install Minimal on your system, add "min" to your PATH, and setup shell completions for bash, fish, and zsh.

Minimal can be unistalled with:
```shell
curl --proto "=https" --tlsv1.2 -fsSL 'https://go.minimal.dev/unstable' | sh -s -- --uninstall
```

## Getting Started

### Create a new project with Minimal

In this example we'll create a new git repo from within a Minimal sandbox using tools from the [Minimal Public Registry](https://github.com/gominimal/pkgs/). In this example we assume your claude code has been granted access to your git repos in order to push your changes there.

```shell
mkdir -p ~/projects/foo
cd  ~/projects/foo

# create and update a minimal.toml file
min init
min add --session git gh claude-code

# start and enter a sandbox, which copies up the CWD file tree into the sandbox
min activate --attach .

git init

# develop specs, generate & test code etc, push to git, etc
# agents can add sw tools from Minimal Public Registry dynamically with "min add"
claude-code

exit
```

Above we show using Claude Code where you have trusted Claude Github App is Github on your behalf.   Below we show using a Github personal access token (PAT) from the MacOS keychain. To create fine-grained PATs (e.g. scoped to a specific repo) go to https://github.com/settings/personal-access-tokens.

Once you have created the PAT and copied it into your keychain (e.g. `security add-generic-password -s "PAT-foo-repo" -a "my-mac-user-name" -w`), and created the new, empty Github repo, the following example shows populating it the repo from within a sandbox.


```shell
mkdir -p ~/projects/foo
cd  ~/projects/foo

# create and update a minimal.toml file
min init
min add --session git gh claude-code mermaid-cli kittyview less emacs

# copy a Github PAT to your clipboard from your MacOS keychain
security find-generic-password -w -s "PAT-foo-repo" -a "my-mac-user-name" | pbcopy

# start and enter a sandbox, which copies up the CWD file tree into the sandbox
min activate --attach .

read -sp "paste GH PAT now:" GH_TOKEN && export GH_TOKEN

git init

claude --dangerously-skip-permissions
# develop specs, generate code etc

git add -A
git commit -m "initial checkin"

git remote add origin https@github.com:<your-repo>.git
git branch -M main
git push -u origin main

exit

```


### Work on an existing project in a Minimal sandbox

In this example we'll work on an existing git repo that already has minimal.toml where we have granted claude code access to our github repos.

```shell
cd  ~/projects/foo

# get latest files on current branch - we need the minimal.toml
git pull

# don't copy any files up we'll git pull in the sandbox
min activate --attach --sync none .


# tell claude to pull https@github.com:<your-repo>.git
# then add new features, fix bugs etc
# then ask claude to create PR
claude

exit
```

### Add a Minimal Loadout with your preferred tools and configurations

TBD

## Building and Testing

Either: `cargo build` for debug (faster build) and `cargo build --release` (slower build, faster execution)

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

We'd love your help! Please [open an Issue](https://github.com/gominimal/minimal/issues/new/choose) (or a [Discussion](https://github.com/gominimal/minimal/discussions/new/choose)( if it's large in scope) to outline the improvments you're seeking

If you want to contribute code, docs, etc please head over to [CONTRIBUTING.md](./CONTRIBUTING.md) for the development workflow and what we look for in a contribution.


### Contributor License Agreement

Before we can merge your first pull request, you'll need to accept our **Individual Contributor License Agreement (ICLA)**. This is a one-time, ~30 second step: [CLA Assistant](https://cla-assistant.io/) will post a link on your PR, you click through, sign in with GitHub, and you're done — you're then covered for all future contributions to this repository.

If you're contributing on your employer's time, or with code your employer might own, your employer will also need a **Corporate CLA (CCLA)** on file listing you as an authorized contributor. See [CONTRIBUTING.md](./CONTRIBUTING.md) for details, or email **security@minimal.dev** if you need help getting one set up.

Full text: [ICLA](./legal/ICLA.md) · [CCLA](./legal/CCLA.md)

## License

This project is licensed under the [Apache License Version 2.0](LICENSE)
- see the [LICENSE](LICENSE) file for details.

