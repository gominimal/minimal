# Add a Mac to the self-hosted runner fleet

This runbook sets up an Apple Silicon Mac as a self-hosted GitHub Actions
runner for this repository. The runner boots real libkrun microVMs on the
Hypervisor framework. GitHub-hosted macOS runners cannot do that, because they
are VMs and cannot nest a hypervisor
([ci-strategy.md](../ci-strategy.md) §2 and §7).

Read the whole runbook before you start. Do step 1 before you register a
second machine, or the release workflow can break.

## Jobs that run on the fleet

Jobs reach a self-hosted Mac through the labels `self-hosted`, `macOS`, and
`ARM64`. These jobs use those labels:

- **CI:** the `e2e` job in
  [`ci-macos.yml`](../../.github/workflows/ci-macos.yml). It also runs from
  [`nightly-tests.yml`](../../.github/workflows/nightly-tests.yml), which calls
  `ci-macos.yml`. The job downloads a prebuilt testbed instead of compiling,
  ad-hoc signs `minvmd` with the hypervisor entitlement, boots VMs, and runs
  `scripts/session-e2e.sh`.
- **Release:** `build-release-macos-arm64`, `sign-macos-artifacts`, and
  `smoke-macos` in [`release.yml`](../../.github/workflows/release.yml). The
  build and sign jobs use the Developer ID identity, and only the original
  Mac has the keychain that holds it.

A Mac that you add for CI capacity runs the `e2e` job. It must not receive
the signing jobs.

## 1. Keep the signing jobs on the signing Mac

GitHub sends a job to any idle runner whose labels match. The signing jobs,
`build-release-macos-arm64` and `sign-macos-artifacts`, run `security
unlock-keychain` on the Developer ID keychain. A Mac without that keychain
fails the step, and the release with it.

`release.yml` routes both jobs with the extra label `minimal-signing`:
`runs-on: [self-hosted, macOS, ARM64, minimal-signing]`. Give the label only
to the Mac that holds the keychain. Check that it does in the organization
settings (**Settings → Actions → Runners → the runner → Labels**). If no
online runner has the label, both jobs wait in the queue and the release does
not start.

Do not give a new Mac the `minimal-signing` label. `smoke-macos` and the CI
`e2e` job stay on the base labels. The smoke job uses signed files from an
earlier job, so any fleet Mac can run it.

A new job that signs or notarizes must also require `minimal-signing`. See
[Pending changes that affect the fleet](#pending-changes-that-affect-the-fleet).

## Privileged tests stay off the fleet

Do not give the runner's user `sudo` to make the privileged e2e cases run. The
box-name service `minzoned` installs as a root LaunchDaemon, and its install
command is one `sudo sh -c '...'`. A `sudoers` entry that allows it gives
full root. The fleet runs code from every pull request branch in this
repository, on machines that keep their state between jobs.

The macOS service path runs on a GitHub-hosted macOS runner instead. On that
runner, `sudo` asks for no password, and GitHub deletes the runner after each
job. The fleet runs
the unprivileged cases only.

## 2. Hardware and macOS

- **Machine:** Apple Silicon, bare metal: a Mac mini or a rented bare-metal
  Mac. A macOS VM, from any provider, cannot run the hypervisor.
- **Memory:** 24 GB or more. A guest VM gets 4096 MiB on arm64 by default
  (`DEFAULT_VM_RAM_MIB` in `crates/minvmd/src/cmd/mod.rs`), and the e2e boots
  more than one VM in some cases.
- **Disk:** 256 GB or more. Each run downloads a guest kernel, rootfs image,
  and initramfs, and leaves boot logs and work directories behind.
- **macOS:** the same major version as the existing runner. Check it there
  with `sw_vers`.
- **Dedicated:** use the machine only as a runner. The e2e job ends with
  `pkill -x minvmd`, `pkill -f __krun-vmm`, and `pkill -f gvproxy`, which stop
  every matching process that the runner's user owns, including a developer's
  own `min` sessions.

## 3. Prepare the machine

Do these steps as an administrator, then create the runner's user.

1. Keep the machine awake and have it restart after a power cut:

   ```sh
   sudo pmset -a sleep 0 disksleep 0 displaysleep 0
   sudo pmset -a autorestart 1
   ```

2. Turn off automatic macOS updates in **System Settings → General → Software
   Update → Automatic updates**. An update restarts the machine in the middle
   of a job. Update it yourself after you stop the runner (see
   [Take a Mac offline](#take-a-mac-offline)).
3. Create a standard (not administrator) user for the runner, such as
   `runner`. Do not let it run `sudo` without a password. The CI lane runs
   without privilege on purpose: the cases that need root self-skip unless a
   job sets `MINIMAL_E2E_PRIVILEGED=1`, and no workflow sets it.
4. Turn on automatic login for that user (**System Settings → Users & Groups
   → Automatically log in as**). The runner service is a LaunchAgent, which
   starts only in a logged-in session. Automatic login requires FileVault to
   be off. Weigh that against how secure the machine's location is.

## 4. Install the tools

Log in as the runner's user for every step from here on.

1. Install the Xcode Command Line Tools. They provide `git`, `codesign`,
   `otool`, `install_name_tool`, and `python3`:

   ```sh
   xcode-select --install
   ```

2. Check the tools that the e2e calls. macOS includes `curl`, `dig`,
   `shasum`, and `launchctl`. Recent macOS versions include `jq`. If this
   command does not print a path for each tool, install the missing one from
   Homebrew:

   ```sh
   command -v jq python3 dig curl git codesign
   ```

3. Install Homebrew only if the Mac must run a job that needs it (see
   [Pending changes that affect the fleet](#pending-changes-that-affect-the-fleet)).
   The CI `e2e` job does not.

The job installs `cargo-nextest` itself (into `~/.install-action`) and
downloads the pinned `gvproxy` on every run. Do not install Rust or libkrun on
a CI-only Mac: the e2e uses the libkrun library in the testbed. Only the
signing Mac builds from source, and it needs `rustup`.

## 5. Register the runner

Register the runner at the **organization** level, in the `default` runner
group. To get a registration token, you must be an organization admin or hold
the "runners and runner groups" permission.

1. In the organization, open **Settings → Actions → Runners → New runner →
   macOS / ARM64**. Run the download and `config.sh` commands it shows, from
   the runner user's home directory, such as `~/actions-runner`.
2. When `config.sh` asks:
   - **Runner group:** `default`. It must allow public repositories, because
     this repository is public. The group already allows them for the
     existing Mac.
   - **Name:** a unique name, such as `minimal-mac-02`. The job log prints it,
     which is how you tell the machines apart.
   - **Labels:** accept the defaults (`self-hosted`, `macOS`, `ARM64`). Do not
     add `minimal-signing`.
   - **Work folder:** accept `_work`.
3. Install and start it as a service:

   ```sh
   cd ~/actions-runner
   ./svc.sh install
   ./svc.sh start
   ./svc.sh status
   ```

Register one runner per machine. The e2e's cleanup stops every `minvmd`,
`__krun-vmm`, and `gvproxy` that the user owns, so two runners on one Mac stop
each other's VMs.

## 6. Check the security guard

A self-hosted runner on a public repository runs whatever code a job checks
out. The `e2e` job only runs on pushes and on pull requests from branches in
this repository. Its `if:` condition checks
`github.event.pull_request.head.repo.full_name == github.repository`, and pull
requests from forks skip the job. Every new workflow job that targets these
labels needs the same guard. Do not rely on the repository's fork-approval
setting instead. The comment on the job in `ci-macos.yml` explains why.

The CI jobs do not read secrets, and the checkout steps set
`persist-credentials: false`. Keep both rules for any job you add.

## 7. Make sure that the new Mac works

1. Start the lane by hand on `main`:

   ```sh
   gh workflow run ci-macos.yml --ref main
   ```

2. The existing Mac can pick the job. To send it to the new one, pause the
   existing runner for one run (`./svc.sh stop` on that machine, then
   `./svc.sh start` afterwards), or wait for regular traffic.
3. Open the `e2e` job's log. The top lines name the runner:

   ```text
   Runner name: 'minimal-mac-02'
   ```

4. The job must pass, and the session e2e must print its own summary. Check
   that the step `VM integration harnesses` ran tests. Its nextest summary
   line must show a test count above zero, such as `22 tests run: 22 passed`.

## Take a Mac offline

The repository variable `RUN_MACOS_CI` set to `false` skips every
self-hosted macOS job on every Mac. The aggregators count a skip as a pass, so
nothing wedges, but nothing tests macOS either. Use it only when the whole
fleet is down.

To service one machine, stop only its runner (`./svc.sh stop`). The other
Macs keep taking jobs.

## Troubleshooting

- **A boot fails with `EINVAL` from `krun_start_enter`:** `minvmd` lost its
  hypervisor entitlement. The job signs it in the step **Codesign minvmd
  (hypervisor entitlement)**. Check that the step ran and that nothing rebuilt
  the binary after it.
- **Every boot after a cancelled run fails:** a leftover `__krun-vmm` or
  `gvproxy` holds the bridge socket. The next run's cleanup step stops them.
  To clear it by hand, run `pkill -f __krun-vmm; pkill -f gvproxy` as the
  runner's user.
- **The e2e fails on socket paths:** macOS limits a Unix socket path to 104
  bytes. The script keeps its work directories under `/tmp/mnl-e2e.*` for this
  reason. Do not point `TMPDIR` or the work folder at a long path.
- **`/tmp` fills up:** a run that died before its cleanup leaves a
  `/tmp/mnl-e2e.*` directory. Delete old ones while the runner is idle.

## Pending changes that affect the fleet

Check open pull requests that touch `.github/workflows/ci-macos.yml`,
`release.yml`, `nightly.yml`, or `scripts/session-e2e.sh` before you add a
Mac. At the time of writing, these change what the Macs run:

- **Notarization in `build-release-macos-arm64`:** adds a `notarytool`
  profile to the signing keychain and the repository variable
  `MACOS_NOTARY_PROFILE`. Signing Mac only.
- **`minzoned` build and signing in `build-release-macos-arm64`:** signing Mac
  only. Its `session-e2e.sh` changes need nothing new on a CI Mac.
- **A nightly `brew-install-nightly` job on the base labels:** it runs
  `brew tap` and `brew install` on whichever Mac takes it, so with this change
  every fleet Mac needs Homebrew. The job also leaves a Homebrew tap on the
  machine.
- **The CI `e2e` waits for the KVM lane on pull requests:** fewer jobs reach
  the Macs. Nothing to install.
