# The macOS system install

A component package (`pkgbuild`, wrapped by `productbuild`) installs minimal
machine-wide under `/usr/local`. Its postinstall does the privileged setup,
so a user on that Mac needs no `min finalize-install`. A fleet deploys the
package through an MDM (gominimal/inbox#1179). The `curl | sh` installer
stays as the per-user path. One artifact set feeds both.

`build-pkg.sh --help` describes the inputs and the payload layout. In short:

- The payload is the darwin/arm64 rows of a staged release's `components`
  manifest. The script fetches and checksum-checks each file like the
  installer does. It maps the installer's prefixes to `/usr/local`: `bin/`
  to `/usr/local/bin`, `lib/` to `/usr/local/lib`, and `data/` (the guest
  images) to `/usr/local/share/minimal`. minvmd looks there after the
  user's own data directory (`crates/minvmd/src/image.rs`). The one
  exception is the box-name service's bundle, `bin/Minimal.app`: root's
  launchd jobs run it, so the payload puts it at
  `/Library/PrivilegedHelperTools/Minimal.app`, where only root writes.
- The package adds two things under `/usr/local`. The shell completions,
  printed by the payload's own `min`, go under the system completion
  directories. `pkg-info` names the release the payload came from and says
  whether it is a test build; it is for a person to read, and no script
  reads it.
- **Root reads nothing from `/usr/local`.** On a Mac where a user owns
  `/usr/local/bin` or `/usr/local/share` (Homebrew's Intel layout, and Macs
  migrated from one), that user can change those files while the package
  installs. So what root runs or reads comes from the package's scripts
  directory and from `/Library`: the service's bundle, the uninstaller, and
  what the postinstall requires of the bundle's signature, which
  `build-pkg.sh` writes into the postinstall when it builds the package.
- `scripts/postinstall` does what `min finalize-install` does for a user,
  with nobody logged in. It first installs `uninstall.sh` (macOS has no
  package uninstall) and the list of the payload's files under
  `/Library/Application Support/minimal`. It checks the box-name service's
  bundle where the payload put it, behind the same Developer ID check. It
  writes the resolver file for `min.internal` and the boot-time
  loopback-range job. It runs the box-name service under a role account,
  `_minimal`, rather than the installing user. `scripts/preinstall` stops
  those two services on an upgrade and moves the earlier bundle aside; a
  postinstall that fails puts it back and starts them again.
  `scripts/uninstall.sh` undoes all of it, account included. Then it
  removes every file in the receipt, and the receipt.
- A first install that fails (the DNS port held by another program, say)
  removes its services, the bundle and the resolver file again, and names
  the uninstaller. Installer keeps no receipt for a failed install, so the
  uninstaller then works from the file list instead and removes what the
  payload placed.

## A test build

`--with <manifest dest>=<path>` replaces payload files with a build of this
tree, before a release includes it:

```
scripts/build-app-bundle.sh assemble target/release/minzoned target/app-bundle-release/Minimal.app
packaging/macos/pkg/build-pkg.sh --channel unstable \
    --with bin/min=target/release/min --with bin/minvmd=target/release/minvmd \
    --with bin/bep=target/release/bep --with bin/Minimal.app=target/app-bundle-release/Minimal.app
```

A test build's bundle carries an ad-hoc signature. Its postinstall accepts
any valid signature on the bundle instead of minimal's Developer ID, and
`pkg-info` says `test_build=1`. The package has no signature until
`--sign` names a Developer ID Installer identity. Gatekeeper refuses an
unsigned package on a double-click. `installer -pkg … -target /` as root
accepts it, which is how the farm installs it in a fresh VM.

## Deploying through an MDM

The package is made for an MDM's push: root, no console user, no terminal,
no network during install. The scripts use only `codesign`, `dscl`,
`dseditgroup`, `launchctl` and `install` from the base system; nothing
reads `$HOME`, `$USER` or `/dev/console`, nothing prompts, nothing opens a
window. The Distribution limits the package to Apple Silicon and to the
minimum macOS (`--min-os`), installs into the local system only, and pins
the two app bundles to their payload paths, so Installer never follows an
older copy of the same bundle elsewhere on the disk.

What an MDM administrator should know:

- **Removal** is `sudo "/Library/Application Support/minimal/uninstall.sh"`, pushed as
  a root script through the MDM agent, which holds Full Disk Access and so
  can delete the role account. It also forgets the receipt. With no Full
  Disk Access it removes everything but the account and exits 1; an MDM
  reports that as a failed policy, so push it through the agent.
- **Background items.** The package installs two LaunchDaemons the old
  way, as files under `/Library/LaunchDaemons` (Apple's `SMAppService`
  needs an app that registers them and a user who approves, which a push
  with nobody logged in has neither of). macOS shows each user a
  "Background Items Added" notice for them, under the name Minimal, and
  lets an administrator switch them off in System Settings > General >
  Login Items. With the service off (measured with `launchctl disable`
  and `bootout`), a lookup of a box name hangs for 60 s and fails, other
  names are unaffected, and `min finalize-install --show` reports the
  names item as waiting on a daemon. A disabled label stays disabled
  across an uninstall; an install or upgrade on such a Mac stops before
  changing anything and names `sudo launchctl enable system/<label>`. A
  fleet approves them
  ahead of the install with a Service Management profile
  (`com.apple.servicemanagement`), by the signing team:

  ```xml
  <key>PayloadType</key><string>com.apple.servicemanagement</string>
  <key>Rules</key>
  <array>
      <dict>
          <key>RuleType</key><string>TeamIdentifier</string>
          <key>RuleValue</key><string>3G47C5HY64</string>
          <key>Comment</key><string>Minimal: the box-name service and its loopback range</string>
      </dict>
  </array>
  ```

  A rule by label needs both: `dev.gominimal.zone` and
  `dev.minimal.local-range`. The team rule matches a released package
  only; a test build's program carries no team.
- **Who may register box names** is the `_minimal` group. The first install
  puts the Mac's administrators in it, which on a managed Mac is often the
  management account alone; add standard users afterwards with
  `dseditgroup -o edit -a USER -t user _minimal`, by MDM script. A managed
  preference the postinstall reads is the open item below.
- **Users who installed with curl before** keep `~/.local/bin/min` first on
  their PATH. The postinstall names each such user in install.log with the
  curl uninstall command. The release's uninstaller before 0.8 then prints
  root commands about the host DNS setup, which must not be run: that setup
  is the package's now. The postinstall's line says so.
- **DNS**: box names resolve through a scoped resolver file,
  `/etc/resolver/min.internal`, pointing at the service on 127.0.0.1. An
  MDM DNS payload (encrypted DNS) or a full-tunnel VPN that claims all
  domains can take precedence over scoped resolvers; test with the fleet's
  VPN client before a wide rollout.
- **Version**: the receipt's version is the payload's `min --version`. An
  MDM compares versions as dotted numbers; a prerelease string
  (`0.8.0-dev.428.g…`) sorts unpredictably, so a fleet pins releases, not
  nightlies.

## Signing and notarizing

The binaries and the two app bundles inside already carry the project's
Developer ID Application identity, hardened runtime and timestamps, and
are notarized by the release workflow. The package needs the matching
**Developer ID Installer** identity (same team), which the release holds
when `--sign` names it:

```
packaging/macos/pkg/build-pkg.sh --version X.Y.Z \
    --sign "Developer ID Installer: Minimal Software Research Ltd. (3G47C5HY64)" \
    --notarize minimal-notary
```

`--sign` signs the product archive (timestamped) and checks the signature
back; `--notarize` submits it with the named `notarytool` keychain profile,
waits, staples the ticket, and runs the Gatekeeper assessment Installer
runs on a double-click. A test build (`--with`) is refused a signature: its
service program is ad-hoc signed, and a Developer ID on the package would
say more than is true. Nothing in the postinstall changes signed code, so
the bundles' seals survive the install; the postinstall requires the
Developer ID on the service bundle before anything names it (team OU
`3G47C5HY64`, in `postinstall` and `build-pkg.sh` alike).

## The disk image

`--dmg` writes `minimal-X.Y.Z.dmg` beside the package: a read-only,
compressed volume named "Minimal" with the package alone at its top, for a
download page. A person opens the image and double-clicks the package;
Gatekeeper judges the package, so the image itself needs no signature.
With `--sign-dmg "Developer ID Application: …"` (the identity the binaries
carry; the Installer identity is for packages only) the image is signed as
well, and with `--notarize` it is notarized and stapled too, so Finder
shows no warning on the image and a Mac offline at first open still finds
the ticket. An MDM takes the package, never the image.

The acceptance farm installs from the image in `vm-pkg-from-dmg`: attached
read-only as Finder would, the package at its top installed, detached, the
whole machine judged afterwards.

## Still open

These come from the proposal's open questions.

- Which `min` wins when a user also has an older `~/.local/bin/min` from
  the curl days. PATH order puts the user's first. The postinstall names
  each such user in install.log, with the curl uninstall command for that
  user. Nothing tells the user in their own shell until the update check
  (inbox #1168) lands.
- Who registers box names. The service admits its own uid, root and the
  members of its group, `_minimal`. The service unit passes
  `minzoned --admit-group _minimal`. The service manager gives the channel
  socket to that group with mode 0660. The first install puts every
  administrator of the Mac in the group (an install run again over an
  empty group does too); an upgrade leaves the group as it is. To add
  another user, run `dseditgroup -o edit -a USER -t user _minimal`. A
  node is the daemon's node id and the user's uid together, so another
  user speaking the same id is another node: nobody can replace or
  release another user's names by naming their daemon, and the service
  keeps no state across a restart. Names stay first-publisher-wins
  across the Mac, so after a restart any member can take a name another
  member had: the group is for users who trust each other. The service
  hands out box addresses machine-wide, as before. `min finalize-install`
  never replaces or removes the shared service, for a member or root
  either: a newer package upgrades it, `uninstall.sh` removes it. The
  experiments behind this are in the farm's
  docs/research/box-name-service-users.md.
- The admission policy for a fleet. Admins only, chosen at first install,
  is the default, and the only knob is the group's membership, which an
  MDM sets with `dseditgroup` after the install. A managed Mac's standard
  users are not admitted until it does. A policy file the postinstall
  reads (a managed preference) would let the package carry it.
- The role account's ids are the lowest free ones from 400 up, where Apple
  also adds role accounts across releases (`_oahd` at 441 came with
  Rosetta). A later macOS could take the id this install chose.
- `install.toml` with `method = "pkg"` waits on inbox #1168.
- A test build's bundles carry version `0.0.0` (`build-app-bundle.sh`
  stamps the release's version only when told one), so Installer's
  bundle-version comparison sees every test build as the same version. A
  release stamps the real version; the farm's upgrade journeys run on test
  builds and prove the scripts, not that comparison. The service's bundle
  is out of it either way: the preinstall moves the earlier one aside, so
  Installer finds nothing to compare with and writes the payload's.
- The pre-install script cannot stop a user's running sessions. An upgrade
  leaves their daemons on the old binaries until they restart.
- `uninstall.sh` needs the Full Disk Access privacy permission to delete
  the role account, even as root. A Terminal with it, or an MDM agent, can.
  Root over ssh can where a person turned Remote Login on in System
  Settings, which grants the ssh service the permission. The service turned
  on any other way has no grant, and root over it cannot. The script then
  removes everything else and exits 1. Its message names the command for a
  session that can.
