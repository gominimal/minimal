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
  user's own data directory (`crates/minvmd/src/image.rs`).
- The package adds three things. The shell completions, printed by the
  payload's own `min`, go under the system completion directories.
  `uninstall.sh` goes in, because macOS has no package uninstall. `pkg-info`
  names the release the payload came from and says whether it is a test
  build.
- `scripts/postinstall` does what `min finalize-install` does for a user,
  with nobody logged in. It copies the box-name service's bundle to
  `/Library/PrivilegedHelperTools` behind the same Developer ID check. It
  writes the resolver file for `min.internal` and the boot-time
  loopback-range job. It runs the box-name service under a role account,
  `_minimal`, rather than the installing user. `scripts/preinstall` stops
  those two services on an upgrade. `scripts/uninstall.sh` undoes all of
  it, account included. Then it removes every file in the receipt, and the
  receipt.

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
- The pre-install script cannot stop a user's running sessions. An upgrade
  leaves their daemons on the old binaries until they restart.
- `uninstall.sh` needs the Full Disk Access privacy permission to delete
  the role account, even as root. A Terminal with it, or an MDM agent, can.
  Root over ssh can where a person turned Remote Login on in System
  Settings, which grants the ssh service the permission. The service turned
  on any other way has no grant, and root over it cannot. The script then
  removes everything else and exits 1. Its message names the command for a
  session that can.
