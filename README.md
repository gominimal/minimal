## Building `minimal`

For now, the minimal tool only runs on amd64 Linux.

8 cores and at least 16 Gb of ram recommended, but it should (slowly) run on a wet piece of spaghetti.

### Dependencies
1. Install a fairly recent version of rust: https://rust-lang.org/tools/install/
2. Install a not-ancient version of git
3. Install deps (openssl, pkg-config, build-essential, git, protoc-compiler): `sudo apt-get install build-essential openssl pkg-config libssl-dev git protobuf-compiler `

### Building the binary
Either: `cargo build` for debug (faster build) and `cargo build --release` (slower build, faster execution)

## Using minimal

Firstly, the current state assumes you can access our staging buckets, so **you need to auth to GCP every day**: `gcloud auth application-default login`

Once you've done that, you can run minimal, either via the build binary in `target/{debug,release}/minimal` or using cargo (which will auto-rebuild as you change rust sauce):

```shell
$> cargo run -- <minimal args>
```

### Minimal commands

```
The Minimal CLI

Usage: minimal [OPTIONS] <COMMAND>

Commands:
  build        Builds package(s), making them available in the local cache
  run          Runs a task specified in `minimal.toml`
  materialize  Materializes an output specified in `minimal.toml`
  update       Refreshes local checkouts of upstream packages & the standard library
  plan         Prints the build plan for the specified package(s)
  check        Validates and formats nickel build-spec files
  help         Print this message or the help of the given subcommand(s)

Options:
      --minimal-dir <MINIMAL_DIR>
          Override the base directory used for operations (default: ~/.cache/minimal)
      --stdlib-dir <STDLIB_DIR>
          Load the minimal standard library from the given path instead
      --packages-dir <PACKAGES_DIR>
          Load packages from the given path instead of using `[base]` in `minimal.toml`
      --no-cache
          Ignore locally-available binary artifacts (results in rebuilds unless present in a remote cache)
      --no-fetch
          Do not fetch binary artifacts from the internet
  -n, --num-parallel-builds <NUM_PARALLEL_BUILDS>
          Configure the number of parallel builds [default: 6]
  -h, --help
          Print help
  -V, --version
          Print version
```

You'll probably use the subcommands `build` and `plan` most of the time. Basically, if you omit `--package(s) <package1>[,<packageN>]` it will build/plan
all packages, otherwise just the ones specified.

The other two switches you'll use a lot are `--no-fetch` and `--no-cache`:

`--no-fetch`: Do not fetch anything from the "remote cache" (the GCP bucket).
`--no-cache`: Rebuild everything thats needed: do not use anything that was built in an earlier invocation nor anything fetched in an earlier invocation.

These args apply to planning as well.

Other stuff thats less important:

 - `minimal new-world-update` - Updates the prebuilt cycle-breakers. Tom plans to rip this out when he replaces prebuilts.
 - `minimal check` - Runs a bunch of formatting and correctness checks on our packaging.
 - `minimal upload-cache` - Ensures all the built artifacts cached locally are present in the remote cache (GCP bucket), uploading them if not.
 - `minimal patched-build <package-name>` - Builds only the specified package, wiring dependencies into the build by package name instead of spec-hash.
