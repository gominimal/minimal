## Building `minimal`

The "minimal" CLI tool runs on amd64 and aarch64 Linux.

8 cores and at least 16 Gb of RAM is recommended to build the entire package registry but it should (slowly) run on a wet piece of spaghetti.

### Dependencies
1. Install a fairly recent version of rust: https://rust-lang.org/tools/install/
2. Install deps (openssl, pkg-config, build-essential, git, protoc-compiler): `sudo apt-get install build-essential openssl pkg-config libssl-dev git protobuf-compiler `

### Building the binary
Either: `cargo build` for debug (faster build) and `cargo build --release` (slower build, faster execution)

## Using minimal

You can run minimal either via the build binary in `target/{debug,release}/minimal` or using cargo (which will auto-rebuild as you change rust sauce):

```shell
$> cargo run -- <minimal args>
```

### Minimal commands

```
The Minimal CLI

Usage: minimal [OPTIONS] <COMMAND>

Commands:
  build        Runs the build task. Shorthand for `minimal run build`
  test         Runs the test task. Shorthand for `minimal run test`
  run          Runs a task specified in `minimal.toml`
  update       Refreshes local checkouts of upstream packages & the standard library
  materialize  Materializes an output specified in `minimal.toml`
  pkg          Builds the specified package(s) in a clean room, making them available in the local cache
  check        Validates and formats nickel build-spec files
  completions  Generate shell completion script
  help         Print this message or the help of the given subcommand(s)

Options:
      --minimal-dir <MINIMAL_DIR>
          Override the base directory used for operations (default: ~/.cache/minimal)
      --stdlib-dir <STDLIB_DIR>
          Load the minimal standard library from the given path instead
  -C, --repo-dir <REPO_DIR>
          Use the given directory as the repository root, instead of searching from the current working directory
      --no-cache
          Ignore locally-available binary artifacts (results in rebuilds unless present in a remote cache)
      --no-fetch
          Do not fetch binary artifacts from the internet
      --no-telemetry
          Do not share build status with sponge [env: MINIMAL_NO_TELEMETRY=]
  -n, --num-parallel-builds <NUM_PARALLEL_BUILDS>
          Configure the number of parallel builds
  -h, --help
          Print help
  -V, --version
          Print version
```

You'll probably use the subcommands `build` and `pkg` most of the time.

Switches for the local & remote cache:

 * `--no-fetch`: Do not fetch anything from the "remote cache" (the GCP bucket).
 * `--no-cache`: Rebuild everything thats needed: do not use anything that was built in an earlier invocation nor anything fetched in an earlier invocation.

These args apply to planning as well.
