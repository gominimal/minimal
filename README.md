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
  run          Runs a task specified in `minimal.toml`
  update       Refreshes local checkouts of upstream packages & the standard library
  add          Add a new tool or dependency
  init         Automatically initialize minimal configuration based on your source tree
  status       Shows the status of Minimal in this codebase
  shell        Launches a development shell (shorthand for `minimal run shell`)
  build        Runs the build task. Shorthand for `minimal run build`
  test         Runs the test task. Shorthand for `minimal run test`
  materialize  Materializes an output specified in `minimal.toml`
  pkg          Builds the specified package(s) in a clean room, making them available in the local cache
  cache        Manipulate the local cache
  check        Validates minimal configuration including packages, stacks, and profiles
  dep          Generates Graphviz source code of the dependency graph
  completions  Generate shell completion script
  help         Print this message or the help of the given subcommand(s)

Options:
      --minimal-dir <MINIMAL_DIR>
          Override the base directory used for operations (default: ~/.cache/minimal)
  -C, --repo-dir <REPO_DIR>
          Use the given directory as the repository root, instead of searching from the current working directory
      --no-cache
          Ignore locally-available binary artifacts (results in rebuilds unless present in a remote cache)
      --no-fetch
          Do not fetch binary artifacts from the internet
      --offline
          Use only what's already in the local cache; fail on any network call
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

## CI/CD

### ci.yml — Build pipeline

Runs on every push and PR to `main`. On pushes to `main`, builds static
musl binaries for amd64 and arm64, creates a GitHub release, and uploads
CLI archives to `gs://minimal-shim/archives/`.

### promote.yml — CLI version promotion

Manual `workflow_dispatch` with inputs:
- `sha` (optional): short SHA to promote (defaults to latest archive in bucket)
- `platforms` (optional): comma-separated list or `"amd64-linux,arm64-linux"`
- `dry_run` (optional, boolean, default `false`): when `true`, opens the approval issue and logs what would be written but skips the actual GCS config write

Verifies the archive exists in GCS, then writes per-platform config files
under `gs://minimal-shim/config/`.

### GCS permissions

CI workflows authenticate via Workload Identity Federation (WIF). The WIF
principal for this repo requires `roles/storage.objectUser` on the
`gs://minimal-shim` bucket, which grants create, delete, get, list, and
update on objects. This is the minimum predefined role that supports
uploading archives and overwriting config files during promotion.

```
principal://iam.googleapis.com/projects/289724348228/locations/global/workloadIdentityPools/github/subject/repo:gominimal/minimal:ref:refs/heads/main
```
