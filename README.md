## Building `minimal`

For now, the minimal tool only runs on Linux.

### Dependencies
1. Install a fairly recent version of rust: https://rust-lang.org/tools/install/
2. Install deps (openssl, pkg-config, git, protoc-compiler): `sudo apt-get install openssl pkg-config libssl-dev git protobuf-compiler`

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
Usage: minimal [OPTIONS] <COMMAND>

Commands:
  build             Builds package(s), making them available in the minimal build cache
  plan              Prints the build plan for the specified package(s)
  new-world-update  Builds packages which have a prebuilt cycle-breaker, and uploads then + updates their build-specs
  oci-image         Materializes an OCI container image for executing the specified package
  check             Validates and formats nickel build-spec files
  upload-cache      Uploads the specified packages and their transitive needs to the cache
  help              Print this message or the help of the given subcommand(s)

Options:
      --cache-dir <CACHE_DIR>
          Override the directory where binary artifacts are cached
      --builds-dir <BUILDS_DIR>
          Override the direct where builds are performed (default: ~/.cache/minimal/sandboxes)
      --download-cache-dir <DOWNLOAD_CACHE_DIR>
          Override the download cache directory (default: ~/.cache/minimal/downloads)
      --packages-dir <PACKAGES_DIR>
          Override the packages/ directory where build-specs are loaded
      --no-cache
          Ignore cached builds (forcing a rebuild)
      --no-fetch
          Do not fetch completed builds from the internet
  -n, --num-parallel-builds <NUM_PARALLEL_BUILDS>
          Configure the number of parallel builds [default: 4]
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
 - `minimal oci-image` - Builds and uploads a container image containing the specified packages.
 - `minimal check` - Runs a bunch of formatting and correctness checks on our packaging.
 - `minimal upload-cache` - Ensures all the built artifacts cached locally are present in the remote cache (GCP bucket), uploading them if not.
