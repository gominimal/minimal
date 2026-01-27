let { harness, .. } = import "minimal.ncl" in
harness {
  name = "test-harness",

  build_packages = ["gcc", "rust", "binutils"],
  build_env_vars = {
    # An attribute on the 'rust' package already wires a state
    # directory `.cargo`, set to `$CARGO_HOME`. We set the location
    # for storing built packages to `$CARGO_HOME/build`, so incremental
    # artifacts are stored in the state dir also.
    CARGO_BUILD_BUILD_DIR = "{cargo-cache-home}/build",

    # Environment variables that configure the compiler/linker
    CC = "gcc",
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER = "gcc",
  },

  build_cmd = "cargo build --release",
}
