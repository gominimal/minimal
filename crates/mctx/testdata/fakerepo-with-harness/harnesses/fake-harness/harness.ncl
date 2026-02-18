let { harness, .. } = import "minimal.ncl" in
harness {
  name = "fake-harness",

  runtime_packages = ["harness-runtime-pkg"],
  build_packages = ["harness-build-pkg"],
  build_env_vars = {
    HARNESS_VAR = "set",
  },

  build_cmd = "harness build cmd",
}
