let { stack, .. } = import "minimal.ncl" in
stack {
  name = "fake-stack",

  runtime_packages = ["stack-runtime-pkg"],
  build_packages = ["stack-build-pkg"],
  build_env_vars = {
    STACK_VAR = "set",
  },

  build_cmd = "stack build cmd",
}
