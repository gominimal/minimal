let { standaloneTest, BuildSpec, OutputLib, Source, .. } = import "minimal.ncl" in
{
  name = "uroot",
  prebuilt = true,
  build_deps = [
    {
      file = "u-root-core-amd64.tar.zst",
      extract = true,
    } | Source,
  ],
  runtime_deps = [],
  outputs = {
    usr = { glob = "usr/**/*" } | OutputLib,
  },

  tests.smoke = standaloneTest "/bbin/touch uwu",
} | BuildSpec
