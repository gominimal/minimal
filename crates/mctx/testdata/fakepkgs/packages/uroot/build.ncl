let { BuildSpec, OutputLib, Source, .. } = import "minimal.ncl" in
{
  name = "uroot",
  prebuilt = true,
  inputs = [
    {
      file = "u-root-core-amd64.tar.zst",
      extract = true,
    } | Source,
  ],
  runtime_deps = [],
  outputs = {
    usr = { glob = "usr/**/*" } | OutputLib,
  },
} | BuildSpec
