let { BuildSpec, HostPath, OutputLib, Local, Prebuilt, .. } = import "minimal.ncl" in
{
  name = "llvm",
  inputs = [
    { package = "llvm" } | Prebuilt,
  ],
  runtime_deps = [],
  cmd = "",
  outputs = {
    usr = { glob = "usr/**/*" } | OutputLib,
  },
} | BuildSpec
