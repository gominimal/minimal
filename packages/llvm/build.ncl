let { BuildSpec, OutputLib, Local, Prebuilt, .. } = import "minimal.ncl" in
let libffi = import "../libffi/build.ncl" in
{
  name = "llvm",
  inputs = [
    { package = "llvm" } | Prebuilt,
  ],
  runtime_deps = [
    libffi,
  ],
  cmd = "",
  outputs = {
    usr = { glob = "usr/**/*" } | OutputLib,
  },
} | BuildSpec
