let { BuildSpec, OutputLib, Local, Prebuilt, .. } = import "minimal.ncl" in
let zlib = import "../zlib/build.ncl" in
{
  name = "binutils",
  inputs = [
    { package = "binutils", sha256 = "d063e1a41e7353394aaa55329d3a537c7000e07110710f56e0260792cf75fb54" } | Prebuilt,
  ],
  runtime_deps = [
    zlib,
  ],
  cmd = "",
  outputs = {
    usr_bin = { glob = "usr/bin/**/*" } | OutputLib,
    usr_lib = { glob = "usr/lib/**/*" } | OutputLib,
    usr_include = { glob = "usr/include/**/*" } | OutputLib,
    usr_share = { glob = "usr/share/**/*" } | OutputLib,
  },
} | BuildSpec
