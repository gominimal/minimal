let { BuildSpec, OutputLib, Local, Prebuilt, .. } = import "minimal.ncl" in
let zlib = import "../zlib/build.ncl" in
{
  name = "binutils",
  inputs = [
    { package = "binutils", sha256 = "0c2d510d101dc38a2374bdf0b97c2dcb98447c2aeb5a505c7dad9958cbcf0864" } | Prebuilt,
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
