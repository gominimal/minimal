let { BuildSpec, HostPath, OutputLib, Local, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "libstdcxx",
  inputs = [
    { file = "build.source.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/gcc-15.2.0.tar.xz",
      sha256 = "438fd996826b0c82485a29da03a72d71d6e3541a83ec702df4271f6fe025d24e"
    } | Source,
    base,
    toolchain,
  ],
  cmd = "./build.source.sh",
  outputs = {
    usr_lib = { glob = "usr/lib/*" } | OutputLib,
    usr_include = { glob = "usr/include/c++/**/*" } | OutputLib,
  },
} | BuildSpec
