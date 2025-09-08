let { BuildSpec, HostPath, OutputLib, Local, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "findutils",
  inputs = [
    {
      url = "gs://minimal-staging-archives/findutils-4.10.0.tar.xz",
      sha256 = "1387e0b67ff247d2abde998f90dfbf70c1491391a59ddfecb8ae698789f0a4f5"
    } | Source,
    { file = "build.source.sh" } | Local,
    base,
    toolchain,
  ],
  cmd = "./build.source.sh",
  outputs = {
    usr_bin = { glob = "usr/bin/**/*" } | OutputLib,
    usr_libexec = { glob = "usr/libexec/**/*" } | OutputLib,
    usr_share = { glob = "usr/share/**/*" } | OutputLib,
  },
} | BuildSpec
