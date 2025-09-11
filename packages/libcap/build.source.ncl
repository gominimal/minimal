let { BuildSpec, OutputLib, Local, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "libcap",
  inputs = [
    { file = "build.source.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/libcap-2.76.tar.xz",
      sha256 = "629da4ab29900d0f7fcc36227073743119925fd711c99a1689bbf5c9b40c8e6f"
    } | Source,
    base,
    toolchain,
  ],
  cmd = "./build.source.sh",
  outputs = {
    sbin = { glob = "usr/sbin/*" } | OutputLib,
    lib = { glob = "usr/lib/*" } | OutputLib,
    usr_include = { glob = "usr/include/**/*" } | OutputLib,
    man = { glob = "usr/share/man/**/*" } | OutputLib,
    pkgconfig = { glob = "usr/lib/pkgconfig/*" } | OutputLib,
  },
} | BuildSpec
