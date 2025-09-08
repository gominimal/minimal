let { BuildSpec, HostPath, OutputLib, Local, Source, Prebuilt, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "zlib",
  inputs = [
    { file = "build.source.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/zlib-1.3.1.tar.gz",
      sha256 = "9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23"
    } | Source,
    base,
    toolchain,
  ],
  cmd = "./build.source.sh",
  outputs = {
    libz = { glob = "usr/lib/libz.so*" } | OutputLib,
    zconf_h = { glob = "usr/include/zconf.h" } | OutputLib,
    zlib_h = { glob = "usr/include/zlib.h" } | OutputLib,
    pkgconfig = { glob = "usr/lib/pkgconfig/zlib.pc" } | OutputLib,
  },
} | BuildSpec
