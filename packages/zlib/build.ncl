let { BuildSpec, OutputLib, Local, Prebuilt, .. } = import "minimal.ncl" in
{
  name = "zlib",
  inputs = [
    { package = "zlib" } | Prebuilt,
  ],
  cmd = "",
  outputs = {
    libz = { glob = "usr/lib/libz.so*" } | OutputLib,
    zconf_h = { glob = "usr/include/zconf.h" } | OutputLib,
    zlib_h = { glob = "usr/include/zlib.h" } | OutputLib,
    pkgconfig = { glob = "usr/lib/pkgconfig/zlib.pc" } | OutputLib,
  },
} | BuildSpec
