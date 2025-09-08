let { BuildSpec, HostPath, OutputLib, Local, Prebuilt, .. } = import "minimal.ncl" in
{
  name = "zstd",
  inputs = [
    { package = "zstd" } | Prebuilt,
  ],
  cmd = "",
  outputs = {
    zstd_bin = { glob = "usr/bin/zstd" } | OutputLib,
    zstdcat = { glob = "usr/bin/zstdcat" } | OutputLib,
    zstdgrep = { glob = "usr/bin/zstdgrep" } | OutputLib,
    zstdless = { glob = "usr/bin/zstdless" } | OutputLib,
    zstdmt = { glob = "usr/bin/zstdmt" } | OutputLib,
    unzstd = { glob = "usr/bin/unzstd" } | OutputLib,
    libzstd = { glob = "usr/lib/libzstd.so*" } | OutputLib,
    libzstd_a = { glob = "usr/lib/libzstd.a" } | OutputLib,
    headers = { glob = "usr/include/*.h" } | OutputLib,
    pkgconfig = { glob = "usr/lib/pkgconfig/libzstd.pc" } | OutputLib,
  },
} | BuildSpec
