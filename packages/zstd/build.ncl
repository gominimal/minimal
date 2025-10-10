let { BuildSpec, Local, OutputLib, Prebuilt, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let lz4 = import "../lz4/build.ncl" in
let make = import "../make/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
let zlib = import "../zlib/build.ncl" in
{
  name = "zstd",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/zstd-1.5.6.tar.gz",
      sha256 = "8c29e06cf42aacc1eafc4077ae2ec6c6fcb96a626157e0593d5e82a34fd403c1"
    } | Source,
    base,
    make,
    lz4,
    toolchain,
    zlib,
  ],
  cmd = "./build.sh",
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

  replace_on_cycle =
    {
      name = "zstd (prebuilt)",
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
    } | BuildSpec,
} | BuildSpec
