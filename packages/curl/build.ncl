let { BuildSpec, Local, OutputBin, OutputData, OutputLib, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let make = import "../make/build.ncl" in
let ca-certificates = import "../ca-certificates/build.ncl" in
let libpsl = import "../libpsl/build.ncl" in
let openssl = import "../openssl/build.ncl" in
let pkgconf = import "../pkgconf/build.ncl" in
let perl = import "../perl/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
let zlib = import "../zlib/build.ncl" in
{
  name = "curl",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/curl-8.15.0.tar.xz",
      sha256 = "6cd0a8a5b126ddfda61c94dc2c3fc53481ba7a35461cf7c5ab66aa9d6775b609"
    } | Source,
    base,
    make,
    perl,
    pkgconf,
    toolchain,
  ],
  runtime_deps = [
    ca-certificates,
    libpsl,
    openssl,
    zlib,
  ],

  cmd = "./build.sh",
  outputs = {
    bins = { glob = "usr/bin/*" } | OutputBin,
    libs = { glob = "usr/lib/libcurl.so*" } | OutputLib,

    ltconfigs = { glob = "usr/lib/libcurl.la" } | OutputData,
    pkgconfigs = { glob = "usr/lib/pkgconfig/**" } | OutputData,

    mans = { glob = "usr/share/man/**" } | OutputData,
    includes = { glob = "usr/include/curl/**" } | OutputData,
  },
} | BuildSpec
