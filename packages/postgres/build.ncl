let { BuildSpec, Local, OutputBin, OutputData, OutputLib, Source, .. } = import "minimal.ncl" in
let make = import "../make/build.ncl" in
let perl = import "../perl/build.ncl" in
let base = import "../base/build.ncl" in
let flex = import "../flex/build.ncl" in
let bison = import "../bison/build.ncl" in
let m4 = import "../m4/build.ncl" in
let pkgconf = import "../pkgconf/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in

let openssl = import "../openssl/build.ncl" in
let readline = import "../readline/build.ncl" in
let icu = import "../icu/build.ncl" in
let zstd = import "../zstd/build.ncl" in
let zlib = import "../zlib/build.ncl" in

let version = "18.0" in
{
  name = "postgres",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/postgresql-%{version}.tar.gz",
      sha256 = "30e97fc1f1594a7226580ea51080d3d883f4a0fb6ff716dbf7ad09e9f7e93ab2",
    } | Source,
    base,
    make,
    perl,
    toolchain,
    flex,
    bison,
    m4,
    pkgconf,
  ],
  runtime_deps = [
    openssl,
    readline,
    icu,
    zstd,
    zlib,
  ],

  cmd = "./build.sh",
  build_args = {
    include version,
  },

  outputs = {
    bins = { glob = "usr/bin/*" } | OutputBin,
    libs = { glob = "usr/lib/**" } | OutputLib,
    includes = { glob = "usr/include/**" } | OutputData,
    share = { glob = "usr/share/postgresql/**" } | OutputData,
  },
} | BuildSpec
