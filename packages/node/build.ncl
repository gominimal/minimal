let { BuildSpec, Local, OutputBin, OutputData, Source, .. } = import "minimal.ncl" in
let make = import "../make/build.ncl" in
let openssl = import "../openssl/build.ncl" in
let python = import "../python/build.ncl" in
let base = import "../base/build.ncl" in
let pkgconf = import "../pkgconf/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
let icu = import "../icu/build.ncl" in
let libuv = import "../libuv/build.ncl" in
let sqlite = import "../sqlite/build.ncl" in
let zlib = import "../zlib/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let gcc = import "../gcc/build.ncl" in

let version = "24.9.0" in
{
  name = "node",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/node-v%{version}.tar.xz",
      sha256 = "f17bc4cb01f59098c34a288c1bb109a778867c14eeb0ebbd608d0617b1193bbf",
    } | Source,
    base,
    make,
    pkgconf,
    python,
    toolchain,
  ],
  runtime_deps = [
    openssl,
    icu,
    libuv,
    zlib,
    sqlite,
    glibc,
    gcc, # TODO: Use a subset thats just libstdc, libm, libgcc_s
  ],

  cmd = "./build.sh",
  build_args = {
    include version,
  },

  outputs = {
    bins = { glob = "usr/bin/*" } | OutputBin,
    node_modules = { glob = "usr/lib/node_modules/**" } | OutputData,

    includes = { glob = "usr/include/**" } | OutputData,
    mans = { glob = "usr/share/man/**" } | OutputData,
  },
} | BuildSpec
