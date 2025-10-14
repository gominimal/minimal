let { BuildSpec, Local, OutputLib, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let make = import "../make/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in

let glibc = import "../glibc/build.ncl" in
let zlib = import "../zlib/build.ncl" in
{
  name = "sqlite",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/sqlite-autoconf-3500400.tar.gz",
      sha256 = "a3db587a1b92ee5ddac2f66b3edb41b26f9c867275782d46c3a088977d6a5b18"
    } | Source,
    base,
    make,
    toolchain,
  ],
  runtime_deps = [
    glibc,
    zlib,
  ],

  cmd = "./build.sh",
  outputs = {
    bin = { glob = "usr/bin/*" } | OutputLib,
    lib = { glob = "usr/lib/*" } | OutputLib,
    usr_include = { glob = "usr/include/*" } | OutputLib,
    man = { glob = "usr/share/man/**/*" } | OutputLib,
    pkgconfig = { glob = "usr/lib/pkgconfig/*.pc" } | OutputLib,
  },
} | BuildSpec
