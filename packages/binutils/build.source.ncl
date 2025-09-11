let { BuildSpec, OutputLib, Local, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let dejagnu = import "../dejagnu/build.ncl" in
let expect = import "../expect/build.ncl" in
let zlib = import "../zlib/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "binutils",
  inputs = [
    {
      url = "gs://minimal-staging-archives/binutils-2.45.tar.xz",
      sha256 = "c50c0e7f9cb188980e2cc97e4537626b1672441815587f1eab69d2a1bfbef5d2"
    } | Source,
    { file = "build.source.sh" } | Local,
    base,
    dejagnu,
    expect,
    zlib,
    toolchain,
  ],
  cmd = "./build.source.sh",
  outputs = {
    etc = { glob = "etc/*" } | OutputLib,
    usr_bin = { glob = "usr/bin/*" } | OutputLib,
    usr_lib = { glob = "usr/lib/*" } | OutputLib,
    usr_lib_ldscripts = { glob = "usr/lib/ldscripts/*" } | OutputLib,
    usr_lib_gprofng = { glob = "usr/lib/gprofng/*" } | OutputLib,
    usr_lib_bfdplugins = { glob = "usr/lib/bfd-plugins/*" } | OutputLib,
    usr_include = { glob = "usr/include/*" } | OutputLib,
  },
} | BuildSpec
