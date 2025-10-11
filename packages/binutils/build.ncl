let { BuildSpec, Local, OutputBin, OutputData, OutputLib, Prebuilt, Source, .. } = import "minimal.ncl" in
# base
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let diffutils = import "../diffutils/build.ncl" in
let grep = import "../grep/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let make = import "../make/build.ncl" in
let perl = import "../perl/build.ncl" in
let sed = import "../sed/build.ncl" in
# toolchain
let binutils = import "../binutils/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let zlib = import "../zlib/build.ncl" in
{
  name = "binutils",
  inputs = [
    {
      url = "gs://minimal-staging-archives/binutils-2.45.tar.xz",
      sha256 = "c50c0e7f9cb188980e2cc97e4537626b1672441815587f1eab69d2a1bfbef5d2",
      extract = true,
    } | Source,
    { file = "build.sh" } | Local,
    # base
    bash,
    coreutils,
    diffutils,
    gawk,
    grep,
    make,
    perl,
    sed,
    # toolchain
    binutils,
    gcc,
    linux_headers,
  ],
  runtime_deps = [
    glibc,
    zlib,
    gcc, # TODO: Subsets for just libstdc++.so.6 & libgcc_s.so.1
  ],
  cmd = "./build.sh",
  outputs = {
    bins = { glob = "usr/bin/*" } | OutputBin,
    libs = { glob = "usr/lib/*.{a,so*}" } | OutputLib,

    ltconfigs = { glob = "usr/lib/*.la" } | OutputData,
    ldscripts = { glob = "usr/lib/ldscripts/*" } | OutputData,

    gprofng_libs = { glob = "usr/lib/gprofng/*.so*" } | OutputLib,
    gprofng_ltconfigs = { glob = "usr/lib/gprofng/*.la" } | OutputData,

    bfdplugins = { glob = "usr/lib/bfd-plugins/**" } | OutputLib,

    etcs = { glob = "etc/*" } | OutputData,
    includes = { glob = "usr/include/**" } | OutputData,
  },

  replace_on_cycle =
    {
      name = "binutils (prebuilt)",
      inputs = [
        { package = "binutils", sha256 = "0c2d510d101dc38a2374bdf0b97c2dcb98447c2aeb5a505c7dad9958cbcf0864" } | Prebuilt,
      ],
      runtime_deps = [
        zlib,
      ],
      cmd = "",
      outputs = {
        usr_bin = { glob = "usr/bin/**/*" } | OutputLib,
        usr_lib = { glob = "usr/lib/**/*" } | OutputLib,
        usr_include = { glob = "usr/include/**/*" } | OutputLib,
        usr_share = { glob = "usr/share/**/*" } | OutputLib,
      },
    } | BuildSpec,
} | BuildSpec
