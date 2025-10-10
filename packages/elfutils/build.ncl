let { BuildSpec, Local, OutputBin, OutputData, OutputLib, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let m4 = import "../m4/build.ncl" in
let make = import "../make/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in

let bzip2 = import "../bzip2/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let libz = import "../zlib/build.ncl" in
let xz = import "../xz/build.ncl" in
let zstd = import "../zstd/build.ncl" in
let gcc = import "../gcc/build.ncl" in
{
  name = "elfutils",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/elfutils-0.192.tar.bz2",
      sha256 = "616099beae24aba11f9b63d86ca6cc8d566d968b802391334c91df54eab416b4"
    } | Source,
    base,
    m4,
    make,
    toolchain,
  ],
  runtime_deps = [
    bzip2,
    glibc,
    libz,
    xz,
    zstd,
    gcc, # TODO: Use subsets for libgcc_s and libstdc++
  ],
  cmd = "./build.sh",
  outputs = {
    bins = { glob = "usr/bin/*" } | OutputBin,
    libs = { glob = "usr/lib/*.{a,so*}" } | OutputLib,

    includes = { glob = "usr/include/**" } | OutputData,
  },
} | BuildSpec
