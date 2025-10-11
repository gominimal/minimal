let { BuildSpec, Local, OutputData, OutputLib, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let python = import "../python/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
let xz = import "../xz/build.ncl" in
{
  name = "boost",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/boost-1.89.0-b2-nodocs.tar.xz",
      sha256 = "875cc413afa6b86922b6df3b2ad23dec4511c8a741753e57c1129e7fa753d700",
    } | Source,
    base,
    python,
    toolchain,
  ],
  runtime_deps = [
    gcc, # TODO: We really need to use a subset for this
    glibc,
    xz,
  ],

  cmd = "./build.sh",

  outputs = {
    libs = { glob = "usr/lib/*" } | OutputLib,

    includes = { glob = "usr/include/boost/**" } | OutputData,
    cmake_data = { glob = "usr/lib/cmake/**/*" } | OutputData,
  },
} | BuildSpec
