let { BuildSpec, OutputData, OutputLib, Local, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let python = import "../python/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
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
  ],

  cmd = "./build.sh",

  outputs = {
    libs = { glob = "usr/lib/*" } | OutputLib,

    includes = { data = "usr/include/**/*" } | OutputData,
    cmake_data = { data = "usr/lib/cmake/**/*" } | OutputData,
  },
} | BuildSpec
