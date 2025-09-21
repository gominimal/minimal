let { BuildSpec, Local, OutputBin, OutputData, OutputLib, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "icu",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/icu4c-77_1-src.tgz",
      sha256 = "588e431f77327c39031ffbb8843c0e3bc122c211374485fa87dc5f3faff24061",
    } | Source,
    base,
    toolchain,
  ],
  runtime_deps = [
    gcc, # TODO: We really need to use a subset for this
  ],

  cmd = "./build.sh",

  outputs = {
    libs = { glob = "usr/lib/**/*" } | OutputLib,
    bins = { path = "usr/bin/*" } | OutputBin,
    sbins = { path = "usr/sbin/*" } | OutputBin,

    includes = { data = "usr/include/**/*" } | OutputData,
  },
} | BuildSpec
