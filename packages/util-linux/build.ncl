let { BuildSpec, Local, OutputBin, OutputData, OutputLib, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "util-linux",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/util-linux-2.40.4.tar.xz",
      sha256 = "5c1daf733b04e9859afdc3bd87cc481180ee0f88b5c0946b16fdec931975fb79"
    } | Source,
    base,
    toolchain,
  ],
  cmd = "./build.sh",
  outputs = {
    bins = { path = "usr/bin/*" } | OutputBin,
    sbins = { path = "usr/sbin/*" } | OutputBin,
    libs = { glob = "usr/lib/*" } | OutputLib,
    includes = { data = "usr/include/**/*" } | OutputData,

    completions = { data = "usr/share/bash-completion/**/*" } | OutputData,
    pkgconfig = { data = "usr/lib/pkgconfig/**/*" } | OutputData,
  },
} | BuildSpec
