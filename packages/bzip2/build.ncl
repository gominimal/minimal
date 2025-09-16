let { BuildSpec, OutputBin, OutputData, OutputLib, Local, Prebuilt, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "bzip2",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/bzip2-1.0.8.tar.gz",
      sha256 = "ab5a03176ee106d3f0fa90e381da478ddae405918153cca248e682cd0c4a2269"
    } | Source,
    base,
    toolchain,
  ],
  cmd = "./build.sh",
  outputs = {
    bunzip2 = { path = "usr/bin/bunzip2" } | OutputBin,
    bzcat = { path = "usr/bin/bzcat" } | OutputBin,
    bzcmp = { path = "usr/bin/bzcmp" } | OutputBin,
    bzdiff = { path = "usr/bin/bzdiff" } | OutputBin,
    bzegrep = { path = "usr/bin/bzegrep" } | OutputBin,
    bzfgrep = { path = "usr/bin/bzfgrep" } | OutputBin,
    bzgrep = { path = "usr/bin/bzgrep" } | OutputBin,
    bzip2 = { path = "usr/bin/bzip2" } | OutputBin,
    bzip2recover = { path = "usr/bin/bzip2recover" } | OutputBin,
    bzless = { path = "usr/bin/bzless" } | OutputBin,
    bzmore = { path = "usr/bin/bzmore" } | OutputBin,

    libbz2 = { glob = "usr/lib/libbz2.so*" } | OutputLib,

    headers = { data = "usr/include/bzlib.h" } | OutputData,
  },

  replace_on_cycle = {
    name = "bzip2 (prebuilt)",
    inputs = [
      { package = "bzip2" } | Prebuilt,
    ],
    cmd = "",
    outputs = {},
  } | BuildSpec,
} | BuildSpec