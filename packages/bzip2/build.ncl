let { BuildSpec, Local, OutputBin, OutputData, OutputLib, Prebuilt, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let make = import "../make/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
let glibc = import "../glibc/build.ncl" in
{
  name = "bzip2",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/bzip2-1.0.8.tar.gz",
      sha256 = "ab5a03176ee106d3f0fa90e381da478ddae405918153cca248e682cd0c4a2269"
    } | Source,
    base,
    make,
    toolchain,
  ],
  runtime_deps = [
    glibc,
  ],

  cmd = "./build.sh",
  outputs = {
    bunzip2 = { glob = "usr/bin/bunzip2" } | OutputBin,
    bzcat = { glob = "usr/bin/bzcat" } | OutputBin,
    bzcmp = { glob = "usr/bin/bzcmp" } | OutputBin,
    bzdiff = { glob = "usr/bin/bzdiff" } | OutputBin,
    bzegrep = { glob = "usr/bin/bzegrep" } | OutputBin,
    bzfgrep = { glob = "usr/bin/bzfgrep" } | OutputBin,
    bzgrep = { glob = "usr/bin/bzgrep" } | OutputBin,
    bzip2 = { glob = "usr/bin/bzip2" } | OutputBin,
    bzip2recover = { glob = "usr/bin/bzip2recover" } | OutputBin,
    bzless = { glob = "usr/bin/bzless" } | OutputBin,
    bzmore = { glob = "usr/bin/bzmore" } | OutputBin,

    libs = { glob = "usr/lib/*" } | OutputLib,

    headers = { glob = "usr/include/bzlib.h" } | OutputData,
  },

  replace_on_cycle =
    {
      name = "bzip2 (prebuilt)",
      inputs = [
        { package = "bzip2" } | Prebuilt,
      ],
      cmd = "",
      outputs = {},
    } | BuildSpec,
} | BuildSpec
