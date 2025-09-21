let { BuildSpec, Local, OutputBin, OutputData, OutputLib, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let pkgconf = import "../pkgconf/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
let ncurses = import "../ncurses/build.ncl" in
{
  name = "procps-ng",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/procps-ng-4.0.5.tar.xz",
      sha256 = "c2e6d193cc78f84cd6ddb72aaf6d5c6a9162f0470e5992092057f5ff518562fa"
    } | Source,
    base,
    pkgconf,
    toolchain,
  ],
  runtime_deps = [
    ncurses,
  ],
  cmd = "./build.sh",
  outputs = {
    bins = { path = "usr/bin/*" } | OutputBin,
    sbins = { path = "usr/sbin/*" } | OutputBin,
    libs = { glob = "usr/lib/*" } | OutputLib,

    includes = { data = "usr/include/libproc2/*" } | OutputData,
    pkgconfig = { data = "usr/lib/pkgconfig/*" } | OutputData,
  },
} | BuildSpec
