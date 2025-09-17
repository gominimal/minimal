let { BuildSpec, OutputLib, Local, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let glibc = import "../glibc/build.source.ncl" in
let ncurses = import "../ncurses/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "less",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/less-679.tar.gz",
      sha256 = "9b68820c34fa8a0af6b0e01b74f0298bcdd40a0489c61649b47058908a153d78"
    } | Source,
    base,
    toolchain,
  ],
  runtime_deps = [
    glibc,
    ncurses,
  ],
  cmd = "./build.sh",
  outputs = {
    bin = { glob = "usr/bin/*" } | OutputLib,
    man = { glob = "usr/share/man/**/*" } | OutputLib,
  },
} | BuildSpec
