let { BuildSpec, OutputLib, Local, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "gzip",
  inputs = [
    { file = "build.source.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/gzip-1.14.tar.xz",
      sha256 = "01a7b881bd220bfdf615f97b8718f80bdfd3f6add385b993dcf6efd14e8c0ac6"
    } | Source,
    base,
    toolchain,
  ],
  cmd = "./build.source.sh",
  outputs = {
    binaries = { glob = "usr/bin/*" } | OutputLib,
    info = { glob = "usr/share/info/*.info" } | OutputLib,
    man = { glob = "usr/share/man/man1/*.1" } | OutputLib,
  },
} | BuildSpec
