let { BuildSpec, Local, OutputLib, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "libunistring",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/libunistring-1.3.tar.xz",
      sha256 = "f245786c831d25150f3dfb4317cda1acc5e3f79a5da4ad073ddca58886569527"
    } | Source,
    base,
    toolchain,
  ],
  cmd = "./build.sh",
  outputs = {
    libs = { glob = "usr/lib/libunistring*" } | OutputLib,
    includes = { glob = "usr/include/*.h" } | OutputLib,
    includes_unistring = { glob = "usr/include/unistring/*.h" } | OutputLib,
    doc = { glob = "usr/share/doc/libunistring-1.3/*" } | OutputLib,
  },
} | BuildSpec
