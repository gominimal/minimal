let { BuildSpec, OutputLib, Local, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "libffi",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/libffi-3.5.2.tar.gz",
      sha256 = "f3a3082a23b37c293a4fcd1053147b371f2ff91fa7ea1b2a52e335676bac82dc"
    } | Source,
    base,
    toolchain,
  ],
  cmd = "./build.sh",
  outputs = {
    lib = { glob = "usr/lib/*" } | OutputLib,
    usr_include = { glob = "usr/include/*" } | OutputLib,
    pkgconfig = { glob = "usr/lib/pkgconfig/*" } | OutputLib,
  },
} | BuildSpec
