let { BuildSpec, OutputLib, Local, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "libxcrypt",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/libxcrypt-4.4.38.tar.xz",
      sha256 = "80304b9c306ea799327f01d9a7549bdb28317789182631f1b54f4511b4206dd6"
    } | Source,
    base,
    toolchain,
  ],
  cmd = "./build.sh",
  outputs = {
    lib = { glob = "usr/lib/*" } | OutputLib,
    usr_include = { glob = "usr/include/**/*" } | OutputLib,
    man = { glob = "usr/share/man/**/*" } | OutputLib,
    pkgconfig = { glob = "usr/lib/pkgconfig/*" } | OutputLib,
  },
} | BuildSpec
