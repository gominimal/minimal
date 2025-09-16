let { BuildSpec, OutputLib, Local, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let bison = import "../bison/build.ncl" in
let m4 = import "../m4/build.ncl" in
let python = import "../python/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "glibc",
  inputs = [
    { file = "build.source.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/glibc-2.42.tar.xz",
      sha256 = "d1775e32e4628e64ef930f435b67bb63af7599acb6be2b335b9f19f16509f17f"
    } | Source,
    base,
    bison,
    m4,
    python,
    toolchain,
  ],
  cmd = "./build.source.sh",
  outputs = {
    etc = { glob = "etc/**/*" } | OutputLib,
    usr = { glob = "usr/**/*" } | OutputLib,
    var = { glob = "var/**/*" } | OutputLib,
  },
} | BuildSpec
