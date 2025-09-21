let { BuildSpec, Local, OutputBin, OutputData, OutputLib, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let sed = import "../sed/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
let zlib = import "../zlib/build.ncl" in
{
  name = "pciutils",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/pciutils-3.14.0.tar.gz",
      sha256 = "e31c79722dbbe9d2906b92996ce295268e54d4342fefe3ff476caa613e51be2a"
    } | Source,
    base,
    sed,
    toolchain,
  ],
  runtime_deps = [
    zlib,
    gcc, # TODO: Just needs libresolv
  ],
  cmd = "./build.sh",
  outputs = {
    lspci = { path = "usr/bin/lspci" } | OutputBin,
    sbins = { path = "usr/sbin/*" } | OutputBin,

    libs = { glob = "usr/lib/*" } | OutputLib,

    includes = { data = "usr/include/**/*" } | OutputData,
    pkgconfig = { data = "usr/lib/pkgconfig/*" } | OutputData,
  },
} | BuildSpec
