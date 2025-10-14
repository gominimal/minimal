let { BuildSpec, Local, OutputBin, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let sed = import "../sed/build.ncl" in
let make = import "../make/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
let glibc = import "../glibc/build.ncl" in
{
  name = "inetutils",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/inetutils-2.6.tar.xz",
      sha256 = "68bedbfeaf73f7d86be2a7d99bcfbd4093d829f52770893919ae174c0b2357ca"
    } | Source,
    base,
    make,
    sed,
    toolchain,
  ],
  runtime_deps = [
    glibc,
  ],

  cmd = "./build.sh",
  outputs = {
    bins = { glob = "usr/bin/*" } | OutputBin,
  },
} | BuildSpec
