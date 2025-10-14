let { BuildSpec, Local, OutputBin, OutputData, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let bison = import "../bison/build.ncl" in
let flex = import "../flex/build.ncl" in
let m4 = import "../m4/build.ncl" in
let pkgconf = import "../pkgconf/build.ncl" in
let make = import "../make/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
let libcap = import "../libcap/build.ncl" in
{
  name = "iproute2",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/iproute2-6.13.0.tar.xz",
      sha256 = "a43aa43338d882b44d01e549f3f105a92ae9feea32a82fae45a88e7a49302819"
    } | Source,
    base,
    bison,
    flex,
    m4,
    make,
    pkgconf,
    toolchain,
  ],
  runtime_deps = [
    libcap,
  ],
  cmd = "./build.sh",
  outputs = {
    sbins = { glob = "usr/sbin/*" } | OutputBin,

    includes = { glob = "usr/include/iproute2/*" } | OutputData,
  },
} | BuildSpec
