let { BuildSpec, Local, OutputBin, OutputData, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
let make = import "../make/build.ncl" in

let glibc = import "../glibc/build.ncl" in
let file = import "../file/build.ncl" in
let ncurses = import "../ncurses/build.ncl" in
let zlib = import "../zlib/build.ncl" in
{
  name = "strace",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/strace-6.17.tar.xz",
      sha256 = "0a7c7bedc7efc076f3242a0310af2ae63c292a36dd4236f079e88a93e98cb9c0"
    } | Source,
    base,
    make,
    toolchain,
  ],
  runtime_deps = [
    glibc,
  ],

  cmd = "./build.sh",
  outputs = {
    strace = { glob = "usr/bin/strace" } | OutputBin,

    mans = { glob = "usr/share/man/**" } | OutputData,
  },
} | BuildSpec
