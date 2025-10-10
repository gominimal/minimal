let { BuildSpec, Local, OutputBin, OutputData, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
let make = import "../make/build.ncl" in

let glibc = import "../glibc/build.ncl" in
let file = import "../file/build.ncl" in
let ncurses = import "../ncurses/build.ncl" in
let zlib = import "../zlib/build.ncl" in
{
  name = "nano",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/nano-8.6.tar.xz",
      sha256 = "f7abfbf0eed5f573ab51bd77a458f32d82f9859c55e9689f819d96fe1437a619"
    } | Source,
    base,
    make,
    toolchain,
  ],
  runtime_deps = [
    glibc,
    file,
    ncurses,
    zlib,
  ],
  cmd = "./build.sh",
  outputs = {
    bin = { glob = "usr/bin/nano" } | OutputBin,
    languages = { glob = "usr/share/nano/*" } | OutputData,
    man = { glob = "usr/share/man/**/*" } | OutputData,
  },
} | BuildSpec
