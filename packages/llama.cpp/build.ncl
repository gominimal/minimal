let { BuildSpec, Local, OutputBin, OutputLib, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let curl = import "../curl/build.ncl" in
let make = import "../make/build.ncl" in
let cmake = import "../cmake/build.ncl" in
let git = import "../git/build.ncl" in
let hwdata = import "../hwdata/build.ncl" in
let pciutils = import "../pciutils/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "llama.cpp",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "https://github.com/ggml-org/llama.cpp/archive/refs/tags/b6529.tar.gz",
      sha256 = "148593cc2d847734e6fa43c364e9bbb66ef8b9c6af27484f552cb6f158fe620b"
    } | Source,
    base,
    git,
    make,
    cmake,
    toolchain,
  ],
  runtime_deps = [
    curl,
    hwdata,
    pciutils,
  ],
  cmd = "./build.sh",
  outputs = {
    bins = { glob = "usr/bin/*" } | OutputBin,

    libs = { glob = "usr/lib/*" } | OutputLib,
  },
} | BuildSpec
