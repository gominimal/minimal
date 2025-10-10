let { BuildSpec, Local, OutputBin, OutputData, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let readline = import "../readline/build.ncl" in
let make = import "../make/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "bc",
  inputs = [
    {
      url = "gs://minimal-staging-archives/bc-7.0.3.tar.xz",
      sha256 = "91eb74caed0ee6655b669711a4f350c25579778694df248e28363318e03c7fc4"
    } | Source,
    { file = "build.sh" } | Local,
    base,
    make,
    toolchain,
  ],
  runtime_deps = [
    readline,
  ],
  cmd = "./build.sh",
  outputs = {
    bins = { glob = "usr/bin/*" } | OutputBin,
    mans = { glob = "usr/share/man/**" } | OutputData,
  },
} | BuildSpec
