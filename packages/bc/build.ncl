let { BuildSpec, OutputLib, Local, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let readline = import "../readline/build.ncl" in
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
    readline,
    toolchain,
  ],
  cmd = "./build.sh",
  outputs = {
    bc_bin = { glob = "usr/bin/bc" } | OutputLib,
    dc_bin = { glob = "usr/bin/dc" } | OutputLib,
    bc_man = { glob = "usr/share/man/man1/bc.1" } | OutputLib,
    dc_man = { glob = "usr/share/man/man1/dc.1" } | OutputLib,
  },
} | BuildSpec
