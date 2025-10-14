let { BuildSpec, Local, OutputBin, OutputData, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let make = import "../make/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
let ncurses = import "../ncurses/build.ncl" in

let version = "1.4.5" in
{
  name = "btop",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "https://github.com/aristocratos/btop/archive/refs/tags/v%{version}.tar.gz",
      sha256 = "0ffe03d3e26a3e9bbfd5375adf34934137757994f297d6b699a46edd43c3fc02",
      extract = true,
    } | Source,
    base,
    make,
    toolchain,
  ],
  runtime_deps = [ncurses],
  cmd = "./build.sh",
  outputs = {
    btop = { glob = "usr/bin/btop" } | OutputBin,
    data = { glob = "usr/share/**/*" } | OutputData,
  },
} | BuildSpec
