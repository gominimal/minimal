let { BuildSpec, Local, OutputBin, OutputData, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let make = import "../make/build.ncl" in
let pkgconf = import "../pkgconf/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
let acl = import "../acl/build.ncl" in
let ncurses = import "../ncurses/build.ncl" in
{
  name = "vim",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/vim-9.1.1629.tar.gz",
      sha256 = "d92c6550e8eca741085fce94e5b0d3d13d2c62fcb5b69bf5a6010d3114de4828"
    } | Source,
    base,
    make,
    pkgconf,
    toolchain,
  ],
  runtime_deps = [
    acl,
    ncurses,
  ],
  cmd = "./build.sh",
  outputs = {
    vim = { glob = "usr/bin/vim" } | OutputBin,
    vimdiff = { glob = "usr/bin/vimdiff" } | OutputBin,

    data = { glob = "usr/share/**/*" } | OutputData,
  },
} | BuildSpec
