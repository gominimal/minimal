let { BuildSpec, OutputBin, OutputData, Local, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
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
    pkgconf,
    toolchain,
  ],
  runtime_deps = [
    acl,
    ncurses,
  ],
  cmd = "./build.sh",
  outputs = {
    vim = { path = "usr/bin/vim" } | OutputBin,
    vimdiff = { path = "usr/bin/vimdiff" } | OutputBin,

    data = { data = "usr/share/**/*" } | OutputData,
  },
} | BuildSpec
