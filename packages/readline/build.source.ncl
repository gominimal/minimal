let { BuildSpec, OutputLib, Local, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let ncurses = import "../ncurses/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "readline",
  inputs = [
    { file = "build.source.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/readline-8.3.tar.gz",
      sha256 = "fe5383204467828cd495ee8d1d3c037a7eba1389c22bc6a041f627976f9061cc"
    } | Source,
    base,
    ncurses,
    toolchain,
  ],
  cmd = "./build.source.sh",
  outputs = {
    libreadline = { glob = "usr/lib/libreadline.so*" } | OutputLib,
    libhistory = { glob = "usr/lib/libhistory.so*" } | OutputLib,
    pkgconfig = { glob = "usr/lib/pkgconfig/*.pc" } | OutputLib,

    headers = { glob = "usr/include/readline/*.h" } | OutputLib,
  },
} | BuildSpec
