let { BuildSpec, Local, OutputData, OutputLib, Prebuilt, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let ncurses = import "../ncurses/build.ncl" in
let make = import "../make/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "readline",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/readline-8.3.tar.gz",
      sha256 = "fe5383204467828cd495ee8d1d3c037a7eba1389c22bc6a041f627976f9061cc"
    } | Source,
    base,
    make,
    toolchain,
  ],
  runtime_deps = [
    ncurses,
  ],
  cmd = "./build.sh",
  outputs = {
    libreadline = { glob = "usr/lib/libreadline.so*" } | OutputLib,
    libhistory = { glob = "usr/lib/libhistory.so*" } | OutputLib,

    pkgconfig = { glob = "usr/lib/pkgconfig/*.pc" } | OutputData,
    headers = { glob = "usr/include/readline/*.h" } | OutputData,
  },

  replace_on_cycle =
    {
      name = "readline (prebuilt)",
      inputs = [
        { package = "readline" } | Prebuilt,
      ],
      runtime_deps = [
        ncurses,
      ],
      cmd = "",
      outputs = {
        usr_lib = { glob = "usr/lib/**/*" } | OutputLib,
        usr_include = { glob = "usr/include/**/*" } | OutputData,
      },
    } | BuildSpec,
} | BuildSpec
