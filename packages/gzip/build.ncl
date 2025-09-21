let { BuildSpec, Local, OutputBin, OutputData, Prebuilt, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "gzip",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/gzip-1.14.tar.xz",
      sha256 = "01a7b881bd220bfdf615f97b8718f80bdfd3f6add385b993dcf6efd14e8c0ac6"
    } | Source,
    base,
    toolchain,
  ],
  cmd = "./build.sh",
  outputs = {
    binaries = { path = "usr/bin/*" } | OutputBin,
    info = { data = "usr/share/info/*.info" } | OutputData,
    man = { data = "usr/share/man/man1/*.1" } | OutputData,
  },

  replace_on_cycle =
    {
      name = "gzip (prebuilt)",
      inputs = [
        { package = "gzip" } | Prebuilt,
      ],
      cmd = "",
      outputs = {
        binaries = { path = "usr/bin/*" } | OutputBin,
      },
    } | BuildSpec,
} | BuildSpec
