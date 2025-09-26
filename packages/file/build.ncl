let { BuildSpec, Local, OutputBin, OutputLib, Prebuilt, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "file",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/file-5.46.tar.gz",
      sha256 = "c9cc77c7c560c543135edc555af609d5619dbef011997e988ce40a3d75d86088"
    } | Source,
    base,
    toolchain,
  ],
  cmd = "./build.sh",
  outputs = {
    file_bin = { glob = "usr/bin/file" } | OutputBin,
    libmagic = { glob = "usr/lib/libmagic.so*" } | OutputLib,
    headers = { glob = "usr/include/magic.h" } | OutputLib,
    magic_data = { glob = "usr/share/misc/magic*" } | OutputLib,
  },

  replace_on_cycle =
    {
      name = "file (prebuilt)",
      inputs = [
        { package = "file" } | Prebuilt,
      ],
      cmd = "",
      outputs = {
        usr_bin = { glob = "usr/bin/**/*" } | OutputBin,
        usr_lib = { glob = "usr/lib/**/*" } | OutputLib,
        usr_include = { glob = "usr/include/**/*" } | OutputLib,
        usr_share = { glob = "usr/share/**/*" } | OutputLib,
      }
    } | BuildSpec,
} | BuildSpec
