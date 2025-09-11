let { BuildSpec, HostPath, OutputLib, OutputBin, Local, Prebuilt, Source, .. } = import "minimal.ncl" in
let acl = import "../acl/build.ncl" in
let attr = import "../attr/build.ncl" in
let base = import "../base/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in

{
  name = "sed",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/sed-4.9.tar.xz",
      sha256 = "6e226b732e1cd739464ad6862bd1a1aba42d7982922da7a53519631d24975181"
    } | Source,
    acl,
    base,
    toolchain,
  ],
  runtime_deps = [
    acl,
    attr,
  ],

  cmd = "./build.sh",
  outputs = {
    usr_bin = { path = "usr/bin/**/*" } | OutputBin,
    usr_share = { glob = "usr/share/**/*" } | OutputLib,
  },

  replace_on_cycle =
    {
      name = "sed (prebuilt)",
      inputs = [
        { package = "sed" } | Prebuilt,
      ],
      runtime_deps = [
        acl,
        attr,
      ],
      cmd = "",
      outputs = {
        sed_bin = { path = "usr/bin/sed" } | OutputBin,
      },
    } | BuildSpec,
} | BuildSpec
