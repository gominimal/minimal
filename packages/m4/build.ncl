let { BuildSpec, OutputBin, OutputLib, Local, Prebuilt, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "m4",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/m4-1.4.20.tar.xz",
      sha256 = "e236ea3a1ccf5f6c270b1c4bb60726f371fa49459a8eaaebc90b216b328daf2b"
    } | Source,
    base,
    toolchain,
  ],
  cmd = "./build.sh",
  outputs = {
    usr_bin = { path = "usr/bin/**/*" } | OutputBin,
    usr_share = { glob = "usr/share/**/*" } | OutputLib,
  },

  replace_on_cycle = {
    name = "m4 (prebuilt)",
    inputs = [
      { package = "m4" } | Prebuilt,
    ],
    cmd = "",
    outputs = {
      usr = { glob = "usr/**/*" } | OutputLib,
    },
  } | BuildSpec,
} | BuildSpec