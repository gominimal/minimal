let { BuildSpec, OutputLib, Local, Prebuilt, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
let zlib = import "../zlib/build.ncl" in
{
  name = "pcre2",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/pcre2-10.46.tar.bz2",
      sha256 = "15fbc5aba6beee0b17aecb04602ae39432393aba1ebd8e39b7cabf7db883299f"
    } | Source,
    base,
    toolchain,
    zlib,
  ],
  cmd = "./build.sh",
  outputs = {
    usr = { glob = "usr/**/*" } | OutputLib,
  },

  replace_on_cycle = {
    name = "pcre2 (prebuilt)",
    inputs = [
      { package = "pcre2" } | Prebuilt,
    ],
    cmd = "",
    outputs = {
      usr = { glob = "usr/**/*" } | OutputLib,
    },
  } | BuildSpec,
} | BuildSpec