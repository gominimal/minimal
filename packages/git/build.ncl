let { BuildSpec, OutputData, OutputLib, OutputBin, Local, Source, .. } = import "minimal.ncl" in
let curl = import "../curl/build.ncl" in
let gettext = import "../gettext/build.ncl" in
let make = import "../make/build.ncl" in
let pcre2 = import "../pcre2/build.ncl" in
let python = import "../python/build.ncl" in
let base = import "../base/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
let zlib = import "../zlib/build.ncl" in
{
  name = "git",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/git-2.51.0.tar.xz",
      sha256 = "60a7c2251cc2e588d5cd87bae567260617c6de0c22dca9cdbfc4c7d2b8990b62",
    } | Source,
    base,
    gettext,
    make,
    python,
    toolchain,
  ],
  runtime_deps = [
    curl,
    pcre2,
    zlib,
  ],
  cmd = "./build.sh",
  outputs = {
    bins = { path = "usr/bin/*" } | OutputBin,
    git_core = { glob = "usr/libexec/git-core/*" } | OutputLib,
    git_core_mergetools = { glob = "usr/libexec/git-core/mergetools/*" } | OutputLib,

    locale = { glob = "usr/share/locale/**/*" } | OutputLib,
  },
} | BuildSpec
