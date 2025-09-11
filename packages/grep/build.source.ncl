let { BuildSpec, OutputLib, Local, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let pcre2 = import "../pcre2/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "grep",
  inputs = [
    { file = "build.source.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/grep-3.12.tar.xz",
      sha256 = "2649b27c0e90e632eadcd757be06c6e9a4f48d941de51e7c0f83ff76408a07b9"
    } | Source,
    base,
    pcre2,
    toolchain,
  ],
  cmd = "./build.source.sh",
  outputs = {
    grep_bin = { glob = "usr/bin/grep" } | OutputLib,
    egrep_bin = { glob = "usr/bin/egrep" } | OutputLib,
    fgrep_bin = { glob = "usr/bin/fgrep" } | OutputLib,
    locales = { glob = "usr/share/locale/**/*" } | OutputLib,
  },
} | BuildSpec
