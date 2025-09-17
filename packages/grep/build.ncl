let { BuildSpec, OutputBin, OutputData, Local, Prebuilt, Source, .. } = import "minimal.ncl" in

let base = import "../base/build.ncl" in
let pcre2 = import "../pcre2/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "grep",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/grep-3.12.tar.xz",
      sha256 = "2649b27c0e90e632eadcd757be06c6e9a4f48d941de51e7c0f83ff76408a07b9"
    } | Source,
    base,
    toolchain,
  ],
  runtime_deps = [
    pcre2,
  ],
  cmd = "./build.sh",
  outputs = {
    grep_bin = { path = "usr/bin/grep" } | OutputBin,
    egrep_bin = { path = "usr/bin/egrep" } | OutputBin,
    fgrep_bin = { path = "usr/bin/fgrep" } | OutputBin,
    locales = { data = "usr/share/locale/**/*" } | OutputData,
  },
  replace_on_cycle = {
    name = "grep (prebuilt)",
    inputs = [
      { package = "grep" } | Prebuilt,
    ],
    runtime_deps = [
      pcre2,
    ],
    cmd = "",
    outputs = {
      grep_bin = { path = "usr/bin/grep" } | OutputBin,
      egrep_bin = { path = "usr/bin/egrep" } | OutputBin,
      fgrep_bin = { path = "usr/bin/fgrep" } | OutputBin,
    },
  } | BuildSpec,
} | BuildSpec