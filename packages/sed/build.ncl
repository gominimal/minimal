let { BuildSpec, Local, OutputBin, OutputLib, Prebuilt, Source, .. } = import "minimal.ncl" in
let acl = import "../acl/build.ncl" in
let attr = import "../attr/build.ncl" in
let bash = import "../gcc/build.ncl" in
let binutils = import "../binutils/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let findutils = import "../findutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let gcc = import "../bash/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let grep = import "../grep/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in

{
  name = "sed",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/sed-4.9.tar.xz",
      sha256 = "6e226b732e1cd739464ad6862bd1a1aba42d7982922da7a53519631d24975181"
    } | Source,
    acl,
    bash,
    binutils,
    coreutils,
    findutils,
    gawk,
    gcc,
    glibc,
    grep,
    linux_headers,
    make,
    sed,
    tar,
  ],
  runtime_deps = [
    acl,
  ],

  cmd = "./build.sh",
  outputs = {
    usr_bin = { glob = "usr/bin/**/*" } | OutputBin,
    usr_share = { glob = "usr/share/**/*" } | OutputLib,
  },

  replace_on_cycle =
    {
      name = "sed (prebuilt)",
      inputs = [
        { package = "sed" } | Prebuilt,
      ],
      # TODO: runtime_deps in a cycle breaker are borked?
      # runtime_deps = [
      #   acl,
      #   attr,
      # ],
      cmd = "",
      outputs = {
        sed_bin = { glob = "usr/bin/sed" } | OutputBin,
      },
    } | BuildSpec,
} | BuildSpec
