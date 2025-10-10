let { BuildSpec, Local, OutputLib, Prebuilt, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
let make = import "../make/build.ncl" in
let glibc = import "../glibc/build.ncl" in
{
  name = "xz",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/xz-5.8.1.tar.xz",
      sha256 = "0b54f79df85912504de0b14aec7971e3f964491af1812d83447005807513cd9e"
    } | Source,
    base,
    make,
    toolchain,
  ],
  runtime_deps = [
    glibc,
  ],

  cmd = "./build.sh",
  outputs = {
    xz_bin = { glob = "usr/bin/xz" } | OutputLib,
    xzcat = { glob = "usr/bin/xzcat" } | OutputLib,
    xzcmp = { glob = "usr/bin/xzcmp" } | OutputLib,
    xzdec = { glob = "usr/bin/xzdec" } | OutputLib,
    xzdiff = { glob = "usr/bin/xzdiff" } | OutputLib,
    xzegrep = { glob = "usr/bin/xzegrep" } | OutputLib,
    xzfgrep = { glob = "usr/bin/xzfgrep" } | OutputLib,
    xzgrep = { glob = "usr/bin/xzgrep" } | OutputLib,
    xzless = { glob = "usr/bin/xzless" } | OutputLib,
    xzmore = { glob = "usr/bin/xzmore" } | OutputLib,
    lzcat = { glob = "usr/bin/lzcat" } | OutputLib,
    lzcmp = { glob = "usr/bin/lzcmp" } | OutputLib,
    lzdiff = { glob = "usr/bin/lzdiff" } | OutputLib,
    lzegrep = { glob = "usr/bin/lzegrep" } | OutputLib,
    lzfgrep = { glob = "usr/bin/lzfgrep" } | OutputLib,
    lzgrep = { glob = "usr/bin/lzgrep" } | OutputLib,
    lzless = { glob = "usr/bin/lzless" } | OutputLib,
    lzma = { glob = "usr/bin/lzma" } | OutputLib,
    lzmadec = { glob = "usr/bin/lzmadec" } | OutputLib,
    lzmainfo = { glob = "usr/bin/lzmainfo" } | OutputLib,
    lzmore = { glob = "usr/bin/lzmore" } | OutputLib,
    unlzma = { glob = "usr/bin/unlzma" } | OutputLib,
    unxz = { glob = "usr/bin/unxz" } | OutputLib,

    liblzma = { glob = "usr/lib/liblzma.so*" } | OutputLib,

    headers = { glob = "usr/include/lzma.h" } | OutputLib,
    lzma_headers = { glob = "usr/include/lzma/*.h" } | OutputLib,
  },

  replace_on_cycle =
    {
      name = "xz (prebuilt)",
      inputs = [
        { package = "xz" } | Prebuilt,
      ],
      cmd = "",
      outputs = {
        usr_bin = { glob = "usr/bin/**/*" } | OutputLib,
        usr_lib = { glob = "usr/lib/**/*" } | OutputLib,
        usr_include = { glob = "usr/include/**/*" } | OutputLib,
      },
    } | BuildSpec,
} | BuildSpec
