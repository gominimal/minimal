let { BuildSpec, HostPath, OutputLib, OutputBin, Local, Source, Prebuilt, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "make",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/make-4.4.1.tar.gz",
      sha256 = "dd16fb1d67bfab79a72f5e8390735c49e3e8e70b4945a15ab1f81ddb78658fb3"
    } | Source,
    base,
    toolchain,
  ],
  cmd = "./build.sh",
  outputs = {
    make_bin = { path = "usr/bin/make" } | OutputBin,
    headers = { glob = "usr/include/*.h" } | OutputLib,
    info_pages = { glob = "usr/share/info/*.info*" } | OutputLib,
    man_pages = { glob = "usr/share/man/man1/*.1" } | OutputLib,
    locale_files = { glob = "usr/share/locale/*/LC_MESSAGES/*.mo" } | OutputLib,
  },

  replace_on_cycle = {
    name = "make (prebuilt)",
    inputs = [
      { package = "make" } | Prebuilt,
    ],
    cmd = "",
    outputs = {
      make = { path = "usr/bin/make" } | OutputBin,
    },
  } | BuildSpec,
} | BuildSpec