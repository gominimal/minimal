let { BuildSpec, Local, OutputBin, OutputLib, Prebuilt, Source, .. } = import "minimal.ncl" in
# base
let bash = import "../bash/build.ncl" in
let bzip2 = import "../bzip2/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let diffutils = import "../diffutils/build.ncl" in
let file = import "../file/build.ncl" in
let findutils = import "../findutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let grep = import "../grep/build.ncl" in
let gzip = import "../gzip/build.ncl" in
let make = import "../make/build.ncl" in
let perl = import "../perl/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let xz = import "../xz/build.ncl" in
# toolchain
let binutils = import "../binutils/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
{
  name = "make",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/make-4.4.1.tar.gz",
      sha256 = "dd16fb1d67bfab79a72f5e8390735c49e3e8e70b4945a15ab1f81ddb78658fb3"
    } | Source,
    # base
    bash,
    bzip2,
    coreutils,
    diffutils,
    file,
    findutils,
    gawk,
    grep,
    gzip,
    make,
    perl,
    sed,
    tar,
    xz,
    # toolchain
    binutils,
    gcc,
    linux_headers,
  ],
  runtime_deps = [
    glibc,
  ],

  cmd = "./build.sh",
  outputs = {
    make_bin = { glob = "usr/bin/make" } | OutputBin,
    headers = { glob = "usr/include/*.h" } | OutputLib,
    info_pages = { glob = "usr/share/info/*.info*" } | OutputLib,
    man_pages = { glob = "usr/share/man/man1/*.1" } | OutputLib,
    locale_files = { glob = "usr/share/locale/*/LC_MESSAGES/*.mo" } | OutputLib,
  },

  replace_on_cycle =
    {
      name = "make (prebuilt)",
      inputs = [
        { package = "make" } | Prebuilt,
      ],
      cmd = "",
      outputs = {
        make = { glob = "usr/bin/make" } | OutputBin,
      },
    } | BuildSpec,
} | BuildSpec
