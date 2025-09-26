let { BuildSpec, Local, OutputData, OutputLib, Prebuilt, Source, .. } = import "minimal.ncl" in
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
# other 
let dejagnu = import "../dejagnu/build.ncl" in
let expect = import "../expect/build.ncl" in
let zlib = import "../zlib/build.ncl" in
{
  name = "binutils",
  inputs = [
    {
      url = "gs://minimal-staging-archives/binutils-2.45.tar.xz",
      sha256 = "c50c0e7f9cb188980e2cc97e4537626b1672441815587f1eab69d2a1bfbef5d2"
    } | Source,
    { file = "build.sh" } | Local,
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
    glibc,
    linux_headers,
    # other
    dejagnu,
    expect,
  ],
  runtime_deps = [
    zlib,
  ],
  cmd = "./build.sh",
  outputs = {
    etc = { glob = "etc/*" } | OutputData,
    usr_bin = { glob = "usr/bin/*" } | OutputLib,
    usr_lib = { glob = "usr/lib/*" } | OutputLib,
    usr_lib_ldscripts = { glob = "usr/lib/ldscripts/*" } | OutputLib,
    usr_lib_gprofng = { glob = "usr/lib/gprofng/*" } | OutputLib,
    usr_lib_bfdplugins = { glob = "usr/lib/bfd-plugins/*" } | OutputLib,
    usr_include = { glob = "usr/include/*" } | OutputData,
  },

  replace_on_cycle =
    {
      name = "binutils (prebuilt)",
      inputs = [
        { package = "binutils", sha256 = "0c2d510d101dc38a2374bdf0b97c2dcb98447c2aeb5a505c7dad9958cbcf0864" } | Prebuilt,
      ],
      runtime_deps = [
        zlib,
      ],
      cmd = "",
      outputs = {
        usr_bin = { glob = "usr/bin/**/*" } | OutputLib,
        usr_lib = { glob = "usr/lib/**/*" } | OutputLib,
        usr_include = { glob = "usr/include/**/*" } | OutputLib,
        usr_share = { glob = "usr/share/**/*" } | OutputLib,
      },
    } | BuildSpec,
} | BuildSpec
