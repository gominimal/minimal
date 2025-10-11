let { BuildSpec, Local, OutputBin, OutputData, OutputLib, Prebuilt, Source, .. } = import "minimal.ncl" in
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
let gmp = import "../gmp/build.ncl" in
let mpc = import "../mpc/build.ncl" in
let mpfr = import "../mpfr/build.ncl" in
let zlib = import "../zlib/build.ncl" in
let zstd = import "../zstd/build.ncl" in
{
  name = "gcc",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/gcc-15.2.0.tar.xz",
      sha256 = "438fd996826b0c82485a29da03a72d71d6e3541a83ec702df4271f6fe025d24e"
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
    glibc,
    linux_headers,
    # other
    gmp,
    mpc,
    mpfr,
    zlib,
    zstd,
  ],
  runtime_deps = [
    gmp,
    mpc,
    mpfr,
    zlib,
    zstd,
  ],
  cmd = "./build.sh",
  outputs = {
    bins = { glob = "usr/bin/*" } | OutputBin,

    libs = { glob = "usr/lib/**/*.{a,o,so*}" } | OutputLib,
    libatomic = { glob = "usr/lib/libatomic.so*" } | OutputLib,
    libgcc = { glob = "usr/lib/libgcc_s.so*" } | OutputLib,
    libgomp = { glob = "usr/lib/libgomp.so*" } | OutputLib,
    libstdcpp = { glob = "usr/lib/libstdc++*.so*" } | OutputLib,

    libs_data = { glob = "usr/lib/**" } | OutputData,
    share_data = { glob = "usr/share/gcc-*/**" } | OutputData,
    ltconfigs = { glob = "usr/lib/**/*.la" } | OutputData,

    # Wildcards are target/version
    libexec_bins = { glob = "usr/libexec/gcc/*/*/{cc1,cc1plus,collect2,lto1,lto-wrapper}" } | OutputBin,
    libexec_libs = { glob = "usr/libexec/gcc/*/*/g++-mapper-server" } | OutputLib,
    plugins = { glob = "usr/libexec/gcc/*/*/plugin/*" } | OutputBin,
    install_tools = { glob = "usr/libexec/gcc/*/*/install-tools/*" } | OutputBin,

    liblto_plugin = { glob = "usr/libexec/gcc/*/*/liblto_plugin.so" } | OutputLib,
    lto_plugin_ltconfig = { glob = "usr/libexec/gcc/*/*/liblto_plugin.la" } | OutputData,

    mans = { glob = "usr/share/man/**" } | OutputData,
    includes = { glob = "usr/include/**" } | OutputData,
  },

  replace_on_cycle =
    {
      name = "gcc (prebuilt)",
      inputs = [
        { package = "gcc", sha256 = "69d6a1da34c99566214174776a09216dffb4b52f67971eb000de3e1f8aae7a86" } | Prebuilt,
      ],
      runtime_deps = [
        gmp,
        mpc,
        mpfr,
        zlib,
        zstd,
      ],
      cmd = "",
      outputs = {
        usr = { glob = "usr/**/*" } | OutputLib,
      },
    } | BuildSpec,
} | BuildSpec
