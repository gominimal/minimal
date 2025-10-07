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
let acl = import "../acl/build.ncl" in
let attr = import "../attr/build.ncl" in
let libcap = import "../libcap/build.ncl" in
let gmp = import "../gmp/build.ncl" in
{
  name = "coreutils",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/coreutils-9.7.tar.xz",
      sha256 = "e8bb26ad0293f9b5a1fc43fb42ba970e312c66ce92c1b0b16713d7500db251bf"
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
    attr,
    libcap,
  ],
  runtime_deps = [
    acl,
    glibc,
    gmp,
    libcap,
  ],
  cmd = "./build.sh",
  outputs = {
    # Core file operations
    ls = { glob = "usr/bin/ls" } | OutputBin,
    cp = { glob = "usr/bin/cp" } | OutputBin,
    mv = { glob = "usr/bin/mv" } | OutputBin,
    rm = { glob = "usr/bin/rm" } | OutputBin,
    mkdir = { glob = "usr/bin/mkdir" } | OutputBin,
    rmdir = { glob = "usr/bin/rmdir" } | OutputBin,
    ln = { glob = "usr/bin/ln" } | OutputBin,
    chmod = { glob = "usr/bin/chmod" } | OutputBin,
    chown = { glob = "usr/bin/chown" } | OutputBin,
    chgrp = { glob = "usr/bin/chgrp" } | OutputBin,

    # Text utilities
    cat = { glob = "usr/bin/cat" } | OutputBin,
    head = { glob = "usr/bin/head" } | OutputBin,
    tail = { glob = "usr/bin/tail" } | OutputBin,
    sort = { glob = "usr/bin/sort" } | OutputBin,
    uniq = { glob = "usr/bin/uniq" } | OutputBin,
    cut = { glob = "usr/bin/cut" } | OutputBin,
    tr = { glob = "usr/bin/tr" } | OutputBin,
    wc = { glob = "usr/bin/wc" } | OutputBin,

    # System utilities
    date = { glob = "usr/bin/date" } | OutputBin,
    whoami = { glob = "usr/bin/whoami" } | OutputBin,
    id = { glob = "usr/bin/id" } | OutputBin,
    pwd = { glob = "usr/bin/pwd" } | OutputBin,
    uname = { glob = "usr/bin/uname" } | OutputBin,

    # Catch-all
    bins = { glob = "usr/bin/*" } | OutputBin,

    libstdbuf = { glob = "usr/libexec/coreutils/libstdbuf.so" } | OutputLib,

    mans = { glob = "usr/share/man/**" } | OutputData,
    infos = { glob = "usr/share/info/*.info" } | OutputLib,
    locales = { glob = "usr/share/locale/**" } | OutputData,
  },

  replace_on_cycle =
    {
      name = "coreutils (prebuilt)",
      inputs = [
        { package = "coreutils", sha256 = "1d0a839341e239e0f8e9efa026d0505f743e7d9965b4d7301f67adef4bc750e2" } | Prebuilt,
      ],
      runtime_deps = [
        acl,
        glibc,
        gmp,
        libcap,
      ],
      cmd = "",
      outputs = {
        usr_bin = { glob = "usr/bin/**/*" } | OutputLib,
        usr_libexec = { glob = "usr/libexec/**/*" } | OutputLib,
        usr_share = { glob = "usr/share/**/*" } | OutputLib,
      },
    } | BuildSpec,
} | BuildSpec
