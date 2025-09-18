let { BuildSpec, OutputBin, OutputLib, Local, Prebuilt, Source, .. } = import "minimal.ncl" in
let acl = import "../acl/build.ncl" in
let attr = import "../attr/build.ncl" in
let base = import "../base/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let libcap = import "../libcap/build.ncl" in
let libgmp = import "../gmp/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "coreutils",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/coreutils-9.7.tar.xz",
      sha256 = "e8bb26ad0293f9b5a1fc43fb42ba970e312c66ce92c1b0b16713d7500db251bf"
    } | Source,
    attr,
    base,
    libcap,
    toolchain,
  ],
  runtime_deps = [
    acl,
    glibc,
    libcap,
    libgmp,
  ],
  cmd = "./build.sh",
  outputs = {
    # Core file operations
    ls = { glob = "usr/bin/ls" } | OutputLib,
    cp = { glob = "usr/bin/cp" } | OutputLib,
    mv = { glob = "usr/bin/mv" } | OutputLib,
    rm = { glob = "usr/bin/rm" } | OutputLib,
    mkdir = { glob = "usr/bin/mkdir" } | OutputLib,
    rmdir = { glob = "usr/bin/rmdir" } | OutputLib,
    ln = { glob = "usr/bin/ln" } | OutputLib,
    chmod = { glob = "usr/bin/chmod" } | OutputLib,
    chown = { glob = "usr/bin/chown" } | OutputLib,
    chgrp = { glob = "usr/bin/chgrp" } | OutputLib,

    # Text utilities
    cat = { glob = "usr/bin/cat" } | OutputLib,
    head = { glob = "usr/bin/head" } | OutputLib,
    tail = { glob = "usr/bin/tail" } | OutputLib,
    sort = { glob = "usr/bin/sort" } | OutputLib,
    uniq = { glob = "usr/bin/uniq" } | OutputLib,
    cut = { glob = "usr/bin/cut" } | OutputLib,
    tr = { glob = "usr/bin/tr" } | OutputLib,
    wc = { glob = "usr/bin/wc" } | OutputLib,

    # System utilities
    date = { glob = "usr/bin/date" } | OutputLib,
    whoami = { glob = "usr/bin/whoami" } | OutputLib,
    id = { glob = "usr/bin/id" } | OutputLib,
    pwd = { glob = "usr/bin/pwd" } | OutputLib,
    uname = { glob = "usr/bin/uname" } | OutputLib,

    # All binaries (catch remaining utilities)
    all_binaries = { glob = "usr/bin/*" } | OutputLib,

    # Library and documentation
    libstdbuf = { glob = "usr/libexec/coreutils/libstdbuf.so" } | OutputLib,
    man_pages = { glob = "usr/share/man/man1/*.1" } | OutputLib,
    info_pages = { glob = "usr/share/info/*.info*" } | OutputLib,
    locale_files = { glob = "usr/share/locale/**/*" } | OutputLib,
  },

  replace_on_cycle = {
    name = "coreutils (prebuilt)",
    inputs = [
      { package = "coreutils", sha256 = "1d0a839341e239e0f8e9efa026d0505f743e7d9965b4d7301f67adef4bc750e2" } | Prebuilt,
    ],
    runtime_deps = [
      acl,
      glibc,
      libcap,
      libgmp,
    ],
    cmd = "",
    outputs = {
      usr_bin = { glob = "usr/bin/**/*" } | OutputLib,
      usr_libexec = { glob = "usr/libexec/**/*" } | OutputLib,
      usr_share = { glob = "usr/share/**/*" } | OutputLib,
    },
  } | BuildSpec,
} | BuildSpec
