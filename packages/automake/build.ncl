let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let autoconf = import "../autoconf/build.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
let m4 = import "../m4/build.ncl" in
let make = import "../make/build.ncl" in
let perl = import "../perl/build.ncl" in
{
    name = "automake",
    inputs = [
        {file = "automake-1.17.tar.xz"} | Local,
        {file = "build.sh"} | Local,
        autoconf,
        busybox_static,
        m4,
        make,
        perl,
    ],
    cmd = "./build.sh",
    outputs = {
        automake_bin = { glob = "bin/automake" } | OutputLib,
        automake_versioned = { glob = "bin/automake-1.17" } | OutputLib,
        aclocal_bin = { glob = "bin/aclocal" } | OutputLib,
        aclocal_versioned = { glob = "bin/aclocal-1.17" } | OutputLib,
        share_automake = { glob = "share/automake-1.17/**/*" } | OutputLib,
        share_aclocal = { glob = "share/aclocal-1.17/**/*" } | OutputLib,
        share_aclocal_base = { glob = "share/aclocal/*" } | OutputLib,
        man_pages = { glob = "share/man/man1/*.1" } | OutputLib,
        info_pages = { glob = "share/info/*.info*" } | OutputLib,
    },
} | BuildSpec
