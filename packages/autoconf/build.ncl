let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
let make = import "../make/build.ncl" in
let m4 = import "../m4/build.ncl" in
let perl = import "../perl/build.ncl" in
{
    name = "autoconf",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "autoconf-2.72.tar.xz"} | Local,
        busybox_static,
        make,
        m4,
        perl,
    ],
    cmd = "./build.sh",
    outputs = {
        autoconf_bin = { glob = "bin/autoconf" } | OutputLib,
        autoheader_bin = { glob = "bin/autoheader" } | OutputLib,
        autom4te_bin = { glob = "bin/autom4te" } | OutputLib,
        autoreconf_bin = { glob = "bin/autoreconf" } | OutputLib,
        autoscan_bin = { glob = "bin/autoscan" } | OutputLib,
        autoupdate_bin = { glob = "bin/autoupdate" } | OutputLib,
        ifnames_bin = { glob = "bin/ifnames" } | OutputLib,
        share_autoconf = { glob = "share/autoconf/**/*" } | OutputLib,
        man_pages = { glob = "share/man/man1/*.1" } | OutputLib,
        info_pages = { glob = "share/info/*.info*" } | OutputLib,
    },
} | BuildSpec