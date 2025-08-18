let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
let make_static = import "../make_static/build.ncl" in
{
    name = "make",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "make-4.4.1.tar.gz"} | Local,
        busybox_static,
        make_static,
    ],
    cmd = "./build.sh",
    outputs = {
        make_bin = { glob = "bin/make" } | OutputLib,
        headers = { glob = "include/*.h" } | OutputLib,
        info_pages = { glob = "share/info/*.info*" } | OutputLib,
        man_pages = { glob = "share/man/man1/*.1" } | OutputLib,
        locale_files = { glob = "share/locale/*/LC_MESSAGES/*.mo" } | OutputLib,
    },
} | BuildSpec
