let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
let make = import "../make/build.ncl" in
let attr = import "../attr/build.ncl" in
{
    name = "acl",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "acl-2.3.2.tar.xz"} | Local,
        busybox_static,
        make,
        attr,
    ],
    cmd = "./build.sh",
    outputs = {
        chacl = { glob = "usr/bin/chacl" } | OutputLib,
        getfacl = { glob = "usr/bin/getfacl" } | OutputLib,
        setfacl = { glob = "usr/bin/setfacl" } | OutputLib,
        libacl = { glob = "usr/lib/libacl.so*" } | OutputLib,
        headers = { glob = "usr/include/sys/*.h" } | OutputLib,
        manpages = { glob = "usr/share/man/man*/*" } | OutputLib,
        docs = { glob = "usr/share/doc/acl-*/*" } | OutputLib,
    },
} | BuildSpec