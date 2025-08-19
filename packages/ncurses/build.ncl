let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
let make = import "../make/build.ncl" in
{
    name = "ncurses",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "ncurses-6.5.tar.gz"} | Local,
        busybox_static,
        make,
    ],
    cmd = "./build.sh",
    outputs = {
        libraries = { glob = "usr/lib/libncurses*.so*" } | OutputLib,
        form_lib = { glob = "usr/lib/libform*.so*" } | OutputLib,
        panel_lib = { glob = "usr/lib/libpanel*.so*" } | OutputLib,
        menu_lib = { glob = "usr/lib/libmenu*.so*" } | OutputLib,
        headers = { glob = "usr/include/*.h" } | OutputLib,
        binaries = { glob = "usr/bin/*" } | OutputLib,
        pkgconfig = { glob = "usr/lib/pkgconfig/*.pc" } | OutputLib,
        manpages = { glob = "usr/share/man/man*/*" } | OutputLib,
        terminfo = { glob = "usr/share/terminfo/**/*" } | OutputLib,
    },
} | BuildSpec
