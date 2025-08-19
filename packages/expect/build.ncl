let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let attr = import "../attr/build.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../sed/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let grep = import "../grep/build.ncl" in
let patch = import "../patch/build.ncl" in
let gzip = import "../gzip/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "../coreutils/build.ncl" in
let tar = import "../tar/build.ncl" in
let tcl = import "../tcl/build.ncl" in
{
    name = "expect",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "expect5.45.4.tar.gz"} | Local,
        {file = "expect-5.45.4-gcc15-1.patch"} | Local,
        attr,
        bash,
        coreutils,
        gawk,
        grep,
        gzip,
        make,
        patch,
        sed,
        tar,
        tcl,
    ],
    cmd = "./build.sh",
    outputs = {
        autoexpect = { glob = "usr/bin/autoexpect" } | OutputLib,
        autopasswd = { glob = "usr/bin/autopasswd" } | OutputLib,
        cryptdir = { glob = "usr/bin/cryptdir" } | OutputLib,
        decryptdir = { glob = "usr/bin/decryptdir" } | OutputLib,
        dislocate = { glob = "usr/bin/dislocate" } | OutputLib,
        ftp_rfc = { glob = "usr/bin/ftp-rfc" } | OutputLib,
        kibitz = { glob = "usr/bin/kibitz" } | OutputLib,
        lpunlock = { glob = "usr/bin/lpunlock" } | OutputLib,
        mkpasswd = { glob = "usr/bin/mkpasswd" } | OutputLib,
        multixterm = { glob = "usr/bin/multixterm" } | OutputLib,
        passmass = { glob = "usr/bin/passmass" } | OutputLib,
        rftp = { glob = "usr/bin/rftp" } | OutputLib,
        rlogin_cwd = { glob = "usr/bin/rlogin-cwd" } | OutputLib,
        timed_read = { glob = "usr/bin/timed-read" } | OutputLib,
        timed_run = { glob = "usr/bin/timed-run" } | OutputLib,
        tknewsbiff = { glob = "usr/bin/tknewsbiff" } | OutputLib,
        tkpasswd = { glob = "usr/bin/tkpasswd" } | OutputLib,
        unbuffer = { glob = "usr/bin/unbuffer" } | OutputLib,
        weather = { glob = "usr/bin/weather" } | OutputLib,
        xkibitz = { glob = "usr/bin/xkibitz" } | OutputLib,
        xpstat = { glob = "usr/bin/xpstat" } | OutputLib,
              
        expect_comm_h = { glob = "usr/include/expect_comm.h" } | OutputLib,
        expect_tcl_h = { glob = "usr/include/expect_tcl.h" } | OutputLib,
        expect_h = { glob = "usr/include/expect.h" } | OutputLib,
        tcldbg_h = { glob = "usr/include/tcldbg.h" } | OutputLib,
    },
} | BuildSpec
