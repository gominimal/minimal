#!/bin/bash

# Script to generate build.ncl for bash package with every file listed individually

cd /home/bweeks/minpkgs/packages/bash

# Start the build.ncl file
cat > build.ncl << 'EOF'
let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
{
    name = "bash",
    inputs = [
        {file = "build.sh"} | Local,
EOF

# Find all files in prebuilt directory and add them as inputs
find prebuilt -type f | sort | while read -r file; do
    echo "        {file = \"$file\"} | Local," >> build.ncl
done

# Add busybox_static and close inputs
cat >> build.ncl << 'EOF'
        busybox_static,
    ],
    cmd = "./build.sh",
    outputs = {
        bin_sh  = { glob = "bin/sh" },
        usr_bin = { glob = "usr/bin/**/*" },
        usr_lib = { glob = "usr/lib/**/*" },
        usr_share = { glob = "usr/share/**/*" },
        usr_include = { glob = "usr/include/**/*" },
    },
} | BuildSpec
EOF

echo "Generated build.ncl for bash package with $(find prebuilt -type f | wc -l) files"
