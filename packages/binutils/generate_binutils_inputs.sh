#!/bin/bash

echo "let {BuildSpec, HostPath, OutputLib, Local, ..} = import \"minimal.ncl\" in"
echo "let busybox_static = import \"../busybox_static/build.ncl\" in"
echo "{"
echo "    name = \"binutils\","
echo "    inputs = ["
echo "        {file = \"build.sh\"} | Local,"

# All files and symlinks excluding usr/share
find prebuilt/ \( -type f -o -type l \) | sort | while read f; do
    echo "        {file = \"$f\"} | Local,"
done

echo "        busybox_static,"
echo "    ],"
echo "    cmd = \"./build.sh\","
echo "    outputs = {"
echo "        usr_bin = { glob = \"usr/bin/**/*\" } | OutputLib,"
echo "        usr_lib = { glob = \"usr/lib/**/*\" } | OutputLib,"
echo "        usr_include = { glob = \"usr/include/**/*\" } | OutputLib,"
echo "        usr_share = { glob = \"usr/share/**/*\" } | OutputLib,"
echo "    },"
echo "} | BuildSpec"
