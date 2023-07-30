#!/bin/bash
set -ex

docker build -f ./Dockerfile -t harness ./harness

docker run -i \
    -v $(realpath -m ./snapshot):/snapshot/ \
    -e IMGTYPE=$IMGTYPE \
    harness

sha256sum ./snapshot/example.bin ./snapshot/vmlinux
