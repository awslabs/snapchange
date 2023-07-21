#!/bin/bash
set -ex

pushd ../../../docker
docker build -t snapchange .
popd

docker build -t harness .

docker run -i \
    -v $(realpath -m ./snapshot):/snapshot/ \
    -e SNAPSHOT_IMGTYPE=initramfs \
    harness

sha256sum ./snapshot/example.bin ./snapshot/vmlinux ./snapshot/cwd/*

mkdir -p snapshot/dict
printf "\xad\xde" > snapshot/dict/dead_le
printf "\xef\xbe" > snapshot/dict/beef_le
printf "YOLO" > snapshot/dict/YOLO
