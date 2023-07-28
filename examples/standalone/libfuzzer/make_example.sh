#!/bin/bash
set -ex

pushd ../../../docker
docker build -t snapchange .
popd

docker build -f ./Dockerfile -t harness .

docker run -i \
    -v $(realpath -m ./snapshot):/snapshot/ \
    harness

sha256sum ./snapshot/example.bin ./snapshot/vmlinux

