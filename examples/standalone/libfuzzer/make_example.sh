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

# Use angr to find constant comparisons to add to the dictionary
mkdir -p snapshot/dict
pip3 install --user angr
python3 ../../../docker/coverage_scripts/angr_snapchange.py --dict-path ./snapshot/dict --auto-dict ./snapshot/example.bin
