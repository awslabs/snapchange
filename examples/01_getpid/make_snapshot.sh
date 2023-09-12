#!/bin/bash
set -ex

# Build the base snapchange image used for snapshotting
pushd ../../docker
make
popd

# Build the target Dockerfile
docker build -t snapchange_example1:target . -f dockers/Dockerfile.target

# Combine the target the snapshot mechanism
docker build -t snapchange_example1:snapshot . -f dockers/Dockerfile.snapshot

# Run the image to take the snapshot
docker run --rm -i \
    -v $(realpath -m ./snapshot):/snapshot/ \
    -e SNAPSHOT_IMGTYPE=initramfs \
    snapchange_example1:snapshot

sha256sum ./snapshot/example1.bin ./snapshot/vmlinux
