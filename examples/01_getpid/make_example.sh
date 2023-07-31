#!/bin/bash
set -ex

# Build the base snapchange image used for snapshotting
pushd ../../docker
docker build -t snapchange .
popd

# Build this example's image
docker build -t snapchange_example1 .

# Run the image to take the snapshot
docker run -i \
    -v $(realpath -m ./snapshot):/snapshot/ \
    -e SNAPSHOT_IMGTYPE=initramfs \
    snapchange_example1

# docker rmi snapchange_example1

sha256sum ./snapshot/example1.bin ./snapshot/vmlinux
