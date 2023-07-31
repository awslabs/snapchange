#!/bin/bash
set -ex

# Build the base snapchange image used for snapshotting
pushd ../../docker
docker build -t snapchange .
popd

# Build the target Dockerfile
docker build -t snapchange_example2:target . -f Dockerfile.target

# Build this example's image
docker build -t snapchange_example2 .

# Run the image to take the snapshot
docker run -i \
    -v $(realpath -m ./snapshot):/snapshot/ \
    -e SNAPSHOT_IMGTYPE=initramfs \
    snapchange_example2

sha256sum ./snapshot/tiffinfo.bin ./snapshot/vmlinux

# Copy the input files
mkdir -p snapshot/input
find snapshot/image/opt/tiff-4.0.4/test/images/*tiff -size -40k -exec cp {} snapshot/input/ \;
