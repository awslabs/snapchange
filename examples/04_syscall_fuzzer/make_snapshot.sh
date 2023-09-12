#!/bin/bash
set -ex

# Build the base snapchange image used for snapshotting
pushd ../../docker
cp Dockerfile.snapshot Dockerfile.ubu20
sed -i 's/ubuntu:22.04/ubuntu:20.04/' Dockerfile.ubu20
docker build \
    -t snapchange_snapshot_linux_v5.4 \
    --build-arg LINUX_VERSION="v5.4" \
    . \
    -f Dockerfile.ubu20 \
    # END
rm Dockerfile.ubu20
popd

# Build the target Dockerfile
docker build -t snapchange_example4:target . -f dockers/Dockerfile.target

# Combine the target the snapshot mechanism
docker build -t snapchange_example4:snapshot . -f dockers/Dockerfile.snapshot

# Run the image to take the snapshot
docker run --rm -i \
    -v $(realpath -m ./snapshot):/snapshot/ \
    -e SNAPSHOT_IMGTYPE=initramfs \
    snapchange_example4:snapshot

sha256sum ./snapshot/example1.bin ./snapshot/vmlinux
