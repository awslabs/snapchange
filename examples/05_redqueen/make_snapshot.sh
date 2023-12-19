#!/bin/bash
set -ex

if command -v podman >/dev/null 2>&1 && ! command -v docker >/dev/null 2>&1; then
    alias docker=podman
fi

# Build the docker to take the snapshot of the binary
docker build \
    -f ./Dockerfile.snapshot \
    -t snapchange_example5 \
    .

# Take the snapshot for this binary
docker run -i \
    -v $(realpath -m ./snapshot):/snapshot/ \
    -e SNAPSHOT_IMGTYPE=initramfs \
    snapchange_example5

# Add snapchange as a dependency for this fuzzer
# cargo add snapchange --path ../../ --features redqueen

# Copy the generated redqueen coverage breakpoints and compare breakpoints
cp harness/config.toml ./snapshot/config.toml
