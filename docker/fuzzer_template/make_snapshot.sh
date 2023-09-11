#!/bin/bash
set -ex

if command -v podman >/dev/null 2>&1 && ! command -v docker >/dev/null 2>&1; then
    alias docker=podman
fi

project="$(basename "$PWD")"

docker build -f ./Dockerfile.harness -t "${project}_harness" .
docker build -f ./Dockerfile.snapshot -t "${project}_snapshot" .

docker run -i \
    -v $(realpath -m ./snapshot):/snapshot/ \
    "${project}_snapshot"
