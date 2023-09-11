#!/usr/bin/env bash
set -e

echo "[+] installing snapchange with docker"

if !command -v docker; then
    if !command -v podman; then
        echo "[ERROR] please install docker (or podman)"
        exit 1
    fi
fi

cd docker
make
