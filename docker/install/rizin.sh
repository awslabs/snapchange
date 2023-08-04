#!/usr/bin/env bash

RZ_VERSION=v0.5.2
RZ_GHIDRA_VERSION=v0.5.0

sudo apt remove -y meson
pip3 install meson

if ! command -v rizin >/dev/null; then
    # install rizin
    set -e
    git clone -b "$RZ_VERSION" --recursive --depth 1 https://github.com/rizinorg/rizin.git || { pushd rizin && git pull && popd; }
    pushd rizin
    meson build
    ninja -C build
    ninja -C build install
    popd
    rm -rf rizin

    # install rizin-ghidra plugin
    git clone -b "$RZ_GHIDRA_VERSION" --recursive --depth 1 https://github.com/rizinorg/rz-ghidra.git || { pushd rz-ghidra && git pull && popd; }
    pushd rz-ghidra
    mkdir build
    pushd build
    cmake -G Ninja ../
    ninja
    ninja install
    popd
    popd
    rm -rf rz-ghidra
else
    echo "rizin already installed @ $(command -v rizin)"
fi

pip3 install -U rzpipe
