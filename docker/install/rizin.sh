#!/usr/bin/env bash
set -e

RZ_VERSION=v0.6.2
RZ_GHIDRA_VERSION=v0.6.0

RZ_GITHUB_STATIC_BUILDS="https://github.com/rizinorg/rizin/releases/download/${RZ_VERSION}/rizin-${RZ_VERSION}-static-x86_64.tar.xz"

if command -v rizin >/dev/null; then
    echo "rizin already installed @ $(command -v rizin)"
    exit 0
fi

if [[ "$RZ_BUILD_FROM_SOURCE" -eq 1 ]]; then
    # rizin requires a newer meson
    if command -v sudo; then
        SUDO=sudo
    else
        SUDO=""
    fi
    "$SUDO" apt-get remove -q -y meson
    pip3 install -U meson

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
    # download statically linked rizin... without rz-ghidra
    pushd /usr/local/ >/dev/null
    wget -q -O /tmp/rizin.tar.xz "$RZ_GITHUB_STATIC_BUILDS"
    tar xJf /tmp/rizin.tar.xz
    rm -f /tmp/rizin.tar.xz
    popd >/dev/null
fi

pip3 install -U rzpipe
