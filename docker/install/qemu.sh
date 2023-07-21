#!/bin/bash

if [[ -z "$DEPTH" ]]; then
    DEPTH="--depth 1"
fi

set -eu -o pipefail

if [ ! -d QEMU ]; then
    # Download v7.1.0 QEMU for this patch
    git clone -b v7.1.0 "$DEPTH" https://github.com/qemu/QEMU
fi

pushd QEMU

# Apply the patch for enabling `vmcall` snapshots
# git am --committer-date-is-author-date --ignore-space-change --ignore-whitespace ../0001-Snapchange-patches.patch
patch -p1 < ../install/0001-Snapchange-patches.patch

# Configure and build the patched QEMU
mkdir build
pushd build
../configure --target-list=x86_64-softmmu --enable-system --disable-werror --enable-virtfs
make -j "$(nproc)"

# Return to the original directory
popd
popd
