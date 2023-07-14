#!/bin/bash

download_prereqs() {
    sudo apt update

    # Ensure prereqs are installed
    sudo apt install -y gcc-9 g++-9 clang make ninja-build debootstrap libelf-dev \
        libssl-dev pkg-config

    # Install QEMU dependencies
    sudo apt install -y libglib2.0-dev libgcrypt20-dev zlib1g-dev autoconf automake libtool \
        bison flex libpixman-1-dev

    # If there isn't a bookworm script for debootstrap (like in Ubuntu 18.04), copy
    # over the bullseye script as it is the same
    if [ ! -f /usr/share/debootstrap/scripts/bookworm ]; then 
        ls /usr/share/deboostrap/scripts/b*
        sudo cp /usr/share/debootstrap/scripts/bullseye /usr/share/debootstrap/scripts/bookworm 
    fi
}

# Download and build an Linux image for use in QEMU snapshots
download_linux() {
    # If the bzImage already exists, no need to rebuild
    if [ -d ./linux/arch/boot/x86_64/bzImage ]; then
        return
    fi

    # If no specific linux kernel given, download the entire kernel
    if [ -z "$VERSION" ]; then
        echo "Downloading latest linux kernel"
        git clone --depth 1 https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git || true
    else
        echo "Downloading kernel version: $VERSION"
        git clone --depth 1 --branch "$VERSION" https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git  || true
    fi

    pushd linux
    make defconfig
    echo CONFIG_CONFIGFS_FS=y            >> .config
    echo CONFIG_SECURITYFS=y             >> .config
    echo CONFIG_DEBUG_INFO=y             >> .config
    echo CONFIG_DEBUG_INFO_DWARF4=y      >> .config
    echo CONFIG_RELOCATABLE=n            >> .config
    echo CONFIG_RANDOMIZE_BASE=n         >> .config

    # Only enable KASAN if asked to
    if [[ "$KASAN" ]]; then 
        echo CONFIG_KASAN=y >> .config
    fi

    # If gcc is not in the path already, set gcc to the active gcc
    if ! which gcc; then
        sudo ln -s `which gcc-9` /usr/bin/gcc
    fi

    yes "" | make -j`nproc` bzImage
    popd
}

# Download and patch QEMU for the `vmcall` snapshot mechanism
download_qemu() {
    if [ ! -d QEMU ]; then
        # Download v7.1.0 QEMU for this patch
        git clone -b v7.1.0 https://github.com/qemu/QEMU
    fi
    pushd QEMU

    # Apply the patch for enabling `vmcall` snapshots
    # git am --committer-date-is-author-date --ignore-space-change --ignore-whitespace ../0001-Snapchange-patches.patch
    patch -p1 < ../0001-Snapchange-patches.patch

    # Configure and build the patched QEMU
    mkdir build
    pushd build
    ../configure --target-list=x86_64-softmmu --enable-system --disable-werror
    make -j`nproc`
    popd

    # Return to the original directory
    popd
}

download_prereqs
download_linux
download_qemu
