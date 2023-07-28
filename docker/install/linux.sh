#!/bin/bash

if [[ -z "$DEPTH" ]]; then
    DEPTH="--depth 1"
fi
if [[ -z "$LINUX_VERSION" ]]; then
    LINUX_VERSION=""
fi
if [[ -z "$LINUX_FORCE_REBUILD" ]]; then
  LINUX_FORCE_REBUILD=0
fi

# Immediately stop execution if an error occurs
set -eu  #-o pipefail

# If gcc is not in the path already, set gcc-9 to the active gcc
if ! command -v gcc >/dev/null; then
    if command -v gcc-9 >/dev/null; then
        sudo ln -s `which gcc-9` /usr/bin/gcc
    fi
    if command -v gcc-10 >/dev/null; then
        sudo ln -s `which gcc-10` /usr/bin/gcc
    fi
    if command -v gcc-11 >/dev/null; then
        sudo ln -s `which gcc-11` /usr/bin/gcc
    fi
fi

if [[ -d linux ]]; then
    echo "[+] reusing existing linux kernel download"
else
    # If no specific linux kernel given, download the entire kernel
    if [[ -z "$LINUX_VERSION" ]]; then
        echo "Downloading latest linux kernel"
        git clone $DEPTH https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
    else
        echo "Downloading kernel version: $LINUX_VERSION"
        git clone $DEPTH --branch "$LINUX_VERSION" https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
    fi
fi

cd linux
make defconfig
./scripts/config --set-val CONFIG_CONFIGFS_FS y
./scripts/config --set-val CONFIG_SECURITYFS y
./scripts/config --set-val CONFIG_DEBUG_INFO y
./scripts/config --set-val CONFIG_DEBUG_INFO_DWARF4 y
./scripts/config --set-val CONFIG_RELOCATABLE n
./scripts/config --set-val CONFIG_RANDOMIZE_BASE n

./scripts/config --set-val BINFMT_SCRIPT y
./scripts/config --set-val BINFMT_ELF y

# we use 9pfs to transfer files via qemu to the host
./scripts/config --set-val CONFIG_NET_9P y
./scripts/config --set-val CONFIG_NET_9P_VIRTIO y
# ./scripts/config --set-val CONFIG_NET_9P_DEBUG y
./scripts/config --set-val CONFIG_9P_FS y
./scripts/config --set-val CONFIG_9P_FS_POSIX_ACL y
./scripts/config --set-val CONFIG_PCI y
./scripts/config --set-val CONFIG_VIRTIO_PCI y

# enable such that we can also run our bundled gdb.static
./scripts/config --set-val CONFIG_USER_NS y

yes "" | make -j "$(nproc)" bzImage

mv vmlinux /snapchange/vmlinux
for bzimg in ./arch/x86/boot/bzImage ./arch/boot/x86_64/bzImage; do
    if [[ -e "$bzimg" ]]; then
        cp "$bzimg" /snapchange/linux.bzImage
        break
    fi
done

./scripts/config --set-val CONFIG_KASAN y

make clean
yes "" | make -j "$(nproc)" bzImage

mv vmlinux /snapchange/vmlinux.kasan
for bzimg in ./arch/x86/boot/bzImage ./arch/boot/x86_64/bzImage; do
    if [[ -e "$bzimg" ]]; then
        cp "$bzimg" /snapchange/linux.kasan.bzImage
        break
    fi
done

cd ..
rm -rf linux
