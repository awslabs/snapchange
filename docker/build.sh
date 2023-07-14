#!/bin/bash

# Build the raw image itself
if [ ! -d ./fuzzer_template ]; then
  cp -r -L ../fuzzer_template .

  pushd fuzzer_template/qemu_snapshot/IMAGE

  # For now, we're using e2cp to interact with the raw image to copy files
  # into the image in preparation for the snapshot. e2cp needs an ext2 format
  # instead of ext4.
  sed -i 's/ext4/ext2/' create-image.sh

  # Create the image
  ./create-image.sh
  sudo rm -rf chroot
  popd
fi

# Compress the image to make the docker image a bit smaller
echo "Compressing the raw linux image"
pigz fuzzer_template/qemu_snapshot/IMAGE/bookworm.img

# Build the docker container
docker build -t snapchange .