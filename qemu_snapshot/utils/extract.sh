#!/bin/sh

# Create the directory to mount the image
sudo mkdir -p /mnt/snapchange

# Mount the image from the snapshot
sudo mount -o loop IMAGE/bookworm.img /mnt/snapchange

# Copy over the files written by `gdbsnapshot.py`
sudo mv /mnt/snapchange/tmp/gdb.vmmap .
sudo mv /mnt/snapchange/tmp/gdb.modules .
sudo mv /mnt/snapchange/tmp/gdb.symbols .

# Copy over the root symbols and, if found, move the user symbols to .symbols in order to
# combine the symbols into one gdb.symbols
if [ -f /mnt/snapchange/tmp/gdb.symbols.root ]; then
    echo "Combining root and user symbols"
    sudo mv /mnt/snapchange/tmp/gdb.symbols.root .
    mv gdb.symbols gdb.symbols.user 
    python3 combine_symbols.py
fi

# Ensure the files are the current user and not root anymore
if [ -f gdb.symbols.root ]; then 
    sudo chown `id -u`:`id -g` gdb.symbols.root
fi
sudo chown `id -u`:`id -g` gdb.symbols
sudo chown `id -u`:`id -g` gdb.modules
sudo chown `id -u`:`id -g` gdb.vmmap

# Unmount the image
sudo umount /mnt/snapchange

# Delete the mount point
sudo rmdir /mnt/snapchange
