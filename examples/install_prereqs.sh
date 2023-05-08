#!/bin/bash

# Install prereqs for the examples
if [ ! -f $HOME/.cargo/bin/cargo ]; then
  # Install rust
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > /tmp/install_rust.sh
  chmod +x /tmp/install_rust.sh
  /tmp/install_rust.sh --default-toolchain nightly -y
  rm /tmp/install_rust.sh
fi 

# Install pre-reqs
sudo apt update
sudo apt install -y clang gcc unzip lcov
