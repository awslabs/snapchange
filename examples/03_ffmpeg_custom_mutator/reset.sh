#!/bin/bash
rm bn_snapchange.py || true
rm Cargo.lock || true
rm Cargo.toml || true
sudo rm -rf qemu_snapshot
rm -rf src
rm -rf FFmpeg
rm -rf snapshot
rm -rf target
rm fuzzer.log
