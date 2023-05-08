#!/bin/bash
rm bn_snapchange.py || true
rm Cargo.lock || true
rm Cargo.toml || true
sudo rm -rf qemu_snapshot
rm -rf src
rm -rf ./target
rm -rf ./syscall_harness/target
rm fuzzer.log
rm -rf ./snapshot/crashes
rm -rf ./snapshot/
