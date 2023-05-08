#!/bin/bash
rm -rf coverage_scripts
rm Cargo.lock || true
rm Cargo.toml || true
sudo rm -rf qemu_snapshot
rm -rf src
rm -rf snapshot
rm -rf target
rm fuzzer.log
