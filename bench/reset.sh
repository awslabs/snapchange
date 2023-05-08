#!/bin/bash
rm -rf coverage_scripts
rm Cargo.lock || true
rm Cargo.toml || true
sudo rm -rf qemu_snapshot
rm -rf snapshot
rm -rf target
rm fuzzer.log
rm -rf gather_data/dataplots
