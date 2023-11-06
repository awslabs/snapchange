#!/bin/bash
set -ex

docker build -f ./Dockerfile -t libfuzzer_harness .

docker run -i \
    -v $(realpath -m ./snapshot):/snapshot/ \
    libfuzzer_harness

sha256sum ./snapshot/example.bin ./snapshot/vmlinux

# Use angr to find constant comparisons to add to the dictionary
mkdir -p snapshot/dict
pip3 install --user angr
python3 ../../docker/coverage_scripts/angr_snapchange.py \
    --dict-path ./snapshot/dict \
    --auto-dict \
    --base-addr 0x555555554000 \
    ./snapshot/example.bin 

# Remove odd dictionary entries just to speed up the example
find ./snapshot/dict -type f | grep -v cafe | grep -v dead | xargs rm

# Remove the unneeded angr covbps since we are using the sancov bps
rm snapshot/*angr.covbps
cp config.toml snapshot
