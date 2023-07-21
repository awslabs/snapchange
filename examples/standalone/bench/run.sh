#!/usr/bin/env bash
set -ex
if ! [[ -d snapshot ]]; then
    ./make_example.sh
fi
pushd snapshot
./reset.sh
popd

cargo build --release
FUZZER=./target/release/example_fuzzer

exec "$FUZZER" $@
