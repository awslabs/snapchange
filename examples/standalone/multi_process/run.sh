#!/usr/bin/env bash
set -ex
# ./make_example.sh
pushd snapshot
./reset.sh
popd
exec cargo run -r -- $@
