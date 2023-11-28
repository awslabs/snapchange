#!/usr/bin/env bash

set -ex

TIMEOUT=10m
DEFAULT_ARGS="-c /2 --ascii-stats --stop-after-first-crash --stop-after-time $TIMEOUT"

if ! [[ -e ./snapshot ]]; then
    ./make_snapshot.sh
fi

if ! [[ -e ./snapshot/__auto_dict ]]; then
    pushd snapshot
    rm -rf dict __auto_dict || true
    python ../../../docker/coverage_scripts/bn_snapchange.py \
        --bps --analysis --cmp --auto-dict \
        --base-addr "$(cat ./gdb.modules | head -n 1 | awk '{ print $1 }')" \
        ./test_cmpsolves.bin
    mv dict __auto_dict
    popd
fi

cp harness/config.toml ./snapshot/config.toml


exec hyperfine \
    --shell bash \
    --export-markdown results.md \
    --warmup 1 \
    --runs 5 \
    -p "pushd snapshot; ./reset.sh; rm dict || true; popd; cargo build -r --features redqueen" \
    -n "redqueen" \
    "./target/release/example_fuzzer fuzz $DEFAULT_ARGS" \
    -p "pushd snapshot; ./reset.sh; ln -s ./__auto_dict dict || true; popd; cargo build -r --features redqueen" \
    -n "redqueen+auto-dict" \
    "./target/release/example_fuzzer fuzz $DEFAULT_ARGS"
    
    # -p "pushd snapshot; ./reset.sh; ln -s ./__auto_dict dict || true; popd; cargo build -r --no-default-features" \
    # -n "auto-dict" \
    # "./target/release/example_fuzzer fuzz $DEFAULT_ARGS" \
