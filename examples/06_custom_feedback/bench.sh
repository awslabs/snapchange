#!/usr/bin/env bash

set -eu

CORES_SETTINGS="/2 1 16"
VARIANTS="maze.small maze.small.nobt maze.big maze.big.nobt"
TRIES=3

rm fuzz.bench.log || true
touch fuzz.bench.log

for bin in $VARIANTS; do
    # build the fuzzer variant
    export MAZE_TARGET="$bin"
    cargo build --release
    for CORES in $CORES_SETTINGS; do
        for i in $(seq "$TRIES"); do
            logf="fuzz.$bin.c$CORES.$i.log"
            if [[ "$CORES" == "/2" ]]; then
                logf="fuzz.$bin.c_half.$i.log"
            fi
            pushd "./snapshot/$MAZE_TARGET"; ./reset.sh; popd >/dev/null
            \time -v ./target/release/maze_fuzzer -p "./snapshot/$MAZE_TARGET" fuzz \
                -c "$CORES" --ascii-stats -v \
                --stop-after-first-crash \
                --stop-after-time 30m \
                2>&1 | tee "$logf"
            statsf="./snapshot/$MAZE_TARGET/data/stats.toml"
            cat "$statsf" >> "$logf"

            success="SUCCESS"
            if grep "crashes = 0" "$statsf" >/dev/null; then
                success="FAILURE - NO CRASHES"
            fi

            cat fuzz.bench.log
            echo "$bin [$i] => $(grep 'wall clock' "$logf") [$(grep 'exec.*sec' "$logf" | tail -n 1) on $CORES cores] $success" | tee -a fuzz.bench.log
        done
    done
done
