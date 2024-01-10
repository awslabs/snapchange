#!/usr/bin/env bash

set -eu

CORES_SETTINGS="/2 1 16"
TRIES=3

rm fuzz.bench.log || true
touch fuzz.bench.log
    
cargo build --release

for maze_size in small big; do
    for nobt in 1 0; do
        for CORES in $CORES_SETTINGS; do
            for i in $(seq "$TRIES"); do
                bin="maze.$maze_size"
                if [[ "$nobt" -eq 1 ]]; then
                    bin="$bin.nobt"
                fi
                export MAZE_NO_BT="$nobt"
                if [[ "$maze_size" == "small" ]]; then
                    export USE_MAZE=0
                elif [[ "$maze_size" == "big" ]]; then
                    export USE_MAZE=1
                fi
                export CHECK_CODE=0

                logf="fuzz.$bin.c$CORES.$i.log"
                if [[ "$CORES" == "/2" ]]; then
                    logf="fuzz.$bin.c_half.$i.log"
                fi
                pushd ./snapshot; ./reset.sh; popd >/dev/null
                \time -v ./target/release/maze_fuzzer fuzz \
                    -c "$CORES" --ascii-stats -v \
                    --stop-after-first-crash \
                    --stop-after-time 30m \
                    2>&1 | tee "$logf"

                statsf="./snapshot/data/stats.toml"
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
done
