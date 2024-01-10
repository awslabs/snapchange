#!/usr/bin/env bash

if [[ -z "$FUZZ_CORES" ]]; then
   FUZZ_CORES="/2"
fi

if [[ -z "$FUZZ_TIMEOUT" ]]; then
   FUZZ_TIMEOUT="5m"
fi

EX="$(basename $PWD)"

COLOR_CLEAR='\e[0m'
COLOR_RED='\e[0;31m'
COLOR_GREEN='\e[0;32m'

function err {
    echo -e "${COLOR_RED}ERROR: $EX - $* $COLOR_CLEAR"
    exit 1
}

function log_success {
    echo -e "${COLOR_GREEN}SUCCESS: $EX - $* $COLOR_CLEAR"
}

function log_info {
    echo -e "INFO: $EX - $*"
}

function setup_build {
    if [[ -d snapshot ]]; then
        # Reset the snapshot from a previous run
        pushd snapshot > /dev/null
        ./reset.sh
        popd > /dev/null
    else
        log_info "creating snapshot"
        if [[ -e Makefile ]]; then
            make snapshot >/dev/null 2>&1
            STATUS=$?
        elif [[ -e ./make_snapshot.sh ]]; then
            ./make_snapshot.sh >/dev/null 2>&1
            STATUS=$?
        else
            err "no script to create snapshot"
        fi
        if [[ "$STATUS" -gt 0 ]]; then
            err "failed to create snapshot"
        fi
    fi

    # Rebuild the fuzzer
    log_info "building fuzzer"
    cargo build -r >/dev/null 2>&1 || err "build failure"
}

function start_fuzzing {
    log_info "start fuzzing"
    cargo run -r -- \
        fuzz \
            -c "$FUZZ_CORES" \
            --ascii-stats \
            --stop-after-time "$FUZZ_TIMEOUT" \
            --stop-after-first-crash \
        >/dev/null 2>&1
}
