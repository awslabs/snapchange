#!/usr/bin/env bash

COLOR_CLEAR='\e[0m'
COLOR_RED='\e[0;31m'
COLOR_GREEN='\e[0;32m'

function err {
    echo -e "${COLOR_RED}ERROR: $* $COLOR_CLEAR"
    exit 1
}

scriptdir="$(dirname "$(realpath "$0")")"
echo "INFO: Building snapchange base images"
make -s -C "$scriptdir/../docker/" >/dev/null 2>&1 || err "failed to build docker base images"

# DIRS="01_getpid 02_libtiff 03_ffmpeg_custom_mutator 04_syscall_fuzzer 05_redqueen 06_custom_feedback 07_libfuzzer"
DIRS="01_getpid 02_libtiff 04_syscall_fuzzer 05_redqueen 06_custom_feedback 07_libfuzzer"

success=""
failed=""

# Make and test all included examples
for dir in $DIRS; do
    if ! [[ -d "$dir" ]]; then
        err "directory $dir not found"
    fi

    pushd "$dir" >/dev/null

    if [[ -e Makefile ]]; then
        make -s test
        STATUS=$?
    else
        if ! [[ -d ./snapshot ]]; then
            if ! ./make_snapshot.sh >/dev/null 2>&1; then
                failed="$failed $dir"
                continue
            fi
        else
            pushd ./snapshot >/dev/null
            ./reset.sh >/dev/null 2>&1
            popd >/dev/null
        fi

        # Test this example
        ./test.sh
        STATUS=$?
    fi

    # Check the result of this test
    popd >/dev/null

    if [[ "$STATUS" -gt 0 ]]; then
        failed="$failed $dir"
    else
        success="$success $dir"
    fi
done

echo "=== results ==="
echo "success: $success"
echo "failed: $failed"
