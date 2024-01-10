#!/usr/bin/env bash

COLOR_CLEAR='\e[0m'
COLOR_RED='\e[0;31m'
COLOR_GREEN='\e[0;32m'

function err {
    echo -e "${COLOR_RED}ERROR: $* $COLOR_CLEAR"
    exit 1
}

# Gather all of the example directories
DIRS=$(ls | grep [0-9].*_)
MAKE_TARGETS="clean reset test"

success=""
failed=""

scriptdir="$(dirname "$(realpath "$0")")"
echo "INFO: Building snapchange base images"
make -s -C "$scriptdir/../docker/" >/dev/null 2>&1 || err "failed to build docker base images"

# Check that the example directories and Makefiles exist
for dir in $DIRS; do
    if ! [[ -d "$dir" ]]; then
        err "directory $dir not found"
    fi

    if [[ ! -e "$dir/Makefile" ]]; then
        err "Makefile not found: $dir"
    fi

    pushd $dir >/dev/null
    for target in $MAKE_TARGETS; do
        make -q $target
        if [[ "$?" -gt 1 ]]; then
            err "Makefile for $dir does not have make target: $target"
        fi
    done
    popd >/dev/null
done


# Make and test all included examples
for dir in $DIRS; do
    pushd "$dir" >/dev/null

    make --silent reset test
    STATUS=$?

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
