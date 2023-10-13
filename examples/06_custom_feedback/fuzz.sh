#!/usr/bin/env bash

export MAZE_TARGET="$1"
shift
pushd "./snapshot/$MAZE_TARGET"; ./reset.sh; popd >/dev/null
set -x
\time -v cargo run -r -- -p "./snapshot/$MAZE_TARGET" fuzz $@
