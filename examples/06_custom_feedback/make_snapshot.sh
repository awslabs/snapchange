#!/bin/bash
set -ex

NAME="snapchange-$(basename "$PWD")"
docker build -f ./Dockerfile -t "$NAME" .

mkdir -p snapshot/
for bin in maze.small maze.big maze.big.nobt maze.small.nobt; do
    BINARY="$bin"
    echo "snapshotting maze variant $BINARY"
    docker run -i \
        -v $(realpath -m ./snapshot/$BINARY):/snapshot/ \
        -e "SNAPSHOT_ENTRYPOINT=/opt/$BINARY" \
        "$NAME"
done
