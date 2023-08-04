#!/bin/bash

# If the snapshot doesn't currently exist, take the snapshot for this example
if [ ! -d ./snapshot ]; then
  ./make_snapshot.sh

fi

# Ensure the base docker containers are built
pushd ../../
./make_base_images.sh
popd

# Build the fuzzer for this example
docker build -t snapchange_example4:fuzzer . -f ../../Dockerfile.fuzzer

# Execute the fuzzer passing the CLI args as if run with `cargo run -r -- `
docker run \
  -it \
  --rm \
  --privileged \
  -v /dev/kvm:/dev/kvm \
  -v $PWD/snapshot:/snapshot \
  snapchange_example4:fuzzer \
  --project /snapshot \
  "$@" \
  # END
