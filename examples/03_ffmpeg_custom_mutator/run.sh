#!/bin/sh

# If the snapshot doesn't currently exist, take the snapshot for this example
if [ ! -d ./snapshot ]; then
  ./make_snapshot.sh

fi

# Build the base snapchange fuzzer container
pushd ../../
docker build -t snapchange_fuzzer . 
popd

# Build the fuzzer for this example
docker build -t snapchange_example3:fuzzer . -f dockers/Dockerfile.fuzzer

# Execute the fuzzer passing the CLI args as if run with `cargo run -r -- `
docker run \
  -it \
  --privileged \
  -v /dev/kvm:/dev/kvm \
  -v $PWD/snapshot:/snapshot \
  snapchange_example3:fuzzer \
  --project /snapshot \
  "$@" \
  # END
