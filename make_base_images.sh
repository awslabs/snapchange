#/bin/bash

# Build the base snapchange fuzzer container
KVM_GID=`/bin/ls -lan /dev/kvm | cut -d' ' -f4`
docker build -t snapchange_base_fuzzer \
  --build-arg user=$USER \
  --build-arg group=kvm \
  --build-arg gid=$KVM_GID \
  . \
  -f Dockerfile.base_fuzzer \
  # END 

# Build the base snapchange target container
docker build -t snapchange_base_target \
  . \
  -f Dockerfile.base_target \
  # END 
