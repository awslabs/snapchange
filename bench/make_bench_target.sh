#!/bin/bash

set -e

AMI=$1

# Install prereqs
install_prereqs() {
  ../examples/install_prereqs.sh
}

# Initialize the fuzz template for this example
init_fuzz_template() {
  # Initialize this example based on the fuzzer template
  cp -r -L ../fuzzer_template/* .

  # Remove the create_snapshot.sh template since this example uses this file (make_example.sh)
  rm create_snapshot.sh

  # Use the solution fuzzer
  cp fuzzer.rs src/fuzzer.rs

  # Copy the src files for this example
  cp main.rs src/main.rs

  # Add snapchange as dependency and build-dependency for this example
  $HOME/.cargo/bin/cargo add snapchange --path ..
}

# Initialize a qemu_snapshot for this target
init_qemu_snapshot() {
  pushd qemu_snapshot
  ./init.sh
  popd
}

build_harness() {
  pushd bench_harness

  # Build the harnesss
  cargo build

  popd
}

take_snapshot() {
  # Sanity check the target has been build
  if [ ! -f "./bench_harness/target/release/bench_harness" ]; then 
    echo "ERROR: bench target not found"
    exit 0
  fi

  # Build the image to execute the harness on start
  pushd ./qemu_snapshot/IMAGE
  ./build.sh ../../bench_harness/target/release/bench_harness
  popd

  # Take the snapshot
  pushd ./qemu_snapshot
  ./snapshot.sh
  popd
}

# Move the snapshot directory out of qemu_snapshot
copy_snapshot_directory() {
  mv qemu_snapshot/output snapshot
}

# Initialize the fuzzer based on the output of the snapshot
init_fuzzer() {
  # Check if fuzzer still has REPLACEME markers that need replacing
  grep REPLACEME src/fuzzer.rs >/dev/null

  # Continue replacing REPLACEME markers if they still exist
  if [ $? -eq 0 ]; then
    # Begin the fuzzer with the SNAPSHOT output from the vm.log
    COMMENTS=`grep SNAPSHOT qemu_snapshot/vm.log | sed 's_^_// _g' | tr '\n' '\r'`
    echo "Found snapshot comments in vm.log:"
    echo $COMMENTS

    # Slight hack to sed a multiline string
    sed -z "s_REPLACEMECOMMENTS_${COMMENTS}_" src/fuzzer.rs | tr '\r' '\n' > /tmp/.fuzzer.rs
    mv /tmp/.fuzzer.rs src/fuzzer.rs

    # Replace the RIP for the snapshot
    # RIP=0000000000401362 RFL=00000306 [-----P-] CPL=3 II=0 A20=1 SMM=0 HLT=0
    NEWRIP=`grep RIP snapshot/*qemuregs | cut -d' ' -f1 | cut -d'=' -f2`
    echo "Found RIP in snapshot: $NEWRIP"
    sed  -i "s/REPLACEMERIP/0x${NEWRIP}/" src/fuzzer.rs

    # Replace the CR3 for the snapshot
    # 16:CR0=80050033 CR2=00007f8814613610 CR3=00000000084be000 CR4=000006f0
    NEWCR3=`grep CR3 snapshot/*qemuregs | cut -d' ' -f3 | cut -d'=' -f2`
    echo "Found CR3 in snapshot: $NEWCR3"
    sed -i "s/REPLACEMECR3/0x${NEWCR3}/" src/fuzzer.rs

    # Replace the RESET breakpoint from the snapshto
    NEWRESET=`grep SNAPSHOT qemu_snapshot/vm.log | rev | cut -d' ' -f1 | rev | tr -d '\r\n'`
    echo "Found RESET in snapshot: $NEWRESET"
    sed -i "s/REPLACEMERESET/${NEWRESET}/" src/fuzzer.rs

    # Replace the RESET breakpoint from the snapshot
    NEWSCRATCH=`grep SNAPSHOT qemu_snapshot/vm.log | rev | cut -d' ' -f3 | rev | tr -d '\r\n'`
    echo "Found SCRATCH in snapshot: $NEWSCRATCH"
    sed -i "s/REPLACEMESCRATCH/${NEWSCRATCH}/" src/fuzzer.rs
  else
    echo "Fuzzer doesn't have REPLACEME markers.. skipping"
  fi

}

install_prereqs
init_fuzz_template
init_qemu_snapshot
build_harness
take_snapshot
copy_snapshot_directory
init_fuzzer
