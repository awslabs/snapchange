#!/bin/bash

set -e 

AMI=$1

# Install dependencies
install_prereqs() {
  if [ ! -f $HOME/.cargo/bin/cargo ]; then
    # Install rust
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > /tmp/install_rust.sh
    chmod +x /tmp/install_rust.sh
    /tmp/install_rust.sh --default-toolchain nightly -y
    rm /tmp/install_rust.sh
  fi 

  # Install pre-reqs
  sudo apt update
  sudo apt install -y clang gcc nasm
}

# Initialize the fuzz template
init_fuzz_template() {
  # Initialize this example based on the fuzzer template
  cp -r -L ../../fuzzer_template/* .

  # Remove the create_snapshot.sh template since this example uses this file (make_example.sh)
  rm create_snapshot.sh

  # Initialize the rust files for this example
  if [ "$AMI" == "ami" ]; then
    # Use the demo challenge fuzzer for the AMI
    cp fuzzer.rs.ami src/fuzzer.rs
  else
    # Use the solution fuzzer
    cp fuzzer.rs src/fuzzer.rs
  fi

  # Copy the source files for this example
  cp main.rs src/
  cp mov_generator.rs src/

  # Add snapchange as library for this example
  $HOME/.cargo/bin/cargo add snapchange --path ../..
  $HOME/.cargo/bin/cargo add rand
}

# Initialize a qemu_snapshot for this target
init_qemu_snapshot() {
  if [ "$AMI" == "ami" ]; then
    # Use the pre-built qemu_snapshot from the init_ami.sh script
    echo "Copying from AMI qemu_snapshot"
    sudo cp -r ../qemu_snapshot .
    sudo chown -R $USER:$USER qemu_snapshot
  else 
    pushd qemu_snapshot
    ./init.sh
    popd
  fi
}

build_harness() {
  # Download the vulnerable FFmpeg
  if [ ! -d FFmpeg ]; then
    git clone https://github.com/FFmpeg/FFmpeg
  fi

  pushd FFmpeg
  git checkout ab77b878f1205225c6de1370fb0e998dbcc8bc69

  # Patch FFmpeg with the snapshot mechanism
  patch -p1 < ../0001-snapshot.patch

  # Build FFmpeg with asan
  ./configure --toolchain=clang-asan --enable-debug=3 --disable-stripping
  make -j`nproc`

  popd
}

take_snapshot() {
  # Sanity check the target has been build
  if [ ! -f "./FFmpeg/ffmpeg" ]; then 
    echo "ERROR: ffmpeg binary not found"
    exit 0
  fi

  # Build the image to execute the harness on start
  pushd ./qemu_snapshot/IMAGE

  # Copy the necessary libraries
  for lib in libxcb.so libxcb-shm.so libXau.so libXdmcp.so libxcb-shape.so libxcb-xfixes.so libasound.so; do
    LIB=$(ldd ../../FFmpeg/ffmpeg | grep $lib | cut -d ' ' -f3)
    if [ -n "$LIB" ]; then
      sudo cp $LIB chroot/lib/x86_64-linux-gnu/
    fi
  done

  # Build the image using the test `dovi-p7.mp4`
  ./build.sh ../../FFmpeg/ffmpeg -i ../../dovi-p7.mp4
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
