#!/bin/bash

set -e

AMI=$1

# Install dependencies
install_prereqs() {
  ../install_prereqs.sh
}

install_prereqs() {

  # Install rust
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > /tmp/install_rust.sh
  chmod +x /tmp/install_rust.sh
  /tmp/install_rust.sh --default-toolchain nightly -y

  # Install pre-reqs
  sudo apt update
  sudo apt install -y clang gcc 

}

# Initialize the fuzz template
init_fuzz_template() {
  # Initialize this example based on the fuzzer template
  cp -r -L ../../fuzzer_template/* .

  # Remove the create_snapshot.sh template since this example uses this file (make_example.sh)
  rm create_snapshot.sh

  # Copy this example's fuzzer into the src/ directory (created by copying from fuzzer_template)
  if [ "$AMI" == "ami" ]; then
    # Use the demo challenge fuzzer for the AMI
    cp fuzzer.rs.ami src/fuzzer.rs
  else
    # Use the solution fuzzer
    cp fuzzer.rs src/fuzzer.rs
  fi

  cp main.rs src/main.rs

  # Add snapchange as library for this example
  $HOME/.cargo/bin/cargo add snapchange --path ../..
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
  wget https://download.osgeo.org/libtiff/tiff-4.0.4.tar.gz
  tar -xzvf tiff-4.0.4.tar.gz
  rm tiff-4.0.4.tar.gz

  pushd tiff-4.0.4

  # Apply the patch for snapshotting libtiff
  patch -p1 < ../0001-snapshot.patch

  # Build libtiff
  CC=clang CXX=clang++ CFLAGS='-ggdb -fsanitize=address' CXXFLAGS='-ggdb -fsanitize=address' ./configure --disable-shared --prefix=$PWD/build
  make -j `nproc`
  make install

  popd
}

take_snapshot() {
  # Sanity check the target has been build
  if [ ! -f "./tiff-4.0.4/build/bin/tiffinfo" ]; then 
    echo "ERROR: example1 target not found"
    exit 0
  fi

  # Build the image to execute the harness on start
  pushd ./qemu_snapshot/IMAGE
  ./build.sh ../../tiff-4.0.4/build/bin/tiffinfo -D -j -c -r -s -w ../../tiff-4.0.4/test/images/logluv-3c-16b.tiff
  popd

  # Take the snapshot
  pushd ./qemu_snapshot
  ./snapshot.sh
  popd
}

# Move the snapshot directory out of qemu_snapshot
copy_snapshot_directory() {
  mv qemu_snapshot/output snapshot

  # Initialize input directory
  mkdir -p snapshot/input

  # Copy test image as the starting corpus
  find tiff-4.0.4/test/images/*tiff -size -40k -exec cp {} snapshot/input/ \;
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

    # 564:[   22.672444] rc.local[186]: SNAPSHOT: Input buffer: 0x631000000800 Buffer len: 0x10000 Size Addr: 0x7fffffffe7b0
    NEWBUFF=`grep SNAPSHOT qemu_snapshot/vm.log | tr -d '\r\n' | rev | cut -d' ' -f7 | rev`
    echo "Found buffer in snapshot: $NEWBUFF"
    sed -i "s/REPLACEMEBUFF/${NEWBUFF}/" src/fuzzer.rs

    # 564:[   22.672444] rc.local[186]: SNAPSHOT: Input buffer: 0x631000000800 Buffer len: 0x10000 Size Addr: 0x7fffffffe7b0
    NEWSIZE=`grep SNAPSHOT qemu_snapshot/vm.log | tr -d '\r\n' | rev | cut -d' ' -f1 | rev`
    echo "Found size addr in snapshot: $NEWSIZE"
    sed -i "s/REPLACEMESIZE/${NEWSIZE}/" src/fuzzer.rs

  else
    echo "Fuzzer doesn't have REPLACEME markers.. skipping"
  fi
}

# Create the coverage breakpoints for this target
create_coverage_breakpoints() {
  # Get the base address of the example from the module list
  BASE=`grep tiffinfo ./snapshot/gdb.modules | cut -d' ' -f1`

  # If binaryninja is available, attempt to create the coverage breakpoints and analysis
  if python3 -c "import binaryninja" 2>/dev/null; then 
    echo "Using Binary Ninja to dump coverage breakpoints"

    # Execute the binja plugin
    python3 ./coverage_scripts/bn_snapchange.py --bps --analysis --base-addr $BASE ./snapshot/tiffinfo.bin
  else
    echo "Using Ghidra to dump coverage breakpoints"

    pushd coverage_scripts

      # Install ghidra
      ../../install_ghidra.sh

      # Use ghidra to find the coverage basic blocks
      python3 ./ghidra_basic_blocks.py --base-addr $BASE ../snapshot/tiffinfo.bin

    popd

    # Install radare2
    # if [ ! -f $HOME/radare2 ]; then
    #   git clone https://github.com/radareorg/radare2 $HOME/radare2
    #   pushd $HOME/radare2
    #   ./sys/install.sh
    #   popd
    # fi

    # Use radare2 to gather the basic blocks
    # /usr/local/bin/r2 -q -B $BASE -c 'aa ; afb @@ *' ./tiffinfo.bin | cut -d' ' -f1 | sort | uniq > ./tiffinfo.bin.covbps
  fi
}

install_prereqs
init_fuzz_template
init_qemu_snapshot
build_harness
take_snapshot
copy_snapshot_directory
init_fuzzer
create_coverage_breakpoints
