# Snapshot in a docker

## Build the docker container

Execute the build script. This will copy the `fuzzer_template` locally and build the raw
linux image. This image will then be copied into the guest to be used as a basis for
each snapshot. The docker image will then be built.

_TODO: Figure out if building the entire image in a single Docker is feesible._

```
./build.sh
```

## Taking a snapshot

The `start.sh` script (the entrypoint of the docker) is used in the container to take the snapshot. This script expects 
the command used to take the snapshot as arguments to executing the containing. 

We can take a snapshot of [Example 1](../examples/01_getpid) as the following.

```
clang ../examples/01_getpid/harness/example1.c -o example1
docker run --rm -t -v $PWD:/out snapchange /out/example1
```

We need to map a local directory into the container and then use that directory as the command
in the container.

In this example:

* We build the `./example1` binary in the current directory
* We map the current directory as `/out` in the container
* Execute the `/out/example1` in the container to take the snapshot

After taking the snapshot, there is a `fuzzer` directory with the snapshot and a fuzzing template.

```
fuzzer/Cargo.toml
fuzzer/snapshot
fuzzer/snapshot/example1.bin
fuzzer/snapshot/fuzzvm.physmem
fuzzer/snapshot/fuzzvm.qemuregs
fuzzer/snapshot/gdb.modules
fuzzer/snapshot/gdb.symbols
fuzzer/snapshot/gdb.vmmap
fuzzer/snapshot/reset.sh
fuzzer/snapshot/vmlinux
fuzzer/src
fuzzer/src/fuzzer.rs
fuzzer/src/main.rs
```

The `fuzzer.rs` will populate the following:

* CR3 found in the `fuzzvm.qemuregs`
* RIP found in the `fuzzvm.qemuregs`
* Any output that contains SNAPSHOT from the execution of the binary

```
// [   22.891946] rc.local[190]: SNAPSHOT Data buffer: 0x555555556004
const CR3: Cr3 = Cr3(0x0000000107c86000);
const START_ADDRESS: u64 = 0x0000555555555365;
```

## Libfuzzer snapshot

The container can also take a snapshot of a binary built with libfuzzer by adding 
the `LIBFUZZER` environment variable.

```
docker run --rm -t -v $PWD:/out -e LIBFUZZER=1 snapchange /out/example1
```

A `vmcall ; int3` is written at the beginning of the `LLVMFuzzerTestOneInput` to facilitate 
the snapshot. Those instructions are then overwritten to the original instructions after the 
snapshot has been taken.


The same `fuzzer` directory is written in the same way as above.
