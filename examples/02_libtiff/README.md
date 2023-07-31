# Tutorial 2 - LibTIFF 4.0.4 

This tutorial is a walkthrough of:

    * Finding a snapshot location from a file read
    * Taking a snapshot of libtiff using `qemu_snapshot`
    * Emulating a read function 
    * Ignoring status messages 
    * Finding a crash via Address Sanitizer
    * Minimizing the crash using the `minimize` subcommand

_There is an included `./make_example.sh` script to build and snapshot this example. This script
goes through each of the steps described below._

# Overview

This example demonstrates [Example 4](https://github.com/antonio-morales/Fuzzing101/tree/main/Exercise%204) 
from the Fuzzing 101 fuzzing series. In this example, CVE-2016-9297 is discovered in
LibTIFF 4.0.4. We will leverage the binary `tiffinfo` included in libtiff for fuzzing.

Let's begin by building LibTIFF and exploring how our input data is processed by the target.

# Building the target

Grab a copy of LibTIFF and ensure it can be built with Address Sanitizer:


### Download and extract the target

```
$ mkdir snapshot_libtiff && cd snapshot_libtiff

$ wget https://download.osgeo.org/libtiff/tiff-4.0.4.tar.gz
$ tar -xzvf tiff-4.0.4.tar.gz
$ cd tiff-4.0.4
```

### Build the target using ASAN

Configure a static build (`--disable-shared`) of libtiff using `clang` with Address Sanitizer (`-fsanitize=address`):

```
$ CC=clang CXX=clang++ CFLAGS='-ggdb -fsanitize=address' CXXFLAGS=$CFLAGS ./configure --disable-shared --prefix=$PWD/build
$ make
$ make install
```

Confirm that the utility `tiffinfo` was built properly and it parses an example input:

```
$ ./build/bin/tiffinfo -D -j -c -r -s -w ./test/images/logluv-3c-16b.tiff
```

```
TIFF Directory at offset 0x10 (16)
  Image Width: 1 Image Length: 1
  Bits/Sample: 16
  Sample Format: signed integer
  Compression Scheme: SGILog
  Photometric Interpretation: CIE Log2(L) (u',v')
  Samples/Pixel: 3
  Rows/Strip: 682
  Planar Configuration: single image plane
  1 Strips:
      0: [       8,        8]
```

And that the utility `tiffinfo` was built with asan:

```
$ nm ./build/bin/tiffinfo | grep asan_report
```

```
000000000049a6a0 T __asan_report_error
000000000049ad50 T __asan_report_exp_load1
000000000049afd0 T __asan_report_exp_load16
000000000049adf0 T __asan_report_exp_load2
000000000049ae90 T __asan_report_exp_load4
000000000049af30 T __asan_report_exp_load8
000000000049b430 T __asan_report_exp_load_n
<snip>
```

# Choosing a snapshot location

_NOTE: Skip this section to jump straight to the snapshot and avoid an explanation of the
steps followed to find this snapshot location_

With the binary built, we can begin exploring how and where our input file is read and
parsed by `tiffinfo` to understand how we can best snapshot the target. An initial
starting point is to run the same command under `strace`:

```
$ strace ./build/bin/tiffinfo -D -j -c -r -s -w ./test/images/logluv-3c-16b.tiff
```

Three particular syscalls explain how the input file is read:

```
# File is opened
openat(AT_FDCWD, "./test/images/logluv-3c-16b.tiff", O_RDONLY) = 3

# 8 bytes are read from the opened file
read(3, "II*\0\20\0\0\0", 8)            = 8

# The file is then mmap'ed to be read further
mmap(NULL, 166, PROT_READ, MAP_SHARED, 3, 0) = 0x7fad6be1c000
```

In the simplest situation for snapshot fuzzing, a single data buffer is read and processed
by the target without more input data being requested. This isn't quite the case here since
we are reading 8 bytes and then mmap'ing a file descriptor, but we can massage the code a
bit to fit the ideal case. 

First step is to find the `read` and `mmap` calls in the source. This can be done in gdb
by setting a breakpoint on `open` looking for the input `logluv-3c-16b.tiff` file. After
hitting the `open` breakpoint, setting a new breakpoint on `read`, and then finally
setting a breakpoint on `mmap` (These code snippets are leveraging 
[pwndbg](https://github.com/pwndbg/pwndbg) for a bit nicer display).

```
$ gdb --args ./build/bin/tiffinfo -D -j -c -r -s -w ./test/images/logluv-3c-16b.tiff

# Run until the open call with the input file in `rdi` (the first argument)
pwndbg> break open
pwndbg> r
RDI  0x7fffffffeae3 ◂— './test/images/logluv-3c-16b.tiff'

# Run until the return and notate the file descriptor as a sanity check
pwndbg> finish
*RAX  0x3

# Run until the next read with the noted file descriptor
pwndbg> break read
pwndbg> c
*RDX  0x8 # Reading 8 bytes
*RDI  0x3 # From the file descriptor of the input file

(ins)pwndbg> k
#0  0x0000000000434464 in read ()
#1  0x000000000054e494 in _tiffReadProc (fd=0x7fff00000003, buf=0x6190000002e8, size=8) 
    at tif_unix.c:75
#2  0x0000000000529931 in TIFFClientOpen (name=0x7fffffffeaa9 "./test/images/logluv-3c-16b.tiff", 
    mode=0x5d9000 <str> "rc", clientdata=0x7fff00000003, readproc=0x54e270 <_tiffReadProc>, 
    writeproc=0x54e510 <_tiffWriteProc>, seekproc=0x54e7b0 <_tiffSeekProc>, 
    closeproc=0x54ea50 <_tiffCloseProc>, sizeproc=0x54ec20 <_tiffSizeProc>, 
    mapproc=0x54ef10 <_tiffMapProc>, unmapproc=0x54f2a0 <_tiffUnmapProc>) at tif_open.c:272

pwndbg> break mmap
pwndbg> c
pwndbg> k
#0  0x0000000000473130 in mmap ()
#1  0x000000000054f12b in _tiffMapProc (fd=0x7fff00000003, pbase=0x619000000418, psize=0x7fffffffda50) 
    at tif_unix.c:138
#2  0x000000000052b899 in TIFFClientOpen (name=0x7fffffffeaa9 "./test/images/logluv-3c-16b.tiff", 
    mode=0x5d9000 <str> "rc", clientdata=0x7fff00000003, readproc=0x54e270 <_tiffReadProc>, 
    writeproc=0x54e510 <_tiffWriteProc>, seekproc=0x54e7b0 <_tiffSeekProc>, 
    closeproc=0x54ea50 <_tiffCloseProc>, sizeproc=0x54ec20 <_tiffSizeProc>, 
    mapproc=0x54ef10 <_tiffMapProc>, unmapproc=0x54f2a0 <_tiffUnmapProc>) at tif_open.c:446

```

The read call can be found in `libtiff/tif_open.c:272` in a wrapper of `ReadOK` and the 
mmap call can be found in `libtiff/tif_open.446`.

```c
libtiff/tif_open.c

  72   │ TIFF*
  73   │ TIFFClientOpen(
<snip>
  86   │     TIFF *tif;
<snip>
 268   │     /*
 269   │      * Read in TIFF header.
 270   │      */
 271   │     if ((m & O_TRUNC) ||
 272 **│         !ReadOK(tif, &tif->tif_header, sizeof (TIFFHeaderClassic))) {
 273   │         if (tif->tif_mode == O_RDONLY) {
 274   │             TIFFErrorExt(tif->tif_clientdata, name,
 275   │                 "Cannot read TIFF header");
 276   │             goto bad;
 277   │         }
```

```c
libtiff/tif_open.c

 438   │  /*
 439   │   * Try to use a memory-mapped file if the client
 440   │   * has not explicitly suppressed usage with the
 441   │   * 'm' flag in the open mode (see above).
 442   │   */
 443   │  if (tif->tif_flags & TIFF_MAPPED)
 444   │  {
 445   │      toff_t n;
 446 **│      if (TIFFMapFileContents(tif,(void**)(&tif->tif_base),&n))
 447   │      {
 448   │          tif->tif_size=(tmsize_t)n;
 449   │          assert((toff_t)tif->tif_size==n);
 450   │      }
 451   │      else
 452   │          tif->tif_flags &= ~TIFF_MAPPED;
 453   │  }
 ```

Both of these function calls are in the same function: `TIFFClientOpen`. Looking over the 
code, these calls are initializing various pieces of the main `tif` structure.

 * The `read` is reading `8` bytes into `tif->tif_header`
 * The `mmap` is setting `tif->tif_base` to a buffer containing the input data and
   `tif->tif_size` to the number of bytes in the buffer.

There are several ways we could handle snapshotting this:

 1) Snapshot just after the `read` syscall. In the fuzzer, fill the buffer handed to `read`
    with `8` bytes of input data. Set another breakpoint (via the fuzzer) after the `mmap`
    syscall and then fill this buffer with the entire input.
 2) Allocate a buffer at the beginning of this function. Snapshot just after allocating
    this buffer. Comment out the `read` and `mmap` function calls and use our allocated 
    buffer instead. 

Option 1 there is less modification to the original source code, meaning a more
accurate representation of the target during fuzzing at the cost of more breakpoints and
a potentially tricker time getting the hooks right.

Option 2 would rely on a little source code modification which would mean a less accurate
representation of the target (and heap state), but allow for a bit easier hooking setup.

This tutorial will combine the two for demonstration. There isn't one correct way of 
tackling the problem, so we will hook the `read` call to write `8` bytes of header into the
fuzzer and then use a bit of source modification to satisfy the `mmap` call.

# Snapshot and source code modifications

For this snapshot:

 * Modify the `mmap` call in source with a pre-allocated buffer to avoid the `mmap` call
 * Hook the `read` call in the fuzzer to read `8` bytes for the header

## Modify the mmap call

To modify the `mmap` call, after the main `tif` object is allocated, create our own
`giant_buffer` for the input.  The addresses of `giant_buffer` and `buffer_size` are
printed as those will be the memory locations to modify during fuzzing.

```c
libtiff/tif_open.c

 121   │ if (tif == NULL) {
 122   │     TIFFErrorExt(clientdata, module, "%s: Out of memory (TIFF structure)", name);
 123   │     goto bad2;
 124   │ }
 125 + │
 126 + │ /* SNAPSHOT DATA */
 127 + │ int buffer_len = 0x10000;
 128 + │ int buffer_size = 0;
 129 + │ void* giant_buffer = 0;
 130 + │ if(getenv("SNAPSHOT") != 0) {
 131 + │     giant_buffer = malloc(buffer_len);
 132 + │     memset(giant_buffer, 0, buffer_len);
 133 + │     buffer_size = 0;
 134 + │     printf("SNAPSHOT: Input buffer: %p Buffer len: 0x%x Size Addr: %p\n", giant_buffer,
 135 + │         buffer_len, &buffer_size);
 136 + │     fflush(stdout);
 137 + │
 138 + │     __asm("int3 ; vmcall");
 139 + │ }
 140 + │
 141 + │ /* END SNAPSHOT DATA */
 142 + │
 143   │ _TIFFmemset(tif, 0, sizeof (*tif));

```

With this buffer allocated (and mutated during fuzzing), we can use it to replace the
`mmap` call:

```c
libtiff/tif_open.c

 463   │             if (tif->tif_flags & TIFF_MAPPED)
 464   │             {
                         // Called during snapshoting (when giant buffer is allocated)
 465 ~ │                 if(giant_buffer != 0) {
 466 ~ │                     tif->tif_base = giant_buffer;
 467 ~ │                     tif->tif_size = (tmsize_t)buffer_size;
 468 ~ │                 } else {
                            // Called during normal execution of the binary
 469 ~ │                     toff_t n;
 470 ~ │                     if (TIFFMapFileContents(tif,(void**)(&tif->tif_base),&n)) {
 471 ~ │                         tif->tif_size=(tmsize_t)n;
 472 ~ │                         assert((toff_t)tif->tif_size==n);
 473 ~ │                     } else {
 474 ~ │                         tif->tif_flags &= ~TIFF_MAPPED;
 475 ~ │                     }
 476 ~ │                 }
 477   │             }
```

With the the input buffer modified, rebuild `tiffinfo` and then take the snapshot.

```
$ make
$ make install
```

Executing `tiffinfo` should now display the address of the new input buffer, the address
to write the current size of the buffer, and then trap on the breakpoint.

```
$ SNAPSHOT=1 ./build/bin/tiffinfo -D -j -c -r -s -w ./test/images/logluv-3c-16b.tiff
SNAPSHOT: Input buffer: 0x631000000800 Buffer len: 0x10000 Size Addr: 0x7fffa6c29510
Trace/breakpoint trap (core dumped)
```

With the binary prepped, the snapshot can now be taken.

## Taking the snapshot

Snapchange includes a [docker](../../docker) to take a snapshot of this example. Briefly, the
project will build a Linux kernel, a patched QEMU which enables snapshotting via
`vmcall` instruction, and use an `initramfs` to run the target binary under `gdb`.

To use the Snapchange docker image to create this snapshot, we write a small [Dockerfile](./Dockerfile) 
which will build this example target and set the variables needed for the `snapchange` image.

Begin by starting with a `base` image and include the requisites: `gdb` and `python3` for taking the
snapshot and `clang` and `compiler-rt` to build the target with clang and Address Sanitizer.

```
FROM alpine:edge as base

RUN apk add --no-cache --initramfs-diskless-boot python3 gdb curl tar build-base perf \
  clang compiler-rt
```

Copy the patch and build the target:

```
COPY 0001-snapshot.patch /opt
RUN cd /opt/ && \
  wget https://download.osgeo.org/libtiff/tiff-4.0.4.tar.gz && \
  tar -xzvf tiff-4.0.4.tar.gz && \
  rm tiff-4.0.4.tar.gz && \
  cd tiff-4.0.4 && \
  patch -p1 < ../0001-snapshot.patch && \
  CC=clang \
    CXX=clang++ \
    CFLAGS='-ggdb -fsanitize=address' \
    CXXFLAGS='-ggdb -fsanitize=address' \
    ./configure --disable-shared --prefix=$PWD/build && \
  make -j `nproc` && \
  make install
```

Then, switch to the base `snapchange` image and copy all of the `base` image into the directory
that snapchange is expecting the target to live (`$SNAPSHOT_INPUT`):

```
FROM snapchange
COPY --from=base / "$SNAPSHOT_INPUT"
```

Write the variables the `snapchange` image is expecting to take the snapshot

```
ENV SNAPSHOT_ENTRYPOINT=/opt/tiff-4.0.4/build/bin/tiffinfo
ENV SNAPSHOT_ENTRYPOINT_ARGUMENTS="-D -j -c -r -s -w /opt/tiff-4.0.4/test/images/logluv-3c-16b.tiff"
ENV SNAPSHOT_EXTRACT="/opt/tiff-4.0.4/test/images"
```

* `SNAPSHOT_ENTRYPOINT` - The command to execute
* `SNAPSHOT_ENTRYPOINT_ARGUMENTS` - Arguments for the target being executed
* `SNAPSHOT_EXTRACT` - Files to extract from the image to the output directory

Now we can build and run the docker image to take the snapshot:

```
# Build the base snapchange image used for snapshotting
pushd ../../docker
docker build -t snapchange .
popd

# Build this example's image
docker build -t snapchange_example2 .

# Run the image to take the snapshot
docker run -i \
    -v $(realpath -m ./snapshot):/snapshot/ \
    -e SNAPSHOT_IMGTYPE=initramfs \
    snapchange_example2
```

Finally, we want to populate the starting corpus using the test files from project itself:

```
mkdir -p snapshot/input
find snapshot/image/opt/tiff-4.0.4/test/images/*tiff -size -40k -exec cp {} snapshot/input/ \;
```

The `snapshot` directory should now contain the following files for the snapshot:

```
$ ls -la snapshot/

.rw-r--r--  5.4G user 31 Jul 13:06 fuzzvm.physmem
.rw-r--r--  2.4k user 31 Jul 13:06 fuzzvm.qemuregs
.rw-------@  133 user 31 Jul 13:06 gdb.modules
.rw-------@ 7.6M user 31 Jul 13:06 gdb.symbols
.rw-------@ 3.8k user 31 Jul 13:06 gdb.vmmap
.rw-------  7.3M user 31 Jul 13:06 guestkernel.kallsyms
drwxrwxr-x     - user 31 Jul 13:10 input
.rwxr-xr-x   118 user 31 Jul 13:06 reset.sh
.rwxr-xr-x  4.4M user 31 Jul 13:05 tiffinfo.bin
.rw-r-----  636k user 31 Jul 13:10 tiffinfo.bin.ghidra.covbps
.rw-r--r--   34k user 31 Jul 13:06 vm.log
.rwxr-xr-x  400M user 31 Jul 13:05 vmlinux
```

Coverage breakpoints are also needed for gathering coverage. Briefly, we create a file
containing all basic blocks found in a binary to use as a coverage signal. The snapchange
docker uses [this](../../docker/coverage_scripts/ghidra_basic_blocks.py) Ghidra plugin
to find the coverage breakpoints in this example. There are a few other examples 
available as well:

#### Binary Ninja

```
python3 ../../docker/coverage_scripts/bn_snapchange.py --bps ./snapshot/tiffinfo.bin
```

#### radare2

```
r2 -q -c 'aa ; afb @@ *' tiffinfo.bin | cut -d' ' -f1 | sort | uniq > tiffinfo.covbps
```

With the snapshot taken, the fuzzer can now be written.

# Fuzzing with snapchange

Each fuzzer must set two associated values: `START_ADDRESS` and `MAX_INPUT_LENGTH`. 
The `START_ADDRESS` provides a check that the fuzzer and snapshot are paired 
correctly. The `START_ADDRESS` can be found in the `RIP` register in 
`./snapshot/fuzzvm.qemuregs`. 

The included `build.rs` will parse the `./snapshot/fuzzvm.qemuregs` to find the required `RIP` and `CR3`
from the snapshot. These constants are written to `src/constants.rs`.

Update the `MAX_INPUT_LENGTH` in `src/fuzzer.rs` to reflect the maximum input bytes the snapshot expects.

```rust
// src/fuzzer.rs

const CR3: Cr3 = Cr3(constants::CR3);
impl Fuzzer for Example2Fuzzer {
    type Input = Vec<u8>;
    const START_ADDRESS: u64 = constants::RIP;
    const MAX_INPUT_LENGTH: usize = 0x10000;
```

We can initialize the hook for `read` in `_tiffReadProc` as well in `fuzzer.rs`. Let's
start with a breakpoint resetting the VM to check that the project was setup properly.

_Note: This breakpoint returns `Execution::Reset` to signal the guest VM to reset. `Execution::Continue`
can also be used to continue execution of the guest VM after this breakpoint is handled._

```rust
// src/fuzzer.rs

fn breakpoints(&self) -> Option<&[Breakpoint]> {
    Some(&[
        // Breakpoint based on a symbol offset 
        Breakpoint {
            lookup:  AddressLookup::SymbolOffset("tiffinfo!_tiffReadProc", 0x0),
            bp_type: BreakpointType::Repeated,
            bp_hook: |fuzzvm: &mut FuzzVm, _input, _fuzzer| { 
                // Do nothing but reset the VM when this symbol has been hit
                Ok(Execution::Reset)
            }
        },
    ])
}
```

A trace can be used to trigger the reset at `_tiffReadProc` and make sure the project has
been setup properly:

```
$ cargo run -r -- trace
```

```
RAX:  0x619000000438 -> ''
RBX:  tiffinfo!_tiffCloseProc+0x0 -> 0xe4834853e5894855
RCX:  tiffinfo!_tiffReadProc+0x0 -> 0xe4834853e5894855
RDX:  0x8
RSI:  0x6190000002e8 -> 0x0
RDI:  0x3
R8 :  0xfefefefefefefe00
R9 :  0xff00000000000000
<snip>
RIP:  0x000000000054e770 RFLAGS: PARITY_FLAG
--------------------------------- INSTRUCTION ----------------------------------
INSTR: tiffinfo!_tiffReadProc+0x0 | push rbp
    RBP:0x7fffffffe850 -> 0x7fffffffe9b0 -> 0x7fffffffea30 -> 0x7fffffffebb0 -> '
    [55]
```

Great! The `_tiffReadProc` symbol was triggered, so now we can emulate the read itself.
The arguments for `_tiffReadProc` are below:

```
libtiff/tif_unix.c

  64   │ static tmsize_t
  65   │ _tiffReadProc(thandle_t fd, void* buf, tmsize_t size)
```

Let's update the hook to parse the arguments. Argument 1 is in `rdi`, argument 2 is in
`rdi`, and argument 3 is in `rdx`.

```rust
// src/fuzzer.rs

fn breakpoints(&self) -> Option<&[Breakpoint]> {
    Some(&[
        Breakpoint {
            lookup:  AddressLookup::SymbolOffset("tiffinfo!_tiffReadProc", 0x0),
            bp_type: BreakpointType::Repeated,
            bp_hook: |fuzzvm: &mut FuzzVm, input, _fuzzer| { 
                let fd   = fuzzvm.rdi();
                let buf  = fuzzvm.rsi();
                let size = fuzzvm.rdx();

                Ok(Execution::Reset)
            }
        },
    ])
}
```

Emulating the read will involve writing `size` bytes from the `input` into the `buf`
address.

```rust
// src/fuzzer.rs

fn breakpoints(&self) -> Option<&[Breakpoint]> {
    Some(&[
        Breakpoint {
            lookup:   AddressLookup::SymbolOffset("tiffinfo!_tiffReadProc", 0x0),
            bp_type: BreakpointType::Repeated,
            bp_hook: |fuzzvm: &mut FuzzVm, input, _fuzzer| { 
                let fd   = fuzzvm.rdi();
                let buf  = fuzzvm.rsi();
                let size = fuzzvm.rdx() as usize;

                // Reset the guest if there aren't enough bytes to satisfy the read
                if input.len() < size {
                    return Ok(Execution::Reset);
                }

                // Write the input bytes into the requested buffer
                fuzzvm.write_bytes_dirty(VirtAddr(buf), fuzzvm.cr3(), &input[..size])?;

                // Set the return bytes as the number of requested bytes
                fuzzvm.set_rax(size as u64);

                // Immediately return from the function as we are emulating it
                fuzzvm.fake_immediate_return()?;

                // Note: Change from Reset -> Continue here to continue the guest VM
                // instead of resetting
                Ok(Execution::Continue)
            }
        },
    })
 }
```

Since we are dealing with an input now, we need to give snapchange an example input to
test with.

```
$ cargo run -r -- trace ./snapshot/input/logluv-3c-16b.tiff
```

```
RIP:  0x00007ffff7f70087 RFLAGS: ZERO_FLAG | PARITY_FLAG
----------------------------------------------------- INSTRUCTION ------------------------------------------------------
INSTR: ld-musl-x86_64.so.1!exit+0x0 | int3
    [cc]

```

Excellent! The fuzzer reached `exit`. With the `read` hook implemented, we also need to
populate the `giant_buffer` that was allocated by us in the harness.

Reminder from taking the snapshot, below are the buffer address and size address:

```
SNAPSHOT: Input buffer: 0x631000000800 Buffer len: 0x10000 Size Addr: 0x7fffffffe950
```

These constants are parsed in the `build.rs` and set to `constants::INPUT` and `constants::INPUT_ADDR`.

We want the input buffer to be populated at the beginning of each fuzz run. This will
happen in the `set_input()` function in the fuzzer.

```rust
// src/fuzzer.rs

fn set_input(&mut self, input: &[u8], fuzzvm: &mut FuzzVm) -> Result<()> {
    // Write the mutated input
    fuzzvm.write_bytes_dirty(VirtAddr(constants::INPUT), CR3, &input)?;

    // Write the mutated input length
    fuzzvm.write::<u32>(VirtAddr(constants::INPUT_ADDR), CR3, input.len() as u32)?;

    Ok(())
}
```

Libtiff also has a few status message wrappers that we don't necessarily need for
fuzzing: `TIFFErrorExt` and `TIFFWarningExt`. Let's permanently patch the snapshot to always
return from theese message wrappers. This is a bit better than adding breakpoints as this
avoids exiting the guest on each hit. Avoiding as many guest exits as possible helps with
the performance of the fuzzer.

```rust
// src/fuzzer.rs

fn init_snapshot(&mut self, fuzzvm: &mut FuzzVm<Self>) -> Result<()> {
    for symbol in ["tiffinfo!TIFFErrorExt", "tiffinfo!TIFFWarningExt"] {
        // Get the virtual address for each of these symbols
        if let Some((virt_addr, cr3)) = fuzzvm.get_symbol_address(symbol) {
            // Patch the first instruction of each symbol to immediately return
            //
            // This is slightly better than a breakpoint since we don't have to
            // exit the guest which is a bit more costly.
            let addr = AddressLookup::Virtual(virt_addr, cr3);
            fuzzvm.patch_bytes_permanent(addr, &[0xc3]);
        }
    }

    Ok(())
}
```

We can now start running the fuzzer:

```
$ cargo run -r -- fuzz -c 4
```

After a bit of time, crashes should be found in `./snapshot/crashes`

```
$ ls ./snapshot/crashes

ASAN_READ_pc:0x5555555a899d_crashing_addr:0x602000000071_tiffinfo!_ZL13printf_commonPvPKcP13__va_list_tag+0x9fd
ASAN_READ_pc:0x5555555a899d_crashing_addr:0x603000000173_tiffinfo!_ZL13printf_commonPvPKcP13__va_list_tag+0x9fd
```

Let's see if the ASAN `read` crashes reproduce with the original binary (the exact crashing file 
will probably be different on your machine). There is a `triage.sh` utility to help execute
a crash file in the target Dockerfile

```
$ cp ./snapshot/crashes/ASAN_READ_pc:0x5555555a899d_crashing_addr:0x602000000071_tiffinfo!_ZL13printf_commonPvPKcP13__va_list_tag+0x9fd/9d39f35e298df2be poc
```

```
./triage.sh poc
```

```
=================================================================
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6030000000b3 at pc 0x55ddf350499d bp 0x7ffc4ddd1630 sp 0x7ffc4ddd0db8
READ of size 20 at 0x6030000000b3 thread T0
    #0 0x55ddf350499c in printf_common(void*, char const*, __va_list_tag*) /home/buildozer/aports/main/llvm-runtimes/src/llvm-project-16.0.6.src/compiler-rt/lib/asan/../sanitizer_common/sanitizer_common_interceptors_format.inc:553:9
    #1 0x55ddf350585b in __interceptor_vfprintf /home/buildozer/aports/main/llvm-runtimes/src/llvm-project-16.0.6.src/compiler-rt/lib/asan/../sanitizer_common/sanitizer_common_interceptors.inc:1718:1
    #2 0x55ddf350585b in __interceptor_fprintf /home/buildozer/aports/main/llvm-runtimes/src/llvm-project-16.0.6.src/compiler-rt/lib/asan/../sanitizer_common/sanitizer_common_interceptors.inc:1775:1
    #3 0x55ddf36075d6 in _TIFFPrintField /opt/tiff-4.0.4/libtiff/tif_print.c:127:4
    #4 0x55ddf360583e in TIFFPrintDirectory /opt/tiff-4.0.4/libtiff/tif_print.c:641:5
    #5 0x55ddf35a00ba in tiffinfo /opt/tiff-4.0.4/tools/tiffinfo.c:449:2
    #6 0x55ddf359fb38 in main /opt/tiff-4.0.4/tools/tiffinfo.c:152:6
    #7 0x7fcdd449e6d0 in libc_start_main_stage2 /home/buildozer/aports/main/musl/src/83b858f83b658bd34eca5d8ad4d145f673ae7e5e/src/env/__libc_start_main.c:95:2

```

Looks like the fuzzer found an out of bounds read with Address Sanitizer!

# Minimizing the crash

With a crashing input in hand, it is often nice to minimize the crash to aid in the root
cause analysis of the crashing input. Snapchange provides a basic minimizer which will
attempt to delete slices of bytes, individual bytes, and then overwrite bytes to find the
relevant bytes for the crash while keeping the crashing state constant.

Execute the `minimize` subcommand with the crashing input:

```
$ cargo run -r -- minimize poc
```

A bit of status about the current state of the minimizer during the process:

```
[2023-07-31T20:28:35Z INFO  snapchange::commands::minimize] Iters   3909/50000 | Exec/sec 1782.17
[2023-07-31T20:28:35Z INFO  snapchange::commands::minimize]     InputClone          :   0.10%
[2023-07-31T20:28:35Z INFO  snapchange::commands::minimize]     InputMinimize       :   0.06%
[2023-07-31T20:28:35Z INFO  snapchange::commands::minimize]     Execution           :  70.06%
[2023-07-31T20:28:35Z INFO  snapchange::commands::minimize]     CheckResult         :   0.06%
[2023-07-31T20:28:35Z INFO  snapchange::commands::minimize]     ResetGuest          :  29.67%
[2023-07-31T20:28:36Z INFO  snapchange::commands::minimize] Iters   4614/50000 | Exec/sec 1347.91
[2023-07-31T20:28:36Z INFO  snapchange::commands::minimize]     InputClone          :   0.08%
[2023-07-31T20:28:36Z INFO  snapchange::commands::minimize]     InputMinimize       :   0.04%
[2023-07-31T20:28:36Z INFO  snapchange::commands::minimize]     Execution           :  71.18%
[2023-07-31T20:28:36Z INFO  snapchange::commands::minimize]     CheckResult         :   0.05%
[2023-07-31T20:28:36Z INFO  snapchange::commands::minimize]     ResetGuest          :  28.62%
```

The minimized input now has been reduced in size a bit as well as has irrelevent bytes
overwritten:

```
$ xxd poc_min_by_size

┌────────┬─────────────────────────┬─────────────────────────┬────────┬────────┐
│00000000│ 4d 4d 00 2a 00 00 0b d4 ┊ cd cd cd cd cd cd cd cd │MM0*00•×┊××××××××│
│00000010│ cd cd cd cd cd cd cd cd ┊ cd cd cd cd cd cd cd cd │××××××××┊××××××××│
│*       │                         ┊                         │        ┊        │
│00000bd0│ cd cd cd cd 00 0f 01 00 ┊ 00 03 00 00 00 01 cd cd │××××0••0┊0•000•××│
│00000be0│ cd cd 01 01 00 03 00 00 ┊ 00 01 cd cd cd cd 01 02 │××••0•00┊0•××××••│
│00000bf0│ 00 03 00 00 00 01 cd cd ┊ cd cd 01 03 00 03 00 00 │0•000•××┊××••0•00│
│00000c00│ 00 01 cd cd cd cd 01 06 ┊ cd cd cd cd cd cd cd cd │0•××××••┊××××××××│
│00000c10│ cd cd cd cd 00 02 00 00 ┊ 00 13 00 00 0c 8e 01 11 │××××0•00┊0•00_×••│
│00000c20│ 00 04 00 00 00 cd 00 00 ┊ 00 cd 01 15 00 03 00 00 │0•000×00┊0×••0•00│
│00000c30│ 00 01 cd cd cd cd 01 16 ┊ 00 03 00 00 00 01 cd cd │0•××××••┊0•000•××│
│00000c40│ cd cd 01 17 00 04 00 00 ┊ 00 01 cd cd cd cd 01 29 │××••0•00┊0•××××•)│
│00000c50│ cd cd cd cd cd cd cd cd ┊ cd cd 01 0e cd cd cd cd │××××××××┊××••××××│
│00000c60│ cd cd cd cd cd cd 01 40 ┊ cd cd cd cd cd cd cd cd │××××××•@┊××××××××│
│00000c70│ cd cd 01 00 cd cd cd cd ┊ cd cd cd cd cd cd cd cd │××•0××××┊××××××××│
│00000c80│ cd cd cd cd cd cd cd cd ┊ cd cd cd cd cd cd cd cd │××××××××┊××××××××│
│*       │                         ┊                         │        ┊        │
│00000ca0│ cd                      ┊                         │×       ┊        │
└────────┴─────────────────────────┴─────────────────────────┴────────┴────────┘
```

This minimized input (ending in `_min_by_size`) should result in the same ASAN crash as before:

```
$ ./triage.sh ./poc_min_by_size

=================================================================
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6030000000b3 at pc 0x556547cf999d bp 0x7ffeff5244f0 sp 0x7ffeff523c78
READ of size 20 at 0x6030000000b3 thread T0
    #0 0x556547cf999c in printf_common(void*, char const*, __va_list_tag*) /home/buildozer/aports/main/llvm-runtimes/src/llvm-project-16.0.6.src/compiler-rt/lib/asan/../sanitizer_common/sanitizer_common_interceptors_format.inc:553:9
    #1 0x556547cfa85b in __interceptor_vfprintf /home/buildozer/aports/main/llvm-runtimes/src/llvm-project-16.0.6.src/compiler-rt/lib/asan/../sanitizer_common/sanitizer_common_interceptors.inc:1718:1
    #2 0x556547cfa85b in __interceptor_fprintf /home/buildozer/aports/main/llvm-runtimes/src/llvm-project-16.0.6.src/compiler-rt/lib/asan/../sanitizer_common/sanitizer_common_interceptors.inc:1775:1
    #3 0x556547dfc5d6 in _TIFFPrintField /opt/tiff-4.0.4/libtiff/tif_print.c:127:4
    #4 0x556547dfa83e in TIFFPrintDirectory /opt/tiff-4.0.4/libtiff/tif_print.c:641:5
    #5 0x556547d950ba in tiffinfo /opt/tiff-4.0.4/tools/tiffinfo.c:449:2
    #6 0x556547d94b38 in main /opt/tiff-4.0.4/tools/tiffinfo.c:152:6
    #7 0x7f746a1026d0 in libc_start_main_stage2 /home/buildozer/aports/main/musl/src/83b858f83b658bd34eca5d8ad4d145f673ae7e5e/src/env/__libc_start_main.c:95:2

```
