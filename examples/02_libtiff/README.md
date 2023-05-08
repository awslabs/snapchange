# Tutorial 2 - LibTIFF 4.0.4 

This tutorial is a walkthrough of:

    * Finding a snapshot location from a file read
    * Taking a snapshot of libtiff using `qemu_snapshot`
    * Emulating a read function 
    * Ignoring status messages 
    * Finding a crash via Address Sanitizer
    * Minimizing the crash using the `minimize` subcommand

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

The `qemu_snapshot` project is how we will take a snapshot for this project. Briefly, the
project will build a Linux kernel, a patched QEMU which enables snapshotting via
`vmcall` instruction, and a Debian disk with the target binary running during boot under
`gdb`.

The fuzzer template included in snapchange contains scripts that facilitates:

    * Building the harness for a target
    * Taking a snapshot of the harness using `qemu_snapshot`
    * Generating a fuzzer.rs template, filling in information for this specific snapshot
    * Generating coverage breakpoints using `bn_snapchange.py` (or radare2)

Copy the fuzzer template (containing `qemu_snapshot`) and target source code from Snapchange as this example's repository:

```sh
$ cp -r -L <snapchange_dir>/fuzzer_template snapchange-example-02
$ cd snapchange-example-02
```

Add snapchange path as a dependency:

```sh
$ cargo add snapchange --path <snapchange_dir>
```

Modify the `snapchange-example-02/create_snapshot.sh` to build and use the example1 binary.

```sh
# Take the snapshot
take_snapshot() {
  # Build the image to execute the harness on start
  pushd ./qemu_snapshot/IMAGE
  ./build.sh ../../tiff-4.0.4/build/bin/tiffinfo -D -j -c -r -s -w ../../tiff-4.0.4/test/images/quad-tile.jpg.tiff
  popd

  # Take the snapshot
  pushd ./qemu_snapshot
  ./snapshot.sh
  popd
}
```

```sh
# Create the coverage breakpoints and analysis 
create_coverage_breakpoints() {
  # Attempt to create the coverage breakpoints and analysis
  # Our example1 binary is renamed to example1.bin in ./snapshot
  if [ ! -f "./snapshot/tiffinfo.bin.covbps" ]; then 
    # Binary Ninja
    python3 bn_snapchange.py --bps --analysis ./snapshot/tiffinfo.bin

    # radare2
    # r2 -q -c 'aa ; afb @@ *' ./snapshot/tiffinfo.bin | cut -d' ' -f1 | sort | uniq > ./snapshot/tiffinfo.bin.covbps
  fi
}
```

Execute the `./create_snapshot.sh` script to build and take the snapshot of the target.

```sh
./create_snapshot.sh
```

After the kernel boots and the binary executes, the snapshot is taken and files are
written to the `output` directory. The utility script also greps for `SNAPSHOT` to 
display any marked messages we had during the execution.

```
[*] Found this SNAPSHOT output from the vm log
[   21.990653] rc.local[193]: SNAPSHOT: Input buffer: 0x631000000800 Buffer len: 0x10000 Size Addr: 0x7fffffffe770
```

The `output` directory (called `OUTPUT_DIR` for the rest of this tutorial) should now
contain the following files for the snapshot:

```
[*] Found the following files
total 2174532
drwxrwxr-x  2 ubuntu ubuntu       4096 Sep 27 14:56 .
drwxrwxr-x  9 ubuntu ubuntu       4096 Sep 27 14:56 ..
-rw-rw-r--  1 ubuntu ubuntu 2147483647 Sep 27 14:56 fuzzvm.physmem
-rw-rw-r--  1 ubuntu ubuntu       2359 Sep 27 14:56 fuzzvm.qemuregs
-rw-r--r--. 1 ubuntu ubuntu        375 Sep 27 14:55 gdb.modules
-rw-r--r--. 1 ubuntu ubuntu    9433789 Sep 27 14:56 gdb.symbols
-rw-r--r--. 1 ubuntu ubuntu       8606 Sep 27 14:55 gdb.vmmap
-rwxr-xr-x  1 ubuntu ubuntu    3328536 Sep 27 14:55 tiffinfo.bin
-rwxrwxr-x  1 ubuntu ubuntu   73646760 Sep 27 14:55 vmlinux
```

Coverage breakpoints are also needed for gathering coverage. Briefly, we create a file
containing all basic blocks found in a binary to use as a coverage signal. We can use 
either the [`bn_snapchange.py`](../../bn_snapchange.py) utility (if [Binary Ninja](https://binary.ninja) is
available) or use the following command with
[radare2](https://github.com/radareorg/radare2):

#### Binary Ninja

```
python3 bn_snapchange.py --bps tiffinfo.bin
```

#### radare2

```
r2 -q -c 'aa ; afb @@ *' tiffinfo.bin | cut -d' ' -f1 | sort | uniq > tiffinfo.covbps
```

With the snapshot taken, the fuzzer can now be written.

# Fuzzing with snapchange

After `./create_snapshot.sh` finishes, the template fuzzer is found in `./src/fuzzer.rs` with
snapshot specific information filled in (`RIP` and `CR3`).

Update the `MAX_INPUT_LENGTH` in `src/fuzzer.rs` to reflect the maximum input bytes the snapshot expects.

```rust
const CR3: Cr3 = Cr3(0x0000000002f70000);
impl Fuzzer for Example2Fuzzer {
    type Input = Vec<u8>;
    const START_ADDRESS: u64 = 0x528a32;
    const MAX_INPUT_LENGTH: usize = 0x10000;
```

Finally, let's initialize an `input` directory of the test images from libtiff that are
less than 30k in size:

```
$ mkdir snapshot/input
$ find tiff-4.0.4/test/images/*tiff -size -30k | xargs -i cp {} snapshot/input
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
            lookup:  BreakpointLookup::SymbolOffset("tiffinfo!_tiffReadProc", 0x0),
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
            lookup:  BreakpointLookup::SymbolOffset("tiffinfo!_tiffReadProc", 0x0),
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
            lookup:   BreakpointLookup::SymbolOffset("tiffinfo!_tiffReadProc", 0x0),
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
RIP:  0x00007ffff7cd5160 RFLAGS: ZERO_FLAG | PARITY_FLAG
----------------------------------------------------- INSTRUCTION ------------------------------------------------------
INSTR: libc.so.6!__GI_exit+0x0 | sub rsp, 0x8
    RSP:0x7fffffffebb8 -> libc.so.6!__libc_start_call_main+0x81 -> '芺'
    ??_Immediate8to64_?? [48, 83, ec, 08]
```

Excellent! The fuzzer reached `exit`. With the `read` hook implemented, we also need to
populate the `giant_buffer` that was allocated by us in the harness.

Reminder from taking the snapshot, below are the buffer address and size address:

```
SNAPSHOT: Input buffer: 0x631000000800 Size Addr: 0x7fffffffe770
```

We want the input buffer to be populated at the beginning of each fuzz run. This will
happen in the `set_input()` function in the fuzzer.

```rust
// src/fuzzer.rs

fn set_input(&mut self, input: &[u8], fuzzvm: &mut FuzzVm) -> Result<()> {
    // SNAPSHOT: Input buffer: 0x631000000800 Size Addr: 0x7fffffffe770

    // Write the mutated input
    fuzzvm.write_bytes_dirty(VirtAddr(0x6310_0000_0800), Cr3(0x276_a000), &input)?;

    // Write the mutated input length
    fuzzvm.write::<u32>(VirtAddr(0x7fff_ffff_e770), Cr3(0x276_a000), input.len() as u32)?;

    Ok(())
}
```

Libtiff also has a few status message wrappers that we don't necessarily need for
fuzzing: `TIFFErrorExt` and `TIFFWarningExt`. Let's hook and immediately return from
these functions to ignore them.

```rust
// src/fuzzer.rs

fn breakpoints(&self) -> Option<&[Breakpoint]> {
    Some(&[
        <snip>
        Breakpoint {
            lookup:   BreakpointLookup::SymbolOffset("tiffinfo!TIFFErrorExt", 0x0),
            bp_type: BreakpointType::Repeated,
            bp_hook: |fuzzvm: &mut FuzzVm, input, _fuzzer| { 
                // let error = fuzzvm.read_c_string(VirtAddr(fuzzvm.rdx()), CR3)?;
                // log::info!("tiffinfo ERROR: {error}");
                fuzzvm.fake_immediate_return()?;
                Ok(Execution::Continue)
            }
        },
        Breakpoint {
            lookup:   BreakpointLookup::SymbolOffset("tiffinfo!TIFFWarningExt", 0x0),
            bp_type: BreakpointType::Repeated,
            bp_hook: |fuzzvm: &mut FuzzVm, input, _fuzzer| { 
                // let error = fuzzvm.read_c_string(VirtAddr(fuzzvm.rdx()), CR3)?;
                // log::info!("tiffinfo WARN: {error}");
                fuzzvm.fake_immediate_return()?;
                Ok(Execution::Continue)
            }
        },
    ])
}
```

We can now start running the fuzzer:

```
$ cargo run -r -- fuzz -c 4
```

After a bit of time, crashes should be found in `./snapshot/crashes`

```
$ ls ./snapshot/crashes

ASAN_OutOfMemory_allocation:0x7e000002_2113929218_bytes
ASAN_OutOfMemory_allocation:0x8c000009_2348810249_bytes
ASAN_OutOfMemory_allocation:0x837f7668_2206168680_bytes
ASAN_OutOfMemory_allocation:0x82837f76_2189655926_bytes
ASAN_OutOfMemory_allocation:0xb8b8b808_3099113480_bytes
ASAN_OutOfMemory_allocation:0xebeccccc_3958164684_bytes
ASAN_READ23_pc:0x43ad6b_crashing_addr:0x603000000146_tiffinfo!_ZL13printf_commonPvPKcP13__va_list_tag+0x95b
ASAN_READ23_pc:0x43ad6b_crashing_addr:0x603000000176_tiffinfo!_ZL13printf_commonPvPKcP13__va_list_tag+0x95b
ASAN_READ23_pc:0x43ad6b_crashing_addr:0x603000000236_tiffinfo!_ZL13printf_commonPvPKcP13__va_list_tag+0x95b
```

Looks like there are a few out of memory allocation errors from ASAN. This is due to the 
2G VM currently used by qemu_snapshot. Let's see if the ASAN `read` crashes reproduce
with the original binary (the exact crashing file will probably be different on your
machine):

```
$ tiff-4.0.4/build/bin/tiffinfo -D -j -c -r -s -w 02_libtiff/snapshot/crashes/ASAN_READ23_pc\:0x43ad6b_crashing_addr\:0x603000000146_tiffinfo\!_ZL13printf_commonPvPKcP13__va_list_tag+0x95b/41356f7c
```

```
TIFF Directory at offset 0xbd4 (3028)
  Image Width: 157 Image Length: 151
  Bits/Sample: 1
  Compression Scheme: None
  Samples/Pixel: 1
  Rows/Strip: 409
  Planar Configuration: single image plane
=================================================================
==42904==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x603000000116 at pc 0x00000043ad6b bp 0x7ffed7150a50 sp 0x7ffed71501d8
READ of size 23 at 0x603000000116 thread T0
    #0 0x43ad6a in printf_common(void*, char const*, __va_list_tag*) (/home/ubuntu/targets/libtiff-4.0.4/tiff-4.0.4/build/bin/tiffinfo+0x43ad6a)
    #1 0x43c1ef in fprintf (/home/ubuntu/targets/libtiff-4.0.4/tiff-4.0.4/build/bin/tiffinfo+0x43c1ef)
    #2 0x534215 in _TIFFPrintField /home/ubuntu/targets/libtiff-4.0.4/tiff-4.0.4/libtiff/tif_print.c:127:4
    #3 0x5321aa in TIFFPrintDirectory /home/ubuntu/targets/libtiff-4.0.4/tiff-4.0.4/libtiff/tif_print.c:641:5
    #4 0x4c50d2 in tiffinfo /home/ubuntu/targets/libtiff-4.0.4/tiff-4.0.4/tools/tiffinfo.c:449:2
    #5 0x4c4af0 in main /home/ubuntu/targets/libtiff-4.0.4/tiff-4.0.4/tools/tiffinfo.c:152:6
    #6 0x7fe689b19082 in __libc_start_main /build/glibc-SzIz7B/glibc-2.31/csu/../csu/libc-start.c:308:16
    #7 0x41c4cd in _start (/home/ubuntu/targets/libtiff-4.0.4/tiff-4.0.4/build/bin/tiffinfo+0x41c4cd)
```

Looks like the fuzzer found an out of bounds read with Address Sanitizer!

# Minimizing the crash

With a crashing input in hand, it is often nice to minimize the crash to aid in the root
cause analysis of the crashing input. Snapchange provides a basic minimizer which will
attempt to delete slices of bytes, individual bytes, and then overwrite bytes to find the
relevant bytes for the crash while keeping the crashing state constant.

Execute the `minimize` subcommand with the crashing input:

```
$ cargo run -r -- minimize ./snapshot/crashes/ASAN_READ23_pc\:0x43ad6b_crashing_addr\:0x603000000146_tiffinfo\!_ZL13printf_commonPvPKcP13__va_list_tag+0x95b/41356f7c
```

A bit of status about the current state of the minimizer during the process:

```
[2022-09-26T19:53:12Z INFO  snapchange::commands::minimize] Minimize State: Slices Input len: 3290
[2022-09-26T19:53:12Z INFO  snapchange::commands::minimize] Minimize State: MultiBytes Input len: 3290
[2022-09-26T19:53:13Z INFO  snapchange::commands::minimize] Exec/sec: 3935.20 Input len: 3277
[2022-09-26T19:53:14Z INFO  snapchange::commands::minimize] Exec/sec: 3965.37 Input len: 3265
[2022-09-26T19:53:14Z INFO  snapchange::commands::minimize] Minimize State: SingleBytes Input len: 3265
[2022-09-26T19:53:15Z INFO  snapchange::commands::minimize] Exec/sec: 3980.17 Input len: 3251
[2022-09-26T19:53:16Z INFO  snapchange::commands::minimize] Exec/sec: 3993.19 Input len: 3238
[2022-09-26T19:53:16Z INFO  snapchange::commands::minimize] Minimize State: Replace(cd) Input len: 3238
[2022-09-26T19:53:17Z INFO  snapchange::commands::minimize] Exec/sec: 3776.88 Input len: 3238
[2022-09-26T19:53:18Z INFO  snapchange::commands::minimize] Exec/sec: 3848.10 Input len: 3238
[2022-09-26T19:53:19Z INFO  snapchange::commands::minimize] Minimized from 3290 -> 3238 bytes
[2022-09-26T19:53:19Z INFO  snapchange::commands::minimize] Writing minimized file: "./snapshot/crashes/ASAN_READ23_pc:0x43ad6b_crashing_addr:0x603000000146_tiffinfo!_ZL13printf_commonPvPKcP13__va_list_tag+0x95b/41356f7c_min_by_size"
```

The minimized input now has been reduced in size a bit as well as has irrelevent bytes
overwritten:

```
$ xxd ASAN_READ23_pc\:0x43ad6b_crashing_addr\:0x603000000146_tiffinfo\!_ZL13printf_commonPvPKcP13__va_list_tag+0x95b/41356f7c_min_by_size
┌────────┬─────────────────────────┬─────────────────────────┬────────┬────────┐
│00000000│ 4d 4d 00 2a 00 00 0b d4 ┊ cd cd cd cd cd cd cd cd │MM0*00•×┊××××××××│
│00000010│ cd cd cd cd cd cd cd cd ┊ cd cd cd cd cd cd cd cd │××××××××┊××××××××│
│*       │                         ┊                         │        ┊        │
│00000bd0│ cd cd cd cd 00 0e 01 00 ┊ 00 03 00 00 00 01 00 9d │××××0••0┊0•000•0×│
│00000be0│ cd cd 01 01 00 03 00 00 ┊ 00 01 00 97 cd cd 01 02 │××••0•00┊0•0×××••│
│00000bf0│ 00 03 00 00 00 01 00 01 ┊ cd cd 01 03 00 03 00 00 │0•000•0•┊××••0•00│
│00000c00│ 00 01 00 01 cd cd cd 06 ┊ cd cd cd cd cd cd cd cd │0•0•×××•┊××××××××│
│00000c10│ cd cd cd cd 00 02 00 00 ┊ 00 16 00 00 0c 82 01 11 │××××0•00┊0•00_×••│
│00000c20│ 00 04 00 00 00 01 cd cd ┊ cd cd cd cd cd cd cd cd │0•000•××┊××××××××│
│00000c30│ cd cd cd cd cd cd 01 cd ┊ cd cd cd cd cd cd cd cd │××××××•×┊××××××××│
│00000c40│ cd cd 01 17 00 04 00 00 ┊ 00 01 cd cd cd cd cd cd │××••0•00┊0•××××××│
│00000c50│ cd cd cd cd cd cd cd cd ┊ cd cd cd cd cd cd cd cd │××××××××┊××××××××│
│*       │                         ┊                         │        ┊        │
│00000ca0│ cd cd cd cd cd cd       ┊                         │××××××  ┊        │
└────────┴─────────────────────────┴─────────────────────────┴────────┴────────┘
```

This minimized input (ending in `_min_by_size`) should result in the same ASAN crash as before:

```
$ ./build/bin/tiffinfo -D -j -c -r -s -w 02_libtiff/snapshot/crashes/ASAN_READ23_pc\:0x43ad6b_crashing_addr\:0x603000000146_tiffinfo\!_ZL13printf_commonPvPKcP13__va_list_tag+0x95b/41356f7c_min_by_size
TIFFReadDirectoryCheckOrder: Warning, Invalid TIFF directory; tags are not sorted in ascending order.
TIFFReadDirectory: Warning, Unknown field with tag 52486 (0xcd06) encountered.
TIFFReadDirectory: Warning, Unknown field with tag 52685 (0xcdcd) encountered.
TIFFReadDirectory: Warning, Unknown field with tag 461 (0x1cd) encountered.
TIFF Directory at offset 0xbd4 (3028)
  Image Width: 157 Image Length: 151
  Bits/Sample: 1
  Compression Scheme: None
  Planar Configuration: single image plane
=================================================================
==46385==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x603000000116 at pc 0x00000043ad6b bp 0x7fff5729cbd0 sp 0x7fff5729c358
READ of size 23 at 0x603000000116 thread T0
    #0 0x43ad6a in printf_common(void*, char const*, __va_list_tag*) (/home/ubuntu/targets/libtiff-4.0.4/tiff-4.0.4/build/bin/tiffinfo+0x43ad6a)
    #1 0x43c1ef in fprintf (/home/ubuntu/targets/libtiff-4.0.4/tiff-4.0.4/build/bin/tiffinfo+0x43c1ef)
    #2 0x534215 in _TIFFPrintField /home/ubuntu/targets/libtiff-4.0.4/tiff-4.0.4/libtiff/tif_print.c:127:4
    #3 0x5321aa in TIFFPrintDirectory /home/ubuntu/targets/libtiff-4.0.4/tiff-4.0.4/libtiff/tif_print.c:641:5
    #4 0x4c50d2 in tiffinfo /home/ubuntu/targets/libtiff-4.0.4/tiff-4.0.4/tools/tiffinfo.c:449:2
    #5 0x4c4af0 in main /home/ubuntu/targets/libtiff-4.0.4/tiff-4.0.4/tools/tiffinfo.c:152:6
    #6 0x7fcaae1b0082 in __libc_start_main /build/glibc-SzIz7B/glibc-2.31/csu/../csu/libc-start.c:308:16
    #7 0x41c4cd in _start (/home/ubuntu/targets/libtiff-4.0.4/tiff-4.0.4/build/bin/tiffinfo+0x41c4cd)
```
