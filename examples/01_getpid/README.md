# Tutorial 1 - Basic usage tutorial

This tutorial is a walkthrough of:

    * Taking a snapshot of a target
    * Writing a fuzzer
    * Using a hook to force a condition
    * Finding a crash

_There is an included `./make_example.sh` script to build and snapshot this example. This script
goes through each of the steps described below._

## Target overview

The following code is the target for this tutorial:

```c
// Example test case for snapshot fuzzing
//
// Test the ability to write arbitrary memory and registers into a snapshot
//
// clang -ggdb -O0 example1.c -o example1

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void fuzzme(char* data) {
    int pid    = getpid();

    // Correct solution: data == "fuzzmetosolveme!", pid == 0xdeadbeef
    if (data[0]  == 'f') {
    if (data[1]  == 'u') {
    if (data[2]  == 'z') {
    if (data[3]  == 'z') {
    if (data[4]  == 'm') {
    if (data[5]  == 'e') {
    if (data[6]  == 't') {
    if (data[7]  == 'o') {
    if (data[8]  == 's') {
    if (data[9]  == 'o') {
    if (data[10] == 'l') {
    if (data[11] == 'v') {
    if (data[12] == 'e') {
    if (data[13] == 'm') {
    if (data[14] == 'e') {
    if (data[15] == '!') {
        pid = getpid();
        if (pid == 0xdeadbeef) {
            *(int*)0xcafecafe = 0x41414141;
        }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }

    return;
}

int main() {
    char* data = "aaaaaaaaaaaaaaaa";

    // Print the memory buffer address and pid address for fuzzing
    printf("SNAPSHOT Data buffer: %p\n", data);

    // Ensure the stdout has been flushed
    fflush(stdout);

    // Snapshot taken here
    if(getenv("SNAPSHOT") != (void*)0) { __asm("int3 ; vmcall"); }

    // Call the fuzzme function
    fuzzme(data);

    return 0;
}
```

There are two main goals for the target:

* Mutate a simple string 
* Modify the return pid of `getpid` syscall to be `0xdeadbeef` to force a crash

Note how the snapshot mechanism is added to the source code. 

```c
// Snapshot taken here
if(getenv("SNAPSHOT") != (void*)0) { __asm("int3 ; vmcall"); }
```

The `int3 ; vmcall` is how the snapshot will trigger. The `int3` is used for `gdb` to 
catch the snapshot and write symbols and memory map to disk. The `vmcall` instruction 
will trigger `QEMU` itself to write the physical memory and register state to disk. The
`strcmp(getenv("SNAPSHOT") != (void*)0)` is to allow runtime triggering of the snapshot 
mechanism.

The target also prints the memory address of the `data` buffer. These
addresses are important for knowing where to write the fuzz case in the snapshot.

The compiled binary used is `example1`. Let's begin with taking the snapshot.

## Snapshot

Snapchange includes a [docker](../../docker) to take a snapshot of this example. Briefly, the
project will build a Linux kernel, a patched QEMU which enables snapshotting via
`vmcall` instruction, and use an `initramfs` to run the target binary under `gdb`.

To use the Snapchange docker image to create this snapshot, we write a small [Dockerfile](./Dockerfile) 
which will build this example target and set the variables needed for the `snapchange` image.

Begin with installing the requisite tools in a `base` image. 

```
FROM alpine:edge as base
RUN apk add --no-cache --initramfs-diskless-boot python3 gdb curl tar build-base perf
```

Copy and build the harness in this `base` image:

```
COPY harness/* /opt/
RUN cd /opt/ && make
```

Then, switch to the base `snapchange_snapshot` image and copy all of the `base` image into the directory
that snapchange is expecting the target to live (`$SNAPSHOT_INPUT`):

```
FROM snapchange_snapshot
COPY --from=base / "$SNAPSHOT_INPUT"
```

Finally, set the variable the `snapchange` image is expecting for how to execute the harness:

```
ENV SNAPSHOT_ENTRYPOINT=/opt/example1
```

* `SNAPSHOT_ENTRYPOINT` - The command to execute

We can now build and run the container to take the snapshot.

```
# Build the base snapchange image used for snapshotting
pushd ../../docker
docker build -t snapchange .
popd

# Build this example's image
docker build -t snapchange_example1 .

# Run the image to take the snapshot
docker run -i \
    -v $(realpath -m ./snapshot):/snapshot/ \
    -e SNAPSHOT_IMGTYPE=initramfs \
    snapchange_example1
```

At the end of snapshot, we should see a listing of the `snapshot` directory:

```
$ ls -la snapshot/

.rw-rw-r--   305 user 31 Jul 10:27 config.toml
.rwxr-xr-x   20k user 31 Jul 10:26 example1.bin
.rw-r-----   750 user 31 Jul 10:27 example1.bin.ghidra.covbps
.rw-r--r--  5.4G user 31 Jul 10:26 fuzzvm.physmem
.rw-r--r--  2.4k user 31 Jul 10:26 fuzzvm.qemuregs
.rw-------@   89 user 31 Jul 10:26 gdb.modules
.rw-------@ 7.3M user 31 Jul 10:26 gdb.symbols
.rw-------@ 1.5k user 31 Jul 10:26 gdb.vmmap
.rw-------  7.3M user 31 Jul 10:26 guestkernel.kallsyms
.rwxr-xr-x   118 user 31 Jul 10:26 reset.sh
.rw-r--r--   29k user 31 Jul 10:26 vm.log
.rwxr-xr-x  400M user 31 Jul 10:26 vmlinux
```

We should see the following files in the `snapshot` directory:

* `fuzzvm.physmem` - Physical memory snapshot
* `fuzzvm.qemuregs` - Register state
* `gdb.modules` - Loaded modules
* `gdb.symbols` - Found symbols
* `gdb.vmmap` - Memory map of the target process
* `example1.bin.ghidra.covbps` - Coverage breakpoints retrieved from `example1.bin` using Ghidra

## Snapchange fuzzing

Each fuzzer must set two associated values: `START_ADDRESS` and `MAX_INPUT_LENGTH`. 
The `START_ADDRESS` provides a check that the fuzzer and snapshot are paired 
correctly. The `START_ADDRESS` can be found in the `RIP` register in 
`./snapshot/fuzzvm.qemuregs`. 

The `MAX_INPUT_LENGTH` is the maximum length for a mutated input. For this example, the maximum input 
length to generate is `16` bytes, the length of the buffer in the original target source code.

The `CR3` is the initial page table used by the snapshot. It can be found in the `CR3` register
in `./snapshot/fuzzvm.qemuregs`. This is mostly a helper variable used throughout the fuzzer.

The `RIP` and `CR3` values are automatically populated in the `build.rs`:

```rust
// src/fuzzer.rs
const CR3: Cr3 = Cr3(constants::CR3);

impl Fuzzer for Example1Fuzzer {
    type Input = Vec<u8>;
    const START_ADDRESS: u64 = constants::RIP;
    const MAX_INPUT_LENGTH: usize = 16;
```

Let's rebuild this example using the updated fuzzer:

```sh
cargo build --release
```

With the fuzzer initialized, we can begin exploring `snapchange` and how to fuzz the
target.

## Snapchange command line

`snapchange` provides a few utilities to help in the fuzzing process. The first is to
attempt to translate and disassemble instructions at a specific address.

```sh
$ cargo run -r -- --help
```

```sh
Replay a given snapshot in KVM

Usage: example_fuzzer [OPTIONS] <COMMAND>

Commands:
  fuzz        Fuzz a project
  project     Gather data about the project
  trace       Collect a single step trace for an input
  minimize    Minimize an input by size or trace length
  coverage    Gather coverage for an input
  find-input  Find an input that hits the given address or symbol
  corpus-min  Minimize the given corpus by moving files that don't add any new coverage to a trash directory
  help        Print this message or the help of the given subcommand(s)

Options:
  -p, --project <PROJECT>  Path to the directory containing the target snapshot state. See documentation for the necessary files [default: ./snapshot]
  -v, --verbose...         More output per occurrence
  -q, --quiet...           Less output per occurrence
  -h, --help               Print help

```

For example, we can `translate` the starting instruction to see what is going to be
executed first.

```sh
cargo run -r -- project translate
```

```sh
[2023-07-31T15:39:55Z INFO  snapchange::commands::project] Translating VirtAddr 0x55555555534e Cr3 0x11128c000
[2023-07-31T15:39:55Z INFO  snapchange::commands::project] VirtAddr 0x55555555534e -> PhysAddr 0x1154e334e
 HEXDUMP
---- address -----   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F    0123456789ABCDEF
0x000055555555534e: 48 8b 45 f8 48 89 c7 e8 5b fe ff ff b8 00 00 00  | H.E.H...[.......
0x000055555555535e: 00 c9 c3 50 58 c3 00 00 00 00 00 00 00 00 00 00  | ...PX...........
0x000055555555536e: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  | ................
0x000055555555537e: ** repeated line(s) **
 POTENTIAL INSTRUCTIONS
0x000055555555534e: 488b45f8               example1!main+0x55 | mov rax, qword ptr [rbp-0x8]
0x0000555555555352: 4889c7                 example1!main+0x59 | mov rdi, rax
0x0000555555555355: e85bfeffff             example1!main+0x5c | call 0xfffffffffffffe60
0x000055555555535a: b800000000             example1!main+0x61 | mov eax, 0x0
0x000055555555535f: c9                     example1!main+0x66 | leave
0x0000555555555360: c3                     example1!main+0x67 | ret

```

Here we see the virtual address to physical address translation, the bytes found at the
translated physical address, and the attempted disassembly of those bytes. 

If we go backwards `4` bytes (from `0x55555555534e` -> `0x55555555534a`), we should see the 
snapshot trigger instructions of `int3; vmcall`:

```sh
cargo run -r -- project translate 0x55555555534a
```

```
0x000055555555534a: cc                     example1!main+0x51 | int3
0x000055555555534b: 0f01c1                 example1!main+0x52 | vmcall
0x000055555555534e: 488b45f8               example1!main+0x55 | mov rax, qword ptr [rbp-0x8]
0x0000555555555352: 4889c7                 example1!main+0x59 | mov rdi, rax
0x0000555555555355: e85bfeffff             example1!main+0x5c | call 0xfffffffffffffe60
0x000055555555535a: b800000000             example1!main+0x61 | mov eax, 0x0
0x000055555555535f: c9                     example1!main+0x66 | leave
0x0000555555555360: c3                     example1!main+0x67 | ret
```

`translate` can be used as a check that the snapshot was taken properly.

Let's setup the fuzzer now to fuzz the target.

## Fuzzing with snapchange - Finding the string

When taking the snapshot, the log file from qemu is found in `snapshot/vm.log`. We have a `build.rs` that will
populate the various constants from this specific snapshot in `src/constants.rs`: `CR3` and `RIP` from the
`fuzzvm.qemuregs` and the data `INPUT` buffer from the `SNAPSHOT Data buffer` print statement in the harness.
    
```
$ cat -p src/constants.rs

pub const CR3: u64 = 0x000000011128c000;
pub const RIP: u64 = 0x000055555555534e;
pub const INPUT: u64 = 0x555555556000;
```

In the fuzzer, the `set_input` function is the function responsible for setting the given
mutated input into the target for the current fuzz case. For now, let's write the mutated 
input into the `INPUT` buffer.

```rust
// src/fuzzer.rs
fn set_input(&mut self, input: &[u8], fuzzvm: &mut FuzzVm) -> Result<()> {
    // Write the mutated input
    fuzzvm.write_bytes_dirty(VirtAddr(constants::INPUT), CR3, &input)?;
    Ok(())
}
```

Each virtual address must always be accompanied by the page table which translates the
virtual address. This page table can be found in the `CR3` register in `./snapshot/fuzzvm.qemuregs`.

The other useful setting to set is when to trigger a reset of the fuzz case. `snapchange`
calls these "reset breakpoints". In this target, if we ever return from the `main`
function, we know the fuzz case is finished and we want to start a different fuzz case. 
Using the `translate` function, we can find the address of the `ret` from `main`.

```
$ cargo run -r -- project translate 0x000055555555534a --instrs 10

POTENTIAL INSTRUCTIONS
0x000055555555534a: cc                     example1!main+0x51 | int3
0x000055555555534b: 0f01c1                 example1!main+0x52 | vmcall
0x000055555555534e: 488b45f8               example1!main+0x55 | mov rax, qword ptr [rbp-0x8]
0x0000555555555352: 4889c7                 example1!main+0x59 | mov rdi, rax
0x0000555555555355: e85bfeffff             example1!main+0x5c | call 0xfffffffffffffe60
0x000055555555535a: b800000000             example1!main+0x61 | mov eax, 0x0
0x000055555555535f: c9                     example1!main+0x66 | leave
0x0000555555555360: c3                     example1!main+0x67 | ret
[...]
```

We can set a `reset_breakpoint` as `0x0000555555555360` such that, if `0x0000555555555360` is ever executed,
to immediately exit the VM and start a new fuzz case. (Reminder, your `cr3` value will
probably be different than the one here)

```rust
// src/fuzzer/current_fuzzer.rs 
fn reset_breakpoints(&self) -> Option<&[AddressLookup]> {
    Some(&[
        AddressLookup::Virtual(VirtAddr(0x0000555555555360), CR3),
    ])
}
```

_If we don't set a `reset_breakpoint`, `snapchange` will reset on an `exit` call._

Let's rebuild `snapchange` and start fuzzing with `4` cores.

```sh
cargo run -r -- fuzz --cores 4
```

`snapchange` currently relies on breakpoint coverage for determining coverage. This
format is a `.covbps` file in the `project directory` containing a list of all
addresses that, if hit, signal a coverage hit. Typically, this is a list of basic blocks
in the target.

There is a [Binary Ninja](https://binary.ninja) script available 
[here](../../docker/coverage_scripts/bn_snapchange.py) to generate basic block coverage, and
the docker uses the Ghidra script available [here](../../docker/coverage_scripts/ghidra_basic_blocks.py) but any 
method of getting basic block coverage will work. For this tutorial there is the
`snapshot/example1.bin.ghidra.covbps` available from the docker container.

There is also a [radare2](https://github.com/radare2/radare2) command to generate similar data:

```Makefile
r2 -q -c 'aa ; s main ; afb' snapshot/example1.bin | cut -d' ' -f1 > snapshot/example1.bin.r2.covbps
```

This file is a list of basic block addresses used as coverage breakpoints.

```sh
$ head snapshot/example1.bin.ghidra.covbps

0x555555555000
0x555555555010
0x555555555020
0x555555555030
0x555555555040
0x555555555050
0x555555555060
...
```

Eventually, we should see the string found in the `snapshot/current_corpus` as
`fuzzmetosolveme!`. The fuzzer is now stuck at the `pid == 0xdeadbeef` check from the harness.  

Let's get a single step trace of this input to see how we can bypass this check.

## Fuzzing with snapchange - Hooking getpid

Single step traces can be really useful for analysis and triage as well as seeing what an
input is doing in the target.

Let's gather a trace of the corpus file containing the password `fuzzmetosolveme!`. In
this case, the file is `c2b9b72428f4059c`:

```
$ xxd snapshot/current_corpus/c2b9b72428f4059c

┌────────┬─────────────────────────┬─────────────────────────┬────────┬────────┐
│00000000│ 66 75 7a 7a 6d 65 74 6f ┊ 73 6f 6c 76 65 6d 65 21 │fuzzmeto┊solveme!│
└────────┴─────────────────────────┴─────────────────────────┴────────┴────────┘
```

```sh
cargo run -r -- trace ./snapshot/current_corpus/c2b9b72428f4059c
```

This will execute the given input gathering a single step trace.

```
[2023-07-31T15:56:23Z INFO  snapchange::commands::trace] Writing trace file: "./snapshot/traces/c2b9b72428f4059c_trace"
```

The single step trace is a verbose trace with the register state of the
relevant instructions for the given step. Checking this trace, we can see how the `getpid` 
function is called.

```sh
$ cat ./snapshot/traces/c2b9b72428f4059c_trace

INSTRUCTION 357 0x00005555555552d9 0x11128c000 | example1!fuzzme+0x124
    call 0xfffffffffffffd67
    ??_NearBranch64_?? [e8, 62, fd, ff, ff]
    /opt/example1.c:33:15
INSTRUCTION 358 0x0000555555555040 0x11128c000 | example1!_init+0x40
    jmp qword ptr [rip+0x2f7a]
    [RIP:0x555555555040+0x2f80=0x555555557fc0]]
    [ff, 25, 7a, 2f, 00, 00]
INSTRUCTION 359 0x00007ffff7fbe146 0x11128c000 | ld-musl-x86_64.so.1!getpid+0x0
    mov eax, 0x27
    EAX:0x21
    ??_Immediate32_?? [b8, 27, 00, 00, 00]
```

At address `0x7ffff7fbe146`, `getpid` is called.  Let's hook this address and change `rax` 
from whatever `getpid` would return to the value the target wants of `0xdeadbeef`.

Two options are available for hooking instructions: by address or by symbol. Let's hook
by symbols for this example. In our fuzzer, we can set a `Breakpoint` of type
`SymbolOffset`. The function is called before the hooked instruction is executed. 

The hook function is given the current `FuzzVm` of the guest being executed. We can set
`rax` to `0xdeadbeef` to force `getpid` to emulate returning this value. This function
also returns an `Execution`. In this case, we want the VM to `Continue` execution (and
not `Reset`), so we return `Execution::Continue` in order for snapchage to know to
continue executing the VM.

```rust
fn breakpoints(&self) -> Option<&[Breakpoint]> {
    Some(&[
        Breakpoint {
            lookup:  AddressLookup::SymbolOffset("ld-musl-x86_64.so.1!getpid", 0x0), 
            bp_type: BreakpointType::Repeated,
            bp_hook: |fuzzvm: &mut FuzzVm, input, _fuzzer| { 
                // Set rax to 0xdeadbeef
                fuzzvm.set_rax(0xdead_beef);

                // Immediately return from this function
                fuzzvm.fake_immediate_return();

                // Continue executing the guest after finishing this hook
                Ok(Execution::Continue)
            }
        },
    ])
}
```

Restarting fuzzing again should result in the passing of this conditional, hitting the
crashing point.

Moving the TUI over to the `Crashes` tab (using `Right` arrow or `k`) should show a newly 
discovered crash:

```
┌Found crashes────────────────────────────────────────────┐
│SIGSEGV_addr_0xcafecafe_code_AddressNotMappedToObject    │
```

We can check the crashing cases in `./snapshot/crashes` (using [fd](https://github.com/sharkdp/fd))

```
$ fd --type file . ./snapshot/crashes
./snapshot/crashes/SIGSEGV_addr_0xcafecafe_code_AddressNotMappedToObject/c2b9b72428f4059c
```

We see a `SIGSEGV` crashing at address `0xcafecafe`. We can then trace this crashing
input to get the crashing trace.

```
cargo run -r -- trace ./snapshot/crashes/SIGSEGV_addr_0xcafecafe_code_AddressNotMappedToObject/c2b9b72428f4059c
```

```
vim ./snapshot/traces/c2b9b72428f4059c_trace

INSTRUCTION 095 0x00005555555552ef 0x11128c000 | example1!fuzzme+0x13a
    mov dword ptr [rax], 0x41414141
    [RAX:0xcafecafe]
    ??_Immediate32_?? [c7, 00, 41, 41, 41, 41]
    /opt/example1.c:35:31
...
INSTRUCTION 1017 0xffffffff81099d60 0x11128c000 | force_sig_fault+0x0
    nop word ptr [rax]
    [RAX:0xffff88810862d580]
    [66, 0f, 1f, 00]
    /snapchange/linux/kernel/signal.c:1731:1
```

And there's the crashing instruction.

## Conclusion

Here we took a look at some of the basics of `snapchange`:

* Taking a snapshot of a target 
* Writing a simple fuzzer for the target by writing mutated bytes
* Examining into the target snapshot using `translate`
* Getting a single step trace for an input using `trace`
