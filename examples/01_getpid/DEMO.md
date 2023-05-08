# Example 01 - Basic fuzzing with Snapchange

Welcome to the Snapchange tutorial! We will begin with a basic fuzzing demo using snapchange
and progress through the various snapchange utilties to help with the fuzzing process.

In this tutorial, we will:

* Fuzz to solve a basic string password
* Write a hook for a system call to return an arbitrary value

This tutorial assumes that you are using the demo AMI. If you want to build your own snapshot
for this example, check the documentation in this Example's README.

## Target

For this example, we will fuzz the following target:

```c
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

    if(getenv("SNAPSHOT") != 0) {
        // Print the memory buffer address and pid address for fuzzing
        printf("SNAPSHOT Data buffer: %p\n", data);

        // Ensure the stdout has been flushed
        fflush(stdout);

        // Snapshot taken here
        __asm("int3 ; vmcall"); 
    }

    // Call the fuzzme function
    fuzzme(data);

    return 0;
}
```

There are two goals for this target:

* Fuzz to find the simple string 'fuzzmetosolveme!'
* Force `getpid` to return `0xdeadbeef` to force a crash

From taking the snapshot we know the following information:

* Data buffer is at `0x5555_5555_60004`
* Length of the data buffer is `16` bytes

## Challenge 0 - Lay of the land

Snapchange provides a command line interface for the various utilities provided. The help 
menus explain what utilities are available.

```
cargo run -r -- --help
```

_NOTE: For those unfamiliar with `cargo run`, `cargo run -r` will build the fuzzer and then execute the 
binary with `--help` as the arguments_

```
Replay a given snapshot in KVM

Usage: snapchange_example1 [OPTIONS] <COMMAND>

Commands:
  fuzz        Fuzz a project
  project     Gather data about the project
  trace       Collect a single step trace for an input
  minimize    Minimize an input by size or trace length
  coverage    Gather coverage for an input
  find-input  Find an input that hits the given address or symbol
  help        Print this message or the help of the given subcommand(s)
```

To begin using Snapchange, let's build and ask Snapchange to disassemble the instructions at
the starting instruction point of the snapshot. By default, the `project translate` command
will translate and disassemble from the starting address of the snapshot.

```
cargo run -r -- project translate
```

```
HEXDUMP
---- address -----   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F    0123456789ABCDEF
0x0000555555555344: 48 8b 45 f8 48 89 c7 e8 59 fe ff ff b8 00 00 00  | H.E.H...Y.......
0x0000555555555354: 00 c9 c3 66 0f 1f 84 00 00 00 00 00 f3 0f 1e fa  | ...f............
0x0000555555555364: 41 57 4c 8d 3d 33 2a 00 00 41 56 49 89 d6 41 55  | AWL.=3*..AVI..AU
0x0000555555555374: 49 89 f5 41 54 41 89 fc 55 48 8d 2d 24 2a 00 00  | I..ATA..UH.-$*..
 POTENTIAL INSTRUCTIONS
0x0000555555555344: 488b45f8    example1!main+0x53  | mov rax, qword ptr [rbp-0x8]
0x0000555555555348: 4889c7      example1!main+0x57  | mov rdi, rax
0x000055555555534b: e859feffff  example1!main+0x5a  | call 0xfffffffffffffe5e
0x0000555555555350: b800000000  example1!main+0x5f  | mov eax, 0x0
0x0000555555555355: c9          example1!main+0x64  | leave
0x0000555555555356: c3          example1!main+0x65  | ret
```

Here we see the bytes found at the starting address and an attempted disassembly of those bytes.

The fuzzer for this example is found in `src/fuzzer.rs` and where the challenges for
this demo will be written.

## Challenge 1 - Injecting mutated data

The first challenge involves writing the `set_input` function found in `src/fuzzer.rs`.

```
fn set_input(&mut self, input: &Self::Input, fuzzvm: &mut FuzzVm<Self>) -> Result<()> {
    Ok(())
}
```

The `set_input` function is given two aruguments:

* `input` : A mutated input
* `fuzzvm` : The guest VM that we can interact with

From the snapshot, we know that the data buffer in memory resides at `0x5555_5555_6004`. 

Write the `set_input` function to write the `input` into the guest at virtual address
`0x5555_5555_6004`.

Useful APIs: `fuzzvm::write_bytes_dirty`

_NOTE: The CR3 (page table) is necessary to translate the virtual address. The page table
for the snapshot is filled in the `CR3` variable at the top of `src/fuzzer.rs`. This value
can be found in the snapshot's register state in `./snapshot/fuzzvm.qemuregs`._

Once the function is written, we can begin fuzzing:

```
cargo run -r -- fuzz -c 4
```

While we are fuzzing, we can monitor the coverage of the fuzzer. We can examine the coverage symbols
seen as well as the addresses of the coverage in real time.


```
cat ./snapshot/coverage.in_order
```

```
$ cat snapshot/coverage.in_order
example1!_init+0x90
example1!fuzzme+0x0 -- /home/ubuntu/snapchange/examples/01_getpid/harness/example1.c:13:25
example1!fuzzme+0x27 -- /home/ubuntu/snapchange/examples/01_getpid/harness/example1.c:18:13
example1!fuzzme+0x3a -- /home/ubuntu/snapchange/examples/01_getpid/harness/example1.c:19:13
example1!fuzzme+0x145 -- /home/ubuntu/snapchange/examples/01_getpid/harness/example1.c:54:5
example1!main+0x53 -- /home/ubuntu/snapchange/examples/01_getpid/harness/example1.c:72:5
example1!fuzzme+0x4d -- /home/ubuntu/snapchange/examples/01_getpid/harness/example1.c:20:13
example1!fuzzme+0x60 -- /home/ubuntu/snapchange/examples/01_getpid/harness/example1.c:21:13
```

```
cat ./snapshot/coverage.addresses
```

```
$ cat snapshot/coverage.addresses
0x555555555090
0x5555555551a9
0x5555555551d0
0x5555555551e3
0x5555555551f6
0x555555555209
```

We can also look at the coverage report for the coverage as well using lcov.

```
$ genhtml -o html ./snapshot/coverage.lcov
$ cd html
$ python3 -m http.server 5432
# Browse to http://<YOUR_IP>:5432
```

After some time, we will see the wanted fuzzed string in the current corpus.

```
$ xxd ./snapshot/current_corpus/c2b9b72428f4059c
00000000: 6675 7a7a 6d65 746f 736f 6c76 656d 6521  fuzzmetosolveme!
```

With the simple string solved, it's now time to hook the `getpid` function to return
our wanted value of `0xdeadbeef`.

## Challenge 2 - Hook getpid

Snapchange proves a hooking mechanism to allow a callback function to be executed when
a breakpoint is hit.

In `src/fuzzer.rs`, the fuzzer provides a `breakpoints` function containing all of the 
target specific breakpoints. The scaffolding for hooking the `getpid` function is below.

```rust
    fn breakpoints(&self) -> Option<&[Breakpoint<Self>]> {
        Some(&[
            Breakpoint {
                lookup: BreakpointLookup::SymbolOffset("libc.so.6!__GI___getpid", 0x0),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm: &mut FuzzVm<Self>, _input, _fuzzer| {
                    // Set the return value to 0xdeadbeef
                    // fuzzvm.??

                    // Fake an immediate return from the function by setting RIP to the
                    // value popped from the stack (this assumes the function was entered
                    // via a `call`)
                    // fuzzvm.??

                    // Continue execution
                    Ok(Execution::Continue)
                },
            },
        ])
    }
```

Inside the `bp_hook` closure, your job is do two things:

* Set the return value (`rax` register) to the value of `0xdeadbeef`
* Return from the `getpid` function so that it never actually executes

Useful APIs for this task: `fuzzvm.set_<reg>` and `fuzzvm.fake_immediate_return`

After writing the hook, we can continue executing to find the crash.

```
cargo run -r -- fuzz -c 4
```

We should now see the crashing input in the `crashes` directory.

```
$ xxd ./snapshot/crashes/SIGSEGV_addr_0xcafecafe_code_AddressNotMappedToObject/c2b9b72428f4059c
00000000: 6675 7a7a 6d65 746f 736f 6c76 656d 6521  fuzzmetosolveme!
```

## Bonus - Tracing

With the crashing input in hand, we can perform a single step trace of the crashing input
in the snapshot with a bit more introspection.

```
cargo run -r -- trace ./snapshot/crashes/SIGSEGV_addr_0xcafecafe_code_AddressNotMappedToObject/c2b9b72428f4059c
```

This will write a file to the `traces` directory containing every instruction executed with the register
state of the instruction during runtime including the kernel as well.

```
$ head -n 30 ./traces/c2b9b72428f4059c_trace

INSTRUCTION 000 0x0000555555555344 0x0986e000 | example1!main+0x53
    mov rax, qword ptr [rbp-0x8]
    RAX:0x0
    [RBP:0x7fffffffebf0+0xfffffffffffffff8=0x7fffffffebe8 size:UInt64->0x555555556004]]
    [48, 8b, 45, f8]
    /home/ubuntu/snapchange/examples/01_getpid/harness/example1.c:72:5
INSTRUCTION 001 0x0000555555555348 0x0986e000 | example1!main+0x57
    mov rdi, rax
    RDI:libc.so.6!_IO_stdfile_1_lock+0x0 -> 0x0
    RAX:example1!_IO_stdin_used+0x4 -> 'fuzzmetosolveme!'
    [48, 89, c7]
    /home/ubuntu/snapchange/examples/01_getpid/harness/example1.c:72:5
INSTRUCTION 002 0x000055555555534b 0x0986e000 | example1!main+0x5a
    call 0xfffffffffffffe5e
    ??_NearBranch64_?? [e8, 59, fe, ff, ff]
    /home/ubuntu/snapchange/examples/01_getpid/harness/example1.c:72:5
INSTRUCTION 003 0x00005555555551a9 0x0986e000 | example1!fuzzme+0x0
    endbr64
    [f3, 0f, 1e, fa]
    /home/ubuntu/snapchange/examples/01_getpid/harness/example1.c:13:25
INSTRUCTION 004 0x00005555555551ad 0x0986e000 | example1!fuzzme+0x4
    push rbp
    RBP:0x7fffffffebf0 -> ''
    [55]
    /home/ubuntu/snapchange/examples/01_getpid/harness/example1.c:13:25
```

```
$ head -n 1090 ./traces/c2b9b72428f4059c_trace | tail -n 30

INSTRUCTION 211 0xffffffff81df8feb 0x0986e000 | exc_page_fault+0x5b
    mov rsi, r14
    RSI:0x6
    R14:0x6
    [4c, 89, f6]
    /home/ubuntu/snapchange/examples/01_getpid/qemu_snapshot/linux/arch/x86/mm/fault.c:1498:3
INSTRUCTION 212 0xffffffff81df8fee 0x0986e000 | exc_page_fault+0x5e
    mov rdi, rbp
    RDI:0xffffc900002fbf58 -> ld-linux-x86-64.so.2!_rtld_global+0x0 -> ld-linux-x86-64.so.2!_end+0x8 ...
    RBP:0xffffc900002fbf58 -> ld-linux-x86-64.so.2!_rtld_global+0x0 -> ld-linux-x86-64.so.2!_end+0x8 ...
    [48, 89, ef]
    /home/ubuntu/snapchange/examples/01_getpid/qemu_snapshot/linux/arch/x86/mm/fault.c:1498:3
INSTRUCTION 213 0xffffffff81df8ff1 0x0986e000 | exc_page_fault+0x61
    call 0xffffffffff276ecf
    ??_NearBranch64_?? [e8, ca, 6e, 27, ff]
    /home/ubuntu/snapchange/examples/01_getpid/qemu_snapshot/linux/arch/x86/mm/fault.c:1498:3
INSTRUCTION 214 0xffffffff8106fec0 0x0986e000 | do_user_addr_fault+0x0
    nop word ptr [rax]
    [RAX:0x7ffffffff000]
    [66, 0f, 1f, 00]
    /home/ubuntu/snapchange/examples/01_getpid/qemu_snapshot/linux/arch/x86/mm/fault.c:1233:1
INSTRUCTION 215 0xffffffff8106fec4 0x0986e000 | do_user_addr_fault+0x4
    push r15
    R15:0x0
    [41, 57]
    /home/ubuntu/snapchange/examples/01_getpid/qemu_snapshot/linux/arch/x86/mm/fault.c:1233:1
```