//! Fuzzer template

#![allow(clippy::missing_docs_in_private_items)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;

use snapchange::prelude::*;

use crate::constants;

#[derive(Error, Debug)]
pub enum FuzzerError {
    #[error("Out of scratch memory")]
    ScratchOutOfMemory,

    #[error("Out of shellcode memory")]
    ShellcodeOutOfMemory,
}

macro_rules! impl_mov_into_reg64 {
    ($func:ident, $op1:expr, $op2:expr) => {
        const fn $func(val: u64) -> [u8; 10] {
            let mut res = [0; 10];
            res[0] = $op1;
            res[1] = $op2;

            let mut index = 0;
            loop {
                if index >= 8 {
                    break;
                }

                res[2 + index] = val.to_le_bytes()[index];

                index += 1;
            }

            res
        }
    };
}

/// The syscall assembly instructions
fn asm_syscall() -> [u8; 2] {
    [0x0f, 0x5]
}

/// mov [r15], rax
fn mov_mem_r15_from_rax() -> [u8; 3] {
    [0x49, 0x89, 0x07]
}

/// mov rdi, [r15]
fn deref_r15_into_rdi() -> [u8; 3] {
    [0x49, 0x8b, 0x3f]
}

// Implement several of the assembly code snippets needed to execute syscalls
impl_mov_into_reg64!(mov_into_rax, 0x48, 0xb8);
impl_mov_into_reg64!(mov_into_rdi, 0x48, 0xbf);
impl_mov_into_reg64!(mov_into_rsi, 0x48, 0xbe);
impl_mov_into_reg64!(mov_into_rdx, 0x48, 0xba);
impl_mov_into_reg64!(mov_into_r10, 0x49, 0xba);
impl_mov_into_reg64!(mov_into_r8, 0x49, 0xb8);
impl_mov_into_reg64!(mov_into_r15, 0x49, 0xbf);

// Addresses in the snapshot for writing shellcode and scratch memory
const SHELLCODE_LENGTH: u64 = 1024 * 1024 - 0x100;
const SCRATCH_LENGTH: u64 = 1024 * 1024 - 0x100;
const SHELLCODE: u64 = constants::SHELLCODE;
const SCRATCH: u64 = constants::SCRATCH;
const CR3: Cr3 = Cr3(constants::CR3);

#[derive(Default)]
pub struct Example04Fuzzer {
    /// Offset to the next address to write shellcode
    shellcode_offset: u64,

    /// Offset to the next address to allocate for scratch space
    scratch_offset: u64,
}

const SYS_FSOPEN: u64 = 430;
const SYS_FSCONFIG: u64 = 431;

// Determines how to prepare the argument for the syscall
#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
enum Argument {
    /// A raw value directly used in a syscall
    Raw(u64),

    /// A pointer that must be dereferenced before using in a syscall
    Pointer(u64),
}

/// A returned file descriptor from `fsopen`
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
struct FileDescriptor(usize);

/// Possible syscalls that can be generated
#[derive(Default, Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
enum Syscall {
    #[default]
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

/// A collection of generated [`Syscall`]s
#[derive(Debug, Clone, Hash, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct Syscalls {
    data: Vec<Syscall>,
}

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
                Syscall::FsOpen {
                    fs_name,
                    flags,
                    ret: _,
                } => {
                    // Write the mutated input
                    let fs_name = fuzzer.write_scratch(fuzzvm, fs_name.as_bytes())?;
                    let fsopen_ret = fuzzer.syscall_2(fuzzvm, SYS_FSOPEN, fs_name, *flags)?;
                    ret_vals.push(fsopen_ret);
                }
                Syscall::FsConfig {
                    fs_fd,
                    cmd,
                    key,
                    val,
                    aux,
                } => {
                    let key = fuzzer.write_scratch(fuzzvm, &key)?;
                    let val = fuzzer.write_scratch(fuzzvm, &val)?;

                    let FileDescriptor(index) = fs_fd;
                    let fsopen_ret = ret_vals[*index];

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
                Syscall::FsOpen {
                    fs_name,
                    flags,
                    ret,
                } => {
                    res.push_str(&format!(
                        "    int fsopen_ret{} = syscall(SYS_FSOPEN, {fs_name:?}, {flags});\n",
                        ret.0
                    ));
                }
                Syscall::FsConfig {
                    fs_fd,
                    cmd,
                    key,
                    val,
                    aux,
                } => {
                    // Create the C string for key to write into the C file
                    let key_str = key.escape_ascii().to_string();
                    /*
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
                    */

                    // Create the C string for val to write into the C file
                    let val_str = val.escape_ascii().to_string();
                    /*
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
                    */

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
}

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u64)]
enum FsConfigCommand {
    SetString = 1,
}

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

    /// Write `bytes` into a scratch memory allocation and return the address of the
    /// written to memory
    fn write_scratch(&mut self, fuzzvm: &mut FuzzVm<Self>, bytes: &[u8]) -> Result<u64> {
        let addr = self.alloc_scratch(bytes.len())?;

        fuzzvm.write_bytes_dirty(VirtAddr(addr), CR3, bytes)?;

        // fuzzvm.hexdump(VirtAddr(addr), CR3, bytes.len())?;

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

    /// Write a `syscall` with two arguments to the shellcode buffer
    /// Arg1 - rdi
    fn syscall_2(
        &mut self,
        fuzzvm: &mut FuzzVm<Self>,
        syscall: u64,
        arg1: u64,
        arg2: u64,
    ) -> Result<Argument> {
        self.write_shellcode(fuzzvm, &mov_into_rdi(arg1))?;
        self.write_shellcode(fuzzvm, &mov_into_rsi(arg2))?;
        self.write_shellcode(fuzzvm, &mov_into_rax(syscall))?;
        self.write_shellcode(fuzzvm, &asm_syscall())?;

        // Set the return address into a scratch memory address
        let ret_addr = self.alloc_scratch(8)?;
        self.write_shellcode(fuzzvm, &mov_into_r15(ret_addr))?;
        self.write_shellcode(fuzzvm, &mov_mem_r15_from_rax())?;

        // Return the memory holding the return value
        Ok(Argument::Pointer(ret_addr))
    }

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
}

impl Fuzzer for Example04Fuzzer {
    type Input = Syscalls;
    const START_ADDRESS: u64 = constants::RIP;
    const MAX_INPUT_LENGTH: usize = 100;

    fn init_vm(&mut self, _fuzzvm: &mut FuzzVm<Self>) -> Result<()> {
        *self = Self::default();
        Ok(())
    }

    fn set_input(
        &mut self,
        input: &InputWithMetadata<Self::Input>,
        fuzzvm: &mut FuzzVm<Self>,
    ) -> Result<()> {
        let _ = input.write(fuzzvm, self);

        Ok(())
    }

    fn reset_breakpoints(&self) -> Option<&[AddressLookup]> {
        // Reset when we return from the shellcode call
        // The first call instruction is 3 bytes long.
        //
        // $ cargo run -r -- project translate 0x55555555c698 -i 2
        //
        // 0x000055555555cb28: ff1424                 syscall_harness!_ZN15syscall_harness4main17hbde6b+ | call qword ptr [rsp]
        // 0x000055555555cb2b: 4881c4d0000000         syscall_harness!_ZN15syscall_harness4main17hbde6b+ | add rsp, 0xd0
        Some(&[AddressLookup::Virtual(
            VirtAddr(Self::START_ADDRESS + 3),
            CR3,
        )])
    }

    fn handle_crash(
        &self,
        input: &InputWithMetadata<Self::Input>,
        _fuzzvm: &mut FuzzVm<Self>,
        crash_file: &Path,
    ) -> Result<()> {
        let c_path = crash_file.with_extension("c");
        std::fs::write(c_path, input.to_c())?;

        Ok(())
    }
}

impl snapchange::FuzzInput for Syscalls {
    /// Read the input bytes as the implemented type
    ///
    /// # Errors
    ///
    /// * Failed to convert the given bytes to `Self`
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }

    /// Convert the implemented type as a `Vec<u8>`
    ///
    /// # Errors
    ///
    /// * Failed to serialize `Self` into the output bytes
    fn to_bytes(&self, output: &mut Vec<u8>) -> Result<()> {
        let res = serde_json::to_string(&self)?;
        output.extend(res.as_bytes());
        Ok(())
    }

    /// Mutate the current object using a `corpus`, `rng`, and `dictionary` that has a
    /// maximum length of `max_length`
    fn mutate(
        input: &mut Self,
        corpus: &[Arc<InputWithMetadata<Self>>],
        rng: &mut Rng,
        dictionary: &Option<Vec<Vec<u8>>>,
        min_length: usize,
        max_length: usize,
        _max_mutations: u64,
    ) -> Vec<String> {
        *input = Syscalls::generate(corpus, rng, dictionary, min_length, max_length).input;

        // Return an empty set of mutations
        Vec::new()
    }

    /// Generate a random version of this type
    fn generate(
        _corpus: &[Arc<InputWithMetadata<Self>>],
        rng: &mut Rng,
        _dictionary: &Option<Vec<Vec<u8>>>,
        _min_length: usize,
        _max_length: usize,
    ) -> InputWithMetadata<Self> {
        let mut res = Vec::new();

        res.push(Syscall::FsOpen {
            fs_name: "debugfs".to_string(),
            flags: 0,
            ret: FileDescriptor(0),
        });

        for _ in 0..rng.next() % 1000 {
            res.push(Syscall::FsConfig {
                fs_fd: FileDescriptor(0),
                cmd: FsConfigCommand::SetString,
                key: vec![rng.next() as u8; rng.next() as usize % 128],
                val: vec![b'A'; rng.next() as usize % 128],
                aux: 0,
            });
        }

        InputWithMetadata::from_input(Syscalls { data: res })
    }

    // this is requrired to conform to snapchange's API
    type MinState = NullMinimizerState;
    /// dummy init minimize
    fn init_minimize(&mut self) -> (Self::MinState, MinimizeControlFlow) {
        NullMinimizerState::init()
    }

    /// Minimize the given `input` based on a minimization strategy
    fn minimize(
        &mut self,
        _state: &mut Self::MinState,
        _current_iteration: u32,
        _last_successful_iteration: u32,
        rng: &mut Rng,
    ) -> MinimizeControlFlow {
        match rng.next() % 5 {
            0 => {
                // Remove a random syscall
                let num_syscalls = input.data.len();
                let index = rng.next() as usize % num_syscalls;

                // Don't remove the first FsOpen syscall
                if index == 0 {
                    return MinimizeControlFlow::Skip;
                }

                input.data.remove(index);
            }
            1 => {
                // Minimize a key of a random syscall
                let num_syscalls = input.data.len();
                let curr_syscall = &mut input.data[rng.next() as usize % num_syscalls];

                match curr_syscall {
                    Syscall::FsConfig { key, .. } => {
                        let key_len = key.len();
                        if key_len == 0 {
                            return MinimizeControlFlow::Skip;
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
                let curr_syscall = &mut input.data[rng.next() as usize % num_syscalls];

                match curr_syscall {
                    Syscall::FsConfig { val, .. } => {
                        let val_len = val.len();
                        if val_len == 0 {
                            return MinimizeControlFlow::Skip;
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
                let curr_syscall = &mut input.data[rng.next() as usize % num_syscalls];

                match curr_syscall {
                    Syscall::FsConfig { key, .. } => {
                        let key_len = key.len();
                        if key_len == 0 {
                            return MinimizeControlFlow::Skip;
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
                let curr_syscall = &mut input.data[rng.next() as usize % num_syscalls];

                match curr_syscall {
                    Syscall::FsConfig { val, .. } => {
                        let val_len = val.len();
                        if val_len == 0 {
                            return MinimizeControlFlow::Skip;
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
                let curr_syscall = &mut input.data[rng.next() as usize % num_syscalls];

                match curr_syscall {
                    Syscall::FsConfig { key, .. } => {
                        let key_len = key.len();
                        if key_len == 0 {
                            return MinimizeControlFlow::Skip;
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
        MinimizeControlFlow::Continue
    }
}
