//! Provides a [`StackUnwinder`] to be able to unwind the stack in a [`FuzzVm`]

use addr2line::gimli;
use addr2line::gimli::{
    BaseAddresses, CfaRule, EhFrame, EhFrameHdr, EndianSlice, LittleEndian, RegisterRule,
    UnwindSection, X86_64,
};
use addr2line::object::{Object, ObjectSection};
use thiserror::Error;

use std::fs::File;
use std::io::Read;
use std::mem::size_of;
use std::ops::Range;
use std::path::PathBuf;

use crate::fuzzer::Fuzzer;
use crate::fuzzvm::FuzzVm;
use crate::VirtAddr;

/// Result type for the stack unwinder
pub type Result<T> = std::result::Result<T, UnwinderError>;

#[derive(Error, Debug)]
#[allow(missing_docs)]
pub enum UnwinderError {
    #[error("Unset RA register at the end of parsing")]
    UnsetRaRegister,

    #[error("Gimli Error: {0:?}")]
    Gimli(addr2line::gimli::Error),

    #[error("Object error: {0:?}")]
    Object(addr2line::object::Error),

    #[error("Io error: {0:?}")]
    Io(std::io::Error),

    #[error("anyhow error: {0:?}")]
    Anyhow(anyhow::Error),

    #[error("Failed to get the data for .eh_frame_hdr")]
    FailedToGetEhFrameHdr,

    #[error("Failed to get the data for .eh_frame")]
    FailedToGetEhFrame,

    #[error("Failed to get the table for .eh_frame")]
    FailedToGetTable,

    #[error("Unhandled gimli register: {0:?}")]
    UndefinedGimliRegister(addr2line::gimli::Register),

    #[error("Unhandled CFA expressions")]
    CfaExpressionUnhandled,

    #[error("No unwinder found for address: {0:#x}")]
    NoUnwinderForAddress(u64),
}

/// Registers tracked during the
#[derive(Debug)]
pub enum TrackedReg {
    /// rsp
    Rsp,
    /// rbp
    Rbp,
    /// ra
    Ra,
}

/// Virtual state used for backtracing
#[derive(Debug, Default)]
pub struct TrackedState {
    /// Tracked register state
    regs: [Option<u64>; std::mem::variant_count::<TrackedReg>()],

    /// Current instruction pointer
    rip: u64,

    /// Current frame address
    frame_addr: u64,
}

/// Get the name of the given gimli Register
fn name(gimli: addr2line::gimli::Register) -> &'static str {
    match gimli {
        X86_64::RSP => "rsp",
        X86_64::RBP => "rbp",
        X86_64::RA => "ra",
        _ => unreachable!(),
    }
}

/// Shows whether or not an address has known or unknown unwind information.
#[derive(Debug, PartialEq, Eq)]
pub enum UnwindInfo {
    /// Found unwind information for this address
    Found(u64),

    /// No unwind information found for this address
    Unknown(u64),
}

impl TrackedState {
    /// Create a tracked state initialized using the given [`FuzzVm`]
    pub fn from_fuzzvm<FUZZER: Fuzzer>(fuzzvm: &FuzzVm<FUZZER>) -> Self {
        let mut state = TrackedState::default();
        state.regs[TrackedReg::Rsp as usize] = Some(fuzzvm.rsp());
        state.regs[TrackedReg::Rbp as usize] = Some(fuzzvm.rbp());
        // state.regs[TrackedReg::Rip as usize] = Some(fuzzvm.rip());
        state.rip = fuzzvm.rip();
        state.frame_addr = fuzzvm.rsp();
        state
    }

    /// Print the state of this `TrackedState`
    pub fn print(&self) {
        println!("FRAME: {:x?}", self.frame_addr);
        println!("RIP:   {:x?}", self.rip);
        println!("RSP:   {:x?}", self.regs[TrackedReg::Rsp as usize]);
        println!("RBP:   {:x?}", self.regs[TrackedReg::Rbp as usize]);
        println!("RA:    {:x?}", self.regs[TrackedReg::Ra as usize]);
    }

    /// Get the current RIP
    pub fn rip(&self) -> u64 {
        self.rip
    }

    /// Set the current RIP
    pub fn set_rip(&mut self, value: u64) {
        self.rip = value;
    }

    /// Set the given gimli register with the given value
    pub fn set(&mut self, gimli_reg: gimli::Register, value: u64) {
        match gimli_reg {
            gimli::X86_64::RSP => self.regs[TrackedReg::Rsp as usize] = Some(value),
            gimli::X86_64::RBP => self.regs[TrackedReg::Rbp as usize] = Some(value),
            gimli::X86_64::RA => self.regs[TrackedReg::Ra as usize] = Some(value),
            _ => log::warn!("Failed setting unknown gimli reg: {gimli_reg:?}"),
        }
    }

    /// Get the given gimli register
    pub fn get(&mut self, gimli_reg: gimli::Register) -> Option<u64> {
        match gimli_reg {
            gimli::X86_64::RSP => self.regs[TrackedReg::Rsp as usize],
            gimli::X86_64::RBP => self.regs[TrackedReg::Rbp as usize],
            gimli::X86_64::RA => self.regs[TrackedReg::Ra as usize],
            _ => {
                log::warn!("Failed getting unknown gimli reg: {gimli_reg:?}");
                None
            }
        }
    }

    /// Undefine the given gimli register
    pub fn undefine(&mut self, gimli_reg: gimli::Register) {
        match gimli_reg {
            gimli::X86_64::RSP => self.regs[TrackedReg::Rsp as usize] = None,
            gimli::X86_64::RBP => self.regs[TrackedReg::Rbp as usize] = None,
            gimli::X86_64::RA => self.regs[TrackedReg::Ra as usize] = None,
            _ => log::warn!("Failed to undefine unknown gimli reg: {gimli_reg:?}"),
        }
    }
}

/// Collection of binaries to attempt to gather the unwind information for an address
#[derive(Clone, Default, Debug)]
pub struct StackUnwinders {
    /// Set of unwinders with a known module range
    known_unwinders: Vec<(Range<u64>, StackUnwinder)>,

    /// Set of unwinders with an unknown module range
    unknown_unwinders: Vec<StackUnwinder>,
}

/// Architecture for a parsed self
enum Arch {
    /// 32-bit architedcture
    Bit32,
    /// 64-bit architedcture
    Bit64,
}

/// Find the entry point of an ELF binary data slice
///
/// # Panics
///
/// * Failed to create the needed slices for `from_le_bytes`
pub fn get_elf_entry_point(path: &PathBuf) -> Option<u64> {
    // Read the first 0x20 bytes from the given path
    let mut data = [0u8; 0x20];
    let mut f = File::open(path).ok()?;
    f.read_exact(&mut data).ok()?;

    // If the ELF magic doens't match, return None
    if data[0..4] != [0x7f, b'E', b'L', b'F'] {
        return None;
    }

    // Get the architecture for this binary
    let arch = match data[4] {
        1 => Arch::Bit32,
        2 => Arch::Bit64,
        _ => return None,
    };

    // Get the entry point address based on the architecture
    let addr = match arch {
        Arch::Bit32 => u64::from(u32::from_le_bytes(
            data[0x18..0x18 + size_of::<u32>()].try_into().unwrap(),
        )),
        Arch::Bit64 => u64::from_le_bytes(data[0x18..0x18 + size_of::<u64>()].try_into().unwrap()),
    };

    Some(addr)
}

impl StackUnwinders {
    /// Attempt to create a [`StackUnwinder`] from the given binary
    ///
    /// # Errors
    ///
    /// * Failed to create a [`StackUnwinder`] for the given binary
    pub fn create_unwinder(
        &mut self,
        bin_file: &PathBuf,
        module_range: Option<Range<u64>>,
    ) -> Result<()> {
        // We need to check if the binary was relocated in the memory map of the snapshot.
        // If the entry point is in the loaded module memory in the snapshot, then the module
        // does not need to be rebased. If the entry point is not in the
        let mut start = 0;
        if let Some(range) = &module_range {
            if let Some(entry_point) = get_elf_entry_point(bin_file) {
                if !range.contains(&entry_point) {
                    // Confirm that adding the module range start to the entry point will
                    // have the entry point be in the module range in the snapshot
                    if range.contains(&(range.start + entry_point)) {
                        start = range.start;
                    }
                }
            }
        }

        // Attempt to get a StackUnwinder for this binary
        let Some(unwinder) = StackUnwinder::new(bin_file, start)? else {
            return Ok(());
        };

        // Add the unwinder to the lists depending on if we know where the module starts
        if let Some(range) = module_range {
            self.known_unwinders.push((range, unwinder));
        } else {
            self.unknown_unwinders.push(unwinder);
        }

        // Return success
        Ok(())
    }

    /// Get the unwind info for the given address
    ///
    /// # Errors
    ///
    /// * No unwinder was found for the current address
    pub fn get_unwind_info<FUZZER: Fuzzer>(
        &self,
        state: &mut TrackedState,
        fuzzvm: &mut FuzzVm<FUZZER>,
    ) -> Result<()> {
        let addr = state.rip;

        // First check if we have a known module range containing the requested address
        for (range, unwinder) in &self.known_unwinders {
            if range.contains(&addr) {
                let res = unwinder.get(state, fuzzvm);
                return res;
            }
        }

        // No unwinders found from known unwinders, check the unknown unwinders
        for unwinder in &self.unknown_unwinders {
            if unwinder.get(state, fuzzvm).is_ok() {
                return Ok(());
            }
        }

        // No unwinder found
        Err(UnwinderError::NoUnwinderForAddress(addr))
    }

    /// Get the backtrace from the current RIP in the given [`FuzzVm`]
    pub fn backtrace<FUZZER: Fuzzer>(&mut self, fuzzvm: &mut FuzzVm<FUZZER>) -> Vec<UnwindInfo> {
        /// Maximum number of the same address that can be repeated in the backtrace before
        /// stopping the search
        const MAX_SAME_RECURSION: usize = 16;

        // The virtual register state
        let mut state = TrackedState::from_fuzzvm(fuzzvm);

        // Init the resulting backtrace
        let mut backtrace = Vec::new();

        while backtrace.len() < 256 {
            // Get the current rip
            let addr = state.rip;

            // Check if the backtrace has the maximum number of the same address at the end
            if backtrace.len() > MAX_SAME_RECURSION {
                let mut iter = backtrace.iter().skip(backtrace.len() - MAX_SAME_RECURSION);

                // Get the first element from the iterator to check against
                let Some(first) = iter.next() else {
                    continue;
                };

                if iter.all(|addr| addr == first) {
                    // Found a backtrace with too many recursions, end the backtrace here
                    // and remove the duplicate entries
                    backtrace.truncate(backtrace.len() - MAX_SAME_RECURSION + 1);
                    break;
                }
            }

            // Get the unwind info for the next address
            if let Err(_e) = self.get_unwind_info(&mut state, fuzzvm) {
                // Add this address to the backtrace as an unknown module
                backtrace.push(UnwindInfo::Unknown(addr));

                // log::info!("Failed to get unwind info at {addr:#x}: {_e:?}");
                break;
            }

            // Add this address to the backtrace
            backtrace.push(UnwindInfo::Found(addr));
        }

        // Return the found backtrace
        backtrace
    }
}

/// Get the address of the instruction containing the `starting_addr` such that it is one instruciton
/// behind the `next_instr` address
pub fn get_instr_containing<FUZZER: Fuzzer>(
    starting_addr: u64,
    next_instr: u64,
    fuzzvm: &mut FuzzVm<FUZZER>,
) -> u64 {
    // Starting from the largest possible instruction, look for a single instruction that decodes
    // such that the second instruction is at `next_instr`
    for offset in (0..=0x10).rev() {
        //
        let curr_addr = starting_addr - offset;

        // Get the instruction for the current address
        let Ok(instr) = fuzzvm
            .memory
            .get_instruction_at(VirtAddr(curr_addr), fuzzvm.cr3())
        else {
            continue;
        };

        let ending_addr = curr_addr + instr.len() as u64;

        // Check if this instruction would decode so that the next instruction
        if ending_addr == next_instr {
            return curr_addr;
        }
    }

    unreachable!("Starting addr: {starting_addr:#x} Ending: {next_instr:#x}");
}

/// Stack unwinder for a single binary
#[derive(Clone)]
pub struct StackUnwinder {
    /// The .eh_frame section copied from a binary
    eh_frame_data: Vec<u8>,

    /// The .eh_frame section copied from a binary
    eh_frame_hdr_data: Vec<u8>,

    /// A `gimli::BaseAddresses`
    base_addresses: BaseAddresses,
}

impl StackUnwinder {
    /// Create a new [`StackUnwinder`] from the given `binary` and its base address
    ///
    /// # Errors
    ///
    /// * Cannot open the given binary
    /// * Failed to mmap the file
    /// * Failed to parse the file using `addr2line::object::File`
    pub fn new(binary: &PathBuf, base_address: u64) -> Result<Option<Self>> {
        // Open a file and parse it with gimli
        let file = File::open(binary).map_err(UnwinderError::Io)?;
        let map = unsafe { memmap::Mmap::map(&file).map_err(UnwinderError::Io)? };
        let object = addr2line::object::File::parse(&*map).map_err(UnwinderError::Object)?;
        let mut base_addresses = addr2line::gimli::BaseAddresses::default();

        // If we don't have an .eh_frame_hdr, return None
        let Some(ref eh_frame_hdr) = object.section_by_name(".eh_frame_hdr") else {
            log::info!("{binary:?} has no .eh_frame_hdr");
            return Ok(None);
        };

        // If we don't have an .eh_frame, return None
        let Some(ref eh_frame) = object.section_by_name(".eh_frame") else {
            log::info!("{binary:?} has no .eh_frame");
            return Ok(None);
        };

        // Set the address of the sections in the base addresses
        base_addresses = base_addresses.set_eh_frame_hdr(eh_frame_hdr.address() + base_address);
        base_addresses = base_addresses.set_eh_frame(eh_frame.address() + base_address);

        // Copy the sections out to store in this struct
        let eh_frame_hdr_data = eh_frame_hdr
            .uncompressed_data()
            .map_err(UnwinderError::Object)?
            .to_vec();

        let eh_frame_data = eh_frame
            .uncompressed_data()
            .map_err(UnwinderError::Object)?
            .to_vec();

        Ok(Some(StackUnwinder {
            eh_frame_data,
            eh_frame_hdr_data,
            base_addresses,
        }))
    }

    /// Get an [`EhFrame`] from the current `eh_frame_data`
    fn eh_frame(&self) -> EhFrame<EndianSlice<'_, LittleEndian>> {
        EhFrame::new(&self.eh_frame_data, LittleEndian)
    }

    /// Get the `register` and offset pair to get to next frame's stack address
    fn get<FUZZER: Fuzzer>(
        &self,
        state: &mut TrackedState,
        fuzzvm: &mut FuzzVm<FUZZER>,
    ) -> Result<()> {
        // Create an UnwindContext
        let mut unwind_context = addr2line::gimli::UnwindContext::new();

        let hdr = EhFrameHdr::new(&self.eh_frame_hdr_data, LittleEndian)
            .parse(&self.base_addresses, 8)
            .map_err(UnwinderError::Gimli)?;

        // Get the current RIP
        let addr = state.rip();

        // Look up the unwind info for the given address
        match hdr
            .table()
            .ok_or(UnwinderError::FailedToGetTable)?
            .unwind_info_for_address(
                &self.eh_frame(),
                &self.base_addresses,
                &mut unwind_context,
                addr,
                |section, bases, offset| section.cie_from_offset(bases, offset),
            ) {
            Ok(unwind_info) => {
                /*
                log::info!("CFA {addr:#x} -> {:?}", unwind_info.cfa());
                println!("BEFORE");
                state.print();
                */

                match unwind_info.cfa() {
                    CfaRule::RegisterAndOffset {
                        register: gimli_register,
                        offset,
                    } => {
                        // Apply the offset to the given gimli register
                        state.frame_addr = state
                            .get(*gimli_register)
                            .ok_or_else(|| UnwinderError::UndefinedGimliRegister(*gimli_register))?
                            .wrapping_add_signed(*offset);
                    }
                    CfaRule::Expression(_) => {
                        return Err(UnwinderError::CfaExpressionUnhandled);
                    }
                }

                for reg in [X86_64::RSP, X86_64::RBP, X86_64::RA] {
                    let _name = name(reg);
                    match unwind_info.register(reg) {
                        RegisterRule::Offset(offset) => {
                            // log::info!("{_name:?} OFFSET {offset}");
                            let addr = state.frame_addr.wrapping_add_signed(offset);
                            let value = fuzzvm
                                .read::<u64>(VirtAddr(addr), fuzzvm.cr3())
                                .map_err(UnwinderError::Anyhow)?;

                            // log::info!( " -> {:#x} {offset} -> Reading {addr:#x} -> {value:#x}", state.frame_addr );
                            state.set(reg, value);
                        }
                        RegisterRule::Undefined | RegisterRule::SameValue => {
                            // log::info!("{_name:?} UNDEFINED");
                            // state.undefine(reg);
                        }
                        x => panic!("Unknown Register Rule: {x:?}"),
                    }
                }

                /*
                println!("AFTER");
                state.print();
                */

                // Update the new stack pointer
                state.regs[TrackedReg::Rsp as usize] = Some(state.frame_addr);

                // Update the return address for the next iteration
                let ret_addr =
                    state.regs[TrackedReg::Ra as usize].ok_or(UnwinderError::UnsetRaRegister)?;

                if ret_addr > 0 {
                    // Get the beginning of the previous instruction
                    let instr_start = get_instr_containing(ret_addr - 1, ret_addr, fuzzvm);
                    state.set_rip(instr_start);
                } else {
                    return Err(UnwinderError::UnsetRaRegister);
                }

                // Return success
                Ok(())
            }
            Err(e) => Err(UnwinderError::Gimli(e)),
        }
    }
}

impl std::fmt::Debug for StackUnwinder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "StackUnwinder {{ {:x?} }}", self.base_addresses)
    }
}
