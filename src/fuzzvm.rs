//! Provides [`FuzzVm`] used for fuzzing on a given core with a snapshot register state
//! and physical memory dump

#![allow(clippy::enum_glob_use)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use iced_x86::Code::*;

use anyhow::{ensure, Context, Result};
use iced_x86::{Instruction, MemorySize, OpKind};
use kvm_bindings::{
    kvm_debugregs, kvm_fpu, kvm_guest_debug, kvm_guest_debug_arch, kvm_msr_entry, kvm_pit_config,
    kvm_regs, kvm_sregs, kvm_userspace_memory_region, kvm_vcpu_events, CpuId, Msrs,
    KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_SINGLESTEP, KVM_GUESTDBG_USE_SW_BP, KVM_MAX_CPUID_ENTRIES,
};
use kvm_ioctls::{SyncReg, VcpuExit, VcpuFd, VmFd};
use thiserror::Error;
use x86_64::registers::control::{Cr0Flags, Cr4Flags, EferFlags};
use x86_64::registers::rflags::RFlags;

use crate::addrs::{Cr3, PhysAddr, VirtAddr};
use crate::colors::Colorized;
use crate::config::Config;
use crate::exception::Exception;
use crate::filesystem::FileSystem;
use crate::fuzzer::{AddressLookup, Breakpoint, BreakpointType, Fuzzer, ResetBreakpointType};
use crate::interrupts::IdtEntry;
use crate::linux::{PtRegs, Signal};
use crate::memory::{ChainVal, Memory, WriteMem};
use crate::msr::Msr;
use crate::page_table::Translation;
use crate::rng::Rng;
use crate::stack_unwinder::{StackUnwinders, UnwindInfo};
use crate::symbols::Symbol;
use crate::utils::rdtsc;
use crate::vbcpu::VbCpu;
use crate::{handle_vmexit, Execution, DIRTY_BITMAPS};
use crate::{try_u32, try_u64, try_u8, try_usize};

#[cfg(feature = "redqueen")]
use crate::{
    cmp_analysis, cmp_analysis::RedqueenArguments, cmp_analysis::RedqueenRule,
    fuzz_input::FuzzInput,
};

use std::collections::{BTreeMap, VecDeque};
use std::convert::TryInto;
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

#[cfg(feature = "redqueen")]
use std::{collections::BTreeSet, path::PathBuf};

/// APIC base we are expecting the guest to adhere to. Primarily comes into play when
/// mapping guest memory regions in KVM as we need to leave to leave a gap in the guest
/// memory for the APIC.
pub const APIC_BASE: u64 = 0xfee0_0000;

/// TSS address
pub const TSS_BASE: u64 = 0xfffb_d000;

/// The CR3 used to signify any possible CR3 for a virutal address
pub(crate) const WILDCARD_CR3: Cr3 = Cr3(0x1234_1234_1234_1234);

/// Sets the type of memory (dirty or not) for a given breakpoint. This is primarily used
/// for coverage breakpoints that have a very expensive cost to reset all coverage
/// breakpoints on each iterations.
#[derive(Debug, Copy, Clone)]
pub enum BreakpointMemory {
    /// Set the written memory as dirty
    Dirty,

    /// Do not set the written memory as dirty
    NotDirty,
}

/// Hook function protoype
pub type HookFn<F> =
    fn(fuzzvm: &mut FuzzVm<F>, input: &<F as Fuzzer>::Input, fuzzer: &mut F) -> Result<Execution>;

/// Type of custom hook to call when a breakpoint is triggered
pub enum BreakpointHook<FUZZER: Fuzzer> {
    /// Call the given function when this breakpoint is hit
    Func(HookFn<FUZZER>),

    /// Call the redqueen parsing
    #[cfg(feature = "redqueen")]
    Redqueen(RedqueenArguments),

    /// No breakpoint hook function set for this breakpoint
    None,
}

/// Custom errors [`FuzzVm`] can throw
#[derive(Error, Debug)]
pub enum Error {
    /// Failed to create the PIT2
    #[error("Failed to create the PIT2")]
    FailedToCreatePIT2,

    /// Failed to create the VCPU
    #[error("Failed to create the VCPU")]
    FailedToCreateVcpu,

    /// The given fuzzer RIP does not match the given snapshot RIP
    #[error("The given fuzzer RIP does not match the given snapshot RIP")]
    SnapshotMismatch,

    /// Attempted to use an out of bounds breakpoint index
    #[error("Attempted to use an out of bounds breakpoint index")]
    InvalidBreakpointIndex,

    /// Hit a breakpoint that was set by some other source other than the fuzzer
    #[error("Hit a breakpoint that was set by some other source other than the fuzzer")]
    ExternalBreakpoint,

    /// Failed to create MSR entries for KVM
    #[error("Failed to create MSR entries for KVM")]
    CreateMsrEntries,

    /// Attempted to read an invalid address for a coverage breakpoint
    #[error("Attempted to read an invalid address for a coverage breakpoint")]
    InvalidCoverageBreakpoint,

    /// Coverage breakpoint original byte failed to match in FuzzVm
    #[error("Coverage breakpoint original byte failed to match in FuzzVm")]
    CoverageBreakpointIncorrectCache,

    /// Breakpoint hook not set for the address
    #[error("A breakpoint hook was not set for the address")]
    BreakpointHookNotSet(VirtAddr, Option<String>),

    /// Found an error when executing a VM
    #[error("Found an error when executing a VM")]
    FailedToExecuteVm(kvm_ioctls::Error),

    /// Caught an unknown breakpoint
    #[error("UnknownBreakpoint_{0:x?}_{1:x?}")]
    UnknownBreakpoint(VirtAddr, Cr3),

    /// Call to `sysconf` failed
    #[error("Call to sysconf failed")]
    SysconfFailed(nix::errno::Errno),

    /// Lookup symbol was not found in the symbols
    #[error("Lookup symbol was not found in symbols: {0}+{1:#x}")]
    LookupSymbolNotFound(&'static str, u64),

    /// Symbol breakpoints are not implemented for Redqueen breakpoints
    #[error("Symbol breakpoints are not implemented for Redqueen breakpoints")]
    SymbolBreakpointsNotImplForRedqueen,
}

/// Reasons for [`FuzzVm`] exits. These are the `Copy` [`VcpuExit`] types so that fuzzers
/// can modify VM state during exits.
#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum FuzzVmExit {
    /// Corresponds to VpuExit::Unknown.
    Unknown = 0,

    /// Corresponds to VcpuExit::Exception.
    Exception = 1,

    /// Corresponds to VcpuExit::Hypercall.
    Hypercall = 2,

    /// Corresponds to VcpuExit::Debug.
    Debug(Exception) = 3,

    /// Corresponds to VcpuExit::Hlt.
    Hlt = 4,

    // /// Corresponds to VcpuExit::IrqWindowOpen.
    // IrqWindowOpen,
    /// Corresponds to VcpuExit::Shutdown.
    Shutdown = 5,

    // /// Corresponds to VcpuExit::FailEntry.
    // FailEntry(u64, u32) = 200,
    // /// Corresponds to VcpuExit::Intr.
    // Intr,
    // /// Corresponds to VcpuExit::SetTpr.
    // SetTpr,
    // /// Corresponds to VcpuExit::TprAccess.
    // TprAccess,
    // /// Corresponds to VcpuExit::S390Sieic.
    // S390Sieic,
    // /// Corresponds to VcpuExit::S390Reset.
    // S390Reset,
    // /// Corresponds to VcpuExit::Dcr.
    // Dcr,
    // /// Corresponds to VcpuExit::Nmi.
    // Nmi,
    /// Corresponds to VcpuExit::InternalError.
    InternalError = 6,
    // /// Corresponds to VcpuExit::Osi.
    // Osi,
    // /// Corresponds to VcpuExit::PaprHcall.
    // PaprHcall,
    // /// Corresponds to VcpuExit::S390Ucontrol.
    // S390Ucontrol,
    // /// Corresponds to VcpuExit::Watchdog.
    // Watchdog,
    // /// Corresponds to VcpuExit::S390Tsch.
    // S390Tsch,
    // /// Corresponds to VcpuExit::Epr.
    // Epr,
    // /// Corresponds to VcpuExit::SystemEvent.
    // SystemEvent(u32 /* type */, u64 /* flags */),
    // /// Corresponds to VcpuExit::S390Stsi.
    // S390Stsi,
    // /// Corresponds to VcpuExit::IoapicEoi.
    // IoapicEoi(u8 /* vector */),
    // /// Corresponds to VcpuExit::Hyperv.
    // Hyperv,
    /// Corresponds to VcpuExit::IoIn
    IoIn(u16 /* port */) = 7,

    /// Corresponds to VcpuExit::IoOut
    IoOut(u16 /* port */) = 8,

    /// A coverage breakpoint was hit
    CoverageBreakpoint(u64) = 9,

    /// A crash breakpoint was hit
    CrashBreakpoint(u64) = 10,

    /// A reset breakpoint was hit
    ResetBreakpoint(u64) = 11,

    /// A force_sig_fault breakpoint was hit
    ForceSigFaultBreakpoint(Signal) = 12,

    /// EFAULT (errno 14) was triggered
    BadAddress(u64) = 13,

    /// Console write was triggered
    ConsoleWriteBreakpoint = 14,

    /// Breakpoint hit from __die
    KernelDieBreakpoint = 15,

    /// KASAN Out of bounds READ
    KasanRead {
        /// IP of the crashing location
        ip: u64,

        /// Size of the out of bouunds read
        size: u64,

        /// Addresses accessed out of bounds
        addr: u64,
    } = 16,

    /// KASAN Out of bounds WRITE
    KasanWrite {
        /// IP of the crashing location
        ip: u64,

        /// Size of the out of bouunds read
        size: u64,

        /// Addresses accessed out of bounds
        addr: u64,
    } = 17,

    /// VM exited due to a symbol that should immediately return
    ImmediateReturn = 18,

    /// Breakpoint from a Debug exception
    Breakpoint(u64) = 19,

    /// Debug VmExit with a Debug exception
    DebugException = 20,

    /// Original exit was handled, continue execution
    Continue = 21,

    /// FindModuleNameAndOffset
    FindModuleNameAndOffset = 22,

    /// ConsoleWrite symbol breakpoint
    ConsoleWrite = 23,

    /// LogStore breakpoint
    LogStore = 24,

    /// A read instruction was run against the given MMIO address.
    MmioRead = 25,

    /// A write instruction was run against the given MMIO address.
    MmioWrite = 26,

    /// Unimplemented VmExit
    Unimpl = 27,

    /// Special case for ForceSigFault(Trap)
    Trap = 28,

    /// Timer has expired
    TimerElapsed = 29,

    /// Total number of FuzzVmExit
    COUNT = 32,
}

impl FuzzVmExit {
    /// Get the ID of the vmexit
    #[must_use]
    pub fn id(&self) -> usize {
        core::intrinsics::discriminant_value(self) as usize
    }

    /// Get the name of a specific `FuzzVmExit` id
    #[must_use]
    pub fn name(val: usize) -> &'static str {
        match val {
            0 => "Unknown",
            1 => "Exception",
            2 => "Hypercall",
            3 => "Debug(Exception Unknown)",
            4 => "Hlt",
            5 => "Shutdown",
            6 => "InternalError",
            7 => "IoIn",
            8 => "IoOut",
            9 => "CoverageBreakpoint",
            10 => "CrashBreakpoint",
            11 => "ResetBreakpoint",
            12 => "ForceSigFaultBreakpoint",
            13 => "BadAddress",
            14 => "ConsoleWriteBreakpoint",
            15 => "KernelDieBreakpoint",
            16 => "KasanRead",
            17 => "KasanWrite",
            18 => "ImmediateReturn",
            19 => "Breakpoint",
            20 => "DebugException",
            21 => "Continue",
            22 => "FindModuleNameAndOffset",
            23 => "ConsoleWrite",
            24 => "LogStore",
            25 => "MmioRead",
            26 => "MmioWrite",
            27 => "Unimpl",
            28 => "Trap",
            29 => "TimerElapse",
            _ => "?UnknownFuzzVmExit?",
        }
    }
}

impl From<VcpuExit<'_>> for FuzzVmExit {
    fn from(val: VcpuExit) -> Self {
        match val {
            VcpuExit::Unknown => FuzzVmExit::Unknown,
            VcpuExit::Exception => FuzzVmExit::Exception,
            VcpuExit::Hypercall => FuzzVmExit::Hypercall,
            VcpuExit::Debug(exception) => match exception.exception.into() {
                Exception::Breakpoint => FuzzVmExit::Breakpoint(exception.pc),
                Exception::Debug => FuzzVmExit::DebugException,
                _ => FuzzVmExit::Debug(exception.exception.into()),
            },
            VcpuExit::Hlt => FuzzVmExit::Hlt,
            // VcpuExit::IrqWindowOpen => FuzzVmExit::IrqWindowOpen,
            VcpuExit::Shutdown => FuzzVmExit::Shutdown,
            // VcpuExit::FailEntry(a, b) => FuzzVmExit::FailEntry(a, b),
            // VcpuExit::Intr => FuzzVmExit::Intr,
            // VcpuExit::SetTpr => FuzzVmExit::SetTpr,
            // VcpuExit::TprAccess => FuzzVmExit::TprAccess,
            // VcpuExit::S390Sieic => FuzzVmExit::S390Sieic,
            // VcpuExit::S390Reset => FuzzVmExit::S390Reset,
            // VcpuExit::Dcr => FuzzVmExit::Dcr,
            // VcpuExit::Nmi => FuzzVmExit::Nmi,
            VcpuExit::InternalError => FuzzVmExit::InternalError,
            // VcpuExit::Osi => FuzzVmExit::Osi,
            // VcpuExit::PaprHcall => FuzzVmExit::PaprHcall,
            // VcpuExit::S390Ucontrol => FuzzVmExit::S390Ucontrol,
            // VcpuExit::Watchdog => FuzzVmExit::Watchdog,
            // VcpuExit::S390Tsch => FuzzVmExit::S390Tsch,
            // VcpuExit::Epr => FuzzVmExit::Epr,
            // VcpuExit::SystemEvent(type_, flags) => FuzzVmExit::SystemEvent(type_, flags),
            // VcpuExit::S390Stsi => FuzzVmExit::S390Stsi,
            // VcpuExit::IoapicEoi(vector) => FuzzVmExit::IoapicEoi(vector),
            // VcpuExit::Hyperv => FuzzVmExit::Hyperv,
            VcpuExit::IoIn(port, _bytes) => {
                FuzzVmExit::IoIn(port)
                // panic!("IoIn: Port: {:#x} bytes: {:x?}\n", port, bytes);
            }
            VcpuExit::IoOut(port, _bytes) => {
                FuzzVmExit::IoOut(port)
                // panic!("IoOut: Port: {:#x} bytes: {:x?}\n", port, bytes);
            }
            VcpuExit::MmioRead(..) => FuzzVmExit::MmioRead,
            VcpuExit::MmioWrite(..) => FuzzVmExit::MmioWrite,
            _ => {
                log::warn!("Unhandled vmexit: {val:?}");
                println!("Unhandled vmexit: {val:?}");
                FuzzVmExit::Unimpl
            }
        }
    }
}

/// Cycle counts while executing `.run()` for a VM
#[derive(Default, Debug, Copy, Clone)]
pub struct VmRunPerf {
    /// Number of cycles, as measured by `rdtsc`, spent executing in the VM
    pub in_vm: u64,

    /// Number of cycles, as measured by `rdtsc`, spent executing before the vcpu.run()
    /// call
    pub pre_run_vm: u64,

    /// Number of cycles, as measured by `rdtsc`, spent executing after the vcpu.run()
    /// call
    pub post_run_vm: u64,
}

/// Cycle counts while resetting guest state
#[derive(Default, Debug, Copy, Clone)]
pub struct GuestResetPerf {
    /// Amount of time spent during restoring guest memory found by KVM
    pub reset_guest_memory_restore: u64,

    /// Amount of time spent during resetting dirty pages set by a fuzzer
    pub reset_guest_memory_custom: u64,

    /// Amount of time spent clearing the dirty page bits
    pub reset_guest_memory_clear: u64,

    /// Amount of time spent during gathering dirty logs from KVM
    pub get_dirty_logs: u64,

    /// Number of pages restored from kvm dirty log
    pub restored_kvm_pages: u32,

    /// Number of pages restored from custom dirty log
    pub restored_custom_pages: u32,

    /// Amount of time during running `fuzzvm.init_guest`
    pub init_guest: InitGuestPerf,

    /// Amount of time during running `fuzzer.apply_fuzzer_breakpoint`
    pub apply_fuzzer_breakpoints: u64,

    /// Amount of time during running `fuzzer.apply_reset_breakpoint`
    pub apply_reset_breakpoints: u64,

    /// Amount of time during running `fuzzer.apply_coverage_breakpoint`
    pub apply_coverage_breakpoints: u64,

    /// Amount of time during running `fuzzer.init_vm`
    pub init_vm: u64,

    /// Amount of time during running the initial `fuzzer.init_snapshot`
    pub init_snapshot: u64,
}

/// Cycle counts while initialzing the guest
#[derive(Default, Debug, Copy, Clone)]
pub struct InitGuestPerf {
    /// Amount of time during running `fuzzvm.init_guest` restoring registers
    pub regs: u64,

    /// Amount of time during running `fuzzvm.init_guest` restoring sregs
    pub sregs: u64,

    /// Amount of time during running `fuzzvm.init_guest` restoring fpu
    pub fpu: u64,

    /// Amount of time during running `fuzzvm.init_guest` restoring MSRs
    pub msrs: u64,

    /// Amount of time during running `fuzzvm.init_guest` restoring debug registers
    pub debug_regs: u64,
}

/// Lightweight VM used for fuzzing a memory snapshot
#[allow(clippy::struct_excessive_bools)]
pub struct FuzzVm<'a, FUZZER: Fuzzer> {
    /// The core id of the core running this VM
    #[allow(dead_code)]
    pub core_id: u64,

    /// Underlying VM from KVM
    pub vm: &'a VmFd,

    /// The CPU for this VM
    pub vcpu: VcpuFd,

    /// Current register state in the VM
    regs: kvm_regs,

    /// Current sreg state in the VM
    pub sregs: kvm_sregs,

    // /// Current fpu state in the VM
    // fpu: kvm_fpu,
    /// Current VCPU events from KVM
    pub vcpu_events: kvm_vcpu_events,

    /// Random number generator
    pub rng: Rng,

    // /// Current debug register state in the VM
    // pub debug_regs: kvm_debugregs,
    /// Underlying physical memory for this VM
    pub memory: Memory,

    /// Original CPU state used to reset the VM
    pub vbcpu: VbCpu,

    /// Is single step enabled for the guest
    pub single_step: bool,

    /// Breakpoints currently set in the VM keyed with their original byte to potentially
    /// restore after it has been hit. The value in this map is the index into the
    /// various breakpoint arrays. This DOES NOT contain coverage breakpoints.
    pub breakpoints: BTreeMap<(VirtAddr, Cr3), usize>,

    /// Original bytes for breakpoints in the VM indexed by the value in
    /// `self.breakpoints`.
    pub breakpoint_original_bytes: Vec<Option<u8>>,

    /// List of type of breakpoints
    pub breakpoint_types: Vec<BreakpointType>,

    /// Potential callbacks executed when the breakpoint at the index in triggered
    pub breakpoint_hooks: Vec<BreakpointHook<FUZZER>>,

    /// Cached breakpoints that have had symbols resolved in order to avoid looking up
    /// symbols each iteration
    #[allow(clippy::type_complexity)]
    pub fuzzer_breakpoint_cache: Option<Vec<(VirtAddr, Cr3, BreakpointType, HookFn<FUZZER>)>>,

    /// If set, will enable single step for the next instruction. After the instruction
    /// is executed, will write a `0xcc` at the given [`VirtAddr`] to reset a breakpoint.
    pub restore_breakpoint: Option<(VirtAddr, Cr3)>,

    /// Clean snapshot buffer to restore the dirty pages from
    pub clean_snapshot: Arc<RwLock<Memory>>,

    /// Memory regions backing this VM (used for deleting the regions to reset the memory
    /// on VM reset)
    pub memory_regions: [kvm_userspace_memory_region; 3],

    /// Number of pages in the memory region indexed by slot
    pub number_of_pages: [u32; 3],

    // /// Number of retired instructions that will cause the next VMExit
    // pub instrs_next_exit: u64,

    // /// Number of instructions executed as counted by `FIXED_CTR0` (the retired
    // /// instructions counter)
    // pub instructions_executed: u64,
    /// Maximum number of retired instructions before causing a VM Exit.
    pub polling_interval: u64,

    /// Current set of single shot breakpoints set that, when hit, add the address to the
    /// coverage database.  This is an Option to enable a `.take()` to avoid a
    /// `&mut self ` collision when applying then breakpoints
    pub coverage_breakpoints: Option<BTreeMap<VirtAddr, u8>>,

    /// Signifies if this VM will exit on syscalls. Handles whether
    /// `EferFlags::SYSTEM_CALL_EXTENSIONS` is enabled.
    pub exit_on_syscall: bool,

    /// Breakpoints that, if hit, signify a crash or reset in the guest. This is an
    /// Option to enable a `.take()` to avoid a `&mut self ` collision when applying then
    /// breakpoints
    pub reset_breakpoints: Option<BTreeMap<(VirtAddr, Cr3), ResetBreakpointType>>,

    /// List of symbols available in this VM
    pub symbols: &'a Option<VecDeque<Symbol>>,

    /// Start time of the current fuzz case, used to determine if the VM should be timed
    /// out
    pub start_time: Instant,

    /// Reusable allocations to get the dirty bitmaps for each memory memory
    pub dirty_bitmaps: [Vec<u64>; 3],

    /// Temp scratch buffer to collect guest memory physical pages that is not
    /// reallocated each reset
    pub scratch_reset_buffer: Vec<u64>,

    /// Data written to the console
    pub console_output: Vec<u8>,

    /// The general purpose registers are dirtied and need to be updated on next entry
    pub dirtied_registers: bool,

    /// Packets sent out by the VM
    pub sent_packets: Vec<Vec<u8>>,

    /// Emulated filesystem
    pub filesystem: Option<FileSystem>,

    /// Fuzzer configuration
    pub config: Config,

    /// Collection of unwinders used to attempt to unwind the stack
    pub unwinders: Option<StackUnwinders>,

    /// Set of redqueen rules used for cmp analysis (our RedQueen implementation)
    #[cfg(feature = "redqueen")]
    pub redqueen_rules: BTreeMap<u64, BTreeSet<RedqueenRule>>,

    /// Parsed redqueen breakpoints used to gather runtime comparison operands
    #[cfg(feature = "redqueen")]
    pub redqueen_breakpoints: Option<Vec<(u64, RedqueenArguments)>>,

    /// Parsed redqueen breakpoints used to gather runtime comparison operands
    #[cfg(feature = "redqueen")]
    pub redqueen_breakpoint_addresses: Option<BTreeSet<u64>>,
}

/// Copy 4096 bytes of the page at `source` to the page at `dest`
unsafe fn copy_page(source: u64, dest: u64) {
    debug_assert!(source & 0xfff == 0, "source addr not a page!");
    debug_assert!(dest & 0xfff == 0, "dest addr not a page!");

    if cfg!(target_feature = "avx512f") {
        use std::arch::x86_64::__m512;
        /// memcpy via avx512 via 4-step unrolling (RRRRWWWW)
        macro_rules! avx512move_unrolled {
            ($i:expr) => {
                let in_addr1 = (source + 64 * ($i * 4 + 0)) as *const __m512;
                let in_addr2 = (source + 64 * ($i * 4 + 1)) as *const __m512;
                let in_addr3 = (source + 64 * ($i * 4 + 2)) as *const __m512;
                let in_addr4 = (source + 64 * ($i * 4 + 3)) as *const __m512;
                let out_addr1 = (dest + 64 * ($i * 4 + 0)) as *mut __m512;
                let out_addr2 = (dest + 64 * ($i * 4 + 1)) as *mut __m512;
                let out_addr3 = (dest + 64 * ($i * 4 + 2)) as *mut __m512;
                let out_addr4 = (dest + 64 * ($i * 4 + 3)) as *mut __m512;
                let read_val1 = std::ptr::read_unaligned(in_addr1);
                let read_val2 = std::ptr::read_unaligned(in_addr2);
                let read_val3 = std::ptr::read_unaligned(in_addr3);
                let read_val4 = std::ptr::read_unaligned(in_addr4);
                std::ptr::write_unaligned(out_addr1, read_val1);
                std::ptr::write_unaligned(out_addr2, read_val2);
                std::ptr::write_unaligned(out_addr3, read_val3);
                std::ptr::write_unaligned(out_addr4, read_val4);
            };
        }

        avx512move_unrolled!(0);
        avx512move_unrolled!(1);
        avx512move_unrolled!(2);
        avx512move_unrolled!(3);
        avx512move_unrolled!(4);
        avx512move_unrolled!(5);
        avx512move_unrolled!(6);
        avx512move_unrolled!(7);
        avx512move_unrolled!(8);
        avx512move_unrolled!(9);
        avx512move_unrolled!(10);
        avx512move_unrolled!(11);
        avx512move_unrolled!(12);
        avx512move_unrolled!(13);
        avx512move_unrolled!(14);
        avx512move_unrolled!(15);
    } else {
        // Copy the snapshot bytes into the guest memory
        std::ptr::copy_nonoverlapping(source as *const u8, dest as *mut u8, 0x1000);
    }
}

impl<'a, FUZZER: Fuzzer> FuzzVm<'a, FUZZER> {
    /// Create a [`FuzzVm`] using the given [`VmFd`] and snapshot registers from
    /// [`VbCpu`] with a memory backing at address `memory_backing`
    ///
    /// # Errors
    ///
    /// * If KVM fails to return valid regs, sregs, fpu, debug regs, or vcpu events
    /// * If the given APIC base isn't `APIC_BASE`
    /// * If the guest fails to initialize properly
    pub fn create(
        core_id: u64,
        fuzzer: &mut FUZZER,
        vm: &'a VmFd,
        virtualbox_cpu: &VbCpu,
        cpuid: &CpuId,
        snapshot_fd: i32,
        clean_snapshot: Arc<RwLock<Memory>>,
        coverage_breakpoints: Option<BTreeMap<VirtAddr, u8>>,
        reset_breakpoints: Option<BTreeMap<(VirtAddr, Cr3), ResetBreakpointType>>,
        symbols: &'a Option<VecDeque<Symbol>>,
        config: Config,
        unwinders: StackUnwinders,
        #[cfg(feature = "redqueen")] redqueen_rules: BTreeMap<u64, BTreeSet<RedqueenRule>>,
        #[cfg(feature = "redqueen")] redqueen_breakpoints: Option<Vec<(u64, RedqueenArguments)>>,
    ) -> Result<Self> {
        // Create a PIT2 timer
        let pit_config = kvm_pit_config::default();
        vm.create_pit2(pit_config)
            .context(Error::FailedToCreatePIT2)?;

        // Set the Task State Segment address to the default TSS base
        vm.set_tss_address(TSS_BASE.try_into()?)?;

        // Create the IRQ chip to enable the APIC for this VM
        vm.create_irq_chip().context("Failed to create IRQCHIP")?;

        // Allocate a CPU for this VM
        let vcpu = vm.create_vcpu(0).context(Error::FailedToCreateVcpu)?;

        // Only used for triggering polling coverage via retired instruction overflows.
        // Currently disabled

        // Init the APIC for this VM (enable NMI for retire instruction counter overflow)
        crate::apic::init(&vcpu).context("Failed to init APIC")?;

        // Set the MSRs available for this guest VM from the available MSRs in KVM
        vcpu.set_cpuid2(cpuid).context("Failed to set CPUIDs")?;

        // Set xcr0 to 7 to enable avx, sse, and x87
        let mut xcrs = vcpu.get_xcrs()?;
        xcrs.xcrs[0].xcr = 0x0;
        xcrs.xcrs[0].value = 0x7;
        vcpu.set_xcrs(&xcrs)?;

        // Setup debug mode for the guest
        let debug_struct = kvm_guest_debug {
            control: KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP | KVM_GUESTDBG_SINGLESTEP,
            pad: 0,
            arch: kvm_guest_debug_arch {
                debugreg: [0, 0, 0, 0, 0, 0, 0, 0x400],
            },
        };

        // Enable guest mode in the guest
        vcpu.set_guest_debug(&debug_struct)
            .context("Failed to set guest debug mode")?;

        // Create the memory backing for the guest VM using the existing snapshot
        let memory = Memory::from_fd(snapshot_fd, config.guest_memory_size)?;

        // Sanity check only `syscall_whitelist` or `syscall_blacklist` is set and not
        // both
        if !fuzzer.syscall_blacklist().is_empty() {
            assert!(
                fuzzer.syscall_whitelist().is_empty(),
                "Syscall blacklist and whitelist set"
            );
        }
        if !fuzzer.syscall_whitelist().is_empty() {
            assert!(
                fuzzer.syscall_blacklist().is_empty(),
                "Syscall blacklist and whitelist set"
            );
        }

        // Check if the fuzzer is requesting to handle any syscalls
        let exit_on_syscall =
            !fuzzer.syscall_whitelist().is_empty() || !fuzzer.syscall_blacklist().is_empty();

        // Create an set for easily searchable redqueen breakpoint addresses
        let mut redqueen_breakpoint_addresses = None;
        if let Some(ref redqueen_bps) = redqueen_breakpoints {
            let mut result = BTreeSet::new();
            redqueen_bps.iter().for_each(|(addr, _)| {
                result.insert(*addr);
            });
            redqueen_breakpoint_addresses = Some(result);
        }

        // Create the overall FuzzVm struct
        let mut fuzzvm = Self {
            core_id,
            regs: vcpu.get_regs()?,
            sregs: vcpu.get_sregs()?,
            // fpu: vcpu.get_fpu()?,
            // debug_regs: vcpu.get_debug_regs()?,
            vcpu_events: vcpu.get_vcpu_events()?,
            rng: Rng::new(),
            single_step: false,
            memory,
            vm,
            vcpu,
            vbcpu: *virtualbox_cpu,
            breakpoints: BTreeMap::new(),
            breakpoint_original_bytes: Vec::new(),
            breakpoint_types: Vec::new(),
            breakpoint_hooks: Vec::new(),
            fuzzer_breakpoint_cache: None,
            restore_breakpoint: None,
            clean_snapshot,
            memory_regions: [
                kvm_userspace_memory_region::default(),
                kvm_userspace_memory_region::default(),
                kvm_userspace_memory_region::default(),
            ],
            number_of_pages: [0; 3],
            // instrs_next_exit: 0,
            // instructions_executed: 0,
            polling_interval: 0,
            coverage_breakpoints,
            exit_on_syscall,
            reset_breakpoints,
            symbols,
            start_time: Instant::now(),
            dirty_bitmaps: [Vec::new(), Vec::new(), Vec::new()],
            scratch_reset_buffer: Vec::new(),
            console_output: Vec::new(),
            dirtied_registers: false,
            sent_packets: Vec::new(),
            filesystem: None,
            config,
            #[cfg(feature = "redqueen")]
            redqueen_rules,
            #[cfg(feature = "redqueen")]
            redqueen_breakpoints,
            #[cfg(feature = "redqueen")]
            redqueen_breakpoint_addresses,
            unwinders: Some(unwinders),
        };

        // Pre-write all of the coverage breakpoints into the memory for the VM. The
        // "clean snapshot" memory also has the coverage breakpoints pre-written so
        // during reset, the breakpoints are already in place.
        let cr3 = Cr3(virtualbox_cpu.cr3);
        if let Some(cov_bps) = fuzzvm.coverage_breakpoints.take() {
            for (addr, byte) in &cov_bps {
                if let Ok(curr_byte) = fuzzvm.read::<u8>(*addr, cr3) {
                    // Sanity check the original memory and the coverage breakpoint original
                    // bytes match
                    ensure!(*byte == curr_byte, Error::CoverageBreakpointIncorrectCache);

                    // Write the breakpoint into the VM memory
                    fuzzvm.write_bytes(*addr, cr3, &[0xcc])?;
                }
            }

            fuzzvm.coverage_breakpoints = Some(cov_bps);
        }

        // Calculate the kernel CR3 based on the instrutions from the single step of
        // the kernel
        //
        // 0x00007ffff7eac249 0x00000000ba693000 | libc-2.31.so!__getpid+0x9 | syscall
        // 0xffffffffa6200010 0x00000000ba693000 | entry_SYSCALL_64+0x0      | swapgs
        // 0xffffffffa6200013 0x00000000ba693000 | entry_SYSCALL_64+0x3      | mov qword ptr gs:[0x6014], rsp
        // 0xffffffffa620001c 0x00000000ba693000 | entry_SYSCALL_64+0xc      | nop
        // 0xffffffffa620001e 0x00000000ba693000 | entry_SYSCALL_64+0xe      | mov rsp, cr3
        // 0xffffffffa6200021 0x00000000ba693000 | entry_SYSCALL_64+0x11     | bts rsp, 0x3f
        // 0xffffffffa6200026 0x00000000ba693000 | entry_SYSCALL_64+0x16     | and rsp, 0xffffffffffffe7ff
        // 0xffffffffa620002d 0x00000000ba693000 | entry_SYSCALL_64+0x1d     | mov cr3, rsp
        let kern_cr3 = Cr3(cr3.0 & 0xffff_ffff_ffff_e7ff);

        // Initialize the used physical pages in order to allocate new physical pages if
        // needed
        fuzzvm.memory.identify_used_phys_pages(&[cr3, kern_cr3]);

        // Init the guest memory backing
        fuzzvm.init_guest_memory_backing()?;

        // Sanity check values in the vbcpu
        // fuzzvm.sanity_check_vbcpu()?;

        // Initialize guest using vbcpu
        fuzzvm.init_guest()?;

        // New reset breakpoints that are given by the target-specific fuzzer
        let mut new_reset_bps = BTreeMap::new();

        // Add the fuzzer specific reset and crash breakpoints if any are requested,
        // translating any symbols if requested
        for (fuzzer_bps, reset_type) in [
            (fuzzer.reset_breakpoints(), ResetBreakpointType::Reset),
            (fuzzer.crash_breakpoints(), ResetBreakpointType::Crash),
        ] {
            let Some(fuzzer_bps) = fuzzer_bps else {
                continue;
            };

            for breakpoint in fuzzer_bps {
                match breakpoint {
                    AddressLookup::Virtual(virt_addr, cr3) => {
                        new_reset_bps.insert((*virt_addr, *cr3), reset_type);
                    }
                    AddressLookup::SymbolOffset(symbol, offset) => {
                        if let Some((virt_addr, cr3)) = fuzzvm.get_symbol_address(symbol) {
                            new_reset_bps.insert((virt_addr.offset(*offset), cr3), reset_type);
                        } else {
                            // Given symbol was not found. Lookup symbols that contain the given symbol
                            // to display as possible symbols that we do know about
                            let possibles = fuzzvm.get_symbols_containing(symbol);
                            if !possibles.is_empty() {
                                // These are `println` instead of `log` so that the possibles can be printed
                                // to the screen even using the TUI.
                                eprintln!("Symbol was not found: {symbol}. Did you mean one of the following?");
                                log::info!("Symbol was not found: {symbol}. Did you mean one of the following?");
                                for p in possibles {
                                    eprintln!(" - {p}");
                                    log::info!(" - {p}");
                                }
                            }
                            return Err(Error::LookupSymbolNotFound(symbol, *offset).into());
                        }
                    }
                }
            }
        }

        // Add all of the reset/crash breakpoints given by the fuzzer
        if let Some(ref mut reset_bps) = fuzzvm.reset_breakpoints {
            reset_bps.append(&mut new_reset_bps);
        }

        // Remove all reset breakpoints from the coverage breakpoints if they exist
        // Reset breakpoints take precedence over the coverage breakpoints since they
        // are used to signal resets or crashes
        if let Some(ref mut cov_bps) = fuzzvm.coverage_breakpoints {
            for (addr, _cr3) in fuzzvm.reset_breakpoints.as_ref().unwrap().keys() {
                cov_bps.remove(addr);
            }
        }

        // Init the VM based on the given fuzzer (called a single time)
        fuzzer.init_snapshot(&mut fuzzvm)?;

        // Init the VM based on the given fuzzer
        fuzzer.init_vm(&mut fuzzvm)?;

        // Apply the breakpoints for the fuzzer
        fuzzvm.apply_fuzzer_breakpoints(fuzzer)?;

        // Apply the crashing breakpoints found in the symbols
        fuzzvm.apply_reset_breakpoints()?;

        // Initialize the filesystem with the files from the fuzzer
        let mut filesystem = FileSystem::default();
        fuzzer.init_files(&mut filesystem)?;
        fuzzvm.filesystem = Some(filesystem);

        // Add a breakpoint to LSTAR which is caught during `syscall` execution to
        // determine if the fuzzer wants to handle the syscall or not
        if fuzzvm.exit_on_syscall {
            let lstar = VirtAddr(fuzzvm.vbcpu.msr_lstar);

            fuzzvm.set_breakpoint(
                lstar,
                cr3,
                BreakpointType::Repeated,
                BreakpointMemory::NotDirty,
                BreakpointHook::Func(|_, _, _| Ok(Execution::Continue)),
            )?;
        }

        // Return the FuzzVm and the VcpuFd
        Ok(fuzzvm)
    }

    /// Enable single step in the guest
    ///
    /// # Example
    ///
    /// ```
    /// let mut fuzzvm = FuzzVm::create(..);
    /// fuzzvm.enable_single_step();
    /// ```
    ///
    /// # Errors
    ///
    /// * Restoring the guest MSRs fails
    #[allow(dead_code)]
    pub fn enable_single_step(&mut self) -> Result<()> {
        /// Enable trap flag for the given [`FuzzVm`]
        #[allow(clippy::unnecessary_wraps)]
        fn enable_trap_flag<FUZZER: Fuzzer>(
            fuzzvm: &mut FuzzVm<FUZZER>,
            _input: &FUZZER::Input,
            _fuzzer: &mut FUZZER,
        ) -> Result<Execution> {
            let mut rflags = RFlags::from_bits_truncate(fuzzvm.rflags());
            rflags.insert(RFlags::TRAP_FLAG);
            fuzzvm.dirtied_registers = true;
            Ok(Execution::Continue)
        }

        self.single_step = true;

        // Since we don't have monitor trap flag access in KVM (without modifying KVM
        // itself), we don't have single step access during an interrupt. To mitigate
        // this, we set a breakpoint at each interrupt service routine and enable the
        // trap flag if we are single stepping
        if self.single_step {
            for vector in 0..255 {
                let addr = self.vbcpu.idtr_base + vector * std::mem::size_of::<IdtEntry>() as u64;
                let cr3 = self.cr3();

                let entry = self.read::<IdtEntry>(VirtAddr(addr), cr3)?;
                let isr = VirtAddr(entry.isr());

                self.set_breakpoint(
                    isr,
                    cr3,
                    BreakpointType::Repeated,
                    BreakpointMemory::NotDirty,
                    BreakpointHook::Func(enable_trap_flag),
                )?;

                // Duplicate the current isr breakpoints with one using the wildcard cr3
                // to continue execution calling an isr from any cr3 and not just the
                // cr3 that started the VM
                let mut curr_index = None;
                if let Some(index) = self.breakpoints.get(&(isr, cr3)) {
                    curr_index = Some(*index);
                    self.breakpoints.insert((isr, WILDCARD_CR3), *index);
                }

                if let Some(index) = curr_index {
                    let orig_type = self.breakpoint_types[index];
                    self.breakpoint_types.push(orig_type);

                    let orig_byte = self.breakpoint_original_bytes[index];
                    self.breakpoint_original_bytes.push(orig_byte);

                    self.breakpoint_hooks
                        .push(BreakpointHook::Func(enable_trap_flag));
                }
            }
        }

        Ok(())
    }

    /// Disable single step in the guest
    ///
    /// # Example
    ///
    /// ```
    /// let mut fuzzvm = FuzzVm::create(..);
    /// fuzzvm.disable_single_step();
    /// ```
    ///
    /// # Errors
    ///
    /// * Restoring the guest MSRs fails
    #[allow(dead_code)]
    pub fn disable_single_step(&mut self) -> Result<()> {
        self.single_step = false;

        Ok(())
    }

    /// Get the current register state of the VM
    ///
    /// # Example
    ///
    /// ```
    /// let mut fuzzvm = FuzzVm::create(..);
    /// let rax = fuzzvm.regs().rax;
    /// ```
    #[must_use]
    pub fn regs(&self) -> &kvm_regs {
        &self.regs
    }

    /// Get the current register state of the VM
    ///
    /// # Example
    ///
    /// ```
    /// let mut fuzzvm = FuzzVm::create(..);
    /// let mut regs = fuzzvm.mut_regs();
    /// regs.rax = 0xdead_beef;
    /// ```
    #[must_use]
    pub fn regs_mut(&mut self) -> &mut kvm_regs {
        &mut self.regs
    }

    /// Get the current special register state of the VM
    ///
    /// # Example
    ///
    /// ```
    /// let mut fuzzvm = FuzzVm::create(..);
    /// let cr0 = fuzzvm.sregs().cr0;
    /// ```
    #[must_use]
    pub fn sregs(&self) -> &kvm_sregs {
        &self.sregs
    }

    /// Get the current special register state of the VM
    #[must_use]
    pub fn _sregs_mut(&mut self) -> &mut kvm_sregs {
        &mut self.sregs
    }

    /// Get the current special register state of the VM
    ///
    /// # Example
    ///
    /// ```
    /// let mut fuzzvm = FuzzVm::create(..);
    /// let dr6 = fuzzvm.debug_regs()?.dr6;
    /// ```
    ///
    /// # Errors
    ///
    /// Failed to get debug registers from KVM
    pub fn debug_regs(&self) -> Result<kvm_debugregs> {
        Ok(self.vcpu.get_debug_regs()?)
    }

    /// Get the current `cr3` register in the VM (ignoring lower 12 bits)
    ///
    /// # Example
    ///
    /// ```
    /// let mut fuzzvm = FuzzVm::create(..);
    /// let cr3 = fuzzvm.cr3();
    /// ```
    #[must_use]
    pub fn cr3(&self) -> Cr3 {
        Cr3(self.sregs.cr3 & !0xfff)
    }

    /// Get the current [`kvm_vcpu_events`] from the guest
    #[must_use]
    pub fn vcpu_events(&self) -> &kvm_vcpu_events {
        &self.vcpu_events
    }

    /// Get the current [`kvm_vcpu_events`] from the guest
    #[must_use]
    pub fn vcpu_events_mut(&mut self) -> &mut kvm_vcpu_events {
        &mut self.vcpu_events
    }

    /// Get the current [`kvm_fpu`] from the guest
    ///
    /// # Errors
    ///
    /// Failed to get fpu from KVM
    pub fn fpu(&self) -> Result<kvm_fpu> {
        Ok(self.vcpu.get_fpu()?)
    }

    /// Sanity check the [`VbCpu`] for erroneous values
    ///
    /// # Errors
    ///
    /// * If the snapshot's apic base is not `APIC_BASE`
    pub fn sanity_check_vbcpu(&mut self) -> Result<()> {
        /// Assembly bytes for `_entry_SYSCALL` to sanity check that LSTAR points the
        /// right addr
        const ENTRY_SYSCALL_BYTES: [u8; 0x30] = [
            0x0f, 0x01, 0xf8, 0x65, 0x48, 0x89, 0x24, 0x25, 0x14, 0x60, 0x00, 0x00, 0x66, 0x90,
            0x0f, 0x20, 0xdc, 0x48, 0x0f, 0xba, 0xec, 0x3f, 0x48, 0x81, 0xe4, 0xff, 0xe7, 0xff,
            0xff, 0x0f, 0x22, 0xdc, 0x65, 0x48, 0x8b, 0x24, 0x25, 0x0c, 0x60, 0x00, 0x00, 0x6a,
            0x2b, 0x65, 0xff, 0x34, 0x25, 0x14,
        ];

        /// Assembly bytes for `_entry_SYSCALL_64` to sanity check that LSTAR points the
        /// right addr
        const ENTRY_SYSCALL64_BYTES_WITH_KCOV: [u8; 0x30] = [
            0x0f, 0x01, 0xf8, 0x65, 0x48, 0x89, 0x24, 0x25, 0x14, 0xa0, 0x00, 0x00, 0x66, 0x90,
            0x0f, 0x20, 0xdc, 0x0f, 0x1f, 0x44, 0x00, 0x00, 0x48, 0x81, 0xe4, 0xff, 0xe7, 0xff,
            0xff, 0x0f, 0x22, 0xdc, 0x65, 0x48, 0x8b, 0x24, 0x25, 0x10, 0xfe, 0x02, 0x00, 0x6a,
            0x2b, 0x65, 0xff, 0x34, 0x25, 0x14,
        ];

        /// `entry_SYSCALL` from KCOV
        const ENTRY_SYSCALL64_BYTES_NO_KCOV: [u8; 0x30] = [
            0x0f, 0x01, 0xf8, 0x65, 0x48, 0x89, 0x24, 0x25, 0x14, 0xa0, 0x00, 0x00, 0x66, 0x90,
            0x0f, 0x20, 0xdc, 0x0f, 0x1f, 0x44, 0x00, 0x00, 0x48, 0x81, 0xe4, 0xff, 0xe7, 0xff,
            0xff, 0x0f, 0x22, 0xdc, 0x65, 0x48, 0x8b, 0x24, 0x25, 0x90, 0xfd, 0x02, 0x00, 0x6a,
            0x2b, 0x65, 0xff, 0x34, 0x25, 0x14,
        ];

        /// `entry_SYSCALL` from KCOV (version 2)
        const ENTRY_SYSCALL64_BYTES_WITH_KCOV2: [u8; 0x30] = [
            0x0f, 0x01, 0xf8, 0x65, 0x48, 0x89, 0x24, 0x25, 0x14, 0xa0, 0x00, 0x00, 0x66, 0x90,
            0x0f, 0x20, 0xdc, 0x0f, 0x1f, 0x44, 0x00, 0x00, 0x48, 0x81, 0xe4, 0xff, 0xe7, 0xff,
            0xff, 0x0f, 0x22, 0xdc, 0x65, 0x48, 0x8b, 0x24, 0x25, 0x0c, 0xa0, 0x00, 0x00, 0x6a,
            0x2b, 0x65, 0xff, 0x34, 0x25, 0x14,
        ];

        /// `entry_SYSCALL` from Linux v5.20
        const ENTRY_SYSCALL64_BYTES_V5_20: [u8; 0x30] = [
            0x0f, 0x01, 0xf8, 0x65, 0x48, 0x89, 0x24, 0x25, 0x14, 0xa0, 0x00, 0x00, 0x66, 0x90,
            0x0f, 0x20, 0xdc, 0x0f, 0x1f, 0x44, 0x00, 0x00, 0x48, 0x81, 0xe4, 0xff, 0xe7, 0xff,
            0xff, 0x0f, 0x22, 0xdc, 0x65, 0x48, 0x8b, 0x24, 0x25, 0x90, 0xfd, 0x01, 0x00, 0x6a,
            0x2b, 0x65, 0xff, 0x34, 0x25, 0x14,
        ];

        // Sanity check the APIC base is expected
        ensure!(self.vbcpu.msr_apic_base & !0xfff == APIC_BASE);

        // Read the bytes from LSTAR
        let bytes: [u8; ENTRY_SYSCALL_BYTES.len()] =
            self.read(VirtAddr(self.vbcpu.msr_lstar), Cr3(self.vbcpu.cr3))?;

        // Ensure the assembly bytes are the correct syscall bytes
        ensure!(
            bytes == ENTRY_SYSCALL_BYTES
                || bytes == ENTRY_SYSCALL64_BYTES_WITH_KCOV
                || bytes == ENTRY_SYSCALL64_BYTES_WITH_KCOV2
                || bytes == ENTRY_SYSCALL64_BYTES_V5_20
                || bytes == ENTRY_SYSCALL64_BYTES_NO_KCOV,
            "LSTAR address {:#x} does not match entry_SYSCALL bytes",
            self.vbcpu.msr_lstar
        );

        Ok(())
    }

    /// Return the current (RIP, CR3) pair for the current instruction location
    #[must_use]
    pub fn current_address(&self) -> (VirtAddr, Cr3) {
        (VirtAddr(self.regs.rip), self.cr3())
    }

    /// Check if performance monitoring is enabled in KVM
    ///
    /// # Errors
    ///
    /// * KVM failed to get cpuids
    pub fn is_performance_monitoring_enabled(&self) -> Result<bool> {
        // Get the VCPU for this core
        let cpuid = self.vcpu.get_cpuid2(KVM_MAX_CPUID_ENTRIES)?;

        // Get the kvm_cpuid2 reference
        let cpuids = cpuid.as_slice();

        // Look through all CPUID entries
        for cpuid in cpuids {
            log::info!("CPUID Entry: {:x?}\n", cpuid);
        }

        Ok(true)
    }

    /// Read bytes from the [`VirtAddr`] translating using [`Cr3`] into the given `buf`
    ///
    /// # Example
    ///
    /// ```rust
    /// let mut fuzzvm = FuzzVm::create(..);
    ///
    /// // Read from the stack
    /// let read_addr = VirtAddr(fuzzvm.rsp());
    ///
    /// // Initialize the buffer to read bytes into
    /// let mut buffer = [0u64; 16];
    ///
    /// // Read 16 u64's from the stack into the given buffer
    /// fuzzvm.read_bytes(read_addr, cr3, &mut buffer)?;
    /// ```
    ///
    /// # Errors
    ///
    /// * Read from an unmapped virtual address
    pub fn read_bytes<T: Copy>(
        &mut self,
        virt_addr: VirtAddr,
        cr3: Cr3,
        buf: &mut [T],
    ) -> Result<()> {
        self.memory.read_bytes(virt_addr, cr3, buf)
    }

    /// Read the requested type from the given [`VirtAddr`] using the [`Cr3`] page table
    ///
    /// # Example
    ///
    /// ```rust
    /// let mut fuzzvm = FuzzVm::create(..);
    /// let addr = VirtAddr(fuzzvm.rsp());
    /// let cr3  = fuzzvm.cr3();
    ///
    /// // Read 16 u64's from the stack
    /// let stack = fuzzvm.read::<[u64; 16]>(addr, cr3)?;
    /// ```
    ///
    /// # Errors
    ///
    /// * Read from an unmapped virtual address
    pub fn read<T: Sized>(&mut self, virt_addr: VirtAddr, cr3: Cr3) -> Result<T> {
        self.memory.read(virt_addr, cr3)
    }

    /// Write the requested type from the given [`VirtAddr`] using given the [`Cr3`] page
    /// table
    ///
    /// # Example
    ///
    /// ```rust
    /// let mut fuzzvm = FuzzVm::create(..);
    /// let addr = VirtAddr(0x401_0000);
    /// let cr3  = fuzzvm.cr3();
    ///
    /// // Write bytes into the VM
    /// fuzzvm.write::<[u8; 16]>(addr, cr3, [0x41; 16])?;
    ///
    /// // Read the bytes in this address
    /// let bytes_found = fuzzvm.read::<[u8; 16]>(addr, cr3)?;
    ///
    /// // Ensure the bytes were written properly
    /// assert!(bytes_found == [0x41; 16]);
    /// ```
    ///
    /// # Errors
    ///
    /// * Write to an unmapped virtual address
    pub fn write<T: Sized>(&mut self, virt_addr: VirtAddr, cr3: Cr3, val: T) -> Result<()> {
        self.memory.write(virt_addr, cr3, val, WriteMem::NotDirty)
    }

    /// Write the requested type from the given [`VirtAddr`] using given the [`Cr3`] page
    /// table and add the written memory to the dirty apge list
    ///
    /// # Example
    ///
    /// ```rust
    /// let mut fuzzvm = FuzzVm::create(..);
    /// let addr = VirtAddr(0x401_0000);
    /// let cr3  = fuzzvm.cr3();
    ///
    /// // Write bytes into the VM
    /// fuzzvm.write_dirty::<[u8; 16]>(addr, cr3, [0x42; 16])?;
    ///
    /// // Read the bytes in this address
    /// let bytes_found = fuzzvm.read::<[u8; 16]>(addr, cr3)?;
    ///
    /// // Ensure the bytes were written properly
    /// assert!(bytes_found == [0x42; 16]);
    /// ```
    ///
    /// # Errors
    ///
    /// * Write to an unmapped virtual address
    pub fn write_dirty<T: Sized>(&mut self, virt_addr: VirtAddr, cr3: Cr3, val: T) -> Result<()> {
        self.memory.write(virt_addr, cr3, val, WriteMem::Dirty)
    }

    /// Write bytes in `buf` to the [`VirtAddr`] translating using [`Cr3`]. The bytes
    /// written this way are not considered dirty and will not be restored on reset.
    ///
    /// # Example
    ///
    /// ```rust
    /// let mut fuzzvm = FuzzVm::create(..);
    /// let rip = fuzzvm.rip();
    /// let cr3 = fuzzvm.cr3();
    ///
    /// // Nop the next 8 bytes of the instruction pointer
    /// let new_bytes = [0x90u8; 8];
    ///
    /// // Write bytes into the VM
    /// fuzzvm.write_bytes(rip, cr3, &new_bytes)?;
    /// ```
    pub fn write_bytes(&mut self, virt_addr: VirtAddr, cr3: Cr3, buf: &[u8]) -> Result<()> {
        self.memory.write_bytes(virt_addr, cr3, buf)
    }

    /// Write bytes in `buf` to the [`VirtAddr`] translating using [`Cr3`] while keeping
    /// track of that we manually dirtied these pages
    ///
    /// # Example
    ///
    /// ```rust
    /// let mut fuzzvm = FuzzVm::create(..);
    /// let rip = fuzzvm.rip();
    /// let cr3 = fuzzvm.cr3();
    ///
    /// // Nop the next 8 bytes of the instruction pointer
    /// let new_bytes = [0x90u8; 8];
    ///
    /// // Write bytes into the VM
    /// fuzzvm.write_bytes_dirty(rip, cr3, &new_bytes)?;
    /// ```
    pub fn write_bytes_dirty(&mut self, virt_addr: VirtAddr, cr3: Cr3, buf: &[u8]) -> Result<()> {
        self.memory.write_bytes_dirty(virt_addr, cr3, buf)
    }

    /// Writes a breakpoint byte `0xcc` at the given [`VirtAddr`] optionally setting the
    /// written memory as dirty or not.
    ///
    /// The `BreakpointMemory` option is primarily used for coverage breakpoints. It
    /// was observed that resetting all coverage breakpoints every iteration is very
    /// costly. In this way, there can be selective choosing of when to reset the
    /// coverage breakpoints rather than assumed each iteration.
    ///
    /// # Errors
    ///
    /// * If we attempt to write to an unmapped virtual address
    /// * If we fail to write the bounds to the translated physical address
    pub fn write_breakpoint(
        &mut self,
        virt_addr: VirtAddr,
        cr3: Cr3,
        mem: BreakpointMemory,
    ) -> Result<()> {
        // The breakpoint byte to write into memory
        let buf = [0xcc];

        // If this breakpoint is not meant to be dirtied, then immediately return
        if matches!(mem, BreakpointMemory::NotDirty) {
            // Write the breakpoint into the memory
            self.memory.write_bytes(virt_addr, cr3, &buf)?;
        } else {
            // Write the breakpoint into the memory
            self.memory.write_bytes_dirty(virt_addr, cr3, &buf)?;
        }

        // Return successs
        Ok(())
    }

    /// Permanently write the given bytes to the current snapshot and the underlying clean snapshot
    /// such that these bytes are no longer replaced during a guest reset
    ///
    /// # Errors
    ///
    /// * If we attempt to write to an unmapped virtual address
    /// * If we fail to write the bounds to the translated physical address
    pub fn patch_bytes_permanent(&mut self, lookup: AddressLookup, new_bytes: &[u8]) -> Result<()> {
        // Get the virtual address from the lookup
        let (virt_addr, cr3) = lookup.get(self)?;

        // Grab the WRITE lock for the clean snapshot since we are modifying the clean snapshot
        let mut clean_snapshot = self.clean_snapshot.write().unwrap();
        clean_snapshot.write_bytes(virt_addr, cr3, new_bytes)?;
        drop(clean_snapshot);

        /// Patch the bytes of the current memory
        self.write_bytes(virt_addr, cr3, new_bytes)
    }

    /// Translate the given guest [`VirtAddr`] using the given page table found at
    /// [`Cr3`]
    ///
    /// # Example
    ///
    /// ```rust
    /// let mut fuzzvm = FuzzVm::create(..);
    /// let rip = VirtAddr(fuzzvm.rip());
    ///
    /// let translation = fuzzvm.translate(rip, fuzzvm.cr3());
    /// if let Some(phys_addr) = translation.phys_addr() {
    ///     log::info!("RIP is currently mapped: {rip:#x?} -> {phys_addr:#x?}");
    /// }
    /// ```
    #[must_use]
    pub fn translate(&self, virt_addr: VirtAddr, cr3: Cr3) -> Translation {
        self.memory.translate(virt_addr, cr3)
    }

    /// Clear the resume flag from [`RFlags`]
    pub fn clear_resume_flag(&mut self) {
        let mut rflags = RFlags::from_bits_truncate(self.regs.rflags);
        rflags.remove(RFlags::RESUME_FLAG);
        self.regs.rflags = rflags.bits();
    }

    /// Read an MSR from the guest
    ///
    /// # Errors
    ///
    /// * If KVM fails to get MSRs
    pub fn get_msr(&self, msr: Msr) -> Result<u64> {
        // Create the MSR entry to read
        let read_msr = [kvm_msr_entry {
            index: msr as u32,
            data: 0,
            ..kvm_bindings::kvm_msr_entry::default()
        }];

        // Prepare the requested MSR for read
        let mut msrs = Msrs::from_entries(&read_msr).map_err(|_| Error::CreateMsrEntries)?;

        // Read the MSR from KVM
        let msrs_read = self.vcpu.get_msrs(&mut msrs)?;

        // Ensure we read one msr
        ensure!(msrs_read == read_msr.len(), "Failed to read MSR: {:?}", msr);

        // Success result
        Ok(msrs.as_slice()[0].data)
    }

    /// Set an MSR in the guest with the given `data`
    ///
    /// # Errors
    ///
    /// * If KVM fails to get MSRs
    pub fn set_msr(&self, msr: Msr, data: u64) -> Result<()> {
        // Create the MSR entry to read
        let write_msr = [kvm_msr_entry {
            index: msr as u32,
            data,
            ..kvm_bindings::kvm_msr_entry::default()
        }];

        // Prepare the requested MSR for read
        let msrs = Msrs::from_entries(&write_msr).map_err(|_| Error::CreateMsrEntries)?;

        // Set the MSRs
        self.vcpu.set_msrs(&msrs)?;

        // Success result
        Ok(())
    }

    /// Get decoded instruction at the given [`VirtAddr`] using the given [`Cr3`]
    ///
    /// # Errors
    ///
    /// * If getting the current instruction at `virt_addr` fails
    pub fn get_current_instruction_string(&mut self) -> Result<String> {
        Ok(self
            .memory
            .get_instruction_string_at(VirtAddr(self.rip()), self.cr3())?
            .0)
    }

    /// Get the [`Instruction`] at the current instruction pointer
    ///
    /// # Errors
    ///
    /// * If `read` fails at the current instruction
    #[allow(dead_code)]
    pub fn get_current_instruction(&mut self) -> Result<Instruction> {
        self.memory
            .get_instruction_at(VirtAddr(self.rip()), self.cr3())
    }

    /// Get decoded instruction at the given [`VirtAddr`] using the given [`Cr3`] with
    /// additional information about the operands from the instruction
    ///
    /// # Example
    ///
    /// ```rust
    /// let mut fuzzvm = FuzzVm::create(..);
    ///
    /// if let Ok(instr) = fuzzvm.get_current_verbose_instruction_string() {
    ///     println!("{instr}");
    /// }
    /// ```
    /// ```text
    /// mov rcx, qword ptr [rsp+0x2b0]
    ///     RCX:0x0
    ///     [RSP:0x7ffffffdd660+0x2b0=0x7ffffffdd910 size:UInt64->0x10007fff3b28]]
    ///     [48, 8b, 8c, 24, b0, 02, 00, 00]
    /// ```
    ///
    /// # Errors
    ///
    /// * If getting the current instruction at `virt_addr` fails
    pub fn get_current_verbose_instruction_string(&mut self) -> Result<String> {
        self.get_verbose_instruction_string_at(VirtAddr(self.rip()), self.cr3())
    }

    /// Get decoded instruction at the given [`VirtAddr`] using the given [`Cr3`] with
    /// additional information about the operands from the instruction
    ///
    /// # Example
    ///
    /// ```rust
    /// let mut fuzzvm = FuzzVm::create(..);
    /// let rip = VirtAddr(fuzzvm.rip());
    ///
    /// if let Ok(instr) = fuzzvm.get_verbose_instruction_string_at(rip, fuzzvm.cr3()) {
    ///     println!("{instr}");
    /// }
    /// ```
    /// ```text
    /// mov rcx, qword ptr [rsp+0x2b0]
    ///     RCX:0x0
    ///     [RSP:0x7ffffffdd660+0x2b0=0x7ffffffdd910 size:UInt64->0x10007fff3b28]]
    ///     [48, 8b, 8c, 24, b0, 02, 00, 00]
    /// ```
    ///
    /// # Errors
    ///
    /// * If getting the current instruction at `virt_addr` fails
    ///
    /// # Panics
    ///
    /// * Unimplemented memory read sizes
    pub fn get_verbose_instruction_string_at(
        &mut self,
        virt_addr: VirtAddr,
        cr3: Cr3,
    ) -> Result<String> {
        let (mut result, instr) = self.memory.get_instruction_string_at(virt_addr, cr3)?;
        let bytes: [u8; 16] = self.read(virt_addr, cr3)?;

        // Add the verbose delimiter
        result.push_str(" \n    ");

        // Parse each operand
        for op in 0..instr.op_count() {
            let op_kind = match op {
                0 => instr.op0_kind(),
                1 => instr.op1_kind(),
                2 => instr.op2_kind(),
                3 => instr.op3_kind(),
                _ => unreachable!(),
            };

            match op_kind {
                OpKind::Register => {
                    let reg = match op {
                        0 => instr.op0_register(),
                        1 => instr.op1_register(),
                        2 => instr.op2_register(),
                        3 => instr.op3_register(),
                        _ => unreachable!(),
                    };

                    let val = self.get_iced_reg(reg);

                    if val & i128::from(u64::MAX) == val {
                        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                        let chain = self.pointer_chain_str(val as u64, self.cr3());

                        // Add the found register to the instruction string
                        result.push_str(&format!("{reg:?}:{chain}\n    "));
                    } else {
                        // Add the found register to the instruction string
                        result.push_str(&format!("{reg:?}\n    "));
                    }
                }
                OpKind::Memory => {
                    let _displ_size = instr.memory_displ_size();
                    let size = instr.memory_size();
                    let index_scale = instr.memory_index_scale();
                    let displacement = i128::from(instr.memory_displacement64());
                    let index = instr.memory_index();
                    let _segment = instr.memory_segment();

                    let base_reg = instr.memory_base();
                    let mut base_addr = 0;
                    if !matches!(base_reg, iced_x86::Register::None) {
                        base_addr = self.get_iced_reg(base_reg);
                    }

                    // Add the found register to the instruction string
                    /*
                    result.push_str(&format!("{:?} displ_size: {:#x} size: {:?} index_scale: {:#x} displacement: {:#x} base: {:?} index: {:?} segment: {:#x?} ",
                            instr.code(),
                            displ_size,
                            size,
                            index_scale,
                            displacement,
                            base,
                            index,
                            segment));
                    */

                    result.push_str(&format!("[{base_reg:?}:{base_addr:#x}"));

                    let mut index_val = None;

                    // Update the index value if an index register is found
                    if !matches!(index, iced_x86::Register::None) {
                        let index_addr = self.get_iced_reg(index);
                        index_val = Some((index, index_addr, i128::from(index_scale)));
                    }

                    // Debug print the registers involved in an index is used
                    if let Some((reg, val, scale)) = index_val {
                        result.push_str(&format!("+{reg:?}:{val:#x}"));

                        if scale > 1 {
                            result.push_str(&format!("*{scale:#x}"));
                        }
                    }

                    // Debub print the displacement if one is used
                    if displacement != 0 {
                        if displacement > 0 {
                            result.push_str(&format!("+{displacement:#x}"));
                        } else {
                            result.push_str(&format!("-{:#x}", displacement.abs()));
                        }
                    }

                    let mut calc_addr = base_addr;

                    if let Some((_reg, val, scale)) = index_val {
                        calc_addr += val * scale;
                    }

                    if displacement != 0 {
                        calc_addr += displacement;
                    }

                    // Based on the instruction code, calculate the address to
                    // dereference or the effective address for an LEA instruction
                    match instr.code() {
                        Lea_r16_m
                        | Lea_r32_m
                        | Lea_r64_m
                        | Jmp_rm64
                        | Xsave_mem
                        | Xrstor_mem
                        | Mov_rm8_r8
                        | Mov_rm16_r16
                        | Mov_rm32_r32
                        | Mov_rm64_r64
                        | Mov_rm16_Sreg
                        | Mov_rm8_imm8
                        | Mov_rm16_imm16
                        | Mov_rm32_imm32
                        | Mov_rm64_imm32
                        | VEX_Vmovups_ymmm256_ymm
                        | EVEX_Vmovups_ymmm256_k1z_ymm
                        | VEX_Vmovupd_ymmm256_ymm
                        | EVEX_Vmovupd_ymmm256_k1z_ymm
                        | VEX_Vmovaps_ymmm256_ymm
                        | EVEX_Vmovaps_ymmm256_k1z_ymm
                        | VEX_Vmovapd_ymmm256_ymm
                        | EVEX_Vmovapd_ymmm256_k1z_ymm
                        | VEX_Vpshufd_ymm_ymmm256_imm8
                        | VEX_Vpshufhw_ymm_ymmm256_imm8
                        | EVEX_Vpshufhw_ymm_k1z_ymmm256_imm8
                        | VEX_Vpshuflw_ymm_ymmm256_imm8
                        | EVEX_Vpshuflw_ymm_k1z_ymmm256_imm8
                        | EVEX_Vpsrlw_ymm_k1z_ymmm256_imm8
                        | EVEX_Vpsraw_ymm_k1z_ymmm256_imm8
                        | EVEX_Vpsllw_ymm_k1z_ymmm256_imm8
                        | EVEX_Vpsrldq_ymm_ymmm256_imm8
                        | EVEX_Vpslldq_ymm_ymmm256_imm8
                        | VEX_Vmovdqa_ymmm256_ymm
                        | EVEX_Vmovdqa32_ymmm256_k1z_ymm
                        | EVEX_Vmovdqa64_ymmm256_k1z_ymm
                        | VEX_Vmovdqu_ymmm256_ymm
                        | EVEX_Vmovdqu32_ymmm256_k1z_ymm
                        | EVEX_Vmovdqu64_ymmm256_k1z_ymm
                        | EVEX_Vmovdqu8_ymmm256_k1z_ymm
                        | EVEX_Vmovdqu16_ymmm256_k1z_ymm
                        | VEX_Vcmpps_ymm_ymm_ymmm256_imm8
                        | VEX_Vcmppd_ymm_ymm_ymmm256_imm8
                        | VEX_Vshufps_ymm_ymm_ymmm256_imm8
                        | VEX_Vshufpd_ymm_ymm_ymmm256_imm8
                        | EVEX_Vpmovuswb_ymmm256_k1z_zmm
                        | EVEX_Vcvtph2ps_zmm_k1z_ymmm256_sae
                        | EVEX_Vpmovusdw_ymmm256_k1z_zmm
                        | EVEX_Vpmovusqd_ymmm256_k1z_zmm
                        | EVEX_Vpmovswb_ymmm256_k1z_zmm
                        | EVEX_Vpmovsdw_ymmm256_k1z_zmm
                        | EVEX_Vpmovsqd_ymmm256_k1z_zmm
                        | EVEX_Vpmovwb_ymmm256_k1z_zmm
                        | EVEX_Vpmovdw_ymmm256_k1z_zmm
                        | EVEX_Vpmovqd_ymmm256_k1z_zmm
                        | EVEX_Vpcompressb_ymmm256_k1z_ymm
                        | EVEX_Vpcompressw_ymmm256_k1z_ymm
                        | EVEX_Vcompressps_ymmm256_k1z_ymm
                        | EVEX_Vcompresspd_ymmm256_k1z_ymm
                        | EVEX_Vpcompressd_ymmm256_k1z_ymm
                        | EVEX_Vpcompressq_ymmm256_k1z_ymm
                        | VEX_Vpermq_ymm_ymmm256_imm8
                        | VEX_Vpermpd_ymm_ymmm256_imm8
                        | VEX_Vpblendd_ymm_ymm_ymmm256_imm8
                        | VEX_Vpermilps_ymm_ymmm256_imm8
                        | VEX_Vpermilpd_ymm_ymmm256_imm8
                        | VEX_Vperm2f128_ymm_ymm_ymmm256_imm8
                        | VEX_Vroundps_ymm_ymmm256_imm8
                        | VEX_Vroundpd_ymm_ymmm256_imm8
                        | VEX_Vblendps_ymm_ymm_ymmm256_imm8
                        | VEX_Vblendpd_ymm_ymm_ymmm256_imm8
                        | VEX_Vpblendw_ymm_ymm_ymmm256_imm8
                        | VEX_Vpalignr_ymm_ymm_ymmm256_imm8
                        | EVEX_Vpalignr_ymm_k1z_ymm_ymmm256_imm8
                        | EVEX_Vinsertf32x8_zmm_k1z_zmm_ymmm256_imm8
                        | EVEX_Vinsertf64x4_zmm_k1z_zmm_ymmm256_imm8
                        | EVEX_Vextractf32x8_ymmm256_k1z_zmm_imm8
                        | EVEX_Vextractf64x4_ymmm256_k1z_zmm_imm8
                        | EVEX_Vcvtps2ph_ymmm256_k1z_zmm_imm8_sae
                        | EVEX_Vinserti32x8_zmm_k1z_zmm_ymmm256_imm8
                        | EVEX_Vinserti64x4_zmm_k1z_zmm_ymmm256_imm8
                        | EVEX_Vextracti32x8_ymmm256_k1z_zmm_imm8
                        | EVEX_Vextracti64x4_ymmm256_k1z_zmm_imm8
                        | EVEX_Vpcmpub_kr_k1_ymm_ymmm256_imm8
                        | EVEX_Vpcmpuw_kr_k1_ymm_ymmm256_imm8
                        | EVEX_Vpcmpb_kr_k1_ymm_ymmm256_imm8
                        | EVEX_Vpcmpw_kr_k1_ymm_ymmm256_imm8
                        | VEX_Vdpps_ymm_ymm_ymmm256_imm8
                        | VEX_Vmpsadbw_ymm_ymm_ymmm256_imm8
                        | EVEX_Vdbpsadbw_ymm_k1z_ymm_ymmm256_imm8
                        | VEX_Vpclmulqdq_ymm_ymm_ymmm256_imm8
                        | EVEX_Vpclmulqdq_ymm_ymm_ymmm256_imm8
                        | VEX_Vperm2i128_ymm_ymm_ymmm256_imm8
                        | VEX_Vpermil2ps_ymm_ymm_ymmm256_ymm_imm4
                        | VEX_Vpermil2ps_ymm_ymm_ymm_ymmm256_imm4
                        | VEX_Vpermil2pd_ymm_ymm_ymmm256_ymm_imm4
                        | VEX_Vpermil2pd_ymm_ymm_ymm_ymmm256_imm4
                        | VEX_Vblendvps_ymm_ymm_ymmm256_ymm
                        | VEX_Vblendvpd_ymm_ymm_ymmm256_ymm
                        | VEX_Vpblendvb_ymm_ymm_ymmm256_ymm
                        | VEX_Vfmaddsubps_ymm_ymm_ymmm256_ymm
                        | VEX_Vfmaddsubpd_ymm_ymm_ymmm256_ymm
                        | VEX_Vfmsubaddps_ymm_ymm_ymmm256_ymm
                        | VEX_Vfmsubaddpd_ymm_ymm_ymmm256_ymm
                        | VEX_Vfmaddps_ymm_ymm_ymmm256_ymm
                        | VEX_Vfmaddpd_ymm_ymm_ymmm256_ymm
                        | VEX_Vfmsubps_ymm_ymm_ymmm256_ymm
                        | VEX_Vfmsubpd_ymm_ymm_ymmm256_ymm
                        | EVEX_Vpshldw_ymm_k1z_ymm_ymmm256_imm8
                        | EVEX_Vpshrdw_ymm_k1z_ymm_ymmm256_imm8
                        | VEX_Vfnmaddps_ymm_ymm_ymmm256_ymm
                        | VEX_Vfnmaddpd_ymm_ymm_ymmm256_ymm
                        | VEX_Vfnmsubps_ymm_ymm_ymmm256_ymm
                        | VEX_Vfnmsubpd_ymm_ymm_ymmm256_ymm
                        | VEX_Vgf2p8affineqb_ymm_ymm_ymmm256_imm8
                        | VEX_Vgf2p8affineinvqb_ymm_ymm_ymmm256_imm8
                        | Xchg_rm8_r8
                        | Xchg_rm16_r16
                        | Xchg_rm32_r32
                        | Xchg_rm64_r64
                        | Bt_rm16_r16
                        | Bt_rm32_r32
                        | Bt_rm64_r64
                        | Bts_rm16_r16
                        | Bts_rm32_r32
                        | Bts_rm64_r64
                        | Btr_rm16_r16
                        | Btr_rm32_r32
                        | Btr_rm64_r64
                        | Bt_rm16_imm8
                        | Bt_rm32_imm8
                        | Bt_rm64_imm8
                        | Bts_rm16_imm8
                        | Bts_rm32_imm8
                        | Bts_rm64_imm8
                        | Btr_rm16_imm8
                        | Btr_rm32_imm8
                        | Btr_rm64_imm8
                        | Btc_rm16_imm8
                        | Btc_rm32_imm8
                        | Btc_rm64_imm8
                        | Btc_rm16_r16
                        | Btc_rm32_r32
                        | Btc_rm64_r64
                        | Movups_xmmm128_xmm
                        | Movupd_xmmm128_xmm
                        | Movaps_xmmm128_xmm
                        | Movapd_xmmm128_xmm
                        | Movdqa_xmmm128_xmm
                        | Movdqu_xmmm128_xmm
                        | Movq_xmmm64_xmm
                        | Pcmpeqb_xmm_xmmm128
                        | VEX_Vmovdqu_xmmm128_xmm
                        | VEX_Vmovdqu_ymm_ymmm256
                        | VEX_Vpcmpeqb_ymm_ymm_ymmm256
                        | Cvtsi2sd_xmm_rm32
                        | Movsd_xmmm64_xmm
                        | Movsd_xmm_xmmm64
                        | Movss_xmmm32_xmm
                        | VEX_Vmovdqu_xmm_xmmm128
                        | VEX_Vmovq_xmm_xmmm64
                        | VEX_Vpcmpeqb_xmm_xmm_xmmm128 => {
                            // We don't care about the destination address. So no need to
                            // dereference it here
                            if calc_addr != base_addr {
                                result.push_str(&format!("={calc_addr:#x}]"));
                            }
                        }

                        Movsxd_r16_rm16 | Movsxd_r32_rm32 | Movsxd_r64_rm32 | Mov_r8_rm8
                        | Mov_r16_rm16 | Mov_r32_rm32 | Mov_r64_rm64 | Mov_Sreg_rm16
                        | Movd_mm_rm32 | Movq_mm_rm64 | Movd_xmm_rm32 | Movq_xmm_rm64
                        | Movzx_r16_rm8 | Movzx_r32_rm8 | Movzx_r64_rm8 | Movzx_r16_rm16
                        | Movzx_r32_rm16 | Movzx_r64_rm16 | Movsx_r16_rm8 | Movsx_r32_rm8
                        | Movsx_r64_rm8 | Movsx_r16_rm16 | Movsx_r32_rm16 | Movsx_r64_rm16
                        | Push_rm16 | Push_rm32 | Push_rm64 | And_rm8_r8 | And_rm16_r16
                        | And_rm32_r32 | And_rm64_r64 | And_r8_rm8 | And_r16_rm16
                        | And_r32_rm32 | And_r64_rm64 | And_rm8_imm8 | And_rm16_imm16
                        | And_rm32_imm32 | And_rm64_imm32 | And_rm8_imm8_82 | And_rm16_imm8
                        | And_rm32_imm8 | And_rm64_imm8 | Add_rm8_r8 | Add_rm16_r16
                        | Add_rm32_r32 | Add_rm64_r64 | Add_r8_rm8 | Add_r16_rm16
                        | Add_r32_rm32 | Add_r64_rm64 | Add_rm8_imm8 | Add_rm16_imm16
                        | Add_rm32_imm32 | Add_rm64_imm32 | Add_rm8_imm8_82 | Add_rm16_imm8
                        | Add_rm32_imm8 | Add_rm64_imm8 | Sub_rm8_r8 | Sub_rm16_r16
                        | Sub_rm32_r32 | Sub_rm64_r64 | Sub_r8_rm8 | Sub_r16_rm16
                        | Sub_r32_rm32 | Sub_r64_rm64 | Sub_rm8_imm8 | Sub_rm16_imm16
                        | Sub_rm32_imm32 | Sub_rm64_imm32 | Sub_rm8_imm8_82 | Sub_rm16_imm8
                        | Sub_rm32_imm8 | Sub_rm64_imm8 | Or_rm8_r8 | Or_rm16_r16 | Or_rm32_r32
                        | Or_rm64_r64 | Or_r8_rm8 | Or_r16_rm16 | Or_r32_rm32 | Or_r64_rm64
                        | Or_rm8_imm8 | Or_rm16_imm16 | Or_rm32_imm32 | Or_rm64_imm32
                        | Or_rm8_imm8_82 | Or_rm16_imm8 | Or_rm32_imm8 | Or_rm64_imm8
                        | Xor_rm8_r8 | Xor_rm16_r16 | Xor_rm32_r32 | Xor_rm64_r64 | Xor_r8_rm8
                        | Xor_r16_rm16 | Xor_r32_rm32 | Xor_r64_rm64 | Xor_rm8_imm8
                        | Xor_rm16_imm16 | Xor_rm32_imm32 | Xor_rm64_imm32 | Xor_rm8_imm8_82
                        | Xor_rm16_imm8 | Xor_rm32_imm8 | Xor_rm64_imm8 | Cmp_rm8_r8
                        | Cmp_rm16_r16 | Cmp_rm32_r32 | Cmp_rm64_r64 | Cmp_rm8_imm8
                        | Cmp_rm16_imm16 | Cmp_rm32_imm32 | Cmp_rm64_imm32 | Cmp_rm8_imm8_82
                        | Cmp_rm16_imm8 | Cmp_rm32_imm8 | Cmp_rm64_imm8 | Test_rm8_imm8
                        | Test_rm16_imm16 | Test_rm32_imm32 | Test_rm8_r8 | Test_rm16_r16
                        | Test_rm32_r32 | Test_rm64_r64 | Cmp_r8_rm8 | Cmp_r16_rm16
                        | Cmp_r32_rm32 | Cmp_r64_rm64 | Movups_xmm_xmmm128 | Movupd_xmm_xmmm128
                        | Movaps_xmm_xmmm128 | Movapd_xmm_xmmm128 | Movdqa_xmm_xmmm128
                        | Movdqu_xmm_xmmm128 | Movlpd_xmm_m64 | Movhpd_xmm_m64 | Movhps_xmm_m64
                        | Movbe_r32_m32 | Movq_xmm_xmmm64 | Call_rm64 | Imul_r16_rm16_imm16
                        | Imul_r32_rm32_imm32 | Imul_r64_rm64_imm32 | Imul_r16_rm16_imm8
                        | Imul_r32_rm32_imm8 | Imul_r64_rm64_imm8 | Imul_r16_rm16
                        | Imul_r32_rm32 | Imul_r64_rm64 | Cmpxchg_rm8_r8 | Cmpxchg_rm16_r16
                        | Cmpxchg_rm32_r32 | Cmpxchg_rm64_r64 | Inc_rm8 | Inc_rm16 | Inc_rm32
                        | Inc_rm64 | Dec_rm8 | Dec_rm16 | Dec_rm32 | Dec_rm64 | Xadd_rm8_r8
                        | Xadd_rm16_r16 | Xadd_rm32_r32 | Xadd_rm64_r64 | Cmpxchg8b_m64
                        | Cmpxchg16b_m128 | Cmovo_r16_rm16 | Cmovo_r32_rm32 | Cmovo_r64_rm64
                        | Cmovno_r16_rm16 | Cmovno_r32_rm32 | Cmovno_r64_rm64 | Cmovb_r16_rm16
                        | Cmovb_r32_rm32 | Cmovb_r64_rm64 | Cmovae_r16_rm16 | Cmovae_r32_rm32
                        | Cmovae_r64_rm64 | Cmove_r16_rm16 | Cmove_r32_rm32 | Cmove_r64_rm64
                        | Cmovne_r16_rm16 | Cmovne_r32_rm32 | Cmovne_r64_rm64 | Cmovbe_r16_rm16
                        | Cmovbe_r32_rm32 | Cmovbe_r64_rm64 | Cmova_r16_rm16 | Cmova_r32_rm32
                        | Cmova_r64_rm64 | Cmovs_r16_rm16 | Cmovs_r32_rm32 | Cmovs_r64_rm64
                        | Cmovns_r16_rm16 | Cmovns_r32_rm32 | Cmovns_r64_rm64 | Cmovp_r16_rm16
                        | Cmovp_r32_rm32 | Cmovp_r64_rm64 | Cmovnp_r16_rm16 | Cmovnp_r32_rm32
                        | Cmovnp_r64_rm64 | Cmovl_r16_rm16 | Cmovl_r32_rm32 | Cmovl_r64_rm64
                        | Cmovge_r16_rm16 | Cmovge_r32_rm32 | Cmovge_r64_rm64 | Cmovle_r16_rm16
                        | Cmovle_r32_rm32 | Cmovle_r64_rm64 | Cmovg_r16_rm16 | Cmovg_r32_rm32
                        | Cmovg_r64_rm64 | Test_rm64_imm32 | Div_rm64 => {
                            // Calculated address is a source address, so we need to
                            // dereference it here
                            #[allow(clippy::cast_possible_truncation)]
                            #[allow(clippy::cast_sign_loss)]
                            let calc_addr = calc_addr as u64;

                            // Dump the memory address
                            #[allow(clippy::cast_possible_truncation)]
                            #[allow(clippy::cast_sign_loss)]
                            if calc_addr != base_addr as u64 {
                                result.push_str(&format!("={calc_addr:#x}"));
                            }

                            result.push_str(&format!(" size:{size:?}"));

                            // Dereference the address based on the read size
                            #[allow(clippy::cast_possible_truncation)]
                            #[allow(clippy::cast_sign_loss)]
                            let val = match size {
                                MemorySize::Int8 => self
                                    .read::<i8>(VirtAddr(calc_addr), self.cr3())
                                    .map(|x| x as u128),
                                MemorySize::Int16 => self
                                    .read::<i16>(VirtAddr(calc_addr), self.cr3())
                                    .map(|x| x as u128),
                                MemorySize::Int32 => self
                                    .read::<i32>(VirtAddr(calc_addr), self.cr3())
                                    .map(|x| x as u128),
                                MemorySize::Int64 => self
                                    .read::<i64>(VirtAddr(calc_addr), self.cr3())
                                    .map(|x| x as u128),
                                MemorySize::UInt8 => self
                                    .read::<u8>(VirtAddr(calc_addr), self.cr3())
                                    .map(u128::from),
                                MemorySize::UInt16 => self
                                    .read::<u16>(VirtAddr(calc_addr), self.cr3())
                                    .map(u128::from),
                                MemorySize::UInt32 => self
                                    .read::<u32>(VirtAddr(calc_addr), self.cr3())
                                    .map(u128::from),
                                MemorySize::UInt64
                                | MemorySize::QwordOffset
                                | MemorySize::Packed64_Float32 => self
                                    .read::<u64>(VirtAddr(calc_addr), self.cr3())
                                    .map(u128::from),
                                MemorySize::UInt128
                                | MemorySize::Packed128_UInt32
                                | MemorySize::Packed128_Float32 => {
                                    self.read::<u128>(VirtAddr(calc_addr), self.cr3())
                                }
                                MemorySize::Float32 => self
                                    .read::<f32>(VirtAddr(calc_addr), self.cr3())
                                    .map(|x| x as u128),
                                MemorySize::Float64 => self
                                    .read::<f64>(VirtAddr(calc_addr), self.cr3())
                                    .map(|x| x as u128),
                                MemorySize::Packed128_Float64 => Ok(0xdead_beef_cafe_babe),
                                x => {
                                    panic!("Unknown read size: {x:?}");
                                }
                            };

                            // Add the dereferenced value or an indicator that the value
                            // couldn't be read
                            if let Ok(val) = val {
                                // Print the dereferenced value
                                result.push_str(&format!("->{val:#x}"));

                                // Special case the mov from u8 to print the character as
                                // well
                                if (0x21..=0x7f).contains(&val)
                                    && matches!(instr.code(), Movzx_r32_rm8)
                                {
                                    result.push_str(&format!("::{}", try_u8!(val) as char));
                                }
                            } else {
                                result.push_str("->????");
                            }

                            if matches!(instr.code(), Call_rm64) {
                                let curr_symbol = self
                                    .get_symbol(calc_addr)
                                    .unwrap_or_else(|| "UnknownSym".to_string());

                                result.push_str(&format!("->{curr_symbol}"));
                            }

                            if matches!(instr.code(), Cmpxchg8b_m64) {
                                result.push_str(&format!(
                                    " EDX:{:#x}::EAX:{:#x} ECX:{:#x}::EBX:{:#x}",
                                    self.edx(),
                                    self.eax(),
                                    self.ecx(),
                                    self.ebx()
                                ));
                            }

                            if matches!(instr.code(), Cmpxchg16b_m128) {
                                result.push_str(&format!(
                                    " RDX:{:#x}::RAX:{:#x} RCX:{:#x}::RBX:{:#x}",
                                    self.rdx(),
                                    self.rax(),
                                    self.rcx(),
                                    self.rbx()
                                ));
                            }

                            // Finish the dereference
                            result.push(']');
                        }
                        Nop_rm16 | Nop_rm32 | Nop_rm64 | Prefetcht0_m8 | Verr_rm16
                        | Verr_r32m16 | Verr_r64m16 | Verw_rm16 | Verw_r32m16 | Verw_r64m16 => {
                            // Nothing to do here
                        }
                        x => {
                            result.push_str(&format!(" TODO:{x:?} "));
                        }
                    }

                    // Close the displayed memory
                    result.push_str("] \n    ");
                }
                _ => {
                    // Add the not yet implemented kind for future implementation
                    result.push_str(&format!("??_{op_kind:?}_?? "));
                }
            }
        }

        // Append the bytes for this instruction to the end
        result.push_str(&format!("{:02x?}", &bytes[..instr.len()]));

        Ok(result)
    }

    /// Print the context of the current state of the guest.
    ///
    /// This is a debugging tool used for getting an idea of the state of the guest
    /// during a breakpoint or at a reset location.
    ///
    /// # Example
    ///
    /// ```rust
    /// let fuzzvm = FuzzVm::create(..);
    /// fuzzvm.print_context()?;
    /// ```
    ///
    /// ```text
    /// ------------------------------------------------------ REGISTERS -------------------------------------------------------
    /// RAX:  0x0
    /// RBX:  0x0
    /// RCX:  example1!_IO_stdin_used+0x4 -> 'asdf aaaaaaaaaaa'
    /// RDX:  0x6
    /// RSI:  example1!_IO_stdin_used+0x31 -> 'APSHOT'
    /// RDI:  example1!_IO_stdin_used+0x4 -> 'asdf aaaaaaaaaaa'
    /// R8 :  0x0
    /// R9 :  0x3f
    /// R10:  libc.so.6!__abi_tag+0x739c -> ' D'
    /// R11:  0x102
    /// R12:  0x7fffffffed28 -> 0x7fffffffef00 -> '/root/example1'
    /// R13:  example1!main+0x0 -> 0x20ec8348e5894855
    /// R14:  0x0
    /// R15:  ld-linux-x86-64.so.2!_rtld_global+0x0 -> ld-linux-x86-64.so.2!_end+0x8 -> 0x0
    /// RSP:  0x7fffffffec10 -> ''
    /// RBP:  0x7fffffffec10 -> ''
    /// CR3:  0x00000000084be000 CR2: 0x00007f8814613610
    /// CR0:  PROTECTED_MODE_ENABLE | MONITOR_COPROCESSOR | EXTENSION_TYPE | NUMERIC_ERROR | WRITE_PROTECT | ALIGNMENT_MASK | PAGING
    /// CR4:  PAGE_SIZE_EXTENSION | PHYSICAL_ADDRESS_EXTENSION | MACHINE_CHECK_EXCEPTION | PAGE_GLOBAL | OSFXSR | OSXMMEXCPT_ENABLE
    /// EFER: SYSTEM_CALL_EXTENSIONS | LONG_MODE_ENABLE | LONG_MODE_ACTIVE | NO_EXECUTE_ENABLE
    /// CS:   33  SS: 2b GS: 00 GS base: 0x0
    /// GDT:  0xfffffe0000001000
    /// RIP:  0x0000000000401371 RFLAGS: (empty)
    /// ----------------------------------------------------- INSTRUCTION ------------------------------------------------------
    /// INSTR: example1!main+0x71 | pop rbp
    ///     RBP:0x7fffffffec10 -> ''
    ///     [5d]
    /// -------------------------------------------------------- STACK ---------------------------------------------------------
    /// +0x00|0x7fffffffec10: (0x0000000000000001) 0x1
    /// +0x08|0x7fffffffec18: (0x00007ffff7de720a) libc.so.6!__libc_start_call_main+0x7a -> 0xe800016f4fe8c789
    /// +0x10|0x7fffffffec20: (0x0000000000000000) 0x0
    /// +0x18|0x7fffffffec28: (0x0000000000401300) example1!main+0x0 -> 0x20ec8348e5894855
    /// +0x20|0x7fffffffec30: (0x0000000100000000) 0x100000000
    /// +0x28|0x7fffffffec38: (0x00007fffffffed28) 0x7fffffffed28 -> 0x7fffffffef00 -> '/root/example1'
    /// +0x30|0x7fffffffec40: (0x0000000000000000) 0x0
    /// +0x38|0x7fffffffec48: (0x1377c63a29a5d427) 0x1377c63a29a5d427
    /// +0x40|0x7fffffffec50: (0x00007fffffffed28) 0x7fffffffed28 -> 0x7fffffffef00 -> '/root/example1'
    /// +0x48|0x7fffffffec58: (0x0000000000401300) example1!main+0x0 -> 0x20ec8348e5894855
    /// ```

    ///
    /// # Errors
    ///
    /// * If getting the current instruction string fails
    /// * If getting any of the modified MSRs fails
    pub fn print_context(&mut self) -> Result<()> {
        /// The type used to print the current stack values
        type StackType = u64;

        /// The current stack size based on the stack type
        const STACK_TYPE_SIZE: usize = std::mem::size_of::<StackType>();

        let rip_string = self.get_current_verbose_instruction_string()?;

        println!("{:-^120}", " REGISTERS ".blue());
        println!(
            "RAX:  {}",
            self.pointer_chain_str(self.regs.rax, self.cr3())
        );
        println!(
            "RBX:  {}",
            self.pointer_chain_str(self.regs.rbx, self.cr3())
        );
        println!(
            "RCX:  {}",
            self.pointer_chain_str(self.regs.rcx, self.cr3())
        );
        println!(
            "RDX:  {}",
            self.pointer_chain_str(self.regs.rdx, self.cr3())
        );
        println!(
            "RSI:  {}",
            self.pointer_chain_str(self.regs.rsi, self.cr3())
        );
        println!(
            "RDI:  {}",
            self.pointer_chain_str(self.regs.rdi, self.cr3())
        );
        println!("R8 :  {}", self.pointer_chain_str(self.regs.r8, self.cr3()));
        println!("R9 :  {}", self.pointer_chain_str(self.regs.r9, self.cr3()));
        println!(
            "R10:  {}",
            self.pointer_chain_str(self.regs.r10, self.cr3())
        );
        println!(
            "R11:  {}",
            self.pointer_chain_str(self.regs.r11, self.cr3())
        );
        println!(
            "R12:  {}",
            self.pointer_chain_str(self.regs.r12, self.cr3())
        );
        println!(
            "R13:  {}",
            self.pointer_chain_str(self.regs.r13, self.cr3())
        );
        println!(
            "R14:  {}",
            self.pointer_chain_str(self.regs.r14, self.cr3())
        );
        println!(
            "R15:  {}",
            self.pointer_chain_str(self.regs.r15, self.cr3())
        );
        println!(
            "RSP:  {}",
            self.pointer_chain_str(self.regs.rsp, self.cr3())
        );
        println!(
            "RBP:  {}",
            self.pointer_chain_str(self.regs.rbp, self.cr3())
        );

        println!(
            "CR3:  {:#018x} CR2: {:#018x}",
            self.sregs.cr3, self.sregs.cr2
        );
        println!("CR0:  {:?}", Cr0Flags::from_bits_truncate(self.sregs.cr0));
        println!("CR4:  {:80?}", Cr4Flags::from_bits_truncate(self.sregs.cr4));
        println!("EFER: {:?}", EferFlags::from_bits_truncate(self.sregs.efer));
        println!(
            "CS:   {:02x}  SS: {:02x} GS: {:02x} GS base: {:#x}",
            self.sregs.cs.selector,
            self.sregs.ss.selector,
            self.sregs.gs.selector,
            self.sregs.gs.base
        );
        println!("GDT:  {:#018x}", self.sregs.gdt.base);
        println!(
            "RIP:  {:#018x} RFLAGS: {:?}",
            self.regs.rip,
            RFlags::from_bits_truncate(self.regs.rflags)
        );

        /*
        if let Ok(fpu) = self.fpu() {
            println!("XMM0: {:x?} | {:?}", self.xmm0(), self.xmm0_f64());
            println!("XMM1: {:x?} | {:?}", self.xmm1(), self.xmm1_f64());
            println!("XMM2: {:x?} | {:?}", self.xmm2(), self.xmm2_f64());
            println!("XMM3: {:x?} | {:?}", self.xmm3(), self.xmm3_f64());
        }
        */

        print!("{:-^120}\n", " INSTRUCTION ".blue());
        let mut rip_symbol = String::new();
        let curr_symbol = self.get_symbol(self.rip());
        rip_symbol.push_str(&curr_symbol.unwrap_or_else(|| "UnknownSym".to_string()));
        rip_symbol.push_str(" | ");

        print!("INSTR: {}", rip_symbol.white());
        for elem in rip_string.split(" || ") {
            println!("{}", elem.white());
        }

        // Attempt read variable length stacks. Repeat trying to read decreasing amounts
        // of stack values until we can read them all
        print!("{:-^120}\n", " STACK ".blue());
        let mut found = false;
        for size in (0..0x14).rev() {
            let mut bytes = vec![0_u64; size];
            if self
                .read_bytes(VirtAddr(self.regs().rsp), self.cr3(), &mut bytes)
                .is_ok()
            {
                for (offset, val) in bytes.iter().enumerate() {
                    print!(
                        "+{:#04x}|{:#x}: ({:#018x}) {}\n",
                        offset * STACK_TYPE_SIZE,
                        self.regs().rsp + (offset * STACK_TYPE_SIZE) as u64,
                        *val,
                        self.pointer_chain_str(*val, self.cr3())
                    );
                }

                found = true;
                break;
            }
        }

        // Was not able to read the stack
        if !found {
            println!("Failed to read stack...");
        }

        println!();

        if !self.console_output.is_empty() {
            println!("{:-^120}", " CONSOLE OUTPUT ".blue());
            unsafe {
                println!("{}", std::str::from_utf8_unchecked(&self.console_output));
            }
        }

        println!("{:-^120}", " BACKTRACE ".blue());
        for line in self.symbolized_backtrace() {
            println!("{line}");
        }

        Ok(())
    }

    /// Get the symbol of the given `addr` from the current symbol database
    ///
    /// # Example
    ///
    /// ```rust
    /// let fuzzvm = FuzzVm::create(...);
    ///
    /// // Get the symbol at the instruction pointer
    /// if let Some(symbol) = fuzzvm.get_symbol(fuzzvm.rip()) {
    ///     log::info!("Symbol at rip: {symbol}");
    /// }
    /// ```
    /// ```
    /// Symbol at rip: example1!main+0x62
    /// ```
    #[must_use]
    pub fn get_symbol(&self, addr: u64) -> Option<String> {
        self.symbols
            .as_ref()
            .and_then(|sym_data| crate::symbols::get_symbol(addr, sym_data))
    }

    /// Set a breakpoint at the given [`VirtAddr`] using [`Cr3`] as the page table,
    /// returning the breakpoint index for the set breakpoint
    ///
    /// # Errors
    ///
    /// * Attempting to set the same breakpoint twice, without removing it first
    pub fn set_breakpoint(
        &mut self,
        virt_addr: VirtAddr,
        cr3: Cr3,
        bp_type: BreakpointType,
        bp_mem: BreakpointMemory,
        bp_hook: BreakpointHook<FUZZER>,
    ) -> Result<()> {
        // Clear the lower 12 bits from cr3
        let cr3 = Cr3(cr3.0 & !0xfff);

        // Sanity check that the requested breakpoint hasn't been set already
        if let Some(prev_index) = self.breakpoints.get(&(virt_addr, cr3)) {
            // If this breakpoint already exist, only need to update the type
            self.breakpoint_types[*prev_index] = bp_type;

            // Write the breakpoint
            self.write_breakpoint(virt_addr, cr3, bp_mem)?;

            // Nothing else to modify
            return Ok(());
        }

        // Get the index for the inserted breakpoint
        let next_bp_index = self.breakpoints.len();

        // Get the original byte where we are replacing with a breakpoint
        let mut orig_byte = self
            .read::<u8>(virt_addr, cr3)
            .context(Error::InvalidCoverageBreakpoint)?;

        // If the current byte is a breakpoint, check if this was a coverage breakpoint
        // use the original, original byte and not the current breakpoint byte
        if orig_byte == 0xcc {
            if let Some(cov_bps) = self.coverage_breakpoints.take() {
                // If there was an original non-breakpoint byte, use the original byte
                // and not the current breakpoint byte
                if let Some(first_byte) = cov_bps.get(&virt_addr) {
                    orig_byte = *first_byte;
                }

                // Restore the coverage breakpoints
                self.coverage_breakpoints = Some(cov_bps);
            }
        }

        // Insert the new breakpoint
        //
        // This must happen AFTER the self.read above since the read could fail with an
        // unmapped address
        self.breakpoints.insert((virt_addr, cr3), next_bp_index);

        // Write the breakpoint
        self.write_breakpoint(virt_addr, cr3, bp_mem)?;

        // Add the breakpoint metadata for this breakpoint
        self.breakpoint_types.push(bp_type);
        self.breakpoint_original_bytes.push(Some(orig_byte));
        self.breakpoint_hooks.push(bp_hook);

        // Successful setting of breakpoint
        Ok(())
    }

    /// Check for the given `subsymbol` in the current symbol list using the current
    /// `Cr3`. This is mostly used as a helper function for
    /// `FuzzVm::apply_fuzzer_breakpoints`.
    ///
    /// # Example
    ///
    /// ```rust
    /// let fuzzvm = FuzzVm::create(...);
    /// if let Some((addr, cr3)) = fuzzvm.get_symbol_address("main") {
    ///     log::info!("Address of 'main': Addr {addr:x?} Cr3 {cr3:x?}");
    /// }
    /// ```
    /// ```text
    /// Address of 'main': Addr VirtAddr(401300) Cr3 Cr3(84be000)
    /// ```
    #[must_use]
    pub fn get_symbol_address(&self, subsymbol: &str) -> Option<(VirtAddr, Cr3)> {
        let mut found = None;

        // Add the fuzzer specific symbols
        if let Some(symbols) = self.symbols {
            for Symbol { address, symbol } in symbols {
                // if symbol.contains(subsymbol) {
                if symbol == subsymbol {
                    let addr = VirtAddr(*address);

                    // Calculate the kernel CR3 based on the instrutions from the single step of
                    // the kernel
                    //
                    // 0x00007ffff7eac249 0x00000000ba693000 | libc-2.31.so!__getpid+0x9 | syscall
                    // 0xffffffffa6200010 0x00000000ba693000 | entry_SYSCALL_64+0x0      | swapgs
                    // 0xffffffffa6200013 0x00000000ba693000 | entry_SYSCALL_64+0x3      | mov qword ptr gs:[0x6014], rsp
                    // 0xffffffffa620001c 0x00000000ba693000 | entry_SYSCALL_64+0xc      | nop
                    // 0xffffffffa620001e 0x00000000ba693000 | entry_SYSCALL_64+0xe      | mov rsp, cr3
                    // 0xffffffffa6200021 0x00000000ba693000 | entry_SYSCALL_64+0x11     | bts rsp, 0x3f
                    // 0xffffffffa6200026 0x00000000ba693000 | entry_SYSCALL_64+0x16     | and rsp, 0xffffffffffffe7ff
                    // 0xffffffffa620002d 0x00000000ba693000 | entry_SYSCALL_64+0x1d     | mov cr3, rsp
                    let kern_cr3 = Cr3(self.cr3().0 & 0xffff_ffff_ffff_e7ff);

                    // Try to translate the symbol address with user and kernel page
                    // tables
                    for cr3 in [self.cr3(), kern_cr3] {
                        if self.translate(addr, cr3).phys_addr().is_some() {
                            if found.is_none() {
                                found = Some((addr, cr3));
                            }
                            break;
                        }

                        log::debug!("FOUND {symbol} {addr:x?} but no translate");
                    }
                }
            }
        }

        found
    }

    /// Get the symbols that contain the given `subsymbol`
    #[must_use]
    pub fn get_symbols_containing(&self, subsymbol: &str) -> Vec<String> {
        let mut possibles = Vec::new();

        // Add the fuzzer specific symbols
        if let Some(symbols) = self.symbols {
            for Symbol { symbol, .. } in symbols {
                if symbol.contains(subsymbol) {
                    possibles.push(symbol.clone());
                }
            }
        }

        possibles
    }

    /// Handle a breakpoint instruction
    ///
    /// Two conditions that are handled:
    ///
    /// * Normal breakpoint
    ///     - Checks if the current address is a breakpoint known by [`FuzzVm`] or by the
    ///     fuzzer to know which hook to execute. Error if the breakpoint is not known.
    ///     - If [`BreakpointType::Repeated`], reset the byte for this instruction after
    ///     the instruction is executed
    ///
    /// * Syscall breakpoint
    ///    - When a fuzzer wants to exit on syscalls, check if the fuzzer wants to handle
    ///    the syscall through either the `syscall_whitelist` or `syscall_blacklist`. If
    ///    so, call the [`Fuzzer::handle_syscall`] for the fuzzer. Otherwise, reset the
    ///    breakpoint (and restore it after one instruction) and allow the guest to
    ///    continue.
    ///
    /// # Errors
    ///
    /// * The breakpoint index found for the current address is out of bounds of the
    ///   breakpoint metadata
    pub fn handle_breakpoint(
        &mut self,
        fuzzer: &mut FUZZER,
        input: &FUZZER::Input,
    ) -> Result<Execution> {
        // Get the current address
        let (virt_addr, cr3) = self.current_address();

        // Remove the lower 12 bits from cr3
        let cr3 = Cr3(cr3.0 & !0xfff);

        // Init the option to write the original byte back when discovered
        let write_back;

        // Default to continuing execution after this breakpoint is handled
        let execution;

        if *virt_addr == self.vbcpu.msr_lstar && self.exit_on_syscall {
            // Get the syscall from the rax
            let syscall = self.rax();

            // Get the fuzzer syscall whitelist/blacklist
            let whitelist = fuzzer.syscall_whitelist();
            let blacklist = fuzzer.syscall_blacklist();

            // Default to not having the fuzzer handle this syscall
            let mut fuzzer_handling = false;

            // Check if the whitelist or blacklist is triggering the fuzzer to handle the
            // syscall
            if !whitelist.is_empty() {
                if whitelist.contains(&syscall) {
                    fuzzer_handling = true;
                } else {
                    let _linux_syscall: crate::linux::Syscall = syscall.try_into().unwrap();
                    // log::info!("Syscall not handled by fuzzer whitelist: {linux_syscall:?}");
                    // panic!();
                }
            } else if !blacklist.is_empty() {
                if blacklist.contains(&syscall) {
                    let _linux_syscall: crate::linux::Syscall = syscall.try_into().unwrap();
                    // log::info!("Syscall ignored due to fuzzer blacklist: {linux_syscall:?}");
                    // panic!();
                } else {
                    fuzzer_handling = true;
                }
            }

            // Let the fuzzer handle the syscall if requested
            if fuzzer_handling {
                // We have hit a syscall. Restore the RIP from RCX and call the fuzzer's
                // handle_syscall
                self.set_rip(self.rcx());
                self.set_rflags(self.r11() & RFlags::TRAP_FLAG.bits());

                /// Macro for copying VBCPU segment to KVM
                macro_rules! set_segment {
                    (sregs $sregs_seg:ident, vbcpu $vbcpu_seg:ident) => {{
                        let access_rights = self.vbcpu.$vbcpu_seg.get_access_rights();
                        self.sregs.$sregs_seg.base =
                            self.vbcpu.$vbcpu_seg.base.try_into().expect(&format!(
                                "Invalid {} base: {:#x}",
                                stringify!($vbcpu_seg),
                                self.vbcpu.$vbcpu_seg.base
                            ));
                        self.sregs.$sregs_seg.limit =
                            self.vbcpu.$vbcpu_seg.limit.try_into().expect(&format!(
                                "Invalid {} limit: {:#x}",
                                stringify!($vbcpu_seg),
                                self.vbcpu.$vbcpu_seg.base
                            ));
                        self.sregs.$sregs_seg.selector = self.vbcpu.$vbcpu_seg.selector;
                        self.sregs.$sregs_seg.type_ = access_rights.segment_type;
                        self.sregs.$sregs_seg.present = access_rights.present;
                        self.sregs.$sregs_seg.dpl = access_rights.privilege_level;
                        self.sregs.$sregs_seg.db = access_rights.operation_size;
                        self.sregs.$sregs_seg.s = access_rights.descriptor_type;
                        self.sregs.$sregs_seg.l = access_rights.long_mode_for_cs;
                        self.sregs.$sregs_seg.g = access_rights.granularity;
                        self.sregs.$sregs_seg.avl = access_rights.avl;
                        self.sregs.$sregs_seg.unusable = access_rights.unusable;
                    }};
                }

                // Copy all segments from VBCPU into the guest SREGS
                set_segment!(sregs cs,  vbcpu cs);
                set_segment!(sregs ss,  vbcpu ss);

                // Hand off execution of this syscall to the fuzzer
                return fuzzer.handle_syscall(self, syscall, input);
            }

            // Fuzzer is not handling the syscall, execute the syscall as normal
            let bp_index = self
                .breakpoints
                .get(&(virt_addr, Cr3(self.vbcpu.cr3)))
                .expect("Failed to find LSTAR breakpoint");

            let orig_byte = self
                .breakpoint_original_bytes
                .get(*bp_index)
                .ok_or(Error::InvalidBreakpointIndex)?
                .ok_or(Error::ExternalBreakpoint)?;

            // Set up the restore breakpoint to continue after the next single step
            self.restore_breakpoint = Some((virt_addr, cr3));

            // Restore the original byte for the LSTAR breakpoint
            self.write_bytes(virt_addr, cr3, &[orig_byte])?;

            // Continue execution
            return Ok(Execution::Continue);
        }

        // The fuzzer is not handling a syscall breakpoint, check if any other
        // breakpoints are being handled
        //
        // Try the breakpoint address with the current cr3. If that fails, then try the wildcard cr3
        if let Some(bp_index) = self
            .breakpoints
            .get(&(virt_addr, cr3))
            .or(self.breakpoints.get(&(virt_addr, WILDCARD_CR3)))
        {
            let bp_index = *bp_index;

            // We have this breakpoint in our database attempt to handle it
            let bp_type = self
                .breakpoint_types
                .get(bp_index)
                .ok_or(Error::InvalidBreakpointIndex)?;

            let orig_byte = self
                .breakpoint_original_bytes
                .get(bp_index)
                .ok_or(Error::InvalidBreakpointIndex)?
                .ok_or(Error::ExternalBreakpoint)?;

            // Explanation of write back based on breakpoint type:
            //
            // Hooks      - Callback function assumes the hook breakpoints is always there
            // Repeated   - This is reset after the next instruction is executed
            // SingleShot - This should always be replaced
            write_back = match bp_type {
                BreakpointType::Hook => None,
                BreakpointType::SingleShot | BreakpointType::Repeated => {
                    Some((virt_addr, cr3, orig_byte))
                }
            };

            // If the breakpoint is to be repeated, notate the `restore_breakpoint`
            // flag to signal that the next instruction should single stepped and
            // then a breakpoint rewritten after the instruction executes
            if matches!(bp_type, BreakpointType::Repeated) {
                self.restore_breakpoint = Some((virt_addr, cr3));
            }

            // If we found an original byte to overwrite, write the byte back now that we
            // have released the immutable ref from `self.breakpoints`
            if let Some((virt_addr, cr3, byte)) = write_back {
                self.write_bytes(virt_addr, cr3, &[byte])?;
            }

            // Let the fuzzer handle the breakpoint
            match self
                .breakpoint_hooks
                .get(bp_index)
                .ok_or(Error::InvalidBreakpointIndex)?
            {
                BreakpointHook::Func(bp_func) => {
                    execution = bp_func(self, input, fuzzer)?;
                }
                BreakpointHook::Redqueen(args) => {
                    let args = args.clone();
                    execution = crate::cmp_analysis::gather_comparison(self, input, &args)?;
                }
                _ => {
                    let sym = self.get_symbol(virt_addr.0);
                    return Err(Error::BreakpointHookNotSet(virt_addr, sym).into());
                }
            }
        } else {
            return Err(Error::UnknownBreakpoint(virt_addr, cr3).into());
        }

        Ok(execution)
    }

    /// Restore all dirty pages as reported by KVM as well as pages dirtied
    /// manually using a function such as [`FuzzVm::write_bytes_dirty`]. Returns the
    /// total number of restored pages.
    fn restore_dirty_pages(&mut self) -> u32 {
        // Reset the scratch reset buffer
        self.scratch_reset_buffer.clear();

        // Gather all of the dirty pages together into the scratch_reset_buffer
        for (slot, bitmap) in self.dirty_bitmaps.iter().enumerate() {
            for (index, byte) in bitmap.iter().enumerate() {
                // Quick continue if there are no available set bits in the current byte
                if *byte == 0 {
                    continue;
                }

                // Get the physical address for this memory region slot
                let phys_addr = self.memory_regions[slot].guest_phys_addr;

                for bit in 0..(std::mem::size_of_val(byte) * 8) {
                    // Ignore this bit if it is not set
                    if *byte & (1 << bit) == 0 {
                        continue;
                    }

                    // Calculate the page index for this dirty bit
                    let page_index = (index * 64 + bit) as u64;

                    // Get the physical address that needs to be restored
                    let curr_phys_addr = phys_addr + page_index * 0x1000;

                    self.scratch_reset_buffer.push(curr_phys_addr);
                }
            }
        }

        // Grab the READ lock for the clean snapshot
        let clean_snapshot = self.clean_snapshot.read().unwrap();

        // Reset the pages currently in the scratch reset buffer
        for curr_phys_addr in &self.scratch_reset_buffer {
            // Calculate the address into the memory and snapshot pages
            let memory_addr = self.memory.backing() + curr_phys_addr;
            let snapshot_addr = clean_snapshot.backing() + curr_phys_addr;

            unsafe { copy_page(snapshot_addr, memory_addr) };
        }

        try_u32!(self.scratch_reset_buffer.len())
    }

    /// Register the guest memory to KVM and create the re-usable allocations used to
    /// query the dirty page bitmaps in [`FuzzVm::get_dirty_logs`].
    ///
    /// # Errors
    ///
    /// * Fails to register guest memory
    fn init_guest_memory_backing(&mut self) -> Result<()> {
        self.memory_regions = crate::register_guest_memory(
            self.vm,
            self.memory.backing() as *mut libc::c_void,
            self.memory.size(),
        )?;

        // Setup the dirty bitmaps for each memory region
        for (slot, mem_region) in self.memory_regions.iter().enumerate() {
            // Compute the length of the bitmap needed for all dirty pages in
            // one memory slot.  One memory page is `page_size` bytes and
            // `KVM_GET_DIRTY_LOG` returns one dirty bit for
            // each page.
            let page_size = match unsafe { libc::sysconf(libc::_SC_PAGESIZE) } {
                -1 => return Err(Error::SysconfFailed(nix::errno::Errno::last()).into()),
                ps => try_u64!(ps),
            };

            // Get the memory size for this memory region
            let memory_size = mem_region.memory_size;

            // For ease of access we are saving the bitmap in a u64 vector.
            // We are using ceil to make sure we count all dirty pages even
            // when `memory_size` is not a multiple of `page_size * 64`.
            let div_ceil = |dividend, divisor| (dividend + divisor - 1) / divisor;

            let bitmap_size = try_usize!(div_ceil(memory_size, page_size * 64));

            // Create the dirty bitmap for this core for this slot
            self.dirty_bitmaps[slot] = vec![0; bitmap_size];

            // Store the pointer for this bitmap in the densely packed bitmap storage
            let core_id = try_usize!(self.core_id);

            DIRTY_BITMAPS[core_id][slot].store(
                self.dirty_bitmaps[slot].as_mut_ptr().cast::<libc::c_void>(),
                Ordering::SeqCst,
            );

            self.number_of_pages[slot] = try_u32!(memory_size / page_size);
        }

        Ok(())
    }

    /*
    /// Attempt to reset the overflow bit for `FIXED_CTR0` in the
    /// [`Msr::Ia32PerfGlobalStatus`]. Returns `true` if the bit was set, otherwise
    /// `false`
    ///
    /// # Errors
    ///
    /// * Failure to set or get an MSR
    pub fn reset_retired_instructions(&mut self) -> Result<bool> {
        let overflow_counter = self.get_msr(Msr::Ia32PerfGlobalStatus)?;

        // If the overflow wasn't set, no need to reset any MSRs
        if overflow_counter & (1 << 32) == 0 {
            return Ok(false);
        }

        // This will cause a interrupt to fire in 1 - POLLING_INTERVAL instructions
        self.instrs_next_exit = self.rng.next() % self.polling_interval + 1;

        // Reset the overflow bit
        self.set_msr(Msr::Ia32PerfGlobalStatus, overflow_counter & !(1 << 32))?;
        self.set_msr(Msr::Ia32FixedCtr0,        MAX_INSTRS - self.instrs_next_exit)?;

        // Remove the pending NMI
        self.vcpu_events_mut().nmi.pending = 0;
        self.vcpu_events_mut().nmi.masked  = 0;

        // Bit was set
        Ok(true)
    }
    */

    /*
    /// Apply the coverage breakpoints to the VM. This will cache the original byte where
    /// the breakpoint
    fn apply_coverage_breakpoints(&mut self) -> Result<()> {
        let coverage_breakpoints = self.coverage_breakpoints.take();

        // Set each breakpoint from the fuzzer
        if let Some(ref cov_bps) = coverage_breakpoints {
            for bp_addr in cov_bps {
                let cr3 = Cr3(self.vbcpu.cr3);

                // If the coverage breakpoint was also a reset breakpoint, ignore the
                // coverage breakpoint and keep the crashing breakpoint
                if let Some(ref reset_bps) = self.reset_breakpoints {
                    if reset_bps.contains_key(&(*bp_addr, cr3)) {
                        log::debug!("Crashing bp found.. ignore coverage: {:#x}", bp_addr.0);
                        continue;
                    }
                }

                /*
                let mut rip_symbol = String::new();
                if let Some(ref sym_data) = self.symbols {
                    let curr_symbol = crate::symbols::get_symbol(bp_addr.0, sym_data);
                    rip_symbol.push_str(&curr_symbol);
                    rip_symbol.push_str(" | ");
                }
                */

                // log::info!("Applying coverage breakpoint: {:#x} {:#x} | {}\n", bp_addr.0, *cr3, rip_symbol);

                if let Err(e) = self.set_breakpoint(
                        *bp_addr,
                        cr3,
                        BreakpointType::SingleShot,
                        BreakpointMemory::NotDirty)
                {
                    if matches!(e.downcast::<Error>()?, Error::InvalidCoverageBreakpoint) {
                        // log::debug!("Failed to read byte for coverage.. ignoring {:#x}", bp_addr.0);
                    }
                }
            }
        }

        // Put back the taken coverage breakpoints
        self.coverage_breakpoints = coverage_breakpoints;

        Ok(())
    }
    */

    /// Returns `true` if the current instruction is a `syscall`
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn _is_syscall(&mut self) -> Result<bool> {
        let mut bytes = [0u8; 2];
        self.read_bytes(VirtAddr(self.rip()), self.cr3(), &mut bytes)?;

        // Check if the current instruction points to a `syscall`
        // $ rasm2 'syscall'
        // 0f05
        Ok(bytes == [0x0f, 0x05])
    }

    /// Step over the current instruction
    #[allow(dead_code)]
    pub fn step_over_instruction(&mut self) -> Result<()> {
        // Get the current instruction
        let curr_instr = self.get_current_instruction()?;

        // Increase the instruction pointer past the current instruction
        self.regs_mut().rip += curr_instr.len() as u64;

        // Successful step
        Ok(())
    }

    /// Read a null-termianted string from the given [`VirtAddr`]
    ///
    /// # Example
    ///
    /// ```rust
    /// let fuzzvm  FuzzVm::create(...);
    /// if let Ok(result) = fuzzvm.read_c_string(VirtAddr(0x402004), fuzzvm.cr3()) {
    ///     log::info!("String at 0x402004: {result}");
    /// }
    /// ```
    /// ```text
    /// String at 0x402004: aaaaaaaaaaaaaaaa
    /// ```
    #[allow(dead_code)]
    pub fn read_c_string(&mut self, virt_addr: VirtAddr, cr3: Cr3) -> Result<String> {
        self.memory.read_c_string(virt_addr, cr3)
    }

    /// Read bytes from `virt_addr` until reading the given `byte`. If `max_size` bytes are read,
    /// return `ByteNotFound`
    ///
    /// # Example
    ///
    /// ```rust
    /// let fuzzvm  FuzzVm::create(...);
    /// if let Ok(result) = fuzzvm.read_bytes_until(VirtAddr(0x402004), fuzzvm.cr3(), b'B', 0x100) {
    ///     log::info!("Split at 0x402004 for b'B': {result:x?}");
    /// }
    /// ```
    /// ```text
    /// Split for 0x402004 for b'B': [41, 41, 41, 41, 42]
    /// ```
    #[allow(dead_code)]
    pub fn read_bytes_until(
        &mut self,
        virt_addr: VirtAddr,
        cr3: Cr3,
        byte: u8,
        max_size: usize,
    ) -> Result<Vec<u8>> {
        self.memory.read_bytes_until(virt_addr, cr3, byte, max_size)
    }

    /// Pop a `u64` from the stack and set `RIP` to that value
    #[allow(dead_code)]
    pub fn fake_immediate_return(&mut self) -> Result<()> {
        // Set the instruction pointer to the first value on the stack
        let rip = self.pop_stack()?;
        self.set_rip(rip);

        // Success
        Ok(())
    }

    /// Print a hexdump of `count` bytes at the given [`VirtAddr`] [`Cr3`]
    ///
    /// # Example
    ///
    /// ```rust
    /// let fuzzvm = FuzzVm::create(...);
    /// fuzzvm.hexdump(VirtAddr(fuzzvm.rip()), fuzzvm.cr3(), 0x20)?;
    /// ```
    /// ```text
    /// ---- address -----   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F    0123456789ABCDEF
    /// 0x0000000000401362: 48 8b 7d f0 e8 f5 fd ff ff 31 c0 48 83 c4 20 cc  | H.}......1.H....
    /// 0x0000000000401372: c3 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 00 f3 0f  | .f..............
    /// ```
    ///
    /// # Errors
    ///
    /// * Fails to read bytes for the hexdump
    pub fn hexdump(&mut self, virt_addr: VirtAddr, cr3: Cr3, count: usize) -> Result<()> {
        self.memory.hexdump(virt_addr, cr3, count)
    }

    /// Attempt to perform a pointer walk from the given [`VirtAddr`] [`Cr3`] (used
    /// predominately for [`FuzzVm::print_context`])
    ///
    /// # Example
    ///
    /// ```rust
    /// let chain = fuzzvm.pointer_chain_str(fuzzvm.rip(), fuzzvm.cr3());
    /// log::info!("{chain}");
    /// ```
    /// ```text
    /// example1!main+0x62 -> 0xfffdf5e8f07d8b48
    /// ```
    fn pointer_chain_str(&mut self, val: u64, cr3: Cr3) -> String {
        // Get the pointer chain for the given values
        let chain = self.memory.pointer_chain(VirtAddr(val), cr3);

        // Convert all of the `ChainVal` into their String representation
        let elems = chain.iter().map(|x| {
            match x {
                ChainVal::Address(addr) => {
                    // Symbols found, attempt to get the symbolf for this address
                    if let Some(found) = self.get_symbol(*addr) {
                        // Color the found symbol
                        format!("{}", found.blue())
                    } else {
                        // No symbol found for this address, just print the address
                        format!("{addr:#x}")
                    }
                }
                _ => {
                    // No symbols found, just print the address
                    format!("{x}")
                }
            }
        });

        let mut res = String::new();
        for (i, elem) in elems.enumerate() {
            if res.len() + elem.len() > 120 {
                res.push_str(" ... ");
                break;
            }

            if i > 0 {
                res.push_str(" -> ");
            }

            res.push_str(&elem);
        }

        res
    }

    /// Disassemble and print `count` number of instructions from `addr`
    ///
    /// # Example
    ///
    /// ```rust
    /// // Print the first 5 instructions at the `force_sig_fault` symbol
    /// if let Some((addr, cr3)) = fuzzvm.get_symbol_address("force_sig_fault") {
    ///     fuzzvm.print_disasm(addr, cr3, 5)?;
    /// }
    /// ```
    ///
    /// ```text
    /// 0xffffffffa6a7fb90: 4883ec38                 | sub rsp, 0x38
    /// 0xffffffffa6a7fb94: 65488b042528000000       | mov rax, qword ptr gs:[0x28]
    /// 0xffffffffa6a7fb9d: 4889442430               | mov qword ptr [rsp+0x30], rax
    /// 0xffffffffa6a7fba2: 31c0                     | xor eax, eax
    /// 0xffffffffa6a7fba4: 893c24                   | mov dword ptr [rsp], edi
    /// ```
    pub fn print_disasm(&mut self, addr: VirtAddr, cr3: Cr3, count: usize) -> Result<()> {
        let mut curr_addr = addr;
        for _ in 0..count {
            let (output_str, instr) = self.memory.get_instruction_string_at(curr_addr, cr3)?;

            let instr_bytes: [u8; 0x10] = self.read(curr_addr, cr3)?;

            let instr_bytes = instr_bytes[..instr.len()]
                .iter()
                .map(|x| format!("{x:02x}"))
                .collect::<String>();

            println!("{:#018x}: {instr_bytes:24} | {output_str}", curr_addr.0);

            curr_addr = curr_addr.offset(instr.len() as u64);
        }

        Ok(())
    }

    /// Return the KASAN line (any WRITE found or first READ found). Used for getting a
    /// directory for a crash triggered by KASAN.
    pub fn get_kasan_crash_path(&mut self) -> Option<String> {
        /// Maximum directory name length for a KASAN crash
        const MAX_PATH_LEN: usize = 164;

        let console_output = unsafe { std::str::from_utf8_unchecked(&self.console_output) };

        // Always check for KASAN, since READ accesses don't reset immediately
        if console_output.contains("KASAN") {
            // Final path for this input
            let mut path = String::new();

            for line in console_output.split('\n') {
                // Look only for the KASAN line and the line after. Ignore all other
                // lines
                if !line.contains("KASAN") {
                    continue;
                }

                // Prioritize WRITEs over READs
                if path.contains("READ") && !line.contains("WRITE") {
                    continue;
                }

                // Set the line to the potential result
                path = line.to_string();

                if path.contains("WRITE") {
                    break;
                }
            }

            // Replace various symbols with `_` for a bit better pathing
            path = path
                .replace(['/', ':', ' ', '(', ')'], "_")
                .replace("__", "_");

            // Truncate the path to the max path len
            path.truncate(MAX_PATH_LEN);

            return Some(path);
        }

        // KASAN not found
        None
    }

    /// Push the given element onto the stack
    #[allow(dead_code)]
    pub fn push_stack<T: Sized>(&mut self, val: T) -> Result<()> {
        // Allocate space on the stack for the given value
        let new_rsp = self.rsp()
            - u64::try_from(std::mem::size_of::<T>())
                .context("Push value size too large for u64")?;

        // Set the new stack value
        self.set_rsp(new_rsp);

        // Write the value onto the stack
        self.write(VirtAddr(new_rsp), self.cr3(), val)?;

        // Success
        Ok(())
    }

    /// Pop and return a `u64` from the stack
    #[allow(dead_code)]
    pub fn pop_stack(&mut self) -> Result<u64> {
        let val = self.read::<u64>(VirtAddr(self.rsp()), self.cr3())?;

        // Set the new stack value
        self.set_rsp(self.rsp() + 8);

        // Success
        Ok(val)
    }

    /// Apply the reset breakpoints to the VM
    fn apply_reset_breakpoints(&mut self) -> Result<()> {
        let reset_breakpoints = self.reset_breakpoints.take();

        if let Some(ref reset_bps) = reset_breakpoints {
            // Set each breakpoint from the fuzzer
            for ((bp_addr, cr3), _symbol_type) in reset_bps.iter() {
                // Ignore wildcard CR3s used for kernel symbol resolution with unknown
                // CR3s. When applying kernel symbol breakpoints, some symbols (like
                // do_idle) can get called with a CR3 not known at runtime. We add those
                // kernel symbols with a wildcard CR3 (0x1234_1234_1234_1234) to
                // symbolize any CR3 with this virtual address
                if *cr3 == WILDCARD_CR3 {
                    continue;
                }

                self.set_breakpoint(
                    *bp_addr,
                    *cr3,
                    BreakpointType::Repeated,
                    BreakpointMemory::NotDirty,
                    BreakpointHook::None,
                )?;
            }
        }

        // Put back the taken reset breakpoints
        self.reset_breakpoints = reset_breakpoints;

        Ok(())
    }

    /// Apply the breakpoints from a [`Fuzzer`] to the VM. This will cache the original
    /// byte where the breakpoint
    fn apply_fuzzer_breakpoints(&mut self, fuzzer: &FUZZER) -> Result<()> {
        // Use the fuzzer breakpoint cache if it has already been initialized
        if let Some(bps) = self.fuzzer_breakpoint_cache.take() {
            for (virt_addr, cr3, bp_type, bp_hook) in &bps {
                self.set_breakpoint(
                    *virt_addr,
                    *cr3,
                    *bp_type,
                    BreakpointMemory::NotDirty,
                    BreakpointHook::Func(*bp_hook),
                )?;
            }

            self.fuzzer_breakpoint_cache = Some(bps);
            return Ok(());
        }

        // It is very expensive to lookup symbols every iteration. A small cache is
        // applied to only lookup the symbols once and then reuse the address each future
        // iteration

        assert!(
            self.fuzzer_breakpoint_cache.is_none(),
            "Initialized breakpoint cache twice?!"
        );

        log::debug!(
            "{:02}: Initializing the fuzzer breakpoint cache",
            self.core_id
        );

        let start = std::time::Instant::now();

        // Initialize the cache the
        let mut cache = Vec::new();

        // Cache all breakpoints as addresses, resolving any symbols requested
        if let Some(bps) = fuzzer.breakpoints() {
            for Breakpoint {
                lookup,
                bp_type,
                bp_hook,
            } in bps
            {
                match lookup {
                    AddressLookup::Virtual(virt_addr, cr3) => {
                        cache.push((*virt_addr, *cr3, *bp_type, *bp_hook));
                    }
                    AddressLookup::SymbolOffset(symbol, offset) => {
                        if let Some((virt_addr, cr3)) = self.get_symbol_address(symbol) {
                            cache.push((virt_addr.offset(*offset), cr3, *bp_type, *bp_hook));
                        } else {
                            // Given symbol was not found. Lookup symbols that contain the given symbol
                            // to display as possible symbols that we do know about
                            let possibles = self.get_symbols_containing(symbol);
                            if !possibles.is_empty() {
                                // These are `println` instead of `log` so that the possibles can be printed to the screen
                                // even using the TUI.
                                eprintln!("Symbol was not found: {symbol}. Did you mean one of the following?");
                                for p in possibles {
                                    eprintln!(" - {p}");
                                }
                            }

                            return Err(Error::LookupSymbolNotFound(symbol, *offset).into());
                        }
                    }
                }
            }
        }

        // Apply the newly generated cache (should only execute once)
        for (virt_addr, cr3, bp_type, bp_hook) in &cache {
            if self.core_id == 1 {
                log::debug!(
                    "Setting fuzzer breakpoint: {virt_addr:x?} {:?}",
                    self.get_symbol(**virt_addr)
                );
            }

            self.set_breakpoint(
                *virt_addr,
                *cr3,
                *bp_type,
                BreakpointMemory::NotDirty,
                BreakpointHook::Func(*bp_hook),
            )?;

            // It is possible for a fuzzer to provide a breakpoint that is also a
            // coverage breakpoint. The fuzzer breakpoint takes precedence, so we remove
            // it from being considered a coverage breakpoint
            if let Some(cov_bps) = &mut self.coverage_breakpoints {
                let _prev_entry = cov_bps.remove(virt_addr);
            }
        }

        log::debug!(
            "{:02}: Initializing the fuzzer breakpoint cache of {} breakpoints took {:?}",
            self.core_id,
            cache.len(),
            start.elapsed()
        );

        // Store the cache
        self.fuzzer_breakpoint_cache = Some(cache);

        Ok(())
    }

    /// Apply the Redqueen breakpoints from a [`Fuzzer`] to the VM. Additionally
    #[cfg(feature = "redqueen")]
    pub fn apply_redqueen_breakpoints(&mut self, fuzzer: &FUZZER) -> Result<()> {
        let mut bps_set = 0;

        let start = std::time::Instant::now();

        if let Some(redqueen_bps) = self.redqueen_breakpoints.take() {
            for (addr, args) in &redqueen_bps {
                self.set_breakpoint(
                    VirtAddr(*addr),
                    self.cr3(),
                    BreakpointType::Repeated,
                    BreakpointMemory::Dirty,
                    BreakpointHook::Redqueen(args.clone()),
                )?;
            }

            self.redqueen_breakpoints = Some(redqueen_bps);
        }

        log::debug!(
            "{:02}: Initializing {} redqueen breakpoints took {:?} ({:6.2} breakpoints/second)",
            self.core_id,
            bps_set,
            start.elapsed(),
            f64::from(bps_set) / start.elapsed().as_secs_f64()
        );

        Ok(())
    }

    /// Read bytes from the [`PhysAddr`] into the given `buf`
    ///
    /// # Errors
    ///
    /// * If the given physical address is out of bounds of the allocated physical memory
    pub fn read_phys_bytes<T: Copy>(&mut self, phys_addr: PhysAddr, buf: &mut [T]) -> Result<()> {
        self.memory.read_phys_bytes(phys_addr, buf)
    }

    /// Sugar around `self.memory.read_phys::<u64>`
    ///
    /// # Errors
    ///
    /// * If the given physical address is out of bounds of the allocated physical memory
    #[allow(dead_code)]
    pub fn read_phys_u64(&mut self, phys_addr: PhysAddr) -> Result<u64> {
        self.memory.read_phys::<u64>(phys_addr)
    }

    /// Write a given value to the given guest [`PhysAddr`]
    ///
    /// # Errors
    ///
    /// * If the given physical address is out of bounds of the allocated physical memory
    #[allow(dead_code)]
    pub fn write_phys<T: Sized>(&mut self, phys_addr: PhysAddr, val: T) -> Result<()> {
        self.memory.write_phys(phys_addr, val)?;

        Ok(())
    }

    /// Write the bytes in `buf` to the [`PhysAddr`].
    ///
    /// # Errors
    ///
    /// * Write to an unmapped virtual address
    /// * Translated physical address is outside the bounds of guest memory
    pub fn write_phys_bytes(&mut self, phys_addr: PhysAddr, buf: &[u8]) -> Result<()> {
        self.memory.write_phys_bytes(phys_addr, buf)?;

        Ok(())
    }

    /// Initialize guest state using the [`VbCpu`] for this [`FuzzVm`]
    ///
    /// # Errors
    ///
    /// * If the snapshot MSRs fail to be set by KVM
    pub fn init_guest(&mut self) -> Result<InitGuestPerf> {
        let mut perf = InitGuestPerf::default();

        /// Helper macro to time the individual components of resetting the guest state
        macro_rules! time {
            ($marker:ident, $expr:expr) => {{
                // Init the timer
                let start = rdtsc();

                // Execute the given expression
                $expr;

                // Calculate the time took to execute $expr
                perf.$marker = rdtsc() - start;
            }};
        }

        time!(regs, self.restore_guest_regs());
        time!(sregs, self.restore_guest_sregs()?);
        time!(fpu, self.restore_guest_fpu()?);
        time!(msrs, self.restore_guest_msrs()?);
        time!(debug_regs, self.restore_guest_debug_regs()?);

        self.vcpu.sync_regs_mut().sregs = self.sregs;
        self.vcpu.set_sync_dirty_reg(SyncReg::SystemRegister);

        self.dirtied_registers = true;

        Ok(perf)
    }

    /// Reset the guest state back to the original snapshot and return the performance
    /// counters of each step
    ///
    /// # Errors
    ///
    /// * If the snapshot MSRs fail to be set by KVM
    pub fn reset_guest_state(&mut self, fuzzer: &mut FUZZER) -> Result<GuestResetPerf> {
        let mut perf = GuestResetPerf::default();

        /// Helper macro to time the individual components of resetting the guest state
        macro_rules! time {
            ($marker:ident, $expr:expr) => {{
                // Init the timer
                let start = rdtsc();

                // Execute the given expression
                let res = $expr;

                // Calculate the time took to execute $expr
                perf.$marker = rdtsc() - start;

                res
            }};
        }

        // Get the dirty log for all memory regions
        time!(get_dirty_logs, self.get_dirty_logs()?);

        // Always just restore the dirty pages
        perf.restored_kvm_pages = time!(reset_guest_memory_restore, self.restore_dirty_pages());

        // Reset the guest memory and get the number of pages restored
        perf.restored_custom_pages = time!(reset_guest_memory_custom, unsafe {
            self.reset_custom_guest_memory()?
        });

        time!(reset_guest_memory_clear, {
            // Clear the dirty logs
            self.clear_dirty_logs()
                .context("Failed to clear dirty logs")?;

            // Reset the custom dirty list
            self.memory.dirty_pages.clear();
        });

        // Reset the guest back to the original snapshot
        perf.init_guest = self.init_guest()?;

        // Reset the internal breakpoint state
        //
        // Want to keep the breakpoint state between runs
        //
        // self.breakpoints.clear();
        // self.breakpoint_original_bytes.clear();
        // self.breakpoint_callbacks.clear();
        // self.breakpoint_types.clear();
        self.restore_breakpoint = None;

        // Init the VM based on the given fuzzer
        time!(init_vm, fuzzer.init_vm(self)?);

        // Apply the breakpoints for the fuzzer
        time!(
            apply_fuzzer_breakpoints,
            self.apply_fuzzer_breakpoints(fuzzer)?
        );

        // Apply the coverage breakpoints for the fuzzer
        time!(apply_reset_breakpoints, self.apply_reset_breakpoints()?);

        // Reset the retired instructions counter
        // self.reset_retired_instructions()?;

        // Reset the start time for the next fuzz case used for determining timeout
        self.start_time = Instant::now();

        // Reset the console output
        self.console_output.clear();

        // Reset the output packets
        self.sent_packets.clear();

        // Reset the LSTAR breakpoint if exiting on syscall
        if self.exit_on_syscall {
            let lstar = VirtAddr(self.vbcpu.msr_lstar);

            self.set_breakpoint(
                lstar,
                self.cr3(),
                BreakpointType::Repeated,
                BreakpointMemory::NotDirty,
                BreakpointHook::Func(|_, _, _| {
                    println!("Hit LSTAR breakpoint!");
                    Ok(Execution::Continue)
                }),
            )?;
        }

        // Reset the physical address to start allocating from
        self.memory.next_avail_phys_page = self.memory.orig_next_avail_phys_page;

        // Initialize the filesystem with the files from the fuzzer
        let mut filesystem = FileSystem::default();
        fuzzer.init_files(&mut filesystem)?;
        self.filesystem = Some(filesystem);

        // Return the guest reset perf
        Ok(perf)
    }

    /// Reset the guest memory pages and returns the number of dirty pages reset
    ///
    /// # Errors
    ///
    /// * If getting the dirty log fails
    ///
    /// # Panics
    ///
    /// * If unable to take the stats lock
    ///
    /// # Safety
    ///
    /// * Unsafe due to the avx512 4KiB memcpy
    pub unsafe fn reset_custom_guest_memory(&mut self) -> Result<u32> {
        // Grab the READ lock for the clean snapshot
        let clean_snapshot = self.clean_snapshot.read().unwrap();

        // Restore the pages that were written to by us
        for custom_dirty_page in &self.memory.dirty_pages {
            // Calculate the address into the memory and snapshot pages
            let memory_addr = self.memory.backing() + custom_dirty_page.0;
            let snapshot_addr = clean_snapshot.backing() + custom_dirty_page.0;

            unsafe { copy_page(snapshot_addr, memory_addr) };
        }

        // Add the fuzzer custom dirty pages to the number of pages restored
        let restored_pages = try_u32!(self.memory.dirty_pages.len());

        Ok(restored_pages)
    }

    /// Restore the guest MSRs using the [`VbCpu`]
    ///
    /// # Errors
    ///
    /// * If KVM fails to set any of the `MODIFIED_MSRS`
    ///
    /// # Panics
    ///
    /// * If an MSR is added to `MODIFIED_MSRS` without it being handled here
    pub fn restore_guest_msrs(&mut self) -> Result<()> {
        // Init the MSRs to write into the guest
        let write_msr = [
            kvm_msr_entry {
                index: Msr::Ia32Efer as u32,
                data: self.vbcpu.msr_efer,
                ..kvm_bindings::kvm_msr_entry::default()
            },
            kvm_msr_entry {
                index: Msr::Ia32Pat as u32,
                data: self.vbcpu.msr_pat,
                ..kvm_bindings::kvm_msr_entry::default()
            },
            kvm_msr_entry {
                index: Msr::Ia32SysenterCs as u32,
                data: self.vbcpu.sysenter_cs,
                ..kvm_bindings::kvm_msr_entry::default()
            },
            kvm_msr_entry {
                index: Msr::Ia32SysenterEip as u32,
                data: self.vbcpu.sysenter_eip,
                ..kvm_bindings::kvm_msr_entry::default()
            },
            kvm_msr_entry {
                index: Msr::Ia32SysenterEsp as u32,
                data: self.vbcpu.sysenter_esp,
                ..kvm_bindings::kvm_msr_entry::default()
            },
            kvm_msr_entry {
                index: Msr::Ia32Star as u32,
                data: self.vbcpu.msr_star,
                ..kvm_bindings::kvm_msr_entry::default()
            },
            kvm_msr_entry {
                index: Msr::Ia32Lstar as u32,
                data: self.vbcpu.msr_lstar,
                ..kvm_bindings::kvm_msr_entry::default()
            },
            kvm_msr_entry {
                index: Msr::Ia32Cstar as u32,
                data: self.vbcpu.msr_cstar,
                ..kvm_bindings::kvm_msr_entry::default()
            },
            kvm_msr_entry {
                index: Msr::Ia32Fmask as u32,
                data: self.vbcpu.msr_sfmask & !(RFlags::TRAP_FLAG.bits()),
                ..kvm_bindings::kvm_msr_entry::default()
            },
            kvm_msr_entry {
                index: Msr::Ia32KernelGsBase as u32,
                data: self.vbcpu.msr_kernel_gs_base,
                ..kvm_bindings::kvm_msr_entry::default()
            },
            /*
            // Add the MSRs for the performance counters
            kvm_msr_entry {
                index: Msr::Ia32PerfGlobalStatus as u32,
                data: 0,
                ..kvm_bindings::kvm_msr_entry::default()
            },
            // Disable FIXED_CTR0
            kvm_msr_entry {
                index: Msr::Ia32PerfGlobalCtrl as u32,
                data: 0,
                ..kvm_bindings::kvm_msr_entry::default()
            },
            // Initialize the counter just under the maximum value so that on overflow,
            // an NMI is generated
            kvm_msr_entry {
                index: Msr::Ia32FixedCtr0 as u32,
                data: init_instr_counter,
                ..kvm_bindings::kvm_msr_entry::default()
            },

            // Enable PMI on overflow for all ring levels
            // Figure 18-2: Layout of IA32_FIXED_CTR_CTRL MSR
            kvm_msr_entry {
                index: Msr::Ia32FixedCtrCtrl as u32,
                data: 0b1011,
                ..kvm_bindings::kvm_msr_entry::default()
            },

            // Enable FIXED_CTR0
            kvm_msr_entry {
                index: Msr::Ia32PerfGlobalCtrl as u32,
                data: 1 << 32,
                ..kvm_bindings::kvm_msr_entry::default()
            },
            */
        ];
        let msrs = Msrs::from_entries(&write_msr).map_err(|_| Error::CreateMsrEntries)?;

        let msrs_written = self.vcpu.set_msrs(&msrs)?;

        ensure!(msrs_written == write_msr.len(), "Failed to write MSR");

        Ok(())
    }

    /// Restore the guest FPU state using the [`VbCpu`]
    ///
    /// # Errors
    ///
    /// * If `fpu.ftwx` from the snapshot [`VbCpu`] cannnot fit into a `u8`
    /// * If `fpu.last_ip` or `fpu.last_dp` from the snapshot [`VbCpu`] cannot fit in a
    ///   `u64`
    pub fn restore_guest_fpu(&mut self) -> Result<()> {
        let mut fpu = self.vcpu.get_fpu()?;

        // Restore the FPU regs
        for (i, reg) in self.vbcpu.xsave_state.x87.fpu_regs.iter().enumerate() {
            fpu.fpr[i] = reg.to_le_bytes();
        }

        // Restore the FPU state
        fpu.fcw = self.vbcpu.xsave_state.x87.fcw;
        fpu.fsw = self.vbcpu.xsave_state.x87.fsw;
        fpu.ftwx = self
            .vbcpu
            .xsave_state
            .x87
            .ftw
            .try_into()
            .context("fpu.ftwx is too large for KVM")?;
        fpu.last_opcode = self.vbcpu.xsave_state.x87.opcode;
        fpu.last_ip = self
            .vbcpu
            .xsave_state
            .x87
            .fpuip
            .try_into()
            .context("fpu.last_ip is too large for KVM")?;
        fpu.last_dp = self
            .vbcpu
            .xsave_state
            .x87
            .fpudp
            .try_into()
            .context("fpu.last_dp is too large for KVM")?;

        // Restore the XMM regs
        for (i, reg) in self.vbcpu.xsave_state.x87.xmm_regs.iter().enumerate() {
            fpu.xmm[i] = reg.to_le_bytes();
        }

        // Restore the XMM state
        fpu.mxcsr = self.vbcpu.xsave_state.x87.mxcsr;

        // Restore the FPU
        self.vcpu.set_fpu(&fpu)?;

        // Return success
        Ok(())
    }

    /// Restore the guest general purpose registers using the [`VbCpu`] for this
    /// [`FuzzVm`]
    pub fn restore_guest_regs(&mut self) {
        // Set the general purpose registers from the vbcpu
        self.regs.rax = self.vbcpu.rax;
        self.regs.rbx = self.vbcpu.rbx;
        self.regs.rcx = self.vbcpu.rcx;
        self.regs.rdx = self.vbcpu.rdx;
        self.regs.rsi = self.vbcpu.rsi;
        self.regs.rdi = self.vbcpu.rdi;
        self.regs.rsp = self.vbcpu.rsp;
        self.regs.rbp = self.vbcpu.rbp;
        self.regs.r8 = self.vbcpu.r8;
        self.regs.r9 = self.vbcpu.r9;
        self.regs.r10 = self.vbcpu.r10;
        self.regs.r11 = self.vbcpu.r11;
        self.regs.r12 = self.vbcpu.r12;
        self.regs.r13 = self.vbcpu.r13;
        self.regs.r14 = self.vbcpu.r14;
        self.regs.r15 = self.vbcpu.r15;
        self.regs.rip = self.vbcpu.rip;
        // self.regs.rflags = self.vbcpu.rflags | 2;
        self.regs.rflags = 2;
    }

    /// Restore the guest special registers using the [`VbCpu`] for this [`FuzzVm`]
    ///
    /// # Errors
    ///
    /// * If given GDTR or IDTR limits are too large for KVM
    pub fn restore_guest_sregs(&mut self) -> Result<()> {
        /// Macro for copying VBCPU segment to KVM
        macro_rules! set_segment {
            (sregs $sregs_seg:ident, vbcpu $vbcpu_seg:ident) => {{
                let access_rights = self.vbcpu.$vbcpu_seg.get_access_rights();
                self.sregs.$sregs_seg.base =
                    self.vbcpu.$vbcpu_seg.base.try_into().expect(&format!(
                        "Invalid {} base: {:#x}",
                        stringify!($vbcpu_seg),
                        self.vbcpu.$vbcpu_seg.base
                    ));
                self.sregs.$sregs_seg.limit =
                    self.vbcpu.$vbcpu_seg.limit.try_into().expect(&format!(
                        "Invalid {} limit: {:#x}",
                        stringify!($vbcpu_seg),
                        self.vbcpu.$vbcpu_seg.base
                    ));
                self.sregs.$sregs_seg.selector = self.vbcpu.$vbcpu_seg.selector;
                self.sregs.$sregs_seg.type_ = access_rights.segment_type;
                self.sregs.$sregs_seg.present = access_rights.present;
                self.sregs.$sregs_seg.dpl = access_rights.privilege_level;
                self.sregs.$sregs_seg.db = access_rights.operation_size;
                self.sregs.$sregs_seg.s = access_rights.descriptor_type;
                self.sregs.$sregs_seg.l = access_rights.long_mode_for_cs;
                self.sregs.$sregs_seg.g = access_rights.granularity;
                self.sregs.$sregs_seg.avl = access_rights.avl;
                self.sregs.$sregs_seg.unusable = access_rights.unusable;
            }};
        }

        // Copy all segments from VBCPU into the guest SREGS
        set_segment!(sregs cs,  vbcpu cs);
        set_segment!(sregs ds,  vbcpu ds);
        set_segment!(sregs es,  vbcpu es);
        set_segment!(sregs fs,  vbcpu fs);
        set_segment!(sregs gs,  vbcpu gs);
        set_segment!(sregs ss,  vbcpu ss);
        set_segment!(sregs ldt, vbcpu ldtr);
        set_segment!(sregs tr,  vbcpu tr);

        // Set the CR* from the snapshot
        self.sregs.cr0 = self.vbcpu.cr0;
        self.sregs.cr2 = self.vbcpu.cr2;
        self.sregs.cr3 = self.vbcpu.cr3;
        self.sregs.cr4 = self.vbcpu.cr4;

        self.sregs.apic_base = self.vbcpu.msr_apic_base;

        // If the fuzzer requests to handle syscall itself, remove the ability for
        // syscalls to be executed
        self.sregs.efer = self.vbcpu.msr_efer;

        self.sregs.gdt.base = self.vbcpu.gdtr_base;
        self.sregs.gdt.limit = self
            .vbcpu
            .gdtr_limit
            .try_into()
            .context("Snapshot GDTR limit too large")?;

        self.sregs.idt.base = self.vbcpu.idtr_base;
        self.sregs.idt.limit = self
            .vbcpu
            .idtr_limit
            .try_into()
            .context("Snapshot IDTR limit too large")?;

        /*
        for vector in 0..255 {
            if vector != 13 && vector != 8 {
                continue;
            }

            let addr = self.vbcpu.idtr_base + vector * std::mem::size_of::<IdtEntry>() as u64;
            let mut blank_entry = IdtEntry::default();
            blank_entry.set_isr(0xffff1234ffff1234);
            self.write::<IdtEntry>(VirtAddr(addr), self.cr3(), blank_entry)?;
        }
        */

        // self.sregs.idt.base  = 0;
        // self.sregs.idt.limit = 0;

        Ok(())
    }

    /// Restore the debug register state to the snapshot
    ///
    /// # Errors
    ///
    /// Fail to get debug registers from KVM
    pub fn restore_guest_debug_regs(&mut self) -> Result<()> {
        // Get the current debug regs
        let mut debug_regs = self.vcpu.get_debug_regs()?;

        // Restore the guest debug regs
        debug_regs.dr6 = self.vbcpu.dr6;
        debug_regs.dr7 = self.vbcpu.dr7;

        // Set teh original debug regs
        self.vcpu.set_debug_regs(&debug_regs)?;

        Ok(())
    }

    /// Pass execution to the VM. Returns the `FuzzVmExit` along with the number of
    /// cycles in the KVM VM itself.
    pub fn run(&mut self, perf: &mut VmRunPerf) -> Result<FuzzVmExit> {
        let start = rdtsc();

        let mut rflags = RFlags::from_bits_truncate(self.regs.rflags);

        // Enable TRAP flag if guest is single stepping
        if self.single_step || self.restore_breakpoint.is_some() {
            rflags.insert(RFlags::TRAP_FLAG);
            self.regs.rflags = rflags.bits();
        } else {
            rflags.remove(RFlags::TRAP_FLAG);
            self.regs.rflags = rflags.bits();
            let rflags = RFlags::from_bits_truncate(self.regs.rflags);
            assert!(!rflags.contains(RFlags::TRAP_FLAG));
            self.dirtied_registers = true;
        }

        // Only copy the registers back to the guest if they were dirtied by the
        // fuzzer
        if self.dirtied_registers {
            self.vcpu.sync_regs_mut().regs = self.regs;
            self.vcpu.set_sync_dirty_reg(SyncReg::Register);
        }

        // Always copy out the general purpose registers, system registers, and
        // events
        self.vcpu.sync_regs_mut().regs = self.regs;
        self.vcpu.set_sync_dirty_reg(SyncReg::Register);
        self.vcpu.set_sync_dirty_reg(SyncReg::SystemRegister);
        self.vcpu.set_sync_valid_reg(SyncReg::Register);
        self.vcpu.set_sync_valid_reg(SyncReg::SystemRegister);
        self.vcpu.set_sync_valid_reg(SyncReg::VcpuEvents);

        // Restore the FPU
        // self.vcpu.set_fpu(&self.vcpu.get_fpu()?)?;

        // Accumulate the cyles spent before the VM run call
        perf.pre_run_vm = rdtsc() - start;

        // Init the timer for the run() call
        let start = rdtsc();

        // Execute the CPU
        let test_res = self.vcpu.run();

        perf.in_vm = rdtsc() - start;

        // Init the timer for the remainder of the function
        let start = rdtsc();

        // Unset the dirtied_registers bit for this round of handling the exit
        self.dirtied_registers = false;

        // Check if the guest exited due to the timer elapsing
        let res: FuzzVmExit = match test_res {
            Err(e) => {
                // When the guest is forced to exit, run() returns EINTR
                if e.errno() == libc::EINTR {
                    crate::KICK_CORES.store(true, std::sync::atomic::Ordering::SeqCst);
                    FuzzVmExit::TimerElapsed
                } else if e.errno() == libc::EFAULT {
                    crate::KICK_CORES.store(true, std::sync::atomic::Ordering::SeqCst);
                    FuzzVmExit::BadAddress(self.rip())
                } else {
                    perf.post_run_vm = rdtsc() - start;
                    let errno = e.errno();
                    println!("ERROR FROM RUN: {e:?} {errno}");
                    return Err(Error::FailedToExecuteVm(e).into());
                }
            }
            Ok(res) => {
                if let VcpuExit::IoOut(port, bytes) = res {
                    /*
                    unsafe {
                        log::info!("{:#x}: {}", port, std::str::from_utf8_unchecked(bytes));
                    }
                    */
                    if port == 0x3f8 {
                        self.console_output.extend(bytes);
                        FuzzVmExit::IoOut(port)
                    } else {
                        FuzzVmExit::IoOut(port)
                    }
                } else {
                    res.into()
                }
            }
        };

        // Save the current register state after execution
        // XXX: If there is a perf hit here, only copy out the data when requested
        // instead of always, each vmexit
        self.regs = self.vcpu.sync_regs().regs;
        self.sregs = self.vcpu.sync_regs().sregs;
        self.vcpu_events = self.vcpu.sync_regs().events;

        // If `restore_breakpoint` has been set before the instruction, it symbolizes a
        // breakpoint should be restored at that location.
        let possible_restore_breakpoint = self.restore_breakpoint.take();
        if let Some((virt_addr, cr3)) = possible_restore_breakpoint {
            self.write_bytes(virt_addr, cr3, &[0xcc])?;
        }

        // Custom handling of VMEXITs
        match res {
            FuzzVmExit::Breakpoint(_) | FuzzVmExit::DebugException => {
                // Check if the breakpoint VmExit was caused by a coverage breakpoint
                let rip = self.regs().rip;

                if let Some(ref cov_bps) = self.coverage_breakpoints {
                    // If the current address can be removed from the coverage database, then
                    // we have hit a new coverage address. Return a CoverageBreakpoint exit.
                    let virt_addr = VirtAddr(rip);

                    if let Some(orig_byte) = cov_bps.get(&virt_addr) {
                        // This breakpoint is a coverage breakpoint. Restore the VM
                        // memory and the global clean memory of this breakpoint so no
                        // other VM has to cover this breakpoint either
                        let orig_byte = *orig_byte;
                        let cr3 = Cr3(self.vbcpu.cr3);

                        // Grab the WRITE lock for the clean snapshot since we are modifying
                        // the clean snapshot
                        let mut clean_snapshot = self.clean_snapshot.write().unwrap();
                        clean_snapshot.write_bytes(virt_addr, cr3, &[orig_byte])?;
                        drop(clean_snapshot);

                        self.write_bytes(virt_addr, cr3, &[orig_byte])?;

                        perf.post_run_vm = rdtsc() - start;
                        return Ok(FuzzVmExit::CoverageBreakpoint(rip));
                    }
                }

                if let Some(reset_bps) = self.reset_breakpoints.take() {
                    for cr3 in [self.cr3(), WILDCARD_CR3] {
                        if let Some(reset_bp_type) = reset_bps.get(&(VirtAddr(rip), cr3)) {
                            let vmexit = match *reset_bp_type {
                                ResetBreakpointType::Reset => {
                                    perf.post_run_vm = rdtsc() - start;
                                    Some(FuzzVmExit::ResetBreakpoint(rip))
                                }
                                ResetBreakpointType::Crash
                                | ResetBreakpointType::ReportGenericError
                                | ResetBreakpointType::ReportOutOfMemory => {
                                    perf.post_run_vm = rdtsc() - start;
                                    Some(FuzzVmExit::CrashBreakpoint(rip))
                                }
                                ResetBreakpointType::HandleInvalidOp => {
                                    // Check if the RIP was a syscall
                                    // Read the register state by the invalid op

                                    // If we hit handle_invalid_op and we aren't exiting on
                                    // syscalls, then this will early return the
                                    // InvalidOpcode (#UD) exception
                                    if self.exit_on_syscall {
                                        let rdi = self.rdi();
                                        let ptregs: PtRegs =
                                            self.read(VirtAddr(rdi), self.cr3())?;

                                        let mut bytes = [0u8; 2];
                                        let ip = VirtAddr(ptregs.ip);
                                        self.read_bytes(ip, self.cr3(), &mut bytes)?;
                                        None
                                    } else {
                                        perf.post_run_vm = rdtsc() - start;
                                        Some(FuzzVmExit::Debug(Exception::InvalidOpcode))
                                    }
                                }
                                ResetBreakpointType::ForceSigFault => {
                                    let signal = self.forced_signal()?;
                                    perf.post_run_vm = rdtsc() - start;

                                    // Special case the trap signal for display in the TUI
                                    if matches!(signal, Signal::Trap) {
                                        Some(FuzzVmExit::Trap)
                                    } else {
                                        Some(FuzzVmExit::ForceSigFaultBreakpoint(signal))
                                    }
                                }
                                ResetBreakpointType::EnableSingleStep => {
                                    log::info!("Enabling single step");
                                    panic!();
                                }
                                ResetBreakpointType::FindModuleNameAndOffset => {
                                    // Immediately return from the function
                                    self.fake_immediate_return()?;

                                    // Write the string to the local console
                                    if let Some(msg) = self.get_symbol(self.rsi()) {
                                        self.console_output.extend(b"    ");
                                        self.console_output.extend(msg.as_bytes());
                                        self.console_output.extend(b" : ");
                                    }

                                    // Return success
                                    self.set_rax(0);

                                    perf.post_run_vm = rdtsc() - start;
                                    Some(FuzzVmExit::FindModuleNameAndOffset)
                                }
                                ResetBreakpointType::ConsoleWrite => {
                                    // Resulting string for log_store is in rsi and len in rdx
                                    /*
                                    log::info!("Hit ConsoleWrite @ {:#x} - {:?}",
                                        self.rip(),
                                        self.get_symbol(self.rip()));
                                    */

                                    // Get the wanted to print string
                                    let buffer = VirtAddr(self.rsi());
                                    let count = try_usize!(self.rdx());
                                    let mut bytes = vec![0_u8; count];
                                    self.read_bytes(buffer, self.cr3(), &mut bytes)?;

                                    // Write the string to the local console
                                    self.console_output.extend(&bytes);

                                    // Immediately return from the function
                                    self.fake_immediate_return()?;

                                    /*
                                    log::info!("Ret to {:#x} - {:?}",
                                        self.rip(),
                                        self.get_symbol(self.rip()));
                                    */

                                    perf.post_run_vm = rdtsc() - start;
                                    // return Ok((FuzzVmExit::ConsoleWrite, perf));
                                    Some(FuzzVmExit::Hlt)
                                }
                                ResetBreakpointType::LogStore => {
                                    // Resulting string for log_store is in r9 and len in rbx

                                    // Get the wanted to print string
                                    let buffer = VirtAddr(self.r9());
                                    let count = try_usize!(self.rbx());
                                    let mut bytes = vec![0_u8; count];
                                    self.read_bytes(buffer, self.cr3(), &mut bytes)?;

                                    // Write the string to the local console
                                    self.console_output.extend(&bytes);
                                    self.console_output.push(b'\n');

                                    // Immediately return from the function
                                    self.fake_immediate_return()?;

                                    perf.post_run_vm = rdtsc() - start;
                                    Some(FuzzVmExit::LogStore)
                                }
                                ResetBreakpointType::ImmediateReturn => {
                                    // Immediately return from the function
                                    self.fake_immediate_return()?;

                                    perf.post_run_vm = rdtsc() - start;
                                    Some(FuzzVmExit::ImmediateReturn)
                                }
                                ResetBreakpointType::KernelDie => {
                                    // self.print_context();

                                    perf.post_run_vm = rdtsc() - start;
                                    Some(FuzzVmExit::KernelDieBreakpoint)
                                }
                                ResetBreakpointType::KasanReport => {
                                    let addr = self.rdi();
                                    let size = self.rsi();
                                    let is_write = self.rdx() != 0;
                                    let ip = self.rcx();

                                    let access = if is_write { "WRITE" } else { "READ" };

                                    // Get the return address to immediately exit
                                    let ret_addr = self.pop_stack()?;

                                    // Immediately return from the function
                                    self.set_rip(ret_addr);

                                    let sym = self
                                        .get_symbol(ip)
                                        .unwrap_or_else(|| format!("_ip_{ip:#x}"));
                                    let info = format!(
                                        "KASAN_{access}_size_{size}_{sym}_addr_{addr:#x}\n"
                                    );

                                    // Write the basic kasan information to the console
                                    self.console_output.extend(info.as_bytes());

                                    // log::info!("{}", self.console_output);

                                    perf.post_run_vm = rdtsc() - start;

                                    if is_write {
                                        Some(FuzzVmExit::KasanWrite { ip, size, addr })
                                    } else {
                                        Some(FuzzVmExit::KasanRead { ip, size, addr })
                                    }
                                }
                            };

                            if let Some(found_exit) = vmexit {
                                // Move reset breakpoints back into `self`
                                self.reset_breakpoints = Some(reset_bps);

                                return Ok(found_exit);
                            }
                        }
                    }

                    // Move reset breakpoints back into `self`
                    self.reset_breakpoints = Some(reset_bps);
                }
            }
            FuzzVmExit::InternalError => {
                log::warn!("Internal error");
            }
            _ => {}
        }

        perf.post_run_vm = rdtsc() - start;
        Ok(res)
    }

    /// Execute the [`FuzzVm`] until a reset or timeout event occurs
    pub fn run_until_reset(
        &mut self,
        fuzzer: &mut FUZZER,
        input: &FUZZER::Input,
        vm_timeout: Duration,
    ) -> Result<(Execution, VmRunPerf)> {
        let mut execution = Execution::Continue;

        // Initialize the performance counters for executing a VM
        let mut perf = crate::fuzzvm::VmRunPerf::default();

        // Top of the run iteration loop for the current fuzz case
        loop {
            // Reset the VM if the vmexit handler says so
            if matches!(execution, Execution::Reset | Execution::CrashReset { .. }) {
                break;
            }

            // Execute the VM
            let ret = self.run(&mut perf)?;

            // Handle the FuzzVmExit to determine
            let ret = handle_vmexit(&ret, self, fuzzer, None, input);
            execution = match ret {
                Err(e) => {
                    return Err(e);
                }
                Ok(execution) => execution,
            };

            // During single step, breakpoints aren't triggered. For this reason,
            // we need to check if the instruction is a breakpoint regardless in order to
            // apply fuzzer specific breakpoint logic. We can ignore the "unknown breakpoint"
            // error that is thrown if a breakpoint is not found;
            if self.single_step {
                if let Ok(new_execution) = self.handle_breakpoint(fuzzer, input) {
                    execution = new_execution;
                } else {
                    // Ignore the unknown breakpoint case since we check every instruction due to
                    // single stepping here.
                }
            }

            // Check if the VM needs to be timed out
            if self.start_time.elapsed() > vm_timeout {
                log::warn!("Coverage Timed out.. exiting");
                execution = Execution::Reset;
            }
        }

        Ok((execution, perf))
    }

    /// Execute the [`FuzzVm`] until a reset or timeout event occurs.
    ///
    /// # Returns
    ///
    /// * Execution at the time of reset
    /// * [`VmRunPerf`] for the execution of the guest
    /// * Set of coverage pair (virtual address, rflags) for use in redqueen
    #[cfg(feature = "redqueen")]
    fn run_until_reset_redqueen(
        &mut self,
        fuzzer: &mut FUZZER,
        input: &FUZZER::Input,
        vm_timeout: Duration,
        coverage: &mut BTreeSet<VirtAddr>,
    ) -> Result<BTreeSet<(VirtAddr, RFlags)>> {
        let mut execution = Execution::Continue;

        // Initialize the performance counters for executing a VM
        let mut perf = crate::fuzzvm::VmRunPerf::default();

        // Initialize the output coverage
        let mut rq_coverage = BTreeSet::new();

        // Top of the run iteration loop for the current fuzz case
        loop {
            // Reset the VM if the vmexit handler says so
            if matches!(execution, Execution::Reset | Execution::CrashReset { .. }) {
                break;
            }

            // Execute the VM
            let ret = self.run(&mut perf)?;

            if let FuzzVmExit::CoverageBreakpoint(rip) = &ret {
                log::debug!("{:#x}: New coverage bp: {rip:#x}", input.fuzz_hash());
                coverage.insert(VirtAddr(*rip));
            }

            // If this breakpoint was a redqueen breakpoint, add the rip and the rflags pairing
            // to the coverage
            if let Some(ref rq_breakpoint_addrs) = self.redqueen_breakpoint_addresses {
                if rq_breakpoint_addrs.contains(&self.rip()) {
                    // Keep the Carry and Zero flags as part of the coverage
                    let flag_mask = RFlags::ZERO_FLAG | RFlags::CARRY_FLAG;
                    // flag_mask |= RFlags::SIGN_FLAG;
                    // flag_mask |= RFlags::AUXILIARY_CARRY_FLAG;

                    let rflags = RFlags::from_bits_truncate(self.rflags() & flag_mask.bits());

                    rq_coverage.insert((VirtAddr(self.rip()), rflags));
                }
            } else {
                panic!("Unknown redqueen addresses");
            }

            // Handle the FuzzVmExit to determine
            let ret = handle_vmexit(&ret, self, fuzzer, None, input);
            execution = match ret {
                Err(e) => {
                    return Err(e);
                }
                Ok(execution) => execution,
            };

            // During single step, breakpoints aren't triggered. For this reason,
            // we need to check if the instruction is a breakpoint regardless in order to
            // apply fuzzer specific breakpoint logic. We can ignore the "unknown breakpoint"
            // error that is thrown if a breakpoint is not found;
            if self.single_step {
                if let Ok(new_execution) = self.handle_breakpoint(fuzzer, input) {
                    execution = new_execution;
                } else {
                    // Ignore the unknown breakpoint case since we check every instruction due to
                    // single stepping here.
                }
            }

            // Check if the VM needs to be timed out
            if self.start_time.elapsed() > vm_timeout {
                log::debug!("Coverage Timed out.. exiting");
                execution = Execution::Reset;
            }
        }

        Ok(rq_coverage)
    }

    /// Get the coverage breakpoints hit by the given `input`
    pub fn gather_coverage(
        &mut self,
        fuzzer: &mut FUZZER,
        input: &FUZZER::Input,
        current_coverage: &[u64],
        vm_timeout: Duration,
    ) -> Result<Vec<u64>> {
        // Reset the guest state
        let _perf = self.reset_guest_state(fuzzer)?;

        // Reset the fuzzer state
        fuzzer.reset_fuzzer_state();

        // Set the input into the VM as per the fuzzer
        fuzzer.set_input(input, self)?;

        let mut hit_breakpoints = BTreeMap::new();

        // Reset all of the current breakpoints
        for hit_bp in current_coverage {
            let bp_addr = VirtAddr(*hit_bp);
            let curr_byte = self.read::<u8>(bp_addr, self.cr3())?;
            if curr_byte != 0xcc {
                // Store the original byte for this address
                hit_breakpoints.insert(*hit_bp, curr_byte);

                // Write a breakpoint at this address to look for coverage
                self.write_bytes_dirty(bp_addr, self.cr3(), &[0xcc])?;
            }
        }

        // Initialize the execution for each vmexit
        let mut execution = Execution::Continue;

        // Initialize the performance counters for executing a VM
        let mut perf = crate::fuzzvm::VmRunPerf::default();

        // Initialize the seen coverage from this execution
        let mut seen_coverage = Vec::new();

        // Top of the run iteration loop for the current fuzz case
        loop {
            // Reset the VM if the vmexit handler says so
            if matches!(execution, Execution::Reset | Execution::CrashReset { .. }) {
                break;
            }

            // Execute the VM
            let ret = self.run(&mut perf)?;

            match ret {
                FuzzVmExit::Breakpoint(rip) | FuzzVmExit::CoverageBreakpoint(rip) => {
                    // Restore the original coverage
                    if let Some(orig_byte) = hit_breakpoints.get(&rip) {
                        // Add the coverage to the list of coverage for this input
                        seen_coverage.push(rip);

                        // Restore the original byte for this breakpoint
                        self.write_bytes_dirty(VirtAddr(rip), self.cr3(), &[*orig_byte])?;

                        execution = Execution::Continue;

                        // Restored byte, continue execution at the top of the loop
                        continue;
                    }
                }
                _ => {}
            }

            // Handle the FuzzVmExit to determine
            let ret = handle_vmexit(&ret, self, fuzzer, None, input);
            execution = match ret {
                Err(e) => {
                    return Err(e);
                }
                Ok(execution) => execution,
            };

            // Check if the VM needs to be timed out
            if self.start_time.elapsed() > vm_timeout {
                log::warn!("Coverage Timed out.. exiting");
                execution = Execution::Reset;
            }
        }

        // Restore the original bytes that we overwrote with breakpoints
        for (addr, orig_byte) in hit_breakpoints {
            self.write_bytes_dirty(VirtAddr(addr), self.cr3(), &[orig_byte])?;
        }

        // Return the coverage breakpoint seen
        Ok(seen_coverage)
    }

    /// Internal function used to reset the guest and run with redqueen breakpoints enabled
    ///
    /// # Returns
    ///
    /// * Coverage of (virtual address, rflags) for each redqueen breakpoint hit
    #[cfg(feature = "redqueen")]
    pub(crate) fn reset_and_run_with_redqueen(
        &mut self,
        input: &FUZZER::Input,
        fuzzer: &mut FUZZER,
        vm_timeout: Duration,
        coverage: &mut BTreeSet<VirtAddr>,
    ) -> Result<BTreeSet<(VirtAddr, RFlags)>> {
        // Reset the guest state in preparation for redqueen
        let _perf = self.reset_guest_state(fuzzer)?;

        // Reset the fuzzer state
        fuzzer.reset_fuzzer_state();

        // Set the input into the VM as per the fuzzer
        fuzzer.set_input(input, self)?;

        // Apply redqueen breakpoints
        self.apply_redqueen_breakpoints(fuzzer)?;

        // Run the guest until reset, gathering redqueen redqueen rules
        let coverage = self.run_until_reset_redqueen(fuzzer, input, vm_timeout, coverage)?;

        Ok(coverage)
    }

    /// Populate the `redqueen_rules` for the given `input`
    #[cfg(feature = "redqueen")]
    pub fn gather_redqueen(
        &mut self,
        input: &FUZZER::Input,
        fuzzer: &mut FUZZER,
        vm_timeout: Duration,
        corpus: &mut Vec<<FUZZER as Fuzzer>::Input>,
        coverage: &mut BTreeSet<VirtAddr>,
        redqueen_coverage: &mut BTreeSet<(VirtAddr, RFlags)>,
        time_spent: Duration,
        metadata_dir: &PathBuf,
    ) -> Result<()> {
        // Init an rng for this gathering of redqueen
        let mut rng = Rng::new();

        // If we've spent too much time during the recursive redqueen calls, return and
        // come back to redqueen on a different iteration
        if time_spent >= self.config.redqueen.timeout {
            log::info!("Core {:#x} Redqueen TIMEOUT: {time_spent:?}", self.core_id);
            return Ok(());
        }

        // Begin the timer for this iteration of redqueen
        let start_time = std::time::Instant::now();

        // Gather then original redqueen rules for this input
        let orig_coverage =
            self.reset_and_run_with_redqueen(input, fuzzer, vm_timeout, coverage)?;

        // Get the found redqueen rules for this input
        let fuzz_hash = input.fuzz_hash();

        if let Some(orig_rules) = self.redqueen_rules.remove(&fuzz_hash) {
            // Replace all of the 2+ byte substrings that need to be replaced via the redqueen rules
            // (Colorization phase from the Redqueen paper)
            // This is to reduce the number of possible redqueen locations in the input
            let mut max_entropy_input = input.clone();

            for rule in &orig_rules {
                let candidates = max_entropy_input.get_redqueen_rule_candidates(rule);

                if candidates.len() > self.config.redqueen.entropy_threshold {
                    for _candidate in candidates {
                        // Clone the input to attempt to increase the entropy
                        let mut test_max_entropy_input = max_entropy_input.clone();

                        // Attempt to increase the entropy of the input if this input
                        // has more rule candidates than the entropy threshold
                        test_max_entropy_input.increase_redqueen_entropy(rule, &mut rng);

                        // Gather the redqueen coverage for this new input
                        let entropy_coverage = self.reset_and_run_with_redqueen(
                            &test_max_entropy_input,
                            fuzzer,
                            vm_timeout,
                            coverage,
                        )?;

                        if entropy_coverage == orig_coverage {
                            // Keep this entropy input since it has the same coverage
                            max_entropy_input = test_max_entropy_input;
                        }
                    }
                }
            }

            let _coverage =
                self.reset_and_run_with_redqueen(&max_entropy_input, fuzzer, vm_timeout, coverage)?;

            if let Some(rules) = self.redqueen_rules.remove(&max_entropy_input.fuzz_hash()) {
                // log::info!("Calling RQ from {fuzz_hash:#x}: {rules:x?}");
                for rule in &rules {
                    // Apply this redqueen rule
                    let candidates = max_entropy_input.get_redqueen_rule_candidates(rule);
                    // log::info!("{rule:x?} Candidates {}", candidates.len());

                    for candidate in &candidates {
                        let mut new_input = max_entropy_input.clone();
                        let original_file = input.fuzz_hash();

                        // Apply the given rule with the candidate
                        let mutation = new_input.apply_redqueen_rule(rule, candidate);

                        // Get the coverage of this mutated input, only using the specific redqueen
                        // breakpoint for this targetted rule
                        let new_rq_coverage = self.reset_and_run_with_redqueen(
                            &new_input, fuzzer, vm_timeout, coverage,
                        )?;

                        // If we've found new coverage, add the new input to the corpus
                        let mut new_coverage = Vec::new();
                        for cov in new_rq_coverage {
                            if redqueen_coverage.insert(cov) {
                                log::info!(
                                    "{:?} | {:#x}: New rq bp: {:x?}",
                                    self.core_id,
                                    input.fuzz_hash(),
                                    cov
                                );

                                new_coverage.push(*cov.0);
                            }
                        }

                        // If this input found new coverage, add it to the corpus
                        // and execute Redqueen on this new input
                        if !new_coverage.is_empty() {
                            // Ensure the metadata directory exists
                            if !metadata_dir.exists() {
                                std::fs::create_dir(metadata_dir)?;
                            }

                            // Get the fuzz hash for this input
                            let hash = new_input.fuzz_hash();

                            let mutation = format!(
                                "RQ_{}",
                                mutation.unwrap_or_else(|| String::from("rq_unknown"))
                            );

                            // Write the metadata for this mutation
                            let mutation_metadata = crate::fuzz_input::InputMetadata {
                                original_file,
                                mutation: vec![mutation],
                                new_coverage,
                            };

                            let filepath = metadata_dir.join(format!("{hash:x}"));
                            std::fs::write(filepath, serde_json::to_string(&mutation_metadata)?)?;

                            let mut input_bytes = Vec::new();
                            new_input.to_bytes(&mut input_bytes)?;
                            let filepath = metadata_dir
                                .parent()
                                .unwrap()
                                .join("current_corpus")
                                .join(format!("{hash:x}"));
                            std::fs::write(filepath, &input_bytes)?;

                            input_bytes.clear();
                            input.to_bytes(&mut input_bytes)?;
                            let filepath = metadata_dir
                                .parent()
                                .unwrap()
                                .join("current_corpus")
                                .join(format!("{original_file:x}"));
                            std::fs::write(filepath, &input_bytes)?;

                            // Add the new input to the corpus
                            corpus.push(new_input.clone());

                            // Recursively attempt to call Redqueen for this new input
                            self.gather_redqueen(
                                &new_input,
                                fuzzer,
                                vm_timeout,
                                corpus,
                                coverage,
                                redqueen_coverage,
                                time_spent + start_time.elapsed(),
                                metadata_dir,
                            )?;

                            // Found a path through the redqueen breakpoint, add the input
                            // to the corpus and go to the next rule
                            // break;
                        }
                    }
                }

                // Restore the max entropy input redqueen rules
                self.redqueen_rules
                    .insert(max_entropy_input.fuzz_hash(), rules);
            } else {
                // println!("No rules for {:#x}", max_entropy_input.fuzz_hash());
            }

            // Restore the original input redqueen rules
            self.redqueen_rules.insert(fuzz_hash, orig_rules);
        } else {
            // log::warn!("No RQ rules generated!");
        }

        assert!(
            self.redqueen_rules.contains_key(&fuzz_hash),
            "No rules found after redqueen"
        );

        // Reset the guest state to remove redqueen breakpoints
        let _perf = self.reset_guest_state(fuzzer)?;

        // Reset the fuzzer state
        fuzzer.reset_fuzzer_state();

        Ok(())
    }

    /// Get the list of addresses of the backtrace for the current VM state
    pub fn backtrace(&mut self) -> Option<Vec<UnwindInfo>> {
        let mut res = None;

        if let Some(mut unwinders) = self.unwinders.take() {
            res = Some(unwinders.backtrace(self));
            self.unwinders = Some(unwinders);
        }

        res
    }

    /// Get the symbolized backtrace for the current VM state
    pub fn symbolized_backtrace(&mut self) -> Vec<String> {
        let mut lines = Vec::new();

        if let Some(addrs) = self.backtrace() {
            if !addrs.is_empty() {
                for addr in addrs {
                    let (addr, known) = match addr {
                        UnwindInfo::Found(addr) => (addr, true),
                        UnwindInfo::Unknown(addr) => (addr, false),
                    };

                    // Start each line with the address
                    let mut line = format!("{addr:#018x}");

                    // If there is a symbol, add it also to the line
                    if let Some(sym) = self.get_symbol(addr) {
                        line.push_str(&format!(" - {sym}"));
                    }

                    if !known {
                        line.push_str(" (Module not found. Add it to the snapshot directory with .bin suffix)");
                    }

                    // Add the formatted line to the results
                    lines.push(line);
                }
            }
        }

        lines
    }
}

/// The address into the guest memory allocation corresponding to a [`PhysAddr`]
#[derive(Debug, Copy, Clone)]
pub struct GuestPhysAddr(pub u64);

impl std::ops::Deref for GuestPhysAddr {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
