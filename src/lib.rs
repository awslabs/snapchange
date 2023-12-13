//! # Snapchange
//!
//! Lightweight fuzzing of a memory snapshot using KVM
//!
//! Snapchange provides the ability to load a raw memory dump and register state into a
//! KVM VM for execution. At a point in execution, this VM can be reset to its initial
//! state by resetting the dirty pages found by KVM or pages manually dirtied by a
//! fuzzer.
//!
//! ## Quick Links:
//!
//! * [Cookbook](crate::_docs::cookbook) provides examples [fuzz](crate::_docs::cookbook#fuzz-commands), [trace](crate::_docs::cookbook#trace-commands), [coverage](crate::_docs::cookbook#coverage-commands), [minimize](crate::_docs::cookbook#minimize-commands), and [project](crate::_docs::cookbook#project-commands) command line utilities
//! * [Taking a snapshot with QEMU](crate::_docs::qemu_snapshot)
//! * [Architecture](crate::_docs::architecture)
//! * [Fuzzer Lifecycle](crate::_docs::fuzzer_lifecycle)
//!
//! ## Tutorials
//!
//! * [Tutorial 1 - Basic Usage](crate::_docs::examples::example1)
//! * [Tutorial 2 - `LibTIFF` with ASAN](crate::_docs::examples::example2)
//! * [Tutorial 3 - `FFmpeg` with custom mutator](crate::_docs::examples::example3)
//! * [Tutorial 4 - Syscall fuzzer](crate::_docs::examples::example4)
//! * [Tutorial 5 - Redqueen](crate::_docs::examples::example5)
//!
//! # Aspirations
//!
//! * Replay a physical memory and register state snapshot using KVM
//! * Parallel execution across multiple cores
//! * Provide a set of introspection features to the guest VM
//! * Real-time coverage state via breakpoint coverage
//! * Real-time performance metrics of fuzzer components
//! * Provide fuzzing utilities such as single-step debug tracing, testcase minimization, and testcase coverage
//! * Input abstraction to allow custom mutation and generation strategies
//!
//! # Example:
//!
//! #### Create a target fuzzer from the fuzzer template
//!
//! ```console
//! $ cp -r -L fuzzer_template your_new_fuzzer
//! ```
//!
//! #### Modify `your_new_fuzzer/create_snapshot.sh` to take a snapshot of your target
//!
//! #### Update `src/fuzzer.rs` to inject mutated data into the guest VM
//!
//! ```rust
//! #[derive(Default)]
//! pub struct TemplateFuzzer;
//!
//! impl Fuzzer for TemplateFuzzer {
//!     // The type of Input being fuzzed. Used to know how to generate and mutate useful inputs.
//!     type Input = Vec<u8>;
//!     // The starting address of the snapshot
//!     const START_ADDRESS: u64 = 0x402363;
//!     // The maximum length of mutated input to generate
//!     const MAX_INPUT_LENGTH: usize = 100;
//!
//!     fn set_input(&mut self, input: &Self::Input, fuzzvm: &mut FuzzVm<Self>) -> Result<()> {
//!         // Write the mutated input into the data buffer in the guest VM
//!         fuzzvm.write_bytes_dirty(VirtAddr(0x402004), CR3, &input)?;
//!         Ok(())
//!     }
//!
//!     fn reset_breakpoints(&self) -> Option<&[AddressLookup]> {
//!         Some(&[
//!             // Reset when the VM hits example1!main+0x123
//!             AddressLookup::SymbolOffset("example1!main", 0x123)
//!         ])
//!     }
//! }
//! ```
//!
//! #### Start fuzzing with 16 cores
//!
//! ```console
//! $ cargo run -r -- fuzz -c 16
//! ```
//!
//! ## Roadmap of the repo:
//!
//! * [`Fuzzer`] - Trait implemented per target to know how to initialize test cases and provide target specific features:
//!     - [`Fuzzer::set_input`]
//!     - [`Fuzzer::reset_breakpoints`]
//! * [`FuzzVm`] - The executor of the VM along with methods to aid in introspection of the VM. This is passed to many of the
//! [`Fuzzer`] functions for use by a fuzzer. Examples:
//!     - [`FuzzVm::write_bytes_dirty`]
//!     - [`FuzzVm::read_bytes`]
//!     - [`FuzzVm::set_rax`]
//!     - [`FuzzVm::print_context`]
//!     - [`FuzzVm::print_disasm`]
//! * [`FuzzInput`] - Trait used to describe how the input for a fuzzer can be serialized, mutated, and minimized.
//!
//!
//!
#![feature(exclusive_range_pattern)]
#![feature(trait_alias)]
#![feature(thread_id_value)]
#![feature(map_try_insert)]
#![feature(stdsimd)]
#![feature(avx512_target_feature)]
#![feature(core_intrinsics)]
#![feature(associated_type_defaults)]
#![feature(variant_count)]
#![feature(path_file_prefix)]
#![feature(iter_array_chunks)]
#![feature(stmt_expr_attributes)]
#![allow(rustdoc::invalid_rust_codeblocks)]
#![deny(missing_docs)]

use feedback::FeedbackTracker;
use kvm_bindings::{
    kvm_cpuid2, kvm_userspace_memory_region, CpuId, KVM_MAX_CPUID_ENTRIES, KVM_MEM_LOG_DIRTY_PAGES,
    KVM_SYNC_X86_EVENTS, KVM_SYNC_X86_REGS, KVM_SYNC_X86_SREGS,
};
use kvm_ioctls::{Cap, Kvm, VmFd};

pub use anyhow;
use anyhow::{ensure, Context, Result};
use clap::Parser;

use nix::sys::signal::{pthread_sigmask, SigSet, SigmaskHow, Signal};
use vmm_sys_util::fam::FamStructWrapper;

extern crate bitflags;

use std::collections::BTreeMap;
use std::convert::TryInto;
use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

pub use rand;

pub mod fuzzvm;
pub use fuzzvm::{FuzzVm, FuzzVmExit};

pub mod addrs;
pub use addrs::{Cr3, PhysAddr, VirtAddr};

pub mod cmdline;
pub use cmdline::{CommandLineArgs, Modules, ProjectState, SubCommand, TemplateCommandLineArgs};

pub mod rng;

mod segment;

mod vbcpu;
pub use vbcpu::VbCpu;

mod msr;
pub use msr::Msr;

mod page_table;

pub mod fuzzer;
pub use fuzzer::Fuzzer;
use fuzzer::ResetBreakpointType;

mod symbols;
pub use symbols::Symbol;

mod exception;

mod apic;

mod interrupts;
mod regs;

mod stats;
pub use stats::{GlobalStats, Stats};

mod timer;

mod kvm;
pub mod linux;

pub mod memory;
pub use memory::Memory;

mod colors;
mod commands;

mod coverage_analysis;
pub mod expensive_mutators;
pub mod feedback;
mod filesystem;
pub mod fuzz_input;
pub mod mutators;

mod stats_tui;
pub mod utils;
pub use utils::write_crash_input;

pub use fuzz_input::{FuzzInput, InputWithMetadata};

#[macro_use]
mod try_macros;
pub mod cmp_analysis;
pub mod config;
pub mod stack_unwinder;

pub mod _docs;

// use mimalloc::MiMalloc;

// #[global_allocator]
// static GLOBAL: MiMalloc = MiMalloc;

pub(crate) type FxIndexMap<K, V> =
    indexmap::IndexMap<K, V, core::hash::BuildHasherDefault<rustc_hash::FxHasher>>;
pub(crate) type FxIndexSet<K> =
    indexmap::IndexSet<K, core::hash::BuildHasherDefault<rustc_hash::FxHasher>>;
pub(crate) type AIndexSet<K> = indexmap::IndexSet<K, ahash::RandomState>;

/// `dbg!` but with hex output
#[macro_export]
macro_rules! dbg_hex {
    // NOTE: We cannot use `concat!` to make a static string as a format argument
    // of `eprintln!` because `file!` could contain a `{` or
    // `$val` expression could be a block (`{ .. }`), in which case the `eprintln!`
    // will be malformed.
    () => {
        eprintln!("[{}:{}]", file!(), line!())
    };
    ($val:expr $(,)?) => {
        // Use of `match` here is intentional because it affects the lifetimes
        // of temporaries - https://stackoverflow.com/a/48732525/1063961
        match $val {
            tmp => {
                eprintln!("[{}:{}] {} = {:#x?}",
                    file!(), line!(), stringify!($val), &tmp);
                tmp
            }
        }
    };
    ($($val:expr),+ $(,)?) => {
        ($(dbg!($val)),+,)
    };
}

/// What to do after handling a [`FuzzVmExit`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Execution {
    /// Hit coverage event and continue execution of the current VM
    CoverageContinue,

    /// Continue execution of the current VM
    Continue,

    /// Reset the VM state and continue execution to the beginning of the snapshot.
    /// Caused by a crash
    CrashReset {
        /// The folder to write the crashing input to in the `crashes` output directory
        path: String,
    },

    /// Reset the VM state and continue execution to the beginning of the snapshot.
    /// Caused by a timeout
    TimeoutReset,

    /// Reset the VM state and continue execution to the beginning of the snapshot
    Reset,
}

impl Execution {
    /// Returns true if the given Execution state is a crash.
    pub fn is_crash(&self) -> bool {
        match &self {
            Self::CrashReset { .. } => true,
            _ => false,
        }
    }
}

/// List of [`Symbol`] sorted in order by address. Always allows to `binary_search_by_key`.
pub type SymbolList = Vec<Symbol>;

/// Maximum number of cores supported
pub(crate) const MAX_CORES: usize = 200;

lazy_static::lazy_static! {
     /// List of Thread IDs created for the fuzz workers used to send signals to forcibly
     /// exit guests periodically
     pub static ref THREAD_IDS: Vec<Mutex<Option<u64>>> = (0..MAX_CORES)
         .map(|_| Mutex::new(None))
         .collect();
}

/// Set by a timer, signals the main thread to kick all cores out of execution
/// periodically
pub static KICK_CORES: AtomicBool = AtomicBool::new(false);

/// Signals that the main thread is finished and the stats worker can exit
pub(crate) static FINISHED: AtomicBool = AtomicBool::new(false);

/// Current number of columns in the terminal
static COLUMNS: AtomicUsize = AtomicUsize::new(0);

/// Unblock SIGALRM for this thread
fn unblock_sigalrm() -> Result<()> {
    // Create the empty sigset to obtain the currently blocked signals
    let mut curr_sigset = SigSet::empty();

    // Get the current unblocked signal set
    pthread_sigmask(SigmaskHow::SIG_UNBLOCK, None, Some(&mut curr_sigset))?;

    // Add SIGALRM to the unblocked signal set
    curr_sigset.add(Signal::SIGALRM);

    // Update the unblocked signal set
    pthread_sigmask(SigmaskHow::SIG_UNBLOCK, Some(&curr_sigset), None)?;

    // Return success
    Ok(())
}

/// Maximum of crash files to write to a given directory
pub(crate) const MAX_CRASHES: usize = 64;

/// Handle the given [`FuzzVmExit`]
fn handle_vmexit<FUZZER: Fuzzer>(
    vmexit: &FuzzVmExit,
    fuzzvm: &mut FuzzVm<FUZZER>,
    fuzzer: &mut FUZZER,
    crash_dir: Option<&Path>,
    input: &InputWithMetadata<FUZZER::Input>,
    feedback: Option<&mut FeedbackTracker>,
) -> Result<Execution> {
    let execution;

    // Determine what to do with the VMExit
    match vmexit {
        FuzzVmExit::Breakpoint(rip) => {
            match fuzzvm.handle_breakpoint(fuzzer, input, feedback) {
                Err(err) => {
                    // log::warn!("Breakpoint fail.. reset: {err:?}");

                    // Get the current symbol at the current instruction
                    let sym = fuzzvm
                        .get_symbol(*rip)
                        .unwrap_or_else(|| "Unknown symbol".to_string());

                    execution = Execution::CrashReset {
                        path: format!("{}_weird_bp_{rip:#x}_{sym}", err.root_cause()),
                    };
                }
                Ok(res) => {
                    execution = res;
                }
            }
        }
        FuzzVmExit::CoverageBreakpoint(_) => {
            // Hit coverage event, continue execution
            execution = Execution::CoverageContinue;
        }
        FuzzVmExit::Shutdown => {
            let events = fuzzvm.vcpu_events();
            log::info!("EVENTS: {:x?}", events);
            log::info!("EVENTS: {:x?}", fuzzvm.vcpu.get_vcpu_events());
            log::info!("SREGS: {:x?}", fuzzvm.sregs());

            if events.exception.nr > 0 {
                match events.exception.nr {
                    1 => panic!("#DB: DEBUG"),
                    2 => panic!("NMI"),
                    3 => panic!("#BP: BREAKPOINT"),
                    4 => panic!("#OF: OVERFLOW"),
                    6 => {
                        fuzzvm.print_context()?;
                        panic!("#UD: INVALID OPCODE");
                    }
                    8 => panic!("#DF: DOUBLE FAULT"),
                    10 => panic!("#TS: INVALID TSS"),
                    11 => panic!("#NP: SEGMENT NOT PRESENT"),
                    12 => panic!("#SS: STACK SEGMENT FAULT"),
                    13 => panic!("#GP: GENERAL PROTECTION"),
                    14 => panic!("#PF: PAGE FAULT"),
                    _ => panic!("UNKNOWN EXCEPTION: {}", events.exception.nr),
                }
            }

            fuzzvm.print_context()?;

            execution = Execution::Reset;
        }
        FuzzVmExit::IoIn(port) => {
            log::debug!("IoIn {port:#x}");
            // execution = Execution::Continue;
            execution = Execution::CrashReset {
                path: format!(
                    "misc/IoIn_Port_{port:#x}_current_cr3_{:x?}_original_cr3_{:x?}",
                    fuzzvm.cr3().0,
                    fuzzvm.vbcpu.cr3,
                ),
            }
        }
        FuzzVmExit::CrashBreakpoint(rip) => {
            // If no crash dir is given, immediately return with Reset
            if crash_dir.is_none() {
                return Ok(Execution::Reset);
            }

            let mut crash_dir = crash_dir.unwrap().to_owned();

            // Get the current symbol at the current instruction
            let sym = fuzzvm
                .get_symbol(*rip)
                .unwrap_or_else(|| "Unknown symbol".to_string());

            // Always assume fatal crash unless ASAN signals it is not fatal
            let mut fatal = true;

            // Check if we hit the ASAN error reporter and parse the ASAN data if so
            let dirname = if sym.contains("ReportGenericError") {
                let pc = fuzzvm.rdi();
                let _sp = fuzzvm.rsi();
                let _bp = fuzzvm.rdx();
                let crashing_addr = fuzzvm.rcx();
                let is_write = fuzzvm.r8b();
                let _size = fuzzvm.r9b();
                fatal = fuzzvm.read::<bool>(VirtAddr(fuzzvm.rsp() + 0x10), fuzzvm.cr3())?;

                let symbol = fuzzvm.get_symbol(pc).unwrap_or_default();
                let op = if is_write > 0 { "WRITE" } else { "READ" };

                // format!("ASAN_{op}{size}_pc:{pc:#x}_crashing_addr:{crashing_addr:#x}_{symbol}")
                format!("ASAN_{op}_pc:{pc:#x}_crashing_addr:{crashing_addr:#x}_{symbol}")
            } else if sym.contains("ReportOutOfMemory") {
                let alloc = fuzzvm.rdi();
                if alloc >= 4 * 1024 * 1024 * 1024 {
                    format!("ASAN_OutOfMemory_allocation:{alloc:#x}_{alloc}_bytes")
                } else {
                    "ASAN_OutOfMemory_(low bytes, probably not exploitable)".to_string()
                }
            } else if sym.contains("abort") {
                "sigabort".to_string()
            } else if sym.contains("raise") | sym.contains("__GI_raise") {
                "sigraise".to_string()
            } else {
                let mut start = "";

                if matches!(vmexit, FuzzVmExit::BadAddress(_)) {
                    crash_dir = crash_dir.join("badaddrs");
                    if !crash_dir.exists() {
                        std::fs::create_dir(&crash_dir)?;
                    }

                    start = "BADADDR_";
                }

                // Default crash handler
                format!("{start}{rip:#x}_{sym}")
            };

            let dirname = dirname.replace(' ', "_");

            // Set the default execution after this
            let mut curr_execution = if fatal {
                Execution::Reset
            } else {
                Execution::Continue
            };

            if let Some(crash_file) =
                write_crash_input(&crash_dir, &dirname, &input, &fuzzvm.console_output)?
            {
                // Allow the fuzzer to handle the crashing state
                // Useful for things like syscall fuzzer to write a C file from the input
                fuzzer.handle_crash(input, fuzzvm, &crash_file)?;

                // Only send back CrashReset for written crashes
                curr_execution = Execution::CrashReset { path: dirname };
            }

            execution = curr_execution;
        }
        FuzzVmExit::ResetBreakpoint(_rip) => {
            execution = Execution::Reset;
        }
        FuzzVmExit::IoOut(port) => {
            if *port == 0x3f9 {
                execution = Execution::Continue;
            } else {
                execution = Execution::CrashReset {
                    path: format!(
                        "misc/IoOut_Port_{port:#x}_current_cr3_{:x?}_original_cr3_{:x?}",
                        fuzzvm.cr3().0,
                        fuzzvm.vbcpu.cr3
                    ),
                }
            }
        }
        FuzzVmExit::ForceSigFaultBreakpoint(signal) => {
            if matches!(signal, linux::Signal::Trap) {
                panic!("ERROR: Should be handled by FuzzVmExit::Trap");
            }

            // If no crash dir is given, immediately return with Reset
            if crash_dir.is_none() {
                return Ok(Execution::Reset);
            }

            // Get the output directory name for this crash
            let dirname = match signal {
                linux::Signal::SegmentationFault { code, address } => {
                    format!("SIGSEGV_addr_{address:#x}_code_{code:x?}")
                }
                linux::Signal::IllegalInstruction { code, address } => {
                    format!("SIGILL_addr_{address:#x}_code_{code:?}")
                }
                linux::Signal::Unknown {
                    signal,
                    code,
                    arg: _,
                } => {
                    format!("ForceSigFault_Unknown_sig{signal:#x}_code{code:#x}")
                }
                linux::Signal::Trap => {
                    // Immediately return from the function
                    fuzzvm.fake_immediate_return()?;

                    // Continue
                    return Ok(Execution::Continue);
                }
            };

            // Reset after handling
            execution = Execution::CrashReset { path: dirname };
        }
        FuzzVmExit::KernelDieBreakpoint => {
            // Get the address of the `pt_regs` structure
            // let regs = fuzzvm.rsi();

            // Read the structure from the memory
            // let ptregs: linux::PtRegs = fuzzvm.read(VirtAddr(regs), fuzzvm.cr3())?;
            execution = Execution::CrashReset {
                path: "kernel_die".to_string(),
            };
        }
        FuzzVmExit::BadAddress(_) | FuzzVmExit::Hlt => {
            execution = Execution::Reset;
        }
        FuzzVmExit::KasanRead { .. } => {
            execution = Execution::CrashReset {
                path: "kasan_read".to_string(),
            };
        }
        FuzzVmExit::KasanWrite { .. } => {
            execution = Execution::CrashReset {
                path: "kasan_write".to_string(),
            };
        }
        FuzzVmExit::ConsoleWriteBreakpoint
        | FuzzVmExit::ImmediateReturn
        | FuzzVmExit::TimerElapsed
        | FuzzVmExit::DebugException
        | FuzzVmExit::Continue
        | FuzzVmExit::FindModuleNameAndOffset
        | FuzzVmExit::LogStore
        | FuzzVmExit::ConsoleWrite => {
            execution = Execution::Continue;
        }
        FuzzVmExit::MmioRead => {
            execution = Execution::CrashReset {
                path: "mmio_read".to_string(),
            };
        }
        FuzzVmExit::MmioWrite => {
            execution = Execution::CrashReset {
                path: "mmio_write".to_string(),
            };
        }
        FuzzVmExit::Unimpl => {
            // log::warn!("Hit unknown vmexit");
            execution = Execution::CrashReset {
                path: "unimpl_vmexit".to_string(),
            };
        }
        FuzzVmExit::Unknown => {
            execution = Execution::CrashReset {
                path: "UnknownVmExit".to_string(),
            };
        }
        FuzzVmExit::Exception => {
            execution = Execution::CrashReset {
                path: "Exception".to_string(),
            };
        }
        FuzzVmExit::Hypercall => {
            execution = Execution::CrashReset {
                path: "Hypercall".to_string(),
            };
        }
        FuzzVmExit::Debug(exception) => {
            execution = Execution::CrashReset {
                path: format!("Debug_{exception:?}"),
            };
        }
        FuzzVmExit::InternalError => {
            execution = Execution::CrashReset {
                path: "InternalError".to_string(),
            };
        }
        FuzzVmExit::Trap => {
            fuzzvm.fake_immediate_return()?;
            execution = Execution::Continue;
        }
        FuzzVmExit::COUNT => unreachable!(),
    }

    // log::info!("Execution: {execution:x?}");

    // Return the execution
    Ok(execution)
}

/// Register the memory allocation given to the [`FuzzVm`] to KVM as the physical
/// memory of the VM, excluding the APIC page. Returns the (physical address, userspace
/// address) for each memory region to aid in resetting the guest VM.
///
/// # Errors
///
/// * Failure from KVM on `set_user_memory_region`
pub fn register_guest_memory(
    vm: &VmFd,
    memory: *mut libc::c_void,
    guest_memory_size: u64,
) -> Result<[kvm_userspace_memory_region; 3]> {
    ensure!(fuzzvm::APIC_BASE < fuzzvm::TSS_BASE);

    let mut memory_regions = [
        kvm_userspace_memory_region::default(),
        kvm_userspace_memory_region::default(),
        kvm_userspace_memory_region::default(),
    ];

    // Get the address of the guest memory allocation
    let mem_addr = memory as u64;

    // Allocate memory from [0, APIC_BASE] in the guest
    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: fuzzvm::APIC_BASE,
        userspace_addr: mem_addr,
        flags: KVM_MEM_LOG_DIRTY_PAGES,
    };

    // Set the memory region into the VM
    unsafe {
        vm.set_user_memory_region(mem_region)
            .context("Failed to set user memory region 0")?;
    }

    memory_regions[0] = mem_region;

    // Calculate the length of the remaining memory after the APIC page
    let mut size_remainder: u64 = fuzzvm::TSS_BASE - fuzzvm::APIC_BASE - 0x1000;

    // Allocate memory from [APIC_BASE + 0x1000..TSS_BASE] in the guest
    let mem_region = kvm_userspace_memory_region {
        slot: 1,
        guest_phys_addr: fuzzvm::APIC_BASE + 0x1000,
        memory_size: size_remainder,
        // userspace_addr: mem_addr + size_remainder,
        userspace_addr: mem_addr + fuzzvm::APIC_BASE + 0x1000,
        flags: KVM_MEM_LOG_DIRTY_PAGES,
    };

    // set the memory region into the vm
    unsafe {
        vm.set_user_memory_region(mem_region)
            .context("failed to set user memory region 1")?;
    }

    memory_regions[1] = mem_region;

    // Calculate the length of the remaining memory after the APIC page
    size_remainder = guest_memory_size - fuzzvm::TSS_BASE - 0x1000;

    // Allocate memory from [TSS_BASE + 0x1000..] in the guest
    let mem_region = kvm_userspace_memory_region {
        slot: 2,
        guest_phys_addr: fuzzvm::TSS_BASE + 0x1000,
        memory_size: size_remainder,
        userspace_addr: mem_addr + fuzzvm::TSS_BASE + 0x1000,
        flags: KVM_MEM_LOG_DIRTY_PAGES,
    };

    // set the memory region into the vm
    unsafe {
        vm.set_user_memory_region(mem_region)
            .context("failed to set user memory region 2")?;
    }

    memory_regions[2] = mem_region;

    Ok(memory_regions)
}

/// Get the supported CPUIDs from KVM
///
/// # Errors
///
/// Returns a larger number of CPUIDs than `KVM_MAX_CPUID_ENTRIES`
///
/// # Panics
///
/// Fails to get the slice of CPUIDs from KVM
#[must_use]
pub fn get_supported_cpuids(kvm: &Kvm) -> CpuId {
    kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
        .expect("Failed to get supporting CPUIDs")
}

/// Sanity check that needed features are enabled in KVM
///
/// # Panics
/// * Required `KVM_SYNC` regs, sregs, or events is missing
/// * If any of the following capabilities are missing:
///     - `SetGuestDebug`
///     - `X86RobustSinglestep`
///     - `VcpuEvents`
///     - `SetTssAddr`
///     - `Irqchip`
///     - `ImmediateExit`
pub fn sanity_check_kvm(kvm: &Kvm) {
    let _api_version = kvm.get_api_version();

    // let _supported_msrs   = get_supported_msrs(kvm)?;
    // let _supported_cpuids = get_supported_cpuids(kvm)?;

    #[allow(clippy::cast_sign_loss)]
    let sync_regs = kvm::check_extension_int(kvm, Cap::SyncRegs) as u32;
    assert!(sync_regs == (KVM_SYNC_X86_REGS | KVM_SYNC_X86_SREGS | KVM_SYNC_X86_EVENTS));

    // assert!(kvm.check_extension(Cap::SetGuestDebug));

    // Enable guest debug for single step and breakpoints
    assert!(kvm.check_extension(Cap::X86RobustSinglestep));
    assert!(kvm.check_extension(Cap::VcpuEvents));
    assert!(kvm.check_extension(Cap::SetTssAddr));
    assert!(kvm.check_extension(Cap::Irqchip));
    assert!(kvm.check_extension(Cap::ImmediateExit));
    assert!(kvm.check_extension(Cap::EnableCapVm));
}

/// Kick cores when triggered by a signal
pub(crate) fn kick_cores() {
    loop {
        if crate::FINISHED.load(Ordering::SeqCst) {
            log::info!("[kick_cores] FINISHED");
            break;
        }

        // If the kick timer has elapsed, it sets this variable
        if KICK_CORES.load(Ordering::SeqCst) {
            // Send SIGALRM to all executing threads
            for core_id in 0..THREAD_IDS.len() {
                // Get stored address of this potential vcpu
                if let Some(thread_id) = *THREAD_IDS[core_id].lock().unwrap() {
                    // Send SIGALRM to the current thread
                    unsafe {
                        libc::pthread_kill(thread_id, libc::SIGALRM);
                    }
                }
            }

            // Reset the kick cores
            KICK_CORES.store(false, Ordering::SeqCst);
        }

        // Minimal sleep to avoid too much processor churn
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    log::info!("[kick_cores] Waiting for all threads to die....");
    log::info!("[kick_cores] FINISHED");
}

/// Block SIGALRM for this thread
pub(crate) fn block_sigalrm() -> Result<()> {
    let mut curr_sigset = SigSet::empty();

    // Get the current unblocked signal set
    pthread_sigmask(SigmaskHow::SIG_BLOCK, None, Some(&mut curr_sigset))?;

    // Add SIGALRM to the unblocked signal set
    curr_sigset.add(Signal::SIGALRM);

    // Update the unblocked signal set
    pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&curr_sigset), None)?;

    // Return success
    Ok(())
}

/// Enable manual dirty log protect in the given VM.
///
/// According to the KVM Documentation, "At the cost of a slightly more complicated
/// operation, this provides better scalability and responsiveness"
fn enable_manual_dirty_log_protect(vm: &VmFd) -> Result<()> {
    /// Argument to enable the `DirtyLogProtect2` capability
    const KVM_DIRTY_LOG_MANUAL_PROTECT_ENABLE: u64 = 1;

    /// Capability number for `DirtyLogProtect2`
    const KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2: u32 = 168;

    // Create the capability to enable in the VM
    let cap = kvm_bindings::kvm_enable_cap {
        cap: KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2,
        args: [KVM_DIRTY_LOG_MANUAL_PROTECT_ENABLE, 0, 0, 0],
        ..kvm_bindings::kvm_enable_cap::default()
    };

    // Enable the capability
    vm.enable_cap(&cap)?;

    // Return success
    Ok(())
}

/// Created environment needed for each of the subcommands available
struct KvmEnvironment {
    /// Open KVM handle
    kvm: Kvm,

    /// Available CPUIDs
    cpuids: FamStructWrapper<kvm_cpuid2>,

    /// Physical memory file from the project
    physmem_file: File,

    /// The address of the clean snapshot with coverage breakpoints applied. This is the
    /// memory region that the cores will use to restore the original snapshot during fuzzing
    clean_snapshot: Arc<RwLock<Memory>>,

    /// Parsed symbols if the project has symbols available
    symbols: Option<SymbolList>,

    /// Parsed symbol breakpoints if any coverage breakpoints are available in the project
    symbol_breakpoints: Option<BTreeMap<(VirtAddr, Cr3), ResetBreakpointType>>,
}

/// Perform KVM initialization routines and common project setup steps for all
/// subcommands
fn init_environment(project_state: &ProjectState) -> Result<KvmEnvironment> {
    // Init KVM for this host
    let kvm = Kvm::new().context("Failed to access KVM")?;

    // Sanity check the necessary KVM features are available
    sanity_check_kvm(&kvm);

    // Get the list of all CPUIDs available in KVM
    let cpuids = get_supported_cpuids(&kvm);

    // Get the sorted symbols and crashing breakpoints
    let (symbols, symbol_breakpoints) = cmdline::parse_symbols(
        &project_state.symbols,
        Cr3(project_state.vbcpu.cr3 & !0xfff),
    )?;

    // Create the VM for this core
    let vm = kvm.create_vm().context("Failed to create VM from KVM")?;

    // Enable dirty bits
    enable_manual_dirty_log_protect(&vm)?;

    // Open the physical memory backing for this snapshot
    let physmem_file = OpenOptions::new()
        .read(true)
        .open(&project_state.physical_memory)?;

    let guest_memory_size = project_state.config.guest_memory_size;

    // Ensure the mmap'ed memory for the snapshot is large enough
    ensure!(
        guest_memory_size >= physmem_file.metadata()?.len(),
        "Snapshot physical memory is larger than expected. \
         Increase config::guest_memory_size"
    );

    // Ensure the expected guest memory size can fit on this system
    let guest_memory_size: usize = guest_memory_size
        .try_into()
        .expect("Guest memory size too large");

    // Create the shared clean memory state to copy from
    let clean_snapshot_buff = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            guest_memory_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_HUGE_2GB,
            physmem_file.as_raw_fd(),
            0,
        )
    };

    assert!(
        clean_snapshot_buff as usize != usize::MAX,
        "Failed to mmap clean snapshot"
    );

    let clean_snapshot = Arc::new(RwLock::new(Memory::from_addr(
        clean_snapshot_buff as u64,
        guest_memory_size.try_into().unwrap(),
    )));

    // Return the created environment
    Ok(KvmEnvironment {
        kvm,
        cpuids,
        physmem_file,
        clean_snapshot,
        symbols,
        symbol_breakpoints,
    })
}

/// Main entrypoint a target calls providing the command line utilities
///
/// # Errors
///
/// * Fail to initialize the kick timer
/// * Fail to set log file for TUI
///
/// # Panics
///
/// * If terminal window width doesn't fit a `usize`
pub fn snapchange_main<FUZZER: Fuzzer + 'static>() -> Result<()> {
    // Get the number of columns for the terminal for print formatting
    #[cfg(not(miri))]
    unsafe {
        let mut winsize: libc::winsize = core::mem::zeroed();
        libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut winsize);
        COLUMNS.store(try_usize!(winsize.ws_col), Ordering::SeqCst);
    };

    // Parse the command line arguments
    let args = CommandLineArgs::parse();

    // Init the logger to, at minimum, info level
    let mut log_level = args.verbosity.log_level_filter();
    if matches!(
        log_level,
        log::LevelFilter::Off | log::LevelFilter::Warn | log::LevelFilter::Error
    ) {
        log_level = log::LevelFilter::Info;
    }

    // All commands besides `fuzz` will use the `env_logger`. Fuzz will use `tui_logger`
    // when TUI is enabled otherwise `env_logger`
    if !matches!(args.command, SubCommand::Fuzz(_)) {
        if matches!(args.command, SubCommand::FindInput(_)) {
            log_level = log::LevelFilter::Off;
        }

        env_logger::Builder::new().filter_level(log_level).init();
    }

    // Get the snapstot state from the given project directory
    #[cfg(not(miri))]
    let proj_state = cmdline::get_project_state(&args.project, Some(&args.command))?;

    #[cfg(miri)]
    let proj_state = ProjectState {};

    // Init the kick timer used by all commands except the project command
    if !matches!(args.command, SubCommand::Project(_)) {
        timer::init_kick_timer()?;
    }

    // Execute the specific subcommand
    let res = match args.command {
        SubCommand::Fuzz(args) => {
            if args.ascii_stats {
                env_logger::Builder::new().filter_level(log_level).init();
            } else {
                tui_logger::init_logger(log_level).unwrap();
                tui_logger::set_default_level(log_level);
                tui_logger::set_log_file("fuzzer.log")?;
            }

            commands::fuzz::run::<FUZZER>(proj_state, &args)
        }
        SubCommand::Trace(args) => commands::trace::run::<FUZZER>(&proj_state, &args),
        SubCommand::Minimize(args) => commands::minimize::run::<FUZZER>(&proj_state, &args),
        SubCommand::Project(args) => commands::project::run(&proj_state, &args),
        SubCommand::Coverage(args) => commands::coverage::run::<FUZZER>(&proj_state, &args),
        SubCommand::FindInput(args) => commands::find_input::run::<FUZZER>(&proj_state, &args),
        SubCommand::CorpusMin(args) => commands::corpus_min::run::<FUZZER>(&proj_state, &args),

        #[cfg(feature = "redqueen")]
        SubCommand::Redqueen(args) => commands::redqueen::run::<FUZZER>(&proj_state, &args),
    };

    // Force flush the event buffer to disk
    tui_logger::move_events();

    res
}

/// Import most important snapchange functions, traits, and types.
/// ```
/// use snapchange::prelude::*;
/// ```
pub mod prelude {
    pub use super::rand::seq::SliceRandom;
    pub use super::rand::Rng as _;
    pub use super::{
        addrs::{Cr3, VirtAddr},
        anyhow,
        anyhow::Result,
        fuzzer::{AddressLookup, Breakpoint, BreakpointType, Fuzzer},
        fuzzvm::FuzzVm,
        rand,
        rng::Rng,
        snapchange_main, Execution, FuzzInput, InputWithMetadata,
        fuzz_input::{NullMinimizerState, BytesMinimizeState, MinimizeControlFlow},
    };

    #[cfg(feature = "custom_feedback")]
    pub use super::feedback::FeedbackTracker;
}
