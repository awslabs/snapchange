//! Fuzzer trait implementation for target specific fuzzers

#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]
#![allow(unused_imports, clippy::module_name_repetitions)]
#![allow(clippy::module_name_repetitions)]
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{anyhow, ensure, Result};
use rand::seq::SliceRandom;
use rand::Rng as _;

use crate::addrs::{Cr3, VirtAddr};
use crate::cmp_analysis::RedqueenRule;
use crate::expensive_mutators;
use crate::filesystem::FileSystem;
use crate::fuzz_input::FuzzInput;
use crate::fuzzvm::{FuzzVm, HookFn};
use crate::mutators;
use crate::rng::Rng;
use crate::Execution;

/// Type of breakpoint being applied
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum BreakpointType {
    /// Breakpoint will only trigger the callback once
    SingleShot,

    /// Breakpoint will be re-applied after triggered
    Repeated,

    /// Breakpoint assumes a hook is handling the instruction. The underlying instruction
    /// is not modified and the breakpoint is not overwritten.
    Hook,
}

/// Type of reset breakpoint applied signifying whether the state should be kept or
/// discarded on reset
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResetBreakpointType {
    /// If this symbol is hit, reset the guest without saving the state or input
    Reset,

    /// If this symbol is hit, signal that the guest has crashed. Reset the guest while
    /// saving the input and crashing state
    Crash,

    /// Address sanitizer report generic error
    ReportGenericError,

    /// Address sanitizer report out of memory error
    ReportOutOfMemory,

    /// Special type for linux crashes during #PF handler. Reset the guest while saving
    /// the input and parse the crashing signal fields from `force_sig_fault`
    ForceSigFault,

    /// If hit, display the contents of the serial write to the screen
    ConsoleWrite,

    /// Kernel called `__die`
    KernelDie,

    /// Kasan report
    KasanReport,

    /// printk message writing post formatting
    LogStore,

    /// Immediately return from this symbol by popping the stack and setting RIP
    ImmediateReturn,

    /// Single step
    EnableSingleStep,

    /// Manually fill in the module name and offset for asan to avoid calling
    /// `llvm-symbolizer`
    FindModuleNameAndOffset,

    /// Handle Invalid Op
    HandleInvalidOp,
}

/// The method used to lookup a given breakpoint
#[derive(Debug)]
#[allow(dead_code)]
pub enum BreakpointLookup {
    /// The address to apply this breakpoint to
    Address(VirtAddr, Cr3),

    /// The symbol substring to look for, plus the given offset, and apply a breakpoint
    /// to if found
    SymbolOffset(&'static str, u64),
}

/// A breakpoint that can be applied to a VM
pub struct Breakpoint<FUZZER: Fuzzer> {
    /// The virtual address or symbol where the breakpoint is applied
    pub lookup: BreakpointLookup,

    /// The type of breakpoint being applied
    pub bp_type: BreakpointType,

    /// Hook function to call when this breakpoint is hit
    pub bp_hook: HookFn<FUZZER>,
}

/// Generic fuzzer trait
pub trait Fuzzer: Default + Sized {
    /// The input type used by this fuzzer
    type Input: FuzzInput;

    /// The maximum length for an input used to truncate long inputs.
    const MAX_INPUT_LENGTH: usize;

    /// The expected starting address of the snapshot for this fuzzer. This is a
    /// sanity check to ensure the fuzzer matches the given snapshot.
    const START_ADDRESS: u64;

    /// Maximum number of mutation functions called during mutation
    const MAX_MUTATIONS: u64 = 16;

    /// Set the current input into the fuzzvm, specific to this fuzzer
    ///
    /// # Errors
    ///
    /// * The target specific fuzzer failed to write the input into the guest
    fn set_input(&mut self, input: &Self::Input, fuzzvm: &mut FuzzVm<Self>) -> Result<()>;

    /// Reset the state of the current fuzzer
    fn reset_fuzzer_state(&mut self) {
        // By default, resetting fuzzer state does nothing
    }

    /// Set of syscalls the fuzzer will manually handle, while ignoring all others.
    /// Cannot be used with `syscall_blacklist`
    fn syscall_whitelist(&self) -> &'static [u64] {
        &[]
    }

    /// Set of syscalls the fuzzer will manually NOT handle, while handling all others.
    /// Cannot be used with `syscall_whitelist`
    fn syscall_blacklist(&self) -> &'static [u64] {
        &[]
    }

    /// Get an input from the corpus based on this scheduling strategy. By default, a
    /// random corpus entry is returned
    fn schedule_next_input(
        &mut self,
        corpus: &[Self::Input],
        rng: &mut Rng,
        dictionary: &Option<Vec<Vec<u8>>>,
    ) -> Self::Input {
        // Small chance to make a new input
        if rng.next() % 0xffff == 42 {
            Self::Input::generate(corpus, rng, dictionary, Self::MAX_INPUT_LENGTH)
        } else {
            // Otherwise attempt to pick one from the corpus
            if let Some(input) = corpus.choose(rng) {
                input.clone()
            } else {
                // Default to generating a new input
                Self::Input::generate(corpus, rng, dictionary, Self::MAX_INPUT_LENGTH)
            }
        }
    }

    /// Mutate the given `input` in place using the `corpus`, `rng`, and `dictionary`
    fn mutate_input(
        &mut self,
        input: &mut Self::Input,
        corpus: &[Self::Input],
        rng: &mut Rng,
        dictionary: &Option<Vec<Vec<u8>>>,
    ) -> Vec<String> {
        Self::Input::mutate(
            input,
            corpus,
            rng,
            dictionary,
            Self::MAX_INPUT_LENGTH,
            Self::MAX_MUTATIONS,
        )
    }

    /// Initialize the VM before starting any fuzz case
    ///
    /// # Errors
    ///
    /// * The target specific fuzzer failed to initialize the VM
    fn init_vm(&mut self, _fuzzvm: &mut FuzzVm<Self>) -> Result<()> {
        Ok(())
    }

    /// Addresses or symbols that, if hit, trigger execution of a callback function.  All
    /// symbols are checked to see if they contain the given symbol substring.
    fn breakpoints(&self) -> Option<&[Breakpoint<Self>]> {
        None
    }

    /// Breakpoints that, if hit, will cause the VM to be reset without saving state
    fn reset_breakpoints(&self) -> Option<&[BreakpointLookup]> {
        None
    }

    /// Breakpoints that, if hit, will cause the VM to be reset while saving input and
    /// state
    fn crash_breakpoints(&self) -> Option<&[BreakpointLookup]> {
        None
    }

    /// Handle a syscall with the given [`FuzzVm`]
    ///
    /// # Errors
    ///
    /// * The fuzzer requested to handle syscalls, but did not implement the syscall
    ///   handler
    fn handle_syscall(
        &mut self,
        _fuzzvm: &mut FuzzVm<Self>,
        syscall: u64,
        _input: &Self::Input,
    ) -> Result<Execution> {
        unimplemented!(
            "Syscall handler not implemented: {:?}",
            crate::linux::Syscall::try_from(syscall)
        )
    }

    /// Fuzzer specific handling of a crashing `input` bytes with the [`FuzzVm`] that
    /// originally will write to `crash_file`. Defaults to nothing.
    ///
    /// # Errors
    ///
    /// * The target specific fuzzer failed to handle a crashing input
    fn handle_crash(
        &self,
        _input: &Self::Input,
        _fuzzvm: &mut FuzzVm<Self>,
        _crash_file: &Path,
    ) -> Result<()> {
        // No action by default
        Ok(())
    }

    /// Fuzzer specific handling of `snapchange -p <PROJECT> trace testcase`
    ///
    /// # Errors
    ///
    /// * The target specific fuzzer failed to execute a testcase
    fn test_trace(&mut self, _fuzzvm: &mut FuzzVm<Self>) -> Result<()> {
        unimplemented!()
    }

    /// Initialize files available to the guest
    ///
    /// # Errors
    ///
    /// * The target specific fuzzer failed to initialize a filesystem
    fn init_files(&self, _fs: &mut FileSystem) -> Result<()> {
        Ok(())
    }

    /// Get the breakpoints used to gather Redqueen metadata
    ///
    /// If a snapshot includes a `.cmps` file, then the fuzzer `build.rs` will attempt to
    /// generate a set of breakpoints. These breakpoints trigger on comparison operations
    /// and are used to help to more precisely mutate an input based on this runtime
    /// information
    #[cfg(feature = "redqueen")]
    fn redqueen_breakpoints(&self) -> Option<&[Breakpoint<Self>]> {
        None
    }

    /// The addresses of the redqueen breakpoints
    #[must_use]
    #[cfg(feature = "redqueen")]
    fn redqueen_breakpoint_addresses() -> &'static [u64] {
        &[]
    }
}
