//! Executing the `minimize` command
use anyhow::{anyhow, ensure, Context, Result};

use std::collections::{BTreeMap, VecDeque};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::time::{Duration, Instant};

use core_affinity::CoreId;
use kvm_bindings::CpuId;
use kvm_ioctls::VmFd;

use crate::config::Config;
use crate::fuzz_input::FuzzInput;
use crate::fuzzer::Fuzzer;
use crate::fuzzvm::FuzzVm;
use crate::stack_unwinder::StackUnwinders;
use crate::{cmdline, fuzzvm, unblock_sigalrm, THREAD_IDS};
use crate::{handle_vmexit, init_environment, KvmEnvironment, ProjectState};
use crate::{Cr3, Execution, ResetBreakpointType, Symbol, VbCpu, VirtAddr};

/// Stages to measure performance during minimization
#[derive(Debug, Copy, Clone)]
#[allow(clippy::missing_docs_in_private_items)]
#[allow(clippy::upper_case_acronyms)]
enum Counters {
    InputClone,
    InputMinimize,
    ResetGuest,
    Execution,
    CheckResult,
}

/// Thread worker used to minimize the input based on the size of the input
fn start_core<FUZZER: Fuzzer>(
    core_id: CoreId,
    vm: &VmFd,
    vbcpu: &VbCpu,
    cpuid: &CpuId,
    snapshot_fd: i32,
    clean_snapshot: u64,
    symbols: &Option<VecDeque<Symbol>>,
    symbol_breakpoints: Option<BTreeMap<(VirtAddr, Cr3), ResetBreakpointType>>,
    coverage_breakpoints: Option<BTreeMap<VirtAddr, u8>>,
    input_case: &Path,
    vm_timeout: Duration,
    max_iterations: u32,
    config: Config,
) -> Result<()> {
    // Use the current fuzzer
    let mut fuzzer = FUZZER::default();

    // Sanity check that the given fuzzer matches the snapshot
    ensure!(
        FUZZER::START_ADDRESS == vbcpu.rip,
        fuzzvm::Error::SnapshotMismatch
    );

    log::info!("Minimizing using {} iterations", max_iterations);

    // Store the thread ID of this thread used for passing the SIGALRM to this thread
    let thread_id = unsafe { libc::pthread_self() };
    *THREAD_IDS[core_id.id].lock().unwrap() = Some(thread_id);

    // Unblock SIGALRM to enable this thread to handle SIGALRM
    unblock_sigalrm()?;

    // Set the core affinity for this core
    core_affinity::set_for_current(core_id);

    #[cfg(feature = "redqueen")]
    let redqueen_rules = BTreeMap::new();

    // Create a 64-bit VM for fuzzing
    let mut fuzzvm = FuzzVm::create(
        u64::try_from(core_id.id)?,
        &mut fuzzer,
        vm,
        vbcpu,
        cpuid,
        snapshot_fd.as_raw_fd(),
        clean_snapshot,
        coverage_breakpoints,
        symbol_breakpoints,
        symbols,
        config,
        StackUnwinders::default(),
        #[cfg(feature = "redqueen")]
        redqueen_rules,
    )?;

    log::info!("Minimize timeout: {:?}", vm_timeout);

    let mut execution;

    // Get the initial input
    let input_bytes = std::fs::read(input_case)?;
    let mut input = <FUZZER::Input as FuzzInput>::from_bytes(&input_bytes)?;

    let start_input_size = input_bytes.len();

    // Set the input into the VM as per the fuzzer
    fuzzer.set_input(&input, &mut fuzzvm)?;

    // Initialize the performance counters for executing a VM
    let mut perf = crate::fuzzvm::VmRunPerf::default();

    // Top of the run iteration loop for the current fuzz case
    for _ in 0.. {
        // Execute the VM
        let ret = fuzzvm.run(&mut perf)?;

        // Handle the FuzzVmExit to determine
        execution = handle_vmexit(&ret, &mut fuzzvm, &mut fuzzer, None, &input)?;

        // During single step, breakpoints aren't triggered. For this reason,
        // we need to check if the instruction is a breakpoint regardless in order to
        // apply fuzzer specific breakpoint logic. We can ignore the "unknown breakpoint"
        // error that is thrown if a breakpoint is not found;
        if let Ok(new_execution) = fuzzvm.handle_breakpoint(&mut fuzzer, &input) {
            execution = new_execution;
        } else {
            // Ignore the unknown breakpoint case since we check every instruction due to
            // single stepping here.
        }

        // Check if the VM needs to be timed out
        if fuzzvm.start_time.elapsed() > vm_timeout {
            log::info!("Tracing VM Timed out.. exiting");
            execution = Execution::Reset;
        }

        // Reset the VM if the vmexit handler says so
        if matches!(execution, Execution::Reset | Execution::CrashReset { .. }) {
            break;
        }
    }

    fuzzvm.print_context()?;

    let mut stack_size = 0x100;
    let mut orig_stack = vec![0_u64; stack_size];
    for _ in 0..0x100 {
        stack_size -= 1;
        orig_stack = vec![0_u64; stack_size];
        if fuzzvm
            .read_bytes(VirtAddr(fuzzvm.rsp()), fuzzvm.cr3(), &mut orig_stack)
            .is_ok()
        {
            continue;
        }
    }

    let orig_reg_state = *fuzzvm.regs();
    let orig_output = fuzzvm.console_output.clone();

    // Create a random number generatr
    let mut rng = crate::rng::Rng::new();

    // Initialize the performance counters for executing a VM
    let mut perf = crate::fuzzvm::VmRunPerf::default();

    log::info!("Input len: {}", input_bytes.len());

    let start = std::time::Instant::now();
    let mut timer = std::time::Instant::now();

    let timers_start = rdtsc();
    let mut timers = [0; std::mem::variant_count::<Counters>()];

    /// Record the number of clock cycles `$work` takes
    macro_rules! time {
        ($marker:ident, $work:expr) => {{
            // Start the timer for this work
            let start = rdtsc();

            // Perform the given work
            let result = $work;

            // Calculate the elapsed time
            let elapsed = rdtsc() - start;

            // Add the time took to exeute this work
            timers[Counters::$marker as usize] += elapsed;

            // Return any result from the work
            result
        }};
    }

    for iters in 0..max_iterations {
        if timer.elapsed() > Duration::from_secs(1) {
            log::info!(
                "Iters {iters:6}/{max_iterations} | Exec/sec {:6.2}",
                f64::from(iters) / start.elapsed().as_secs_f64()
            );

            let curr_time = rdtsc() - timers_start;

            /// Display the percentage of time the given `Counter` has taken thus far
            macro_rules! stats {
                ($counter:ident) => {{
                    log::info!(
                        "    {:20}: {:6.2}%",
                        stringify!($counter),
                        timers[Counters::$counter as usize] as f64 / curr_time as f64 * 100.,
                    );
                }};
            }

            stats!(InputClone);
            stats!(InputMinimize);
            stats!(Execution);
            stats!(CheckResult);
            stats!(ResetGuest);

            timer = Instant::now();
        }

        // Clone a new input for this minimization run
        let mut curr_input = time!(InputClone, { input.clone() });

        // Minimize the input based on the Input type
        time!(InputMinimize, {
            FUZZER::Input::minimize(&mut curr_input, &mut rng);
        });

        // Reset the guest with the minimized input
        time!(ResetGuest, {
            // Reset the guest back to the beginning
            fuzzvm.reset_guest_state(&mut fuzzer)?;

            // Reset the fuzzer state
            fuzzer.reset_fuzzer_state();

            if !orig_output.is_empty() {
                assert!(fuzzvm.console_output != orig_output);
            }

            // Set the input into the VM as per the fuzzer
            fuzzer.set_input(&curr_input, &mut fuzzvm)?;
        });

        // Execute the guest until reset, timeout, or crash
        time!(Execution, {
            // Execute the new input once
            loop {
                // Execute the VM
                let ret = fuzzvm.run(&mut perf)?;

                // Handle the FuzzVmExit to determine
                execution = handle_vmexit(&ret, &mut fuzzvm, &mut fuzzer, None, &curr_input)?;

                // During single step, breakpoints aren't triggered. For this reason,
                // we need to check if the instruction is a breakpoint regardless in order to
                // apply fuzzer specific breakpoint logic. We can ignore the "unknown breakpoint"
                // error that is thrown if a breakpoint is not found;
                if let Ok(new_execution) = fuzzvm.handle_breakpoint(&mut fuzzer, &input) {
                    execution = new_execution;
                } else {
                    // Ignore the unknown breakpoint case since we check every instruction
                    // due to single stepping here.
                }

                // Check if the VM needs to be timed out
                if fuzzvm.start_time.elapsed() > vm_timeout {
                    log::info!("VM Timed out.. exiting");
                    execution = Execution::Reset;
                }

                // Reset the VM if the vmexit handler says so
                if matches!(
                    execution,
                    Execution::Reset
                        | Execution::CrashReset { .. }
                        | Execution::TimeoutReset { .. }
                ) {
                    break;
                }
            }
        });

        // Check if the VM resulted in the same crashing state. If so, keep the minimized input as the
        // current best input
        time!(CheckResult, {
            let curr_reg_state = *fuzzvm.regs();
            let mut curr_stack = vec![0u64; stack_size];
            fuzzvm.read_bytes(VirtAddr(fuzzvm.rsp()), fuzzvm.cr3(), &mut curr_stack)?;

            // If the guest exited with the same final state, then keep the minimized input
            let success = orig_reg_state == curr_reg_state
                && orig_stack == curr_stack
                && orig_output == fuzzvm.console_output;

            if success {
                input = curr_input;
            }
        });
    }

    let ext = "min_by_size";

    // Get the new minimized filename
    let orig_file_name = input_case
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("UNKNOWNFILENAME"));
    let mut min_file = input_case.to_path_buf();
    min_file.set_file_name(&format!("{}_{ext}", orig_file_name.to_string_lossy()));

    let mut result_bytes = Vec::new();
    input.to_bytes(&mut result_bytes)?;

    // Write the minimized file
    log::info!(
        "Minimized from {} -> {} bytes",
        start_input_size,
        result_bytes.len()
    );

    log::info!("Writing minimized file: {:?}", min_file);
    std::fs::write(&min_file, &result_bytes)?;

    // Allow the fuzzer to handle the crashing state
    // Useful for things like syscall fuzzer to write a C file from the input
    fuzzer.handle_crash(&input, &mut fuzzvm, &min_file)?;

    Ok(())
}

/// Execute the Minimize subcommand to gather a single step trace over an input
pub(crate) fn run<FUZZER: Fuzzer>(
    project_state: &ProjectState,
    args: &cmdline::Minimize,
) -> Result<()> {
    let KvmEnvironment {
        kvm,
        cpuids,
        physmem_file,
        clean_snapshot_addr,
        symbols,
        symbol_breakpoints,
    } = init_environment(project_state)?;

    // Create the VM for this core
    let vm = kvm.create_vm().context("Failed to create VM from KVM")?;
    // Get the first available core to trace on
    let core_id = *core_affinity::get_core_ids()
        .ok_or_else(|| anyhow!("Failed to get core ids"))?
        .first()
        .ok_or_else(|| anyhow!("No valid cores"))?;

    // Start executing on this core
    start_core::<FUZZER>(
        core_id,
        &vm,
        &project_state.vbcpu,
        &cpuids,
        physmem_file.as_raw_fd(),
        clean_snapshot_addr,
        &symbols,
        symbol_breakpoints,
        None, // No need to apply coverage breakpoints for minimize
        &args.path,
        args.timeout,
        args.iterations_per_stage,
        project_state.config.clone(),
    )?;

    // Success
    Ok(())
}

/// Wrapper around `rdtsc`
fn rdtsc() -> u64 {
    unsafe { std::arch::x86_64::_rdtsc() }
}
