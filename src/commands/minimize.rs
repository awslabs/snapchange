//! Executing the `minimize` command
use anyhow::{anyhow, ensure, Context, Result};
use rustc_hash::FxHashSet;

use std::collections::{BTreeMap, VecDeque};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use core_affinity::CoreId;
use kvm_bindings::CpuId;
use kvm_ioctls::VmFd;

use crate::cmdline::{self, MinimizeCodeCovLevel};
use crate::config::Config;
use crate::fuzz_input::FuzzInput;
use crate::fuzzer::{BreakpointType, Fuzzer};
use crate::fuzzvm::FuzzVm;
use crate::memory::Memory;
use crate::stack_unwinder::StackUnwinders;
use crate::{fuzzvm, unblock_sigalrm, THREAD_IDS};
use crate::{init_environment, KvmEnvironment, ProjectState};
use crate::{Cr3, Execution, ResetBreakpointType, Symbol, VbCpu, VirtAddr};

/// Stages to measure performance during minimization
#[derive(Debug, Copy, Clone)]
#[allow(clippy::missing_docs_in_private_items)]
#[allow(clippy::upper_case_acronyms)]
enum Counters {
    InputClone,
    InputMinimize,
    RunInput,
    CheckResult,
}

pub(crate) struct MinimizerConfig {
    ignore_reg_state: bool,
    ignore_feedback: bool,
    codecov_level: MinimizeCodeCovLevel,
    ignore_stack: bool,
    ignore_console: bool,
    dump_feedback: bool,
}

/// Thread worker used to minimize the input based on the size of the input
fn start_core<FUZZER: Fuzzer>(
    core_id: CoreId,
    vm: &VmFd,
    vbcpu: &VbCpu,
    cpuid: &CpuId,
    snapshot_fd: i32,
    clean_snapshot: Arc<RwLock<Memory>>,
    symbols: &Option<VecDeque<Symbol>>,
    symbol_reset_breakpoints: Option<BTreeMap<(VirtAddr, Cr3), ResetBreakpointType>>,
    coverage_breakpoints: Option<FxHashSet<VirtAddr>>,
    input_case: &Path,
    vm_timeout: Duration,
    max_iterations: u32,
    config: Config,
    min_params: MinimizerConfig,
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
    let redqueen_breakpoints = None;

    if min_params.codecov_level == MinimizeCodeCovLevel::Hitcounts
        || min_params.codecov_level == MinimizeCodeCovLevel::BasicBlock
    {
        if !coverage_breakpoints.is_some() {
            anyhow::bail!("code coverage level requires breakpoint addresses!");
        }
    }

    let bp_type = if min_params.codecov_level == MinimizeCodeCovLevel::Hitcounts {
        BreakpointType::Repeated
    } else {
        BreakpointType::SingleShot
    };
    let mut covbps_addrs = vec![];
    if let Some(covbps) = coverage_breakpoints {
        if min_params.codecov_level == MinimizeCodeCovLevel::Hitcounts
            || min_params.codecov_level == MinimizeCodeCovLevel::BasicBlock
        {
            covbps_addrs.extend(covbps.iter().cloned());
        } else if min_params.codecov_level == MinimizeCodeCovLevel::Symbols {
            let symbols = symbols
                .as_ref()
                .context("code coverage level requires symbols")?;
            for sym in symbols.iter() {
                if sym.address == 0 {
                    log::warn!("symbol at null {:?}", sym);
                } else {
                    covbps_addrs.push(VirtAddr(sym.address));
                }
            }
        }
    }

    if !min_params.ignore_feedback {
        log::info!(
            "considering {} coverage breakpoints for feedback",
            covbps_addrs.len()
        );
    }

    // Create a 64-bit VM for fuzzing
    let mut fuzzvm = FuzzVm::create(
        u64::try_from(core_id.id)?,
        &mut fuzzer,
        vm,
        vbcpu,
        cpuid,
        snapshot_fd.as_raw_fd(),
        clean_snapshot,
        None, // do not setup regular coverage breakpoints
        symbol_reset_breakpoints,
        symbols,
        config,
        StackUnwinders::default(),
        #[cfg(feature = "redqueen")]
        redqueen_breakpoints,
    )?;

    log::info!("Minimize timeout: {:?}", vm_timeout);

    // Get the initial input
    let input_bytes = std::fs::read(input_case)?;
    let starting_input = <FUZZER::Input as FuzzInput>::from_bytes(&input_bytes)?;
    let mut input = starting_input.clone();

    let start_input_size = input_bytes.len();

    // Initialize the performance counters for executing a VM
    let (orig_execution, mut orig_feedback) = fuzzvm.gather_feedback(
        &mut fuzzer,
        &starting_input,
        vm_timeout,
        &covbps_addrs,
        bp_type,
    )?;
    fuzzvm.print_context()?;
    log::info!("Original execution ended with {:?}", orig_execution);

    if !min_params.ignore_feedback {
        log::info!("Obtained {} feedback entries.", orig_feedback.len());
    }
    orig_feedback.ensure_clean(); // remove the feedback log
    if min_params.dump_feedback {
        let data = serde_json::to_string(&orig_feedback)?;
        let mut save_path = std::path::PathBuf::from(input_case);
        save_path.set_extension("feedback");
        std::fs::write(save_path, data)?;
    }

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

    let orig_reg_state = if min_params.ignore_reg_state {
        kvm_bindings::kvm_regs {
            rip: fuzzvm.rip(),
            ..Default::default()
        }
    } else {
        *fuzzvm.regs()
    };

    let orig_output = fuzzvm.console_output.clone();

    // Create a random number generatr
    let mut rng = crate::rng::Rng::new();

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

    let mut last_feedback = None;
    let mut last_execution = Execution::Continue;
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
            stats!(RunInput);
            stats!(CheckResult);

            timer = Instant::now();
        }

        // Clone a new input for this minimization run
        let mut curr_input = time!(InputClone, { input.clone() });

        // Minimize the input based on the Input type
        time!(InputMinimize, {
            FUZZER::Input::minimize(&mut curr_input, &mut rng);
        });

        let (execution, mut feedback) = time!(
            RunInput,
            fuzzvm.gather_feedback(&mut fuzzer, &curr_input, vm_timeout, &covbps_addrs, bp_type)?
        );

        // Check if the VM resulted in the same crashing state. If so, keep the minimized input as the
        // current best input
        time!(CheckResult, {
            let mut success = true;

            // check if the execution stopped because of the same reason!
            success &= orig_execution == execution;

            // check if the same feedback was returned.
            if !min_params.ignore_feedback {
                feedback.ensure_clean();
                if min_params.codecov_level < MinimizeCodeCovLevel::Hitcounts {
                    success &= orig_feedback.eq_with(
                        &feedback,
                        // crate::feedback::classify_hitcount_into_bucket_afl_style,
                        |x| if x > 0 { 1 } else { 0 },
                    );
                } else {
                    success &= orig_feedback.eq_with(
                        &feedback,
                        crate::feedback::classify_hitcount_into_bucket_afl_style,
                    );
                }
                // if success && !orig_feedback.eq_codecov_exact(&feedback) {
                //     log::warn!("Hitcount clamping affected minimization!");
                // }
            }

            let curr_reg_state = if min_params.ignore_reg_state {
                kvm_bindings::kvm_regs {
                    rip: fuzzvm.rip(),
                    ..Default::default()
                }
            } else {
                *fuzzvm.regs()
            };
            // If the guest exited with the same final state, then keep the minimized input
            success &= orig_reg_state == curr_reg_state;

            if !min_params.ignore_stack {
                let mut curr_stack = vec![0u64; stack_size];
                fuzzvm.read_bytes(VirtAddr(fuzzvm.rsp()), fuzzvm.cr3(), &mut curr_stack)?;
                success &= orig_stack == curr_stack;
            }

            if !min_params.ignore_console {
                success &= orig_output == fuzzvm.console_output;
            }

            if success {
                input = curr_input;
                feedback.ensure_clean(); // remove the feedback log
                last_feedback = Some(feedback.clone());
                last_execution = execution;
            }
        });
    }

    if input == starting_input {
        log::error!("minimizing failed! -> no change");
        return Ok(());
    }

    let mut result_bytes = Vec::new();
    input.to_bytes(&mut result_bytes)?;

    // Write the minimized file
    log::info!(
        "Minimized from {} -> {} bytes",
        start_input_size,
        result_bytes.len()
    );

    // Get the new minimized filename
    let orig_file_name = input_case
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("UNKNOWNFILENAME"));
    let mut min_file = std::path::PathBuf::from(orig_file_name);
    min_file.as_mut_os_string().push(".min"); // we are not using set_extension, since we do not
                                              // want to replace an existing extension.

    log::info!("Writing minimized file: {:?}", min_file);
    std::fs::write(&min_file, &result_bytes)?;

    if min_params.dump_feedback {
        if let Some(feedback) = last_feedback {
            let data = serde_json::to_string(&feedback)?;
            let mut save_path = min_file.clone();
            save_path.as_mut_os_string().push(".feedback");
            std::fs::write(save_path, data)?;
        } else {
            log::warn!("no feedback");
        }
    }

    if last_execution.is_crash() {
        // Allow the fuzzer to handle the crashing state
        // Useful for things like syscall fuzzer to write a C file from the input
        fuzzer.handle_crash(&input, &mut fuzzvm, &min_file)?;
    }

    Ok(())
}

/// Execute the Minimize subcommand
pub(crate) fn run<FUZZER: Fuzzer>(
    project_state: &ProjectState,
    args: &cmdline::Minimize,
) -> Result<()> {
    let KvmEnvironment {
        kvm,
        cpuids,
        physmem_file,
        clean_snapshot,
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

    let minparams = MinimizerConfig {
        ignore_stack: args.ignore_stack,
        ignore_reg_state: args.rip_only,
        ignore_feedback: args.ignore_feedback,
        codecov_level: args.consider_coverage,
        ignore_console: args.ignore_console_output,
        dump_feedback: args.dump_feedback_to_file,
    };

    // only use coverage breakpoints if we are supposed to ignore the coverage feedback.
    let covbps = if !args.ignore_feedback && minparams.codecov_level > MinimizeCodeCovLevel::None {
        // Init the coverage breakpoints mapping to byte
        let mut covbp_bytes = FxHashSet::default();
        // Write the remaining coverage breakpoints into the "clean" snapshot
        if let Some(covbps) = project_state.coverage_breakpoints.as_ref() {
            let cr3 = Cr3(project_state.vbcpu.cr3);
            // Small scope to drop the clean snapshot lock
            let mut curr_clean_snapshot = clean_snapshot.write().unwrap();
            for addr in covbps.iter() {
                if let Ok(_orig_byte) = curr_clean_snapshot.read::<u8>(*addr, cr3) {
                    // curr_clean_snapshot.write_bytes(*addr, cr3, &[0xcc])?;
                    // covbp_bytes.insert(*addr, orig_byte);
                    covbp_bytes.insert(*addr);
                }
            }
        }
        Some(covbp_bytes)
    } else {
        None
    };

    // Start executing on this core
    start_core::<FUZZER>(
        core_id,
        &vm,
        &project_state.vbcpu,
        &cpuids,
        physmem_file.as_raw_fd(),
        clean_snapshot,
        &symbols,
        symbol_breakpoints,
        covbps,
        &args.path,
        args.timeout,
        args.iterations_per_stage,
        project_state.config.clone(),
        minparams,
    )?;

    // Success
    Ok(())
}

/// Wrapper around `rdtsc`
fn rdtsc() -> u64 {
    unsafe { std::arch::x86_64::_rdtsc() }
}
