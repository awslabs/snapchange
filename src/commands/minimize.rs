//! Executing the `minimize` command
use anyhow::{anyhow, ensure, Context, Result};
use rustc_hash::FxHashSet;

use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use core_affinity::CoreId;
use kvm_bindings::CpuId;
use kvm_ioctls::VmFd;

use crate::cmdline::{self, MinimizeCodeCovLevel};
use crate::config::Config;
use crate::fuzz_input::{FuzzInput, InputWithMetadata, MinimizeControlFlow, MinimizerState};
use crate::fuzzer::{BreakpointType, Fuzzer};
use crate::fuzzvm::{FuzzVm, ResetBreakpoints};
use crate::memory::Memory;
use crate::stack_unwinder::StackUnwinders;
use crate::{fuzzvm, unblock_sigalrm, SymbolList, THREAD_IDS};
use crate::{init_environment, KvmEnvironment, ProjectState};
use crate::{Cr3, Execution, VbCpu, VirtAddr};

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

#[derive(Debug, Clone, Copy)]
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
    symbols: &Option<SymbolList>,
    symbol_reset_breakpoints: Option<&ResetBreakpoints>,
    coverage_breakpoints: Option<&FxHashSet<VirtAddr>>,
    input_fuzzcase: &PathBuf,
    output_fuzzcase: &PathBuf,
    vm_timeout: Duration,
    max_iterations: u32,
    config: Config,
    min_params: MinimizerConfig,
    project_dir: &PathBuf,
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

    use MinimizeCodeCovLevel::{BasicBlock, Hitcounts};
    if matches!(min_params.codecov_level, Hitcounts | BasicBlock) && !coverage_breakpoints.is_some()
    {
        anyhow::bail!("code coverage level requires breakpoint addresses!");
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
        symbol_reset_breakpoints.cloned(),
        symbols,
        config,
        StackUnwinders::default(),
        #[cfg(feature = "redqueen")]
        redqueen_breakpoints,
    )?;

    log::info!("Minimize timeout: {:?}", vm_timeout);

    // Get the initial input

    let input_bytes = std::fs::read(&input_fuzzcase)?;
    let start_input_size = input_bytes.len();

    let starting_input: InputWithMetadata<FUZZER::Input> =
        InputWithMetadata::from_path(input_fuzzcase, project_dir)?;
    let mut input = starting_input.fork();

    let start_length = input.len();
    let start_entropy = input.entropy_metric();

    // Initialize the performance counters for executing a VM
    let (orig_execution, mut orig_feedback) = fuzzvm.gather_feedback(
        &mut fuzzer,
        &starting_input,
        vm_timeout,
        covbps_addrs.iter().cloned(),
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
        let mut save_path = std::path::PathBuf::from(input_fuzzcase);
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
    let mut current_iteration = 0u32;
    let mut last_successful_iteration = 0u32;
    let mut max_iterations = max_iterations;
    let (mut minimizer_state, initial_cf) = input.input.init_minimize();
    match initial_cf {
        MinimizeControlFlow::Stop => {
            // odd, but ok...
            max_iterations = 0;
        }
        MinimizeControlFlow::ContinueFor(required_iterations) => {
            if (current_iteration + required_iterations) < max_iterations {
                max_iterations += required_iterations;
            }
        }
        _ => {}
    }
    while current_iteration < max_iterations {
        if timer.elapsed() > Duration::from_secs(1) {
            log::info!(
                "Iters {current_iteration:6}/{max_iterations} Last success at {last_successful_iteration} | Exec/sec {:6.2}",
                f64::from(current_iteration) / start.elapsed().as_secs_f64()
            );
            if let Some(length) = input.len() {
                log::info!(
                    "Minimized from {} -> {} bytes",
                    start_length.unwrap(),
                    length
                );
            }
            if let Some(entropy) = input.entropy_metric() {
                log::info!(
                    "Minimized from {:.6} -> {:.6} entropy metric",
                    start_entropy.unwrap(),
                    entropy
                );
            }

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
        let mut curr_input = time!(InputClone, { input.fork() });

        // Minimize the input based on the Input type
        let cf = time!(InputMinimize, {
            curr_input.minimize(
                &mut minimizer_state,
                current_iteration,
                last_successful_iteration,
                &mut rng,
            )
        });

        match cf {
            // minimize was not able to create a new input, so we try with the next iteration
            MinimizeControlFlow::Skip => {
                continue;
            }
            MinimizeControlFlow::ContinueFor(required_iterations) => {
                if (current_iteration + required_iterations) < max_iterations {
                    max_iterations += required_iterations;
                }
            }
            _ => {}
        }

        let (execution, mut feedback) = time!(
            RunInput,
            if min_params.codecov_level >= MinimizeCodeCovLevel::Hitcounts {
                // run input without any feedback mechanism -> fast basic check
                let (execution, feedback) = fuzzvm.gather_feedback(
                    &mut fuzzer,
                    &curr_input,
                    vm_timeout,
                    vec![],
                    bp_type,
                )?;

                // fast check whether we superficially hit the same exit and not something
                // completely different.
                if orig_reg_state.rip == fuzzvm.rip() && orig_execution == execution {
                    // and only if it looks to be the same; do a reset and gather detailed feedback
                    // with hitcounts.
                    fuzzvm.gather_feedback(
                        &mut fuzzer,
                        &curr_input,
                        vm_timeout,
                        covbps_addrs.iter().cloned(),
                        bp_type,
                    )?
                } else {
                    (execution, feedback)
                }
            } else {
                fuzzvm.gather_feedback(
                    &mut fuzzer,
                    &curr_input,
                    vm_timeout,
                    covbps_addrs.iter().cloned(),
                    bp_type,
                )?
            }
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
                last_successful_iteration = current_iteration;
            }
        });

        if matches!(cf, MinimizeControlFlow::Stop) || minimizer_state.is_stop_state() {
            break;
        }

        current_iteration += 1;
    }

    if input == starting_input {
        log::error!("minimizing failed! -> no change");
        return Ok(());
    }

    let result_bytes = input.input_as_bytes()?;

    // Write the minimized file
    log::info!(
        "Minimized from {} -> {} bytes",
        start_input_size,
        result_bytes.len()
    );

    log::info!("Writing minimized file: {:?}", output_fuzzcase);
    std::fs::write(&output_fuzzcase, &result_bytes)?;

    if min_params.dump_feedback {
        if let Some(feedback) = last_feedback {
            let data = serde_json::to_string(&feedback)?;
            let mut save_path = output_fuzzcase.clone();
            save_path.as_mut_os_string().push(".feedback");
            std::fs::write(save_path, data)?;
        } else {
            log::warn!("no feedback");
        }
    }

    if last_execution.is_crash() {
        // Allow the fuzzer to handle the crashing state
        // Useful for things like syscall fuzzer to write a C file from the input
        fuzzer.handle_crash(&input, &mut fuzzvm, &output_fuzzcase)?;
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
        ignore_console: args.ignore_console_output,
        dump_feedback: args.dump_feedback_to_file,
        codecov_level: args.consider_coverage.unwrap_or_else(|| {
            // try to guess what we are minimizing and decide what kind of code coverage we want to
            // look at.
            let current_corpus = Some(std::ffi::OsStr::new("current_corpus"));
            if args.path.file_name() == current_corpus
                || args
                    .path
                    .parent()
                    .map_or(true, |parent| parent.file_name() == current_corpus)
            {
                log::info!("guessing you want to minimize based on code coverage with hitcounts");
                MinimizeCodeCovLevel::Hitcounts
            } else {
                MinimizeCodeCovLevel::None
            }
        }),
    };

    log::debug!("{:?}", minparams);

    // only use coverage breakpoints if we are supposed to ignore the coverage feedback.
    let covbps = if !args.ignore_feedback && minparams.codecov_level > MinimizeCodeCovLevel::None {
        // Init the coverage breakpoints mapping to byte
        let mut covbp_bytes = FxHashSet::default();
        // Write the remaining coverage breakpoints into the "clean" snapshot
        if let Some(covbps) = project_state.coverage_basic_blocks.as_ref() {
            let cr3 = Cr3(project_state.vbcpu.cr3);
            // Small scope to drop the clean snapshot lock
            let mut curr_clean_snapshot = clean_snapshot.write().unwrap();
            for addr in covbps.keys().copied() {
                if let Ok(_orig_byte) = curr_clean_snapshot.read::<u8>(addr, cr3) {
                    // curr_clean_snapshot.write_bytes(*addr, cr3, &[0xcc])?;
                    // covbp_bytes.insert(*addr, orig_byte);
                    covbp_bytes.insert(addr);
                }
            }
        }
        Some(covbp_bytes)
    } else {
        None
    };

    let filepaths = if args.path.is_dir() {
        crate::utils::get_files(&args.path, true)?
    } else {
        vec![args.path.clone()]
    };

    let mut minimized = 0_u32;
    for (infile, outfile) in filepaths
        .iter()
        // only check files that are not minimized already
        .filter(|p| p.extension().map_or(true, |x| x != "min"))
        .map(|infile| {
            if args.in_place {
                let outfile = infile.clone();
                (infile, outfile)
            } else {
                let outfile = infile.with_extension("min");
                (infile, outfile)
            }
        })
    {
        // TODO(mrodler): the second iteration of this panics! fix this.
        // Start executing on this core
        start_core::<FUZZER>(
            core_id,
            &vm,
            &project_state.vbcpu,
            &cpuids,
            physmem_file.as_raw_fd(),
            clean_snapshot.clone(),
            &symbols,
            symbol_breakpoints.as_ref(),
            covbps.as_ref(),
            &infile,
            &outfile,
            args.timeout,
            args.iterations_per_stage,
            project_state.config.clone(),
            minparams.clone(),
            &project_state.path,
        )?;
        minimized += 1;
    }
    if minimized > 1 {
        log::info!("minimized {} files", minimized);
    }

    // Success
    Ok(())
}

/// Wrapper around `rdtsc`
fn rdtsc() -> u64 {
    unsafe { std::arch::x86_64::_rdtsc() }
}
