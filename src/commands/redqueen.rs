//! Execute the `redqueen` command to gather Redqueen coverage for a single input

#[cfg(feature = "redqueen")]
use std::sync::{Arc, RwLock};

#[cfg(feature = "redqueen")]
use anyhow::{anyhow, ensure, Context, Result};

#[cfg(feature = "redqueen")]
use core_affinity::CoreId;
#[cfg(feature = "redqueen")]
use kvm_bindings::CpuId;
#[cfg(feature = "redqueen")]
use kvm_ioctls::VmFd;

#[cfg(feature = "redqueen")]
use std::{fs::File, os::unix::io::AsRawFd, path::PathBuf, time::Duration};

#[cfg(feature = "redqueen")]
use crate::{
    cmdline,
    cmp_analysis::RedqueenCoverage,
    feedback::FeedbackLog,
    feedback::FeedbackTracker,
    fuzz_input::{FuzzInput, InputWithMetadata},
    fuzzer::Fuzzer,
    fuzzvm,
    fuzzvm::{CoverageBreakpoints, FuzzVm, ResetBreakpoints},
    init_environment,
    stack_unwinder::StackUnwinders,
    unblock_sigalrm, KvmEnvironment, Memory, ProjectState, SymbolList, VbCpu, THREAD_IDS,
};

/// Execute the c subcommand to gather coverage for a particular input
#[cfg(feature = "redqueen")]
pub(crate) fn run<FUZZER: Fuzzer>(
    project_state: &ProjectState,
    args: &cmdline::RedqueenAnalysis,
) -> Result<()> {
    ensure!(
        project_state.coverage_basic_blocks.is_some(),
        "Must have covbps to gather coverage"
    );

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

    // Init the fake coverage breakpoints for this command
    let covbp_bytes = CoverageBreakpoints::default();

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
        covbp_bytes,
        &args.path,
        project_state,
    )?;

    // Success
    Ok(())
}

/// Thread worker used to gather coverage for a specific input
#[cfg(feature = "redqueen")]
pub(crate) fn start_core<FUZZER: Fuzzer>(
    core_id: CoreId,
    vm: &VmFd,
    vbcpu: &VbCpu,
    cpuid: &CpuId,
    snapshot_fd: i32,
    clean_snapshot: Arc<RwLock<Memory>>,
    symbols: &Option<SymbolList>,
    symbol_breakpoints: Option<ResetBreakpoints>,
    coverage_breakpoints: CoverageBreakpoints,
    input_case: &PathBuf,
    project_state: &ProjectState,
) -> Result<()> {
    // Store the thread ID of this thread used for passing the SIGALRM to this thread

    let thread_id = unsafe { libc::pthread_self() };
    *THREAD_IDS[core_id.id].lock().unwrap() = Some(thread_id);

    // Unblock SIGALRM to enable this thread to handle SIGALRM
    unblock_sigalrm()?;

    // Set the core affinity for this core
    core_affinity::set_for_current(core_id);

    let ProjectState {
        binaries,
        config,
        redqueen_breakpoints,
        path: project_dir,
        ..
    } = project_state;

    // Use the current fuzzer
    let mut fuzzer = FUZZER::default();

    // Sanity check that the given fuzzer matches the snapshot
    ensure!(
        FUZZER::START_ADDRESS == vbcpu.rip,
        fuzzvm::Error::SnapshotMismatch
    );

    log::info!("Collect the binary contexts");
    let mut contexts = Vec::new();
    for binary in binaries {
        let file = File::open(binary)?;
        let map = unsafe { memmap::Mmap::map(&file)? };
        let object = addr2line::object::File::parse(&*map)?;
        let tmp = addr2line::Context::new(&object)?;
        contexts.push(tmp);
    }

    let mut feedback = FeedbackTracker::default();

    // Create a 64-bit VM for fuzzing
    let mut fuzzvm = FuzzVm::<FUZZER>::create(
        u64::try_from(core_id.id)?,
        &mut fuzzer,
        vm,
        vbcpu,
        cpuid,
        snapshot_fd.as_raw_fd(),
        clean_snapshot,
        Some(coverage_breakpoints),
        symbol_breakpoints,
        symbols,
        config.clone(),
        StackUnwinders::default(),
        redqueen_breakpoints.clone(),
    )?;

    // Get the input to trace
    let input = InputWithMetadata::from_path(input_case, project_dir)?;

    // Run the guest until reset
    let vm_timeout = Duration::from_secs(1);

    // Initialize a covbps set that will not be used during this redqueen run
    // (During normal fuzzing, we keep track of the coverage during redqueen
    //  as well. Mimic that here, but it won't be used since we aren't applying
    //  coverage breakpoints for this command).
    // let mut covbps = BTreeSet::new();

    fuzzvm.reset_and_run_with_redqueen(&input, &mut fuzzer, vm_timeout, &mut feedback)?;

    for log_entry in feedback.take_log() {
        if let FeedbackLog::Redqueen(RedqueenCoverage {
            virt_addr,
            rflags,
            hit_count,
        }) = log_entry
        {
            // let rflags = RFlags::from_bits_truncate(rflags);
            // println!("Address: {virt_addr:#018x?} RFLAGS: {rflags:?} Hits: {hit_count}");
            let virt_addr = virt_addr.0;
            println!("{virt_addr:#x} {rflags:#x} {hit_count:#x}");
        }
    }

    if fuzzvm.redqueen_rules.is_empty() {
        let _entropy_input =
            fuzzvm.increase_input_entropy(&input, &feedback, &mut fuzzer, vm_timeout)?;
    }

    for (id, rules) in fuzzvm.redqueen_rules {
        println!("{id:#x}");
        for rule in rules {
            println!(" Rule: {rule:x?}");
            let candidates = input.get_redqueen_rule_candidates(&rule);
            for candidate in candidates {
                println!("  {candidate:x?}");
            }
        }
    }

    Ok(())
}
