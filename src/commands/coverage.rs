//! Execute the `coverage` command

use anyhow::{anyhow, ensure, Context, Result};

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::convert::Into;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use core_affinity::CoreId;
use kvm_bindings::CpuId;
use kvm_ioctls::VmFd;

use crate::fuzz_input::InputWithMetadata;
use crate::fuzzer::Fuzzer;
use crate::fuzzvm::{FuzzVm, FuzzVmExit};
use crate::memory::Memory;
use crate::{cmdline, fuzzvm, unblock_sigalrm, SymbolList, THREAD_IDS};
use crate::{handle_vmexit, init_environment, KvmEnvironment, ProjectState};
use crate::{Cr3, Execution, ResetBreakpointType, Symbol, VirtAddr};

/// Execute the Coverage subcommand to gather coverage for a particular input
pub(crate) fn run<FUZZER: Fuzzer>(
    project_state: &ProjectState,
    args: &cmdline::Coverage,
) -> Result<()> {
    ensure!(
        project_state.coverage_breakpoints.is_some(),
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

    log::info!(
        "Init {} coverage",
        project_state
            .coverage_breakpoints
            .as_ref()
            .context("coverage command requires coverage breakpoints!")?
            .len()
    );

    // Start executing on this core
    start_core::<FUZZER>(
        core_id,
        &vm,
        &cpuids,
        physmem_file.as_raw_fd(),
        clean_snapshot,
        &symbols,
        symbol_breakpoints,
        &args.path,
        args.timeout,
        project_state,
        args.context,
        args.coverage_path.as_ref(),
    )?;

    // Success
    Ok(())
}

/// Thread worker used to gather coverage for a specific input
pub(crate) fn start_core<FUZZER: Fuzzer>(
    core_id: CoreId,
    vm: &VmFd,
    cpuid: &CpuId,
    snapshot_fd: i32,
    clean_snapshot: Arc<RwLock<Memory>>,
    symbols: &Option<SymbolList>,
    symbol_breakpoints: Option<BTreeMap<(VirtAddr, Cr3), ResetBreakpointType>>,
    input_case: &PathBuf,
    vm_timeout: Duration,
    project_state: &ProjectState,
    display_context: bool,
    out_path: Option<&PathBuf>,
) -> Result<()> {
    // Store the thread ID of this thread used for passing the SIGALRM to this thread
    let thread_id = unsafe { libc::pthread_self() };
    *THREAD_IDS[core_id.id].lock().unwrap() = Some(thread_id);

    // Unblock SIGALRM to enable this thread to handle SIGALRM
    unblock_sigalrm()?;

    // Set the core affinity for this core
    core_affinity::set_for_current(core_id);

    let ProjectState {
        vbcpu,
        config,
        path: project_dir,
        ..
    } = project_state;
    let contexts = crate::stats::get_binary_contexts(&project_state.path)?;

    // Use the current fuzzer
    let mut fuzzer = FUZZER::default();

    // Sanity check that the given fuzzer matches the snapshot
    ensure!(
        FUZZER::START_ADDRESS == vbcpu.rip,
        fuzzvm::Error::SnapshotMismatch
    );

    #[cfg(feature = "redqueen")]
    let redqueen_breakpoints = None;

    // Create a 64-bit VM for fuzzing
    let mut fuzzvm = FuzzVm::<FUZZER>::create(
        u64::try_from(core_id.id)?,
        &mut fuzzer,
        vm,
        &vbcpu,
        cpuid,
        snapshot_fd.as_raw_fd(),
        clean_snapshot,
        None,
        symbol_breakpoints,
        symbols,
        config.clone(),
        crate::stack_unwinder::StackUnwinders::default(),
        #[cfg(feature = "redqueen")]
        redqueen_breakpoints,
    )?;

    // Get the input to trace
    let input = InputWithMetadata::from_path(input_case, &project_dir)?;

    log::info!(
        "gathering coverage for input {} with timeout: {:?}",
        input_case.display(),
        vm_timeout
    );
    // Init timer to mark how long the tracing took
    let start = std::time::Instant::now();
    let (execution, feedback) = fuzzvm.gather_feedback(
        &mut fuzzer,
        &input,
        vm_timeout,
        project_state
            .coverage_breakpoints
            .as_ref()
            .unwrap()
            .iter()
            .cloned(),
        crate::fuzzer::BreakpointType::Repeated,
    )?;
    log::info!(
        "Coverage gathering took {:4.2?} - exit reason: {:?}",
        start.elapsed(),
        execution
    );

    let orig_file_name = input_case
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("UNKNOWNFILENAME"))
        .to_string_lossy();

    let coverage_dir = if let Some(out) = out_path {
        out.clone()
    } else {
        project_dir.join("./coverage_per_input")
    };
    if !coverage_dir.exists() {
        std::fs::create_dir_all(&coverage_dir)?;
    }

    // Get the coverage file with just addresses
    let coverage_addrs = coverage_dir.join(format!("{orig_file_name}.coverage_addrs"));
    // Write the coverage raw addresses file (used with addr2line to get source cov)
    log::info!("Writing addresses hit to {}", coverage_addrs.display());
    crate::stats::write_text_coverage(&feedback, &coverage_addrs)?;

    // Get the coverage lighthouse file
    let lighthouse_file = coverage_dir.join(format!("{orig_file_name}.coverage_lighthouse"));
    // Wrtie the lighthouse coverage data
    log::info!(
        "Writing lighthouse coverage to {}",
        lighthouse_file.display()
    );
    crate::stats::write_lighthouse_coverage(&project_state.modules, &feedback, &lighthouse_file)?;

    // Get the lcov coverage file
    let coverage_lcov = coverage_dir.join(format!("{orig_file_name}.lcov.info"));
    log::info!("Writing lcov coverage to {}", coverage_lcov.display());
    crate::stats::write_lcov_info(project_state, &contexts, &feedback, &coverage_lcov)?;

    // write nicely formatted text coverage
    let symbols_file = coverage_dir.join(format!("{orig_file_name}.coverage_symbols"));
    log::info!(
        "Writing human readable coverage to file {}",
        symbols_file.display()
    );
    crate::stats::write_human_readable_text_coverage(
        project_state,
        &contexts,
        symbols.as_ref(),
        &feedback,
        symbols_file,
    )?;

    if display_context {
        fuzzvm.print_context()?;
    }

    Ok(())
}
