//! Execute the `coverage` command

use anyhow::{anyhow, ensure, Context, Result};

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use core_affinity::CoreId;
use kvm_bindings::CpuId;
use kvm_ioctls::VmFd;

use crate::config::Config;
use crate::fuzz_input::{FuzzInput, InputWithMetadata};
use crate::fuzzer::Fuzzer;
use crate::fuzzvm::{FuzzVm, FuzzVmExit};
use crate::memory::Memory;
use crate::{cmdline, fuzzvm, unblock_sigalrm, Modules, THREAD_IDS};
use crate::{handle_vmexit, init_environment, KvmEnvironment, ProjectState};
use crate::{Cr3, Execution, ResetBreakpointType, Symbol, VbCpu, VirtAddr};

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

    // Init the coverage breakpoints mapping to byte
    let mut covbp_bytes = BTreeMap::new();

    let cr3 = Cr3(project_state.vbcpu.cr3);

    log::info!(
        "Init {} coverage",
        project_state.coverage_breakpoints.as_ref().unwrap().len()
    );

    // Small scope to drop the clean snapshot lock after populating the
    // coverage bytes
    {
        let mut curr_clean_snapshot = clean_snapshot.read().unwrap();
        for addr in project_state.coverage_breakpoints.as_ref().unwrap() {
            if let Ok(orig_byte) = curr_clean_snapshot.read_byte(*addr, cr3) {
                covbp_bytes.insert(*addr, orig_byte);
            }
        }
    }

    log::info!("Found {} coverage", covbp_bytes.keys().len());

    // Start executing on this core
    start_core::<FUZZER>(
        core_id,
        &vm,
        &cpuids,
        physmem_file.as_raw_fd(),
        clean_snapshot,
        &symbols,
        symbol_breakpoints,
        covbp_bytes,
        &args.path,
        args.timeout,
        &project_state,
        args.context,
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
    symbols: &Option<VecDeque<Symbol>>,
    symbol_breakpoints: Option<BTreeMap<(VirtAddr, Cr3), ResetBreakpointType>>,
    coverage_breakpoints: BTreeMap<VirtAddr, u8>,
    input_case: &PathBuf,
    vm_timeout: Duration,
    project_state: &ProjectState,
    display_context: bool,
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
        modules,
        binaries,
        config,
        path: project_dir,
        ..
    } = project_state;

    let vbcpu = project_state.vbcpu;
    let modules = &project_state.modules;
    let binaries = &project_state.binaries;
    let config = &project_state.config;
    let project_dir = &project_state.path;

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

    // Initialize the lcov list
    let mut lcov = BTreeMap::new();
    for addr in coverage_breakpoints.keys() {
        let addr = *addr;

        for ctx in &contexts {
            if let Some(loc) = ctx.find_location(*addr)? {
                // Insert valid file:line into the BTreeMap for producing lcov
                if let (Some(file), Some(line)) = (loc.file, loc.line) {
                    lcov.entry(file)
                        .or_insert_with(BTreeMap::new)
                        .insert(line, 0);
                }
            }
        }
    }

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
        Some(coverage_breakpoints),
        symbol_breakpoints,
        symbols,
        config.clone(),
        crate::stack_unwinder::StackUnwinders::default(),
        #[cfg(feature = "redqueen")]
        redqueen_breakpoints,
    )?;

    log::info!("Coverage timeout: {:?}", vm_timeout);

    let mut execution = Execution::Continue;

    // Init timer to mark how long the tracing took
    let start = std::time::Instant::now();

    // Get the input to trace
    let input = InputWithMetadata::from_path(input_case, &project_dir)?;

    // Set the input into the VM as per the fuzzer
    fuzzer.set_input(&input, &mut fuzzvm)?;

    let mut coverage = BTreeSet::new();

    // Initialize the coverage symbols
    let mut symbol_data = String::new();

    // Top of the run iteration loop for the current fuzz case
    loop {
        // Reset the VM if the vmexit handler says so
        if matches!(execution, Execution::Reset | Execution::CrashReset { .. }) {
            break;
        }

        // Execute the VM
        let ret = fuzzvm.run()?;

        if let FuzzVmExit::CoverageBreakpoint(rip) = ret {
            if coverage.insert(rip) {
                // Get the symbol for RIP if we have a symbols database
                if let Some(ref sym_data) = symbols {
                    // Get the symbol itself
                    if let Some(curr_symbol) = crate::symbols::get_symbol(rip, sym_data) {
                        symbol_data.push_str(&curr_symbol.to_string());
                    }

                    // Add the source line information if we have it
                    for ctx in &contexts {
                        if let Some(loc) = ctx.find_location(rip)? {
                            let curr_line = format!(
                                "{}:{}:{}",
                                loc.file.unwrap_or("??"),
                                loc.line.unwrap_or(0),
                                loc.column.unwrap_or(0)
                            );

                            symbol_data.push(' ');
                            symbol_data.push_str(&curr_line);

                            // Insert valid file:line into the BTreeMap for producing lcov
                            if let (Some(file), Some(line)) = (loc.file, loc.line) {
                                lcov.entry(file)
                                    .or_insert_with(BTreeMap::new)
                                    .insert(line, 1);
                            }
                        }
                    }

                    // Add the new line
                    symbol_data.push('\n');
                }
            }
        }

        // Handle the FuzzVmExit to determine
        let ret = handle_vmexit(&ret, &mut fuzzvm, &mut fuzzer, None, &input, None);

        execution = match ret {
            Err(e) => {
                log::info!("ERROR: {:x?}", e);
                break;
            }
            Ok(execution) => execution,
        };

        // During single step, breakpoints aren't triggered. For this reason,
        // we need to check if the instruction is a breakpoint regardless in order to
        // apply fuzzer specific breakpoint logic. We can ignore the "unknown breakpoint"
        // error that is thrown if a breakpoint is not found;
        if let Ok(new_execution) = fuzzvm.handle_breakpoint(&mut fuzzer, &input, None) {
            execution = new_execution;
        } else {
            // Ignore the unknown breakpoint case since we check every instruction due to
            // single stepping here.
        }

        // Check if the VM needs to be timed out
        if fuzzvm.start_time.elapsed() > vm_timeout {
            log::warn!("Coverage Timed out.. exiting");
            execution = Execution::Reset;
        }
    }

    let orig_file_name = input_case
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("UNKNOWNFILENAME"))
        .to_string_lossy();

    let coverage_dir = Path::new("./coverages").join(&*orig_file_name);
    if !coverage_dir.exists() {
        std::fs::create_dir_all(&coverage_dir)?;
    }

    // Get the coverage file with just addresses
    let coverage_addrs = coverage_dir.join(format!("{orig_file_name}.coverage_addrs"));

    // Get the coverage lighthouse file
    let lighthouse_file = coverage_dir.join(format!("{orig_file_name}.coverage_lighthouse"));

    // Get the symbol coverage file
    let symbols_file = coverage_dir.join(format!("{orig_file_name}.coverage_symbols"));

    // Get the lcov coverage file
    let coverage_lcov = coverage_dir.join(format!("{orig_file_name}.lcov"));

    // Collect the lighthouse coverage data
    let mut lighthouse_data = String::new();
    for addr in &coverage {
        if let Some((module, offset)) = modules.contains(*addr) {
            lighthouse_data.push_str(&format!("{module}+{offset:x}\n"));
        } else {
            lighthouse_data.push_str(&format!("{addr:x}\n"));
        }
    }

    // Write the lighthouse coverage data
    log::info!("Writing lighthouse coverage to {lighthouse_file:?}");
    std::fs::write(&lighthouse_file, &lighthouse_data)
        .expect("Failed to write coverage lighthouse file");

    if !symbol_data.is_empty() {
        // Write the lighthouse coverage data
        log::info!("Writing symbol coverage to {symbols_file:?}");
        std::fs::write(&symbols_file, &symbol_data)
            .expect("Failed to write coverage lighthouse file");
    }

    // Write the coverage raw addresses file (used with addr2line to get source cov)
    log::info!("Writing addresses hit to {coverage_addrs:?}");
    std::fs::write(
        &coverage_addrs,
        coverage
            .iter()
            .map(|addr| format!("{addr:#x}"))
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .expect("Failed to write coverage address file");

    // Write the lcov output format
    let mut lcov_res = String::new();
    lcov_res.push_str("TN:\n");
    for (file, lines) in &lcov {
        lcov_res.push_str(&format!("SF:{file}\n"));
        for (line, hit_val) in lines {
            lcov_res.push_str(&format!("DA:{line},{hit_val}\n"));
        }
        lcov_res.push_str("end_of_record\n");
    }
    #[allow(clippy::needless_borrow)]
    std::fs::write(&coverage_lcov, &lcov_res)?;

    log::info!("Coverage gathering took {:4.2?}", start.elapsed());

    if display_context {
        fuzzvm.print_context()?;
    }

    Ok(())
}
