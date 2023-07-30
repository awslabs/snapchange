//! Executing the `trace` command

use anyhow::{anyhow, ensure, Context, Result};

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use core_affinity::CoreId;
use kvm_bindings::CpuId;
use kvm_ioctls::VmFd;

use crate::config::Config;
use crate::fuzz_input::FuzzInput;
use crate::fuzzer::Fuzzer;
use crate::fuzzvm::{FuzzVm, FuzzVmExit};
use crate::memory::Memory;
use crate::stack_unwinder::StackUnwinders;
use crate::{cmdline, fuzzvm, unblock_sigalrm, THREAD_IDS};
use crate::{handle_vmexit, init_environment, KvmEnvironment, ProjectState};
use crate::{Cr3, Execution, ResetBreakpointType, Symbol, VbCpu, VirtAddr};

/// Thread worker to execute a single input and write the single step trace for that
/// input
#[allow(clippy::needless_pass_by_value)]
fn start_core<FUZZER: Fuzzer>(
    core_id: CoreId,
    vm: &VmFd,
    vbcpu: &VbCpu,
    cpuid: &CpuId,
    snapshot_fd: i32,
    clean_snapshot: Arc<RwLock<Memory>>,
    symbols: &Option<VecDeque<Symbol>>,
    symbol_breakpoints: Option<BTreeMap<(VirtAddr, Cr3), ResetBreakpointType>>,
    vm_timeout: Duration,
    config: Config,
    next_file_index: Arc<AtomicUsize>,
    files: Arc<Vec<PathBuf>>,
    finished: Arc<AtomicBool>,
    wanted_virt_addr: VirtAddr,
) -> Result<Vec<PathBuf>> {
    // Store the thread ID of this thread used for passing the SIGALRM to this thread
    let thread_id = unsafe { libc::pthread_self() };
    *THREAD_IDS[core_id.id].lock().unwrap() = Some(thread_id);

    // Unblock SIGALRM to enable this thread to handle SIGALRM
    unblock_sigalrm()?;

    // Set the core affinity for this core
    core_affinity::set_for_current(core_id);

    // Create a default fuzzer for single shot, tracing execution with the given input
    let mut fuzzer = FUZZER::default();

    // Sanity check that the given fuzzer matches the snapshot
    ensure!(
        FUZZER::START_ADDRESS == vbcpu.rip,
        fuzzvm::Error::SnapshotMismatch
    );

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
        None,
        symbol_breakpoints,
        symbols,
        config,
        StackUnwinders::default(),
        #[cfg(feature = "redqueen")]
        redqueen_rules,
    )?;

    log::info!("Tracing timeout: {:?}", vm_timeout);

    let mut found_files = Vec::new();

    'next_input: loop {
        let file_index = next_file_index.fetch_add(1, Ordering::SeqCst);
        if file_index >= files.len() || finished.load(Ordering::SeqCst) {
            break;
        }

        let input_path = &files[file_index];

        // If we are tracing an input, set that input in the guest
        let input = <FUZZER::Input as FuzzInput>::from_bytes(&std::fs::read(input_path)?)?;

        // Reset the guest state
        let _guest_reset_perf = fuzzvm.reset_guest_state(&mut fuzzer)?;

        // Reset the fuzzer state
        fuzzer.reset_fuzzer_state();

        // Write the breakpoint to hit for the requested address/symbol
        fuzzvm.write_bytes(wanted_virt_addr, fuzzvm.cr3(), &[0xcc])?;

        // Start the execution as continue
        let mut execution = Execution::Continue;

        // Set the input into the VM as per the fuzzer
        fuzzer.set_input(&input, &mut fuzzvm)?;

        // Initialize the performance counters for executing a VM
        let mut perf = crate::fuzzvm::VmRunPerf::default();

        // Top of the run iteration loop for the current fuzz case
        loop {
            // Reset the VM if the vmexit handler says so
            if matches!(execution, Execution::Reset | Execution::CrashReset { .. }) {
                break;
            }

            // Execute the VM
            let ret = fuzzvm.run(&mut perf)?;

            // If we caught a breakpoint containing the requested address or symbol, save this file
            // and try the next file
            match ret {
                FuzzVmExit::Breakpoint(addr) if addr == *wanted_virt_addr => {
                    // Save the found input
                    found_files.push(input_path.clone());

                    // Mark the cores as finished
                    finished.store(true, Ordering::SeqCst);
                    continue 'next_input;
                }
                _ => {}
            }

            // Handle the FuzzVmExit to determine
            let ret = handle_vmexit(&ret, &mut fuzzvm, &mut fuzzer, None, &input);

            execution = match ret {
                Err(e) => {
                    log::error!("ERROR: {:x?}", e);
                    Execution::Reset
                }
                Ok(execution) => execution,
            };

            // During single step, breakpoints aren't triggered. For this reason,
            // we need to check if the instruction is a breakpoint regardless in order to
            // apply fuzzer specific breakpoint logic. We can ignore the "unknown breakpoint"
            // error that is thrown if a breakpoint is not found;
            if fuzzvm.single_step {
                if let Ok(new_execution) = fuzzvm.handle_breakpoint(&mut fuzzer, &input) {
                    execution = new_execution;
                } else {
                    // Ignore the unknown breakpoint case since we check every instruction due to
                    // single stepping here.
                }
            }

            // Check if the VM needs to be timed out
            if fuzzvm.start_time.elapsed() > vm_timeout {
                execution = Execution::Reset;
            }
        }
    }

    Ok(found_files)
}

/// Gather files recursively from the given directory and write the paths to `out`
fn gather_files(dir: &std::path::PathBuf, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                gather_files(&path, out)?;
            } else {
                out.push(path);
            }
        }
    }
    Ok(())
}

/// Execute the Trace subcommand to gather a single step trace over an input
pub(crate) fn run<FUZZER: Fuzzer>(
    project_state: &ProjectState,
    args: &cmdline::FindInput,
) -> Result<()> {
    let KvmEnvironment {
        kvm,
        cpuids,
        physmem_file,
        clean_snapshot,
        symbols,
        symbol_breakpoints,
    } = init_environment(project_state)?;

    // Parse the given translation address or default to the starting RIP of the snapshot
    let wanted_virt_addr = match &args.location {
        Some(addr) => crate::utils::parse_cli_symbol(addr, &symbols)?,
        None => VirtAddr(project_state.vbcpu.rip),
    };

    // Get the files to execute over
    let mut files = Vec::new();
    for path in ["current_corpus", "input", "crashes"] {
        let curr_dir = project_state.path.join(path);
        gather_files(&curr_dir, &mut files)?;
    }

    let mut threads = Vec::new();
    let files = Arc::new(files);

    // Get the number of cores to fuzz with
    let mut cores = args.cores.unwrap_or(1);
    if cores == 0 {
        log::warn!("No cores given. Defaulting to 1 core");
        cores = 1;
    }

    let core_ids =
        core_affinity::get_core_ids().ok_or_else(|| anyhow!("Failed to get core ids"))?;

    // Get the symbols and symbol breakpoints for each core
    let mut starting_symbols = (0..=cores).map(|_| symbols.clone()).collect::<Vec<_>>();
    let mut starting_configs = (0..=cores)
        .map(|_| project_state.config.clone())
        .collect::<Vec<_>>();
    let mut starting_symbps = (0..=cores)
        .map(|_| symbol_breakpoints.clone())
        .collect::<Vec<_>>();

    let next_file_index = Arc::new(AtomicUsize::new(0));
    let finished = Arc::new(AtomicBool::new(false));

    for id in 1..=cores {
        let files = files.clone();
        let physmem_file_fd = physmem_file.as_raw_fd();

        // Copy the CPUIDs for this core
        let cpuids = cpuids.clone();

        // Create the VM for this core
        let vm = kvm.create_vm().context("Failed to create VM from KVM")?;

        let timeout = args.timeout;
        let vbcpu = project_state.vbcpu;

        let curr_symbols = std::mem::take(&mut starting_symbols[id]);
        let config = std::mem::take(&mut starting_configs[id]);
        let symbol_breakpoints = std::mem::take(&mut starting_symbps[id]);
        let core_id = core_ids[id];

        let next_file_index = next_file_index.clone();
        let finished = finished.clone();

        let clean_snapshot = clean_snapshot.clone();

        // Start executing on this core
        let t = std::thread::spawn(move || {
            start_core::<FUZZER>(
                core_id,
                &vm,
                &vbcpu,
                &cpuids,
                physmem_file_fd,
                clean_snapshot,
                &curr_symbols,
                symbol_breakpoints,
                timeout,
                config,
                next_file_index,
                files,
                finished,
                wanted_virt_addr,
            )
        });

        threads.push(t);
    }

    let mut found = HashSet::new();

    for t in threads {
        let res = t.join();
        let Ok(Ok(files)) = res else { continue; };

        for file in files {
            found.insert(file);
        }
    }

    // Print the found files
    println!("Inputs containing {:#x}", wanted_virt_addr.0);

    for f in &found {
        println!("{f:?}");
    }

    // Exit the program
    Ok(())
}
