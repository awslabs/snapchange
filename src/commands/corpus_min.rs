//! Execute the `coverage` command

use anyhow::{ensure, Context, Result};

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, VecDeque};
use std::mem::size_of;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
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
use crate::{cmdline, fuzzvm, unblock_sigalrm, THREAD_IDS};
use crate::{handle_vmexit, init_environment, KvmEnvironment, ProjectState};
use crate::{Cr3, Execution, ResetBreakpointType, Symbol, VbCpu, VirtAddr};

/// Get all of the files found in the given path recursively
fn get_files(path: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut files = Vec::new();
    let entries = std::fs::read_dir(path)?;

    for entry in entries {
        let entry = entry?;
        let file_type = entry.file_type()?;

        if file_type.is_dir() {
            let dir_files = get_files(&entry.path())?;
            files.extend(dir_files);
        } else if file_type.is_file() {
            files.push(entry.path());
        }
    }

    Ok(files)
}

/// Execute the Coverage subcommand to gather coverage for a particular input
pub(crate) fn run<FUZZER: Fuzzer>(
    project_state: &ProjectState,
    args: &cmdline::CorpusMin,
) -> Result<()> {
    ensure!(
        project_state.coverage_breakpoints.is_some(),
        "Must have covbps to gather minimize a corpus"
    );

    // Get the number of cores to fuzz with
    let mut cores = args.cores.unwrap_or(1);
    if cores == 0 {
        log::warn!("No cores given. Defaulting to 1 core");
        cores = 1;
    }

    let KvmEnvironment {
        kvm,
        cpuids,
        physmem_file,
        clean_snapshot,
        symbols,
        symbol_breakpoints,
    } = init_environment(project_state)?;

    // Init the coverage breakpoints mapping to byte
    let mut covbp_bytes = BTreeMap::new();
    //
    let cr3 = Cr3(project_state.vbcpu.cr3);
    let mut total_coverage = Vec::new();

    // Gather the total coverage for this project
    {
        let mut curr_clean_snapshot = clean_snapshot.read().unwrap();
        for addr in project_state.coverage_breakpoints.as_ref().unwrap() {
            if let Ok(orig_byte) = curr_clean_snapshot.read_byte(*addr, cr3) {
                covbp_bytes.insert(*addr, orig_byte);
                total_coverage.push(addr.0);
            }
        }
    }

    // Create the trash dir if it doesn't exist
    if !args.trash_dir.exists() {
        std::fs::create_dir_all(&args.trash_dir)?;
    }
    log::info!(
        "Reading files from {:?}, moving trash files to {:?}",
        args.input_dir,
        args.trash_dir
    );

    // Gather the paths to gather the coverage for
    let paths = get_files(&args.input_dir)?;

    log::info!("Found {} coverage", covbp_bytes.keys().len());
    log::info!("Found {} files to minimize", paths.len());

    // Initialize the variables passed to each core
    let paths = Arc::new(paths);
    // let total_coverage = Arc::new(total_coverage);

    // The number of inputs to process
    let chunk_size: usize = args.chunk_size;
    let mut minimizer = CorpusMinimizer::default();

    //
    for chunk in (0..paths.len()).step_by(chunk_size) {
        let ending_index = (chunk + chunk_size).min(paths.len());
        log::info!("Chunk: {chunk} Ending: {ending_index}");
        let path_index = Arc::new(AtomicUsize::new(chunk));

        let mut threads = Vec::new();

        for core_id in 0..cores {
            // Create the VM for this core
            let Ok(vm) = kvm.create_vm().context("Failed to create VM from KVM") else {
                continue;
            };

            // Get the variables for this thread
            let paths = paths.clone();
            let path_index = path_index.clone();
            let vbcpu = project_state.vbcpu.clone();
            let cpuids = cpuids.clone();
            let physmem_file_fd = physmem_file.as_raw_fd();
            let config = project_state.config.clone();
            let symbols = symbols.clone();
            let symbol_breakpoints = symbol_breakpoints.clone();
            let covbp_bytes = covbp_bytes.clone();
            let timeout = args.timeout.clone();
            let clean_snapshot = clean_snapshot.clone();

            // Start executing on this core
            let t = std::thread::spawn(move || {
                start_core::<FUZZER>(
                    CoreId { id: core_id },
                    &vm,
                    &vbcpu,
                    &cpuids,
                    physmem_file_fd,
                    clean_snapshot,
                    &symbols,
                    symbol_breakpoints,
                    covbp_bytes,
                    timeout,
                    config,
                    paths,
                    path_index,
                    ending_index,
                )
            });

            threads.push(t);
        }

        // Spawn the kick cores thread to prevent cores being stuck in an infinite loop
        let kick_cores_thread = std::thread::spawn(move || {
            // Ignore the SIGALRM for this thread
            crate::block_sigalrm().unwrap();

            // Set the core affinity for this core to always be 0
            core_affinity::set_for_current(CoreId { id: 0 });

            // Reset the finished marker
            crate::FINISHED.store(false, Ordering::SeqCst);

            // Start the kick cores worker
            loop {
                if crate::FINISHED.load(Ordering::SeqCst) {
                    log::info!("[kick_cores] FINISHED");
                    break;
                }

                // If the kick timer has elapsed, it sets this variable
                if crate::KICK_CORES.load(Ordering::SeqCst) {
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
                    crate::KICK_CORES.store(false, Ordering::SeqCst);
                }

                // Minimal sleep to avoid too much processor churn
                std::thread::sleep(std::time::Duration::from_millis(1000));
            }
        });

        let mut chunk_coverage = BTreeMap::new();

        // When each thread finishes, accumulate the coverage for this chunk of inputs
        while let Some(t) = threads.pop() {
            log::info!("Waiting on thread {:?} to join", t.thread().id());
            let res = t.join().unwrap();
            match res {
                Ok(mut cov) => {
                    chunk_coverage.append(&mut cov);
                }
                x => panic!("Unknown thread result: {x:?}"),
            }
        }

        // Tell the kick cores thread that we are done
        crate::FINISHED.store(true, Ordering::SeqCst);
        kick_cores_thread.join().unwrap();

        // Add this chunk's coverage to the total corpus minimizer
        log::info!("Starting to add input");
        let start = std::time::Instant::now();
        minimizer.add_inputs(chunk_coverage);
        log::info!("Add inputs: {:?}", start.elapsed());

        // Reduce the corpus seen thus far by removing inputs that don't add any new coverage
        log::info!("Starting to minimize");
        let start = std::time::Instant::now();
        let trash = minimizer.reduce();
        log::info!(
            "Reduce: {:?} with {} trash files",
            start.elapsed(),
            trash.len()
        );

        // Move all of the trash files to the given trash directory
        for t in trash {
            if let Some(old_path) = paths.get(t) {
                let filename = old_path.as_path().file_name().unwrap();
                let new_path = args.trash_dir.join(filename);
                log::info!("Moving trash file from {old_path:?} to {new_path:?}");
                std::fs::rename(old_path, new_path)?;
            }
        }
    }

    // Gather the paths to gather the coverage for
    let new_paths = get_files(&args.input_dir)?;
    log::info!("Reduced corpus from {} to {}", paths.len(), new_paths.len());

    let cov_out = project_state.path.join("coverage.addresses.min");
    let result = minimizer
        .addr_to_inputs
        .keys()
        .map(|addr| format!("{addr:#x}"))
        .collect::<Vec<_>>()
        .join("\n");

    std::fs::write(&cov_out, result)?;

    log::info!(
        "Wrote coverage ({}) for minimized coverage to {cov_out:?}",
        minimizer.addr_to_inputs.len()
    );

    // Success
    Ok(())
}

/// Thread worker used to gather coverage for a specific input
pub(crate) fn start_core<FUZZER: Fuzzer>(
    core_id: CoreId,
    vm: &VmFd,
    vbcpu: &VbCpu,
    cpuid: &CpuId,
    snapshot_fd: i32,
    clean_snapshot: Arc<RwLock<Memory>>,
    symbols: &Option<VecDeque<Symbol>>,
    symbol_breakpoints: Option<BTreeMap<(VirtAddr, Cr3), ResetBreakpointType>>,
    coverage_breakpoints: BTreeMap<VirtAddr, u8>,
    vm_timeout: Duration,
    config: Config,
    paths: Arc<Vec<PathBuf>>,
    path_index: Arc<AtomicUsize>,
    ending_index: usize,
) -> Result<BTreeMap<usize, BTreeSet<u64>>> {
    // Store the thread ID of this thread used for passing the SIGALRM to this thread
    let thread_id = unsafe { libc::pthread_self() };
    *THREAD_IDS[core_id.id].lock().unwrap() = Some(thread_id);

    // Unblock SIGALRM to enable this thread to handle SIGALRM
    unblock_sigalrm()?;

    // Set the core affinity for this core
    core_affinity::set_for_current(core_id);

    // Use the current fuzzer
    let mut fuzzer = FUZZER::default();

    // Sanity check that the given fuzzer matches the snapshot
    ensure!(
        FUZZER::START_ADDRESS == vbcpu.rip,
        fuzzvm::Error::SnapshotMismatch
    );

    #[cfg(feature = "redqueen")]
    let redqueen_rules = BTreeMap::new();

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
        config,
        crate::stack_unwinder::StackUnwinders::default(),
        #[cfg(feature = "redqueen")]
        redqueen_rules,
    )?;

    let start = std::time::Instant::now();
    let mut result = BTreeMap::new();
    let start_index = path_index.load(Ordering::SeqCst);

    loop {
        let curr_index = path_index.fetch_add(1, Ordering::SeqCst);
        if curr_index >= ending_index {
            break;
        }

        // Print an approximate status message
        if (curr_index - start_index) > 0 && curr_index % 100 == 0 {
            let inputs_left = ending_index - curr_index;
            let time_per_input = start.elapsed().as_secs_f64() / (curr_index - start_index) as f64;
            let time_left = Duration::from_secs_f64(time_per_input * inputs_left as f64);

            let seconds = time_left.as_secs();
            let hours = seconds / 3600;
            let mins = (seconds % 3600) / 60;
            let secs = seconds % 60;

            log::info!(
                "{:8.2?} | {curr_index:>10} / {:8} (~time left {time_left:6.2?} | {hours:02}:{mins:02}:{secs:02})",
                start.elapsed(),
                ending_index,
            );
        }

        // Initialize variables needed for this run
        let mut execution = Execution::Continue;
        let mut coverage = BTreeSet::new();
        let mut perf = crate::fuzzvm::VmRunPerf::default();

        // Get the current input to gather coverage for
        let input_case = &paths[curr_index];

        // Restore all of the known coverage
        let Some(cov_bps) = fuzzvm.coverage_breakpoints.take() else { unreachable!() };
        for (addr, _byte) in cov_bps.iter() {
            fuzzvm.write_bytes_dirty(*addr, fuzzvm.cr3(), &[0xcc])?;
        }
        fuzzvm.coverage_breakpoints = Some(cov_bps);

        // Get the input to trace
        let input = FUZZER::Input::from_bytes(&std::fs::read(input_case)?)?;

        // Set the input into the VM as per the fuzzer
        fuzzer.set_input(&input, &mut fuzzvm)?;

        // Top of the run iteration loop for the current fuzz case
        loop {
            // Reset the VM if the vmexit handler says so
            if matches!(execution, Execution::Reset | Execution::CrashReset { .. }) {
                break;
            }

            // Execute the VM
            let ret = fuzzvm.run(&mut perf)?;

            if let FuzzVmExit::CoverageBreakpoint(rip) = ret {
                coverage.insert(rip);
            }

            // Handle the FuzzVmExit to determine
            let ret = handle_vmexit(&ret, &mut fuzzvm, &mut fuzzer, None, &input);

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
            if let Ok(new_execution) = fuzzvm.handle_breakpoint(&mut fuzzer, &input) {
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

        // Insert the coverage for this path index
        result.insert(curr_index, coverage);

        // Reset the guest state
        let _perf = fuzzvm.reset_guest_state(&mut fuzzer)?;

        // Reset the fuzzer state
        fuzzer.reset_fuzzer_state();
    }

    Ok(result)
}

/// Naive corpus minimizer
///
/// Algorithm:
///
/// Repeatedly keep inputs that contain the rarest known coverage addresses
///
/// * Collect coverage from all known inputs
/// * Identify all inputs that hit each specific coverage address
/// loop {
///   * Look for the coverage address with the fewest inputs (aka current rarest address)
///   * Choose one of the inputs that hits this address
///   * Save this input into a new minimizer
///   * Remove this input's coverage from all known coverage addresses
///   * loop until there are no more known coverage addresses with inputs
/// }
#[derive(Default)]
struct CorpusMinimizer {
    /// Mapping of coverage addresses to the path index the input that hits this address
    pub addr_to_inputs: BTreeMap<u64, BTreeSet<usize>>,

    /// Directory of all input path indexes and their respective coverage
    pub input_coverage: BTreeMap<usize, BTreeSet<u64>>,
}

// Get a human readable string of the given number of bytes
fn get_byte_size(size: u64) -> String {
    let units = ["B", "KB", "MB", "GB"];

    let mut size = size as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < units.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    format!("{:.2} {}", size, units[unit_index])
}

impl CorpusMinimizer {
    pub fn size(&self) {
        let sum: usize = self
            .addr_to_inputs
            .iter()
            .map(|(k, v)| std::mem::size_of::<u64>() + v.len() * size_of::<usize>())
            .sum();
        log::info!("Size of addr_to_inputs: {}", get_byte_size(sum as u64));

        let sum: usize = self
            .input_coverage
            .iter()
            .map(|(k, v)| std::mem::size_of::<u64>() + v.len() * size_of::<u64>())
            .sum();
        log::info!("Size of input_coverage: {}", get_byte_size(sum as u64));
    }

    /// Add the given set of inputs to this minimizer.
    pub fn add_inputs(&mut self, mut inputs: BTreeMap<usize, BTreeSet<u64>>) {
        while let Some((path_index, coverage)) = inputs.pop_first() {
            // Add each address in this coverage to the total known coverage
            for addr in &coverage {
                self.addr_to_inputs
                    .entry(*addr)
                    .or_default()
                    .insert(path_index);
            }

            // Insert this input's coverage to the database
            self.input_coverage.insert(path_index, coverage);
        }
    }

    /// Reduce the current set of inputs and return the inputs removed from the database
    pub fn reduce(&mut self) -> Vec<usize> {
        let mut new_minimizer = CorpusMinimizer::default();
        let mut curr_path_index;

        log::info!("Starting inputs: {}", self.input_coverage.len());
        self.size();

        let mut heap = BinaryHeap::new();

        loop {
            // Get the address coveraged by the fewest number of inputs
            heap.clear();

            // Insert the current inputs to the binary heap
            for (addr, hits) in self.addr_to_inputs.iter() {
                heap.push(Reverse((hits.len(), *addr)));
            }

            // Get the current rarest coverage address
            let Some(Reverse((_num_hits, address))) = heap.pop() else {
                break;
            };

            // Get the first path index that hits the current "rare" address
            curr_path_index = *self
                .addr_to_inputs
                .get(&address)
                .unwrap()
                .iter()
                .next()
                .unwrap();

            // Get the total coverage of the input that we need to keep
            let coverage = self.input_coverage.remove(&curr_path_index).unwrap();

            for addr in &coverage {
                // Remove this address from the current database
                self.addr_to_inputs.remove_entry(addr);

                // Add the address to the reduced database with only this path index as the entry
                let mut new_set = BTreeSet::new();
                new_set.insert(curr_path_index);
                new_minimizer.addr_to_inputs.insert(*addr, new_set);
            }

            // Add this input and it's coverage to the reduced database
            new_minimizer
                .input_coverage
                .insert(curr_path_index, coverage);
        }

        // Return the removed path indexes
        let trash = self.input_coverage.keys().map(|x| *x).collect();

        // Replace the current minimizer with the newly created one
        *self = new_minimizer;

        log::info!("Starting inputs after: {}", self.input_coverage.len());

        // Return the inputs not needed for the new minimizer
        trash
    }
}
