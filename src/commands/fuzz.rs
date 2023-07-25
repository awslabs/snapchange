//! Execute the `fuzz` command

use anyhow::{ensure, Context, Result};

use std::collections::VecDeque;

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use core_affinity::CoreId;
use kvm_bindings::CpuId;
use kvm_ioctls::VmFd;

use crate::cmdline;
use crate::cmdline::ProjectCoverage;

use crate::config::Config;
use crate::coverage_analysis::CoverageAnalysis;
use crate::enable_manual_dirty_log_protect;
use crate::fuzz_input::{FuzzInput, InputMetadata};
use crate::fuzzer::Fuzzer;
use crate::fuzzvm::FuzzVm;
use crate::rng::Rng;
use crate::stats::{self, PerfMark};
use crate::try_u64;
use crate::utils::save_input_in_dir;
use crate::{block_sigalrm, kick_cores, Stats, FINISHED};

use crate::memory::Memory;
use crate::{fuzzvm, unblock_sigalrm, write_crash_input, THREAD_IDS};
use crate::{handle_vmexit, init_environment, KvmEnvironment, ProjectState};
use crate::{Cr3, Execution, ResetBreakpointType, Symbol, VbCpu, VirtAddr};

#[cfg(feature = "redqueen")]
use x86_64::registers::rflags::RFlags;

#[cfg(feature = "redqueen")]
use crate::cmp_analysis::RedqueenRule;

use crate::stack_unwinder::StackUnwinders;

/// DEBUGGING ONLY: Enable single step for all cores when fuzzing to debug what is happening during fuzzing
///
/// During testing, sometimes a crash was written to disk that did not reproduce in the
/// single step trace. This flag enables writing a single step trace of any crash found.
/// Since this enables single step for all fuzzing cores, it drastically reduces
/// performance of the fuzzing and should only be used for testing.
const SINGLE_STEP: bool = false;

/// Single step debugging enabled for all cores
pub static SINGLE_STEP_DEBUG: AtomicBool = AtomicBool::new(false);

/// Execute the fuzz subcommand to fuzz the given project
pub(crate) fn run<FUZZER: Fuzzer + 'static>(
    mut project_state: ProjectState,
    args: &cmdline::Fuzz,
) -> Result<()> {
    log::info!("{:x?}", project_state.config);

    let KvmEnvironment {
        kvm,
        cpuids,
        physmem_file,
        clean_snapshot,
        symbols,
        symbol_breakpoints,
    } = init_environment(&project_state)?;

    // Get the number of cores to fuzz with
    let mut cores = args.cores.unwrap_or(1);
    if cores == 0 {
        log::warn!("No cores given. Defaulting to 1 core");
        cores = 1;
    }

    // Init list of all cores executing
    let mut threads = Vec::new();

    // Create a `Stats` for each core
    let stats: Vec<Arc<Mutex<Stats<FUZZER>>>> = (1..=cores)
        .map(|_| Arc::new(Mutex::new(Stats::default())))
        .collect();

    // Wrap the stats vec to pass to the CtrlC handler
    let stats = Arc::new(stats);

    // Get the first core to keep the main thread on
    let core_ids = core_affinity::get_core_ids().unwrap();
    let first_core = core_ids[0];

    // Create the directory to write crash files into if it doesn't exist
    let mut crash_dir = project_state.path.clone();
    crash_dir.push("crashes");
    if !crash_dir.exists() {
        std::fs::create_dir(&crash_dir).context("Failed to create crash dir")?;
    }

    log::warn!("Starting all {} worker threads", cores);

    // Read the input corpus from the given input directory
    let mut input_corpus = Vec::new();

    // Use the user given input directory or default to <PROJECT_DIR>/input
    let input_dir = if let Some(input_dir) = &args.input_dir {
        input_dir.clone()
    } else if project_state.path.join("current_corpus").exists() {
        // If no input dir was given, and the current corpus exists, use the old corpus
        project_state.path.join("current_corpus")
    } else if project_state.path.join("input").exists() {
        // If no given input or current corpus, use "input" directory
        project_state.path.join("input")
    } else {
        // Default to the standard current_corpus directory
        project_state.path.join("current_corpus")
    };

    // Get the corpus directory
    let mut corpus_dir = project_state.path.clone();
    corpus_dir.push("current_corpus");
    if !corpus_dir.exists() {
        std::fs::create_dir(&corpus_dir).context("Failed to create crash dir")?;
    }

    let num_files = input_dir.read_dir()?.count();

    // Give some statistics on reading the initial corpus
    let mut start = std::time::Instant::now();
    let mut count = 0_u32;
    if input_dir.exists() {
        for (i, file) in input_dir.read_dir()?.enumerate() {
            if start.elapsed() >= std::time::Duration::from_millis(1000) {
                let left = num_files - i;
                println!(
                    "{i:9} / {num_files:9} | Reading corpus {:8.2} files/sec | {:6.2} seconds left",
                    count as f64 / start.elapsed().as_secs_f64(),
                    left as f64 / (count as f64 / start.elapsed().as_secs_f64()),
                );
                start = std::time::Instant::now();
                count = 0;
            }

            count += 1;

            let filepath = file?.path();

            // Ignore directories if they exist
            if filepath.is_dir() {
                log::debug!("Ignoring directory found in input dir: {:?}", filepath);
                continue;
            }

            // Add the input to the input corpus
            input_corpus.push(FUZZER::Input::from_bytes(&std::fs::read(filepath)?)?);
        }
    } else {
        log::warn!("No input directory found: {input_dir:?}, starting with an empty corpus!");
    }

    // Initialize the dictionary
    let mut dict = None;
    let dict_dir = project_state.path.join("dict");
    if dict_dir.exists() {
        let mut new_dict = Vec::new();

        for file in std::fs::read_dir(dict_dir)? {
            let file = file?;
            new_dict.push(std::fs::read(file.path())?);
        }

        dict = Some(new_dict);
    } else {
        log::warn!("No dictionary in use. {dict_dir:?} not found.");
    }

    // Start each core with the full corpus based on the configuration
    let input_corpus_len = input_corpus.len();
    let max_new_corpus_size = project_state.config.stats.maximum_new_corpus_size;
    let starting_corp_len = input_corpus_len.min(max_new_corpus_size);
    log::info!("Starting corp len: {starting_corp_len}");
    let mut corp_counter = 0;

    log::info!(
        "Starting corpus: Total {} Per core {}",
        input_corpus_len,
        starting_corp_len
    );

    // Set the fuzz vm timeout
    let vm_timeout = args.timeout;

    log::info!("Execution timeout: {:?}", vm_timeout);

    let physmem_file_fd = physmem_file.as_raw_fd();

    // Get the coverage breakpoints for this core
    let ProjectCoverage {
        coverage_left,
        prev_coverage,
        prev_redqueen_coverage,
    } = project_state.coverage_left()?;

    log::info!("Coverage left: {}", coverage_left.len());

    // Init the coverage breakpoints mapping to byte
    let mut covbp_bytes = BTreeMap::new();

    // Start timer for writing all coverage breakpoints
    let start = Instant::now();

    // Write the remaining coverage breakpoints into the "clean" snapshot
    let mut count = 0;
    let cr3 = Cr3(project_state.vbcpu.cr3);

    {
        // Small scope to drop the clean snapshot lock
        let mut curr_clean_snapshot = clean_snapshot.write().unwrap();
        for addr in &coverage_left {
            if let Ok(orig_byte) = curr_clean_snapshot.read::<u8>(*addr, cr3) {
                curr_clean_snapshot.write_bytes(*addr, cr3, &[0xcc])?;
                covbp_bytes.insert(*addr, orig_byte);
                count += 1;
            }
        }
    }

    log::info!("Pre-populating coverage breakpoints");
    log::info!(
        "Given {:?} | Valid {:?} | Can write {:16.2} covbps/sec",
        coverage_left.len(),
        covbp_bytes.len(),
        f64::from(count) / start.elapsed().as_secs_f64()
    );

    #[cfg(feature = "redqueen")]
    let redqueen_rules: BTreeMap<u64, BTreeSet<RedqueenRule>> = BTreeMap::new();

    /*
    let redqueen_rules_path = project_state.path.join("redqueen.rules");
    let redqueen_rules_bytes = std::fs::read(&redqueen_rules_path).unwrap_or_default();
    if !redqueen_rules_bytes.is_empty() {
        redqueen_rules = serde_json::from_slice(&redqueen_rules_bytes)?;
    }
    log::info!("Redqueen rules: {}", redqueen_rules.len());
    */

    // Due to the time it takes to clone large corpi, symbols, or coverage breakpoints,
    // we bulk clone as many as we need for all the cores at once and then `.take` them
    // from these collections
    let start = std::time::Instant::now();
    let mut starting_symbols = (0..=cores).map(|_| symbols.clone()).collect::<Vec<_>>();
    log::info!("Cloned {} symbols in {:?}", cores, start.elapsed());

    let start = std::time::Instant::now();
    let mut starting_covbps = (0..=cores).map(|_| covbp_bytes.clone()).collect::<Vec<_>>();
    log::info!("Cloned {} covbps in {:?}", cores, start.elapsed());

    let start = std::time::Instant::now();
    let mut starting_dicts = (0..=cores).map(|_| dict.clone()).collect::<Vec<_>>();
    log::info!("Cloned {} dictionaries in {:?}", cores, start.elapsed());

    let start = std::time::Instant::now();
    let mut starting_configs = (0..=cores)
        .map(|_| project_state.config.clone())
        .collect::<Vec<_>>();
    log::info!("Cloned {} configs in {:?}", cores, start.elapsed());

    let start = std::time::Instant::now();
    let mut starting_unwinders = (0..=cores)
        .map(|_| project_state.unwinders.clone())
        .collect::<Vec<_>>();
    log::info!("Cloned {} unwinders in {:?}", cores, start.elapsed());

    let start = std::time::Instant::now();
    let mut starting_prev_coverage = (0..=cores)
        .map(|_| prev_coverage.clone())
        .collect::<Vec<_>>();
    log::info!(
        "Cloned {} previous coverage ({}) in {:?}",
        cores,
        prev_coverage.len(),
        start.elapsed()
    );

    #[cfg(feature = "redqueen")]
    let mut starting_prev_redqueen_coverage = {
        let start = std::time::Instant::now();
        let result = (0..=cores)
            .map(|_| prev_redqueen_coverage.clone())
            .collect::<Vec<_>>();
        log::info!(
            "Cloned {} previous redqueen coverage in {:?}",
            cores,
            start.elapsed()
        );
        result
    };

    #[cfg(feature = "redqueen")]
    let mut starting_redqueen_rules = {
        let start = std::time::Instant::now();
        let result = (0..=cores)
            .map(|_| redqueen_rules.clone())
            .collect::<Vec<_>>();
        log::info!("Cloned {} redqueen rules in {:?}", cores, start.elapsed());
        result
    };

    let start = std::time::Instant::now();
    let mut starting_sym_breakpoints = (0..=cores)
        .map(|_| symbol_breakpoints.clone())
        .collect::<Vec<_>>();
    log::info!(
        "Cloned {} symbol breakpoints in {:?}",
        cores,
        start.elapsed()
    );

    const BETWEEN_WAIT_FOR_MILLIES: u64 = 100;

    // Create a thread for each active CPU core.
    for id in 1..=cores {
        let core_id = CoreId {
            id: usize::try_from(id)?,
        };

        // there is a bit of a race condition here: if the sigalarm timer hits exactly while we are
        // in the `KVM_CREATE_VM` ioctl (via kvm.create_vm() below), the ioctl will be interrupted
        // and return EINTR. We don't really want that to happen, so we block SIGALRM for the
        // current thread until we are done with the kvm ioctl.
        block_sigalrm()?;

        // Create the VM for this core
        let vm = kvm.create_vm().context("Failed to create VM from KVM")?;

        // Enable dirty bits
        enable_manual_dirty_log_protect(&vm)?;

        // restore previous state.
        unblock_sigalrm()?;

        // Copy the CPUIDs for this core
        let cpuids = cpuids.clone();

        // Get core local copies of the symbols and crashing symbols
        let id: usize = id.try_into().unwrap();

        // Get the stats for this core
        let core_stats = stats[core_id.id - 1].clone();

        // Create this core's corpus
        let mut rng = Rng::new();
        let mut corpus = Vec::new();
        let mut seen = BTreeSet::new();
        for _ in 0..starting_corp_len {
            let corp_counter = rng.next() as usize % input_corpus.len();
            if !seen.insert(corp_counter) {
                continue;
            }

            corpus.push(input_corpus[corp_counter].clone());
        }

        // Add a single input if none found
        if corpus.is_empty() {
            let mut rng = Rng::new();
            let input = FUZZER::Input::generate(&[], &mut rng, &dict, FUZZER::MAX_INPUT_LENGTH);
            input_corpus.push(input.clone());
            corpus.push(input);
        }

        log::info!("Created corpus {id} of len {}", corpus.len());

        // Get the starting resources for this specific core
        let curr_symbols = std::mem::take(&mut starting_symbols[id]);
        let symbol_breakpoints = std::mem::take(&mut starting_sym_breakpoints[id]);
        let coverage_breakpoints = Some(std::mem::take(&mut starting_covbps[id]));
        let dictionary = std::mem::take(&mut starting_dicts[id]);
        let prev_coverage = std::mem::take(&mut starting_prev_coverage[id]);
        let config = std::mem::take(&mut starting_configs[id]);

        let unwinders = std::mem::take(&mut starting_unwinders[id]);

        #[cfg(feature = "redqueen")]
        let prev_redqueen_coverage = std::mem::take(&mut starting_prev_redqueen_coverage[id]);

        #[cfg(feature = "redqueen")]
        let redqueen_rules = std::mem::take(&mut starting_redqueen_rules[id]);

        // Get an owned copy of the crash dir for this core
        let project_dir = project_state.path.clone();

        if id % 5 == 0 {
            println!("Starting core: {}/{}", core_id.id, cores);
        }

        let clean_snapshot = clean_snapshot.clone();

        // make a Copy of those two that will be moved into the thread closure
        let stop_after_time = args.stop_after_time;
        let stop_after_first_crash = args.stop_after_first_crash;

        // Start executing on this core
        let thread = std::thread::spawn(move || -> Result<()> {
            let result = std::panic::catch_unwind(|| -> Result<()> {
                start_core::<FUZZER>(
                    core_id,
                    &vm,
                    &project_state.vbcpu,
                    &cpuids,
                    physmem_file_fd,
                    clean_snapshot,
                    &curr_symbols,
                    symbol_breakpoints,
                    coverage_breakpoints,
                    &core_stats,
                    &project_dir,
                    vm_timeout,
                    corpus,
                    &dictionary,
                    prev_coverage,
                    &config,
                    stop_after_time,
                    stop_after_first_crash,
                    unwinders,
                    #[cfg(feature = "redqueen")]
                    prev_redqueen_coverage,
                    #[cfg(feature = "redqueen")]
                    redqueen_rules,
                    #[cfg(feature = "redqueen")]
                    project_state.redqueen_available,
                )
            });

            // Ensure this thread is signalling it is not alive
            core_stats.lock().unwrap().alive = false;

            match result {
                Ok(no_panic_result) => no_panic_result,
                Err(_panic_result) => {
                    // Convert the panic result into a string for printing
                    // while the other threads are shutting down
                    /*
                    let err_msg = panic_result.downcast::<String>().ok();
                    log::warn!("ERROR FROM CORE {id}: {err_msg:?}");
                    tui_logger::move_events();
                    println!("ERROR FROM CORE {id}: {err_msg:?}");
                    FINISHED.store(true, Ordering::SeqCst);
                    */

                    // If any thread panics, force all other threads to die
                    FINISHED.store(true, Ordering::SeqCst);

                    Ok(())
                }
            }
        });

        // Sleep to let the system catch up to the threads being created
        std::thread::sleep(std::time::Duration::from_millis(BETWEEN_WAIT_FOR_MILLIES));

        // Add this thread to the total list of threads
        threads.push(Some(thread));
    }

    // Collect all the threads
    // let mut results  = Vec::new();

    //  Setup the CTRL+C handler
    let ctrl_c_stats = stats.clone();
    let res = ctrlc::set_handler(move || {
        log::info!("CTRL C PRESSED!");

        // Signal cores to terminate
        for core_stats in ctrl_c_stats.iter() {
            core_stats.lock().unwrap().forced_shutdown = true;
            // core_stats.lock().unwrap().alive = false;
        }

        // Signal stats display to terminate
        FINISHED.store(true, Ordering::SeqCst);
    });

    if let Err(e) = res {
        log::warn!("Error setting CTRL+C hander: {e:}");
    }

    // Spawn the kick cores thread
    let kick_cores_thread = std::thread::spawn(move || {
        // Ignore the SIGALRM for this thread
        block_sigalrm().unwrap();

        // Set the core affinity for this core to always be 0
        core_affinity::set_for_current(first_core);

        // Start the kick cores worker
        kick_cores();
    });

    // The command line argument is set when asking for ASCII stats. Invert this
    // result to determine if we use TUI.
    let tui = !args.ascii_stats;

    let project_dir = project_state.path.clone();

    let mut cov_analysis = None;
    let mut cov_analysis_state = None;
    project_dir
        .read_dir()
        .expect("Failed to read project_dir")
        .for_each(|file| {
            if let Ok(file) = file {
                if let Some(extension) = file.path().extension() {
                    if extension.to_str() == Some("coverage_analysis") {
                        cov_analysis = Some(file);
                    } else if extension.to_str() == Some("coverage_analysis_state") {
                        cov_analysis_state = Some(file);
                    }
                }
            }
        });

    let mut coverage_analysis = None;

    if let Some(state_file) = cov_analysis_state {
        log::info!("Loading coverage analysis from state");
        coverage_analysis = Some(CoverageAnalysis::load_state(&state_file.path())?);
    } else if let Some(cov_file) = cov_analysis {
        log::info!("Loading coverage analysis from binary ninja file");
        let analysis = CoverageAnalysis::from_binary_ninja(&cov_file.path())?;
        let state_file = cov_file.path().with_extension("coverage_analysis_state");
        analysis.save_state(&state_file)?;

        coverage_analysis = Some(analysis);
    };

    let stop_after_first_crash = args.stop_after_first_crash;

    // Spawn the stats thread if there isn't a single step trace happening
    let curr_stats = stats;
    let stats_thread = std::thread::spawn(move || {
        // Ignore the SIGALRM for this thread
        block_sigalrm().unwrap();

        // Set the core affinity for this core to always be 0
        core_affinity::set_for_current(first_core);

        // let prev_coverage = prev_coverage.iter().map(|x| x.0).collect();

        // Start the stats worker
        let res = stats::worker(
            curr_stats,
            &project_state.modules,
            &project_dir,
            prev_coverage,
            prev_redqueen_coverage,
            &input_corpus,
            project_state.coverage_breakpoints,
            &symbols,
            coverage_analysis,
            tui,
            &project_state.config,
            stop_after_first_crash,
        );

        if let Err(e) = res {
            FINISHED.store(true, Ordering::SeqCst);
            eprintln!("{e:?}");
        }
    });

    let mut errors = Vec::new();

    'done: loop {
        let mut all_finished = true;

        #[allow(clippy::needless_range_loop)]
        for index in 0..threads.len() {
            if let Some(thread) = threads[index].take() {
                if thread.is_finished() {
                    match thread.join() {
                        Err(e) => {
                            FINISHED.store(true, Ordering::SeqCst);

                            errors.push(format!(
                                "Thread {index} panic: {:?}",
                                e.downcast::<String>()
                            ));
                            // errors.push(e);

                            /*
                            for stat in stats.iter() {
                                stat.lock().unwrap().alive = false;
                            }
                            */

                            break 'done;
                        }
                        Ok(Err(e)) => {
                            // Some thread exited with an error. Force all
                            // threads to also die
                            crate::stats_tui::restore_terminal()?;
                            FINISHED.store(true, Ordering::SeqCst);
                            println!("Thread {index} returned err.. {e:?}");
                        }
                        x => {
                            println!("Thread {index} returned success.. {x:?}");
                        }
                    }
                } else {
                    all_finished = false;
                    threads[index] = Some(thread);
                }
            }
        }

        if all_finished || FINISHED.load(Ordering::SeqCst) {
            break;
        }

        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    // if all threads exiting on their own, we need to make sure to signal the stats and kick
    // threads to stop.
    FINISHED.store(true, Ordering::SeqCst);

    println!("Stats thread: {:?}", stats_thread.join());
    println!("Kick thread: {:?}", kick_cores_thread.join());

    for error in errors {
        eprintln!("{error:?}");
    }

    Ok(())
}

/// Thread worker used to fuzz the given [`VbCpu`] state with the given physical memory.
fn start_core<FUZZER: Fuzzer>(
    core_id: CoreId,
    vm: &VmFd,
    vbcpu: &VbCpu,
    cpuid: &CpuId,
    snapshot_fd: i32,
    clean_snapshot: Arc<RwLock<Memory>>,
    symbols: &Option<VecDeque<Symbol>>,
    symbol_breakpoints: Option<BTreeMap<(VirtAddr, Cr3), ResetBreakpointType>>,
    coverage_breakpoints: Option<BTreeMap<VirtAddr, u8>>,
    core_stats: &Arc<Mutex<Stats<FUZZER>>>,
    project_dir: &Path,
    vm_timeout: Duration,
    mut corpus: Vec<FUZZER::Input>,
    dictionary: &Option<Vec<Vec<u8>>>,
    prev_coverage: BTreeSet<VirtAddr>,
    config: &Config,
    stop_after_time: Option<Duration>,
    stop_after_first_crash: bool,
    unwinders: StackUnwinders,
    #[cfg(feature = "redqueen")] prev_redqueen_coverage: BTreeSet<(VirtAddr, RFlags)>,
    #[cfg(feature = "redqueen")] redqueen_rules: BTreeMap<u64, BTreeSet<RedqueenRule>>,
    #[cfg(feature = "redqueen")] redqueen_availble: bool,
) -> Result<()> {
    /// Helper macro to time the individual components of resetting the guest state
    macro_rules! time {
        ($marker:ident, $expr:expr) => {{
            // Init the timer
            core_stats
                .lock()
                .unwrap()
                .perf_stats
                .start(PerfMark::$marker);

            // Execute the given expression
            let result = $expr;

            // Calculate the time took to execute $expr
            core_stats
                .lock()
                .unwrap()
                .perf_stats
                .mark(PerfMark::$marker);

            // Return the result from the expression
            result
        }};
    }

    // Store the thread ID of this thread used for passing the SIGALRM to this thread
    let thread_id = unsafe { libc::pthread_self() };
    *THREAD_IDS[core_id.id].lock().unwrap() = Some(thread_id);

    // Set the core affinity for this core
    core_affinity::set_for_current(core_id);

    // Unblock SIGALRM to enable this thread to handle SIGALRM
    unblock_sigalrm()?;

    let mut fuzzer = FUZZER::default();

    // RNG for this core used for mutation of inputs
    let mut rng = Rng::new();

    // Sanity check that the given fuzzer matches the snapshot
    ensure!(
        FUZZER::START_ADDRESS == vbcpu.rip,
        fuzzvm::Error::SnapshotMismatch
    );

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
        config.clone(),
        unwinders,
        #[cfg(feature = "redqueen")]
        redqueen_rules,
    )?;

    let mut coverage = prev_coverage;
    log::info!("Starting with {} coverage", coverage.len());

    #[cfg(feature = "redqueen")]
    let mut redqueen_coverage = prev_redqueen_coverage;

    // Addresses covered by the current input
    let mut new_coverage_for_input = BTreeSet::new();

    // Number of iterations before syncing stats
    let mut coverage_sync = std::time::Instant::now();
    let mut last_sync = std::time::Instant::now();
    let mut last_corpus_sync = std::time::Instant::now();

    // Start the performance counter for the total elapsed time
    core_stats.lock().unwrap().perf_stats.start(PerfMark::Total);

    let mut iters = 0;

    // Sanity warn that all cores are in single step when debugging
    if SINGLE_STEP && SINGLE_STEP_DEBUG.load(Ordering::SeqCst) {
        log::warn!("SINGLE STEP FUZZING ENABLED");
        log::warn!("SINGLE STEP FUZZING ENABLED");
        log::warn!("SINGLE STEP FUZZING ENABLED");
        fuzzvm.enable_single_step()?;
    }

    // Get the crash dir for this project
    let crash_dir = project_dir.join("crashes");

    // Get the corpus dir for this project
    let corpus_dir = project_dir.join("current_corpus");

    let fuzz_start_time = std::time::Instant::now();

    'finish: for _iter in 0usize.. {
        // Signal that this core is alive
        core_stats.lock().unwrap().alive = true;

        // Mark and reset the performance counter for the total elapsed time
        core_stats.lock().unwrap().perf_stats.mark(PerfMark::Total);
        core_stats.lock().unwrap().perf_stats.start(PerfMark::Total);

        // Sync the corpus with the main stats
        if last_corpus_sync.elapsed() >= config.stats.merge_coverage_timer {
            // Replace the fuzzer corpus
            let mut curr_stats = core_stats.lock().unwrap();

            if let Some(new_corp) = curr_stats.new_corpus.take() {
                if !new_corp.is_empty() {
                    // Send the current corpus to the main corpus collection
                    curr_stats.old_corpus = Some(corpus);

                    corpus = new_corp;
                }
            }

            /*
            // Sync this core's redqueen rules with the main thread's rules
            if fuzzvm.core_id <= REDQUEEN_CORES {
                // Add this core's rules to the total rules from the main thread
                curr_stats.redqueen_rules.append(&mut fuzzvm.redqueen_rules);

                // Copy the newly updated main thread's stats to this core (effectively
                // syncing the rules with the core)
                fuzzvm.redqueen_rules = curr_stats.redqueen_rules.clone();
            }
            */

            // Reset the last corpus sync counter
            last_corpus_sync = Instant::now();
        }

        // Sync the current stats to the main stats
        if last_sync.elapsed() >= config.stats.stats_sync_timer {
            time!(StatsSync, {
                // Add the current iterations to the coverage
                core_stats.lock().unwrap().iterations += iters;

                // Reset the local coverage to match the global coverage set in stats
                /*
                core_stats.lock().unwrap().redqueen_coverage.append(&mut redqueen_coverage);
                for cov in &core_stats.lock().unwrap().redqueen_coverage {
                    redqueen_coverage.insert(*cov);
                }
                */

                // Update the number of remaining number of coverage breakpoints
                if let Some(ref cov_bps) = fuzzvm.coverage_breakpoints {
                    core_stats.lock().unwrap().cov_left = u32::try_from(cov_bps.len())?;
                }

                // Reset the iteration counter
                iters = 0;

                // Reset the last sync counter
                last_sync = Instant::now();
            });
        }

        if coverage_sync.elapsed() >= config.stats.coverage_sync_timer {
            time!(SyncCov1, {
                // Append the current coverage
                core_stats.lock().unwrap().coverage.append(&mut coverage);
            });

            time!(SyncCov2, {
                // Reset the local coverage to match the global coverage set in stats
                for addr in &core_stats.lock().unwrap().coverage {
                    coverage.insert(*addr);
                }
            });

            // Reset the last sync counter
            coverage_sync = Instant::now();
        }

        iters += 1;

        // Reset new coverage marker
        new_coverage_for_input.clear();

        // Reset the fuzzer state
        fuzzer.reset_fuzzer_state();

        // Get a random input from the corpus
        let mut input = time!(
            ScheduleInput,
            fuzzer.schedule_next_input(&corpus, &mut rng, dictionary)
        );

        let original_file = input.fuzz_hash();

        let orig_corpus_len = corpus.len();
        let orig_coverage_len = coverage.len();

        // Gather redqueen for this input if there aren't already replacement rules found
        #[cfg(feature = "redqueen")]
        if redqueen_availble {
            time!(Redqueen, {
                // If this input has never been through redqueen or hit the small change to go through again,
                // execute redqueen on this input
                if fuzzvm.core_id <= config.redqueen.cores
                    && (!fuzzvm.redqueen_rules.contains_key(&input.fuzz_hash())
                        || (fuzzvm.rng.next() % 1000) == 42)
                {
                    let redqueen_time_spent = Duration::from_secs(0);

                    // Signal this thread is in redqueen
                    core_stats.lock().unwrap().in_redqueen = true;
                    core_stats.lock().unwrap().iterations = 0;

                    let orig_corpus_len = corpus.len();

                    // Execute redqueen for this input
                    fuzzvm.gather_redqueen(
                        &input,
                        &mut fuzzer,
                        vm_timeout,
                        &mut corpus,
                        &mut coverage,
                        &mut redqueen_coverage,
                        redqueen_time_spent,
                        &project_dir.join("metadata"),
                    )?;

                    // Signal this thread is in not in redqueen
                    core_stats.lock().unwrap().in_redqueen = false;

                    // If redqueen found new inputs, write them to disk
                    if corpus.len() > orig_corpus_len {
                        for input in &corpus {
                            save_input_in_dir(input, &corpus_dir)?;
                        }
                    }
                }
            });

            /*
            // Sanity check redqueen breakpoints are being overwritten
            for addr in FUZZER::redqueen_breakpoint_addresses() {
                if fuzzvm.read::<u8>(VirtAddr(*addr), fuzzvm.cr3())? == 0xcc {
                    log::info!("RQ addr still in place! {addr:#x}");
                    panic!();
                }
            }
            */
        }

        if corpus.len() != orig_corpus_len {
            log::info!("Redqueen new corpus! {orig_corpus_len} -> {}", corpus.len());
        }

        if coverage.len() != orig_coverage_len {
            log::info!(
                "Redqueen new coverage! {orig_coverage_len} -> {}",
                coverage.len()
            );
        }

        // Mutate the input based on the fuzzer
        let mutation = time!(
            InputMutate,
            fuzzer.mutate_input(&mut input, &corpus, &mut rng, dictionary)
        );

        // Set the input into the VM as per the fuzzer
        time!(InputSet, fuzzer.set_input(&input, &mut fuzzvm)?);

        let mut execution;

        let mut symbol = String::new();
        let mut instrs = Vec::new();
        let mut i = 0;

        // if SINGLE_STEP_DEBUG.load(Ordering::SeqCst) || fuzzvm.rng.next() % 2 == 0 {
        /*
        if SINGLE_STEP {
            if fuzzvm.rng.next() % 2 == 0 {
                SINGLE_STEP_DEBUG.store(true, Ordering::SeqCst);
                fuzzvm.enable_single_step()?;
            } else {
                SINGLE_STEP_DEBUG.store(false, Ordering::SeqCst);
                fuzzvm.disable_single_step()?;
            }
        }
        */

        let mut perf = crate::fuzzvm::VmRunPerf::default();

        // Top of the run iteration loop for the current fuzz case
        loop {
            if SINGLE_STEP && SINGLE_STEP_DEBUG.load(Ordering::SeqCst) {
                // Add the current instruction to the trace
                let rip = fuzzvm.regs().rip;
                let cr3 = fuzzvm.cr3();
                let instr = fuzzvm
                    .get_current_verbose_instruction_string()
                    .ok()
                    .unwrap_or_else(|| String::from("???"));

                // Get the symbol for RIP if we have a symbols database
                if let Some(ref sym_data) = symbols {
                    // Clear the re-used String allocation for the symbol
                    symbol.clear();

                    // Get the symbol itself
                    let curr_symbol = crate::symbols::get_symbol(rip, sym_data)
                        .unwrap_or_else(|| "UnknownSym".to_string());
                    symbol.push_str(&curr_symbol.to_string());
                }

                let instr = format!(
                    "INSTRUCTION {:07} {:#018x} {:#010x} | {:60}\n    {instr}",
                    i,
                    rip,
                    u64::try_from(cr3.0).unwrap(),
                    symbol
                );

                instrs.push(instr);

                i += 1;
            }

            // Execute the VM
            let ret = fuzzvm.run(&mut perf)?;

            // Add the performance counters to the stats from execution of the VM
            core_stats
                .lock()
                .unwrap()
                .perf_stats
                .add(PerfMark::InVm, perf.in_vm);
            core_stats
                .lock()
                .unwrap()
                .perf_stats
                .add(PerfMark::PreRunVm, perf.pre_run_vm);
            core_stats
                .lock()
                .unwrap()
                .perf_stats
                .add(PerfMark::PostRunVm, perf.post_run_vm);

            core_stats.lock().unwrap().inc_vmexit(&ret);

            // Get the RIP to check for coverage
            let rip = VirtAddr(fuzzvm.rip());

            // Handle the FuzzVmExit to determine if the VM should continue or reset
            execution = time!(
                HandleVmExit,
                handle_vmexit(&ret, &mut fuzzvm, &mut fuzzer, Some(&crash_dir), &input)?
            );

            // If we hit a coverage execution, add the RIP to
            if matches!(execution, Execution::CoverageContinue) && coverage.insert(rip) {
                // log::info!("New cov: {rip:x?}");
                new_coverage_for_input.insert(rip);
            }

            // If we hit a coverage execution, add the RIP to
            if fuzzvm.single_step
                && fuzzvm
                    .coverage_breakpoints
                    .as_ref()
                    .unwrap()
                    .contains_key(&rip)
                && coverage.insert(rip)
            {
                // log::info!("New cov: {rip:#x}");
                new_coverage_for_input.insert(rip);
            }

            if SINGLE_STEP {
                // During single step, breakpoints aren't triggered. For this reason,
                // we need to check if the instruction is a breakpoint regardless in order to
                // apply fuzzer specific breakpoint logic. We can ignore the "unknown breakpoint"
                // error that is thrown if a breakpoint is not found;
                if let Ok(new_execution) = fuzzvm.handle_breakpoint(&mut fuzzer, &input) {
                    execution = new_execution;
                }
            }

            if fuzzvm.start_time.elapsed() > vm_timeout {
                execution = Execution::TimeoutReset;
            }

            match execution {
                Execution::Reset | Execution::CrashReset { .. } | Execution::TimeoutReset => {
                    // Reset the VM if requested
                    break;
                }
                Execution::Continue | Execution::CoverageContinue => {
                    // Nothing to do for continuing execution
                }
            }
        }

        // Exit the fuzz loop if told to
        // MUST BE IN THE RUN LOOP
        if core_stats.lock().unwrap().forced_shutdown || crate::FINISHED.load(Ordering::SeqCst) {
            break 'finish;
        }

        /*
        if SINGLE_STEP && SINGLE_STEP_DEBUG.load(Ordering::SeqCst) {
            log::info!("Writing {} instrs", instrs.len());
            std::fs::write(format!("/tmp/instrs_{}", instrs.len()), instrs.join("\n"));
        }
        */

        // If crashed, increase the crashes in the stats
        if matches!(execution, Execution::TimeoutReset) {
            // Increment the timeouts count
            core_stats.lock().unwrap().timeouts += 1;

            time!(SaveTimeoutInput, {
                let mut input_bytes = Vec::new();
                input.to_bytes(&mut input_bytes)?;

                // Attempt to write the crashing input and pass to fuzzer if it is a new input
                if let Some(crash_file) =
                    write_crash_input(&crash_dir, "timeout", &input_bytes, &fuzzvm.console_output)?
                {
                    if SINGLE_STEP && SINGLE_STEP_DEBUG.load(Ordering::SeqCst) {
                        std::fs::write(
                            crash_file.with_extension("single_step"),
                            instrs.join("\n"),
                        )?;
                    }

                    // Allow the fuzzer to handle the crashing state
                    // Useful for things like syscall fuzzer to write a C file from the
                    // input
                    fuzzer.handle_crash(&input, &mut fuzzvm, &crash_file)?;
                }
            });
        }

        // Check if the input hit any kasan_report blocks
        if let Some(path) = fuzzvm.get_kasan_crash_path() {
            let mut input_bytes = Vec::new();
            input.to_bytes(&mut input_bytes)?;

            // Found a valid KASAN output, write out the crashing input
            if let Some(crash_file) =
                write_crash_input(&crash_dir, &path, &input_bytes, &fuzzvm.console_output)?
            {
                // Inc the number of crashes found
                core_stats.lock().unwrap().crashes += 1;

                // Allow the fuzzer to handle the crashing state
                // Useful for things like syscall fuzzer to write a C file from the input
                fuzzer.handle_crash(&input, &mut fuzzvm, &crash_file)?;
            }
            if stop_after_first_crash {
                break;
            }
        } else if let Execution::CrashReset { path } = execution {
            // Inc the number of crashes found
            core_stats.lock().unwrap().crashes += 1;

            if !fuzzvm.console_output.is_empty() {
                if let Ok(_out) = std::str::from_utf8(&fuzzvm.console_output) {
                    // println!("{}", _out);
                }
            }

            let new_coverage: Vec<u64> = new_coverage_for_input.iter().map(|x| x.0).collect();

            let mut input_bytes = Vec::new();
            input.to_bytes(&mut input_bytes)?;

            // Attempt to write the crashing input and pass to fuzzer if it is a new input
            if let Some(crash_file) =
                write_crash_input(&crash_dir, &path, &input_bytes, &fuzzvm.console_output)?
            {
                if SINGLE_STEP && SINGLE_STEP_DEBUG.load(Ordering::SeqCst) {
                    std::fs::write(crash_file.with_extension("single_step"), instrs.join("\n"))?;
                }

                // If this was a newly written crash file, allow the fuzzer to handle the
                // crashing state. Useful for things like syscall fuzzer to write a C
                // file from the input
                fuzzer.handle_crash(&input, &mut fuzzvm, &crash_file)?;

                let mutation_metadata = InputMetadata {
                    original_file,
                    mutation: mutation.clone(),
                    new_coverage,
                };

                // Write the metadata for this new input
                let metadata_path = project_dir.join("metadata");
                if !metadata_path.exists() {
                    let _ = std::fs::create_dir(&metadata_path);
                }

                // Get the fuzz hash for this input
                let hash = input.fuzz_hash();
                let filepath = metadata_path.join(format!("crash_{hash:016x}"));
                std::fs::write(filepath, serde_json::to_string(&mutation_metadata)?)?;
            }

            if stop_after_first_crash {
                break;
            }
        }

        // If this input generated new coverage, add the input to the corpus
        if !new_coverage_for_input.is_empty() {
            // Gather the mutation metadata for this iteration
            let new_coverage: Vec<u64> = new_coverage_for_input.iter().map(|x| x.0).collect();

            let mutation_metadata = InputMetadata {
                original_file,
                mutation,
                new_coverage,
            };

            // Write the metadata for this new input
            let metadata_path = project_dir.join("metadata");
            if !metadata_path.exists() {
                std::fs::create_dir(&metadata_path)?;
            }

            // Get the fuzz hash for this input
            let hash = input.fuzz_hash();
            let filepath = metadata_path.join(format!("{hash:016x}"));
            std::fs::write(filepath, serde_json::to_string(&mutation_metadata)?)?;

            // Save this input in the corpus dir
            save_input_in_dir(&input, &corpus_dir)?;

            // Add the input to the corpus
            corpus.push(input);
        }

        if !fuzzvm.console_output.is_empty() {
            log::debug!("Console output!");
            unsafe {
                log::debug!(
                    "{:?}",
                    std::str::from_utf8_unchecked(&fuzzvm.console_output)
                );
            }
        }

        // Reset the guest state
        let guest_reset_perf = fuzzvm.reset_guest_state(&mut fuzzer)?;

        /// Small macro to add the various guest reset performance stats
        macro_rules! log_fuzzvm_perf_stats {
            ($mark:ident, $time:ident) => {
                core_stats
                    .lock()
                    .unwrap()
                    .perf_stats
                    .add(PerfMark::$mark, guest_reset_perf.$time);
            };
            ($mark:ident, init_guest.$time:ident) => {
                core_stats
                    .lock()
                    .unwrap()
                    .perf_stats
                    .add(PerfMark::$mark, guest_reset_perf.init_guest.$time);
            };
        }

        // Add the guest reset stats
        log_fuzzvm_perf_stats!(ResetGuestMemory, reset_guest_memory_restore);
        log_fuzzvm_perf_stats!(ResetCustomGuestMemory, reset_guest_memory_custom);
        log_fuzzvm_perf_stats!(ClearGuestMemory, reset_guest_memory_clear);
        log_fuzzvm_perf_stats!(GetDirtyLogs, get_dirty_logs);
        log_fuzzvm_perf_stats!(InitGuestRegs, init_guest.regs);
        log_fuzzvm_perf_stats!(InitGuestSregs, init_guest.sregs);
        log_fuzzvm_perf_stats!(InitGuestFpu, init_guest.fpu);
        log_fuzzvm_perf_stats!(InitGuestMsrs, init_guest.msrs);
        log_fuzzvm_perf_stats!(InitGuestDebugRegs, init_guest.msrs);
        log_fuzzvm_perf_stats!(ApplyFuzzerBreakpoint, apply_fuzzer_breakpoints);
        log_fuzzvm_perf_stats!(ApplyResetBreakpoint, apply_reset_breakpoints);
        log_fuzzvm_perf_stats!(ApplyCoverageBreakpoint, apply_coverage_breakpoints);
        log_fuzzvm_perf_stats!(InitVm, init_vm);
        core_stats.lock().unwrap().dirty_pages_kvm += try_u64!(guest_reset_perf.restored_kvm_pages);
        core_stats.lock().unwrap().dirty_pages_custom += try_u64!(guest_reset_perf.restored_custom_pages);

        /*
        if guest_reset_perf.restored_pages > 60000 {
            let path = format!("dirty_pages_{}", guest_reset_perf.restored_pages);

            // Attempt to write the crashing input and pass to fuzzer if it is a new input
            if let Some(crash_file) = write_crash_input(crash_dir, &path, &input,
                &fuzzvm.console_output)? {

                if SINGLE_STEP_DEBUG.load(Ordering::SeqCst) {
                    std::fs::write(crash_file.with_extension("single_step"),
                        instrs.join("\n"))?;
                }
            }
        }
        */

        if let Some(t) = stop_after_time {
            if fuzz_start_time.elapsed() >= t {
                break;
            }
        }
    }

    // remove this thread from the list to avoid being "kicked" by the kick_cores_thread
    *THREAD_IDS[core_id.id].lock().unwrap() = None;

    // Append the current coverage
    core_stats.lock().unwrap().coverage.append(&mut coverage);
    // core_stats.lock().unwrap().redqueen_coverage.append(&mut redqueen_coverage);

    // Write this current corpus to disk
    for input in &corpus {
        save_input_in_dir(input, &corpus_dir)?;
    }

    // Save the corpus in old_corpus for stats to sync with
    core_stats.lock().unwrap().old_corpus = Some(corpus);

    // Signal this thread is dead
    core_stats.lock().unwrap().alive = false;

    Ok(())
}
