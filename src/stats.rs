//! Statistics gathered across all fuzzing cores
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::format_in_format_args)]

use addr2line::gimli::{EndianReader, RunTimeEndian};
use addr2line::Context;

use anyhow::Result;
use crossterm::event::KeyCode;

use rand::seq::IteratorRandom;
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use tui::text::Span;
use tui::widgets::ListItem;
use tui_logger::{TuiWidgetEvent, TuiWidgetState};
use x86_64::registers::rflags::RFlags;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{DirEntry, File};
use std::path::Path;

use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::addrs::VirtAddr;
use crate::cmdline::Modules;
use crate::cmp_analysis::RedqueenCoverage;
use crate::config::Config;
use crate::coverage_analysis::CoverageAnalysis;
use crate::fuzz_input::FuzzInput;
use crate::fuzzer::Fuzzer;
use crate::fuzzvm::FuzzVmExit;
use crate::rng::Rng;
use crate::stats_tui::StatsApp;
use crate::symbols::Symbol;
use crate::utils::save_input_in_dir;

/// Size of the rolling window to calculate the iters/sec
const ITERS_WINDOW_SIZE: usize = 10;

/// Duration to wait between printing the stats
const PRINT_SLEEP: Duration = std::time::Duration::from_secs(1);

/// The number of coverage blockers to print during ASCII stats
const ASCII_COVERAGE_BLOCKERS: usize = 20;

/// Stats available from each core
#[derive(Default)]
pub struct Stats<FUZZER: Fuzzer> {
    /// Number of iterations this core has performed
    pub iterations: u64,

    /// Number of iterations this core has performed in redqueen
    pub rq_iterations: u64,

    /// Signals to a core to force exit
    pub forced_shutdown: bool,

    /// Signals that this core is alive
    pub alive: bool,

    /// Signals that this core is in redqueen
    pub in_redqueen: bool,

    /// Current address coverage found by this core
    pub coverage: BTreeSet<VirtAddr>,

    /// Current redqueen coverage seen by this core
    pub redqueen_coverage: BTreeSet<RedqueenCoverage>,

    /// Current redqueen redqueen rules seen by this core
    // pub redqueen_rules: BTreeMap<u64, BTreeSet<RedqueenRule>>,

    /// Number of restored pages
    pub restored_pages: u64,

    /// Number of timeouts in this core
    pub timeouts: u32,

    /// Number of dirty pages during each reset used to show the average number of dirty
    /// pages per reset reported by kvm's dirty log.
    pub dirty_pages_kvm: u64,

    /// Number of dirty pages that are reported by custom dirty logs.
    pub dirty_pages_custom: u64,

    /// Remaining number of breakpoints
    pub cov_left: u32,

    /// Number of inputs in the corpus
    pub corpus_len: u32,

    /// Number of crashes seen
    pub crashes: u32,

    /// The current corpus on the fuzzer. This is copied into by each fuzzing core and is
    /// collected by the stats worker to collect the total corpus across all workers.
    pub old_corpus: Option<Vec<FUZZER::Input>>,

    /// A new corpus to be picked up by the fuzzer. This is populated by the main stats
    /// worker containing some random inputs from the total corpus.
    pub new_corpus: Option<Vec<FUZZER::Input>>,

    /// Performance metrics for this core indexed by `PerfMark`
    pub perf_stats: PerfStats,

    /// Number of [`FuzzVmExit`] seen
    pub vmexits: [u64; std::mem::variant_count::<FuzzVmExit>()],

    /// Performance metrics for the stats loop itself
    pub tui_perf_stats: [f64; std::mem::variant_count::<TuiPerfStats>()],
}

impl<FUZZER: Fuzzer> Stats<FUZZER> {
    /// Increment the hit count for the given [`FuzzVmExit`]
    pub fn inc_vmexit(&mut self, vmexit: &FuzzVmExit) {
        let index = vmexit.id();
        self.vmexits[index] += 1;
    }
}

/// Current stats to display to the screen
#[allow(clippy::module_name_repetitions)]
#[derive(Serialize, Deserialize)]
pub struct GlobalStats {
    /// Elapsed time
    pub time: String,

    /// Number of iterations across all cores
    pub iterations: u64,

    /// Total coverage seen
    pub coverage: usize,

    /// Total coverage seen in redqueen
    pub rq_coverage: usize,

    /// Seconds since the last coverage
    pub last_coverage: u64,

    /// Executions per second (total)
    pub exec_per_sec: u64,

    /// Executions per second (total) in Redqueen
    pub rq_exec_per_sec: u64,

    /// Number of timeouts
    pub timeouts: u32,

    /// Number of coverage points not yet hit
    pub coverage_left: u64,

    /// Average number of dirty pages restored on each reset
    pub dirty_pages: u64,

    /// number of pages in dirty_pages that are reported by kvm dirty log
    pub dirty_pages_kvm: u64,

    /// number of pages in dirty_pages that are reported by custom dirty logs
    pub dirty_pages_custom: u64,

    /// Size of the total corpus
    pub corpus: u32,

    /// Bitmap of alive cores
    pub alive: u64,

    /// Total number of crashes hit
    pub crashes: u32,

    /// Currently dead cores
    pub dead: Vec<usize>,

    /// Current cores in redqueen
    pub in_redqueen: Vec<usize>,

    /// Performance metrics for this core indexed by `PerfMark`
    #[serde(skip)]
    pub perfs: ([u64; PerfMark::Count as usize], u64, u64),

    /// Number of vmexits found across all cores
    pub vmexits: [u64; std::mem::variant_count::<FuzzVmExit>()],
}

/// Performance statistics
#[derive(Clone)]
#[allow(clippy::module_name_repetitions)]
pub struct PerfStats {
    /// The start time of the performance metrics
    pub start_time: u64,

    /// Start times for the performance marks available
    starts: [u64; PerfMark::Count as usize],

    /// Time spent during child timers
    child_time: [u64; PerfMark::Count as usize],

    /// Elapsed times for the performance marks
    elapsed: [u64; PerfMark::Count as usize],

    /// Hit count for this timer
    hits: [u64; PerfMark::Count as usize],

    /// The current timer
    current: Option<PerfMark>,
}

impl std::default::Default for PerfStats {
    fn default() -> PerfStats {
        PerfStats {
            start_time: 0,
            starts: [0_u64; PerfMark::Count as usize],
            child_time: [0_u64; PerfMark::Count as usize],
            elapsed: [0_u64; PerfMark::Count as usize],
            hits: [0_u64; PerfMark::Count as usize],
            current: None,
        }
    }
}

#[derive(Clone)]
pub struct PerfStatTimer<FUZZER: Fuzzer> {
    timer: PerfMark,
    start_time: u64,
    parent: Option<PerfMark>,
    core_stats: Arc<Mutex<Stats<FUZZER>>>,
}
impl<FUZZER: Fuzzer> PerfStatTimer<FUZZER> {
    pub fn new(core_stats: Arc<Mutex<Stats<FUZZER>>>, timer: PerfMark) -> PerfStatTimer<FUZZER> {
        let parent = core_stats.lock().unwrap().perf_stats.current;
        core_stats.lock().unwrap().perf_stats.current = Some(timer);

        PerfStatTimer {
            timer,
            start_time: crate::utils::rdtsc(),
            parent,
            core_stats,
        }
    }
}

impl<FUZZER: Fuzzer> Drop for PerfStatTimer<FUZZER> {
    fn drop(&mut self) {
        // Get the stats to update them
        let stats = &mut self.core_stats.lock().unwrap().perf_stats;

        // Update the current node
        stats.current = self.parent;

        let elapsed = crate::utils::rdtsc() - self.start_time;

        // If there is a parent timer, remove the elapsed time from the parent timer
        if let Some(parent) = self.parent {
            stats.child_time[parent as usize] =
                stats.child_time[parent as usize].wrapping_add(elapsed);
        }

        // Get the time spent in child timers
        let child_time = stats.child_time[self.timer as usize];

        // Reset the child timer for this timer
        stats.child_time[self.timer as usize] = 0;

        // Update this timer's elapsed time
        stats.elapsed[self.timer as usize] = stats.elapsed[self.timer as usize]
            .wrapping_add(elapsed)
            .checked_sub(child_time)
            .expect(&format!(
                "Failed on drop: {:?} curr elapsed {:#x} elapsed {:#x} child time {:#x}",
                self.timer, stats.elapsed[self.timer as usize], elapsed, child_time
            ));

        // Update hit counts
        stats.hits[self.timer as usize] += 1;
    }
}

impl PerfStats {
    #[inline]
    /// Start the timer for the given [`PerfMark`]
    pub fn start(&mut self, mark: PerfMark) {
        // log::info!("Starting {:20?}", mark);
        assert!(
            self.current.is_none(),
            "Attempted to start {mark:?} but {:?} is already running",
            self.current
        );

        let start = crate::utils::rdtsc();
        self.starts[mark as usize] = start;

        if mark != PerfMark::Total {
            self.current = Some(mark);
        }
    }

    #[inline]
    /// Mark the current elapsed time for the given [`PerfMark`]
    pub fn mark(&mut self, mark: PerfMark) {
        let time = (crate::utils::rdtsc() - self.starts[mark as usize]).saturating_div(1);
        // log::info!("Marking {:20?}: {:#018x}", mark, time);

        self.elapsed[mark as usize] += time;
        self.current = None;
    }

    #[inline]
    /// Add the given cycles to the given [`PerfMark`]
    pub fn add(&mut self, mark: PerfMark, cycles: u64) {
        // log::info!("Adding {:20?}: {:#018x}", mark, cycles);
        self.elapsed[mark as usize] += cycles.saturating_div(1);
    }
}

/// Macro used for creating a `const` slice of all elements in the array
#[macro_export]
macro_rules! impl_enum {
    (   // Base case of an enum that we want only one item of
        $(#[$attr:meta])*
        pub enum $name:ident {
            $(
                $(#[$inner:ident $($args:tt)*])*
                $field:vis $var_name:ident,
            )* $(,)?
        }
    ) => {
        $(#[$attr])*
        #[allow(non_camel_case_types)]
        pub enum $name {
            $(
                $(#[$inner $($args)*])*
                $field $var_name,
            )*

            Count
        }

        /// Get all of the current elements
        #[allow(dead_code)]
        impl $name {
            pub const fn elements() -> &'static [$name] {
                &[
                    $($name::$var_name,)*
                ]
            }
        }

        /// Get all of the strings of the elements
        #[allow(dead_code)]
        impl $name {
            pub const fn names() -> &'static [&'static str] {
                &[
                    $((stringify!($var_name)),)*
                ]
            }
        }
    }
}

impl_enum!(
    /// Various marks where performance metrics are gathered. This is used as the index into
    /// the `Stats.perf_stats`
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub enum PerfMark {
        /// Total elapsed clock cycles
        Total,

        /// Amount of time spent during reset guest memory
        ResetGuestMemory,

        /// Amount of time spent during resetting guest memory set by a fuzzer
        ResetCustomGuestMemory,

        /// Amount of time spent during clearing the dirty pages
        ClearGuestMemory,

        /// Amount of time during running `fuzzvm.init_guest` restoring registers
        InitGuestRegs,

        /// Amount of time during running `fuzzvm.init_guest` restoring system registers
        InitGuestSregs,

        /// Amount of time during running `fuzzvm.init_guest` restoring FPU registers
        InitGuestFpu,

        /// Amount of time during running `fuzzvm.init_guest` restoring MSRs
        InitGuestMsrs,

        /// Amount of time during running `fuzzer.apply_fuzzer_breakpoint`
        ApplyFuzzerBreakpoint,

        /// Amount of time during running `fuzzer.apply_reset_breakpoint`
        ApplyResetBreakpoint,

        /// Amount of time during running `fuzzer.apply_coverage_breakpoint`
        ApplyCoverageBreakpoint,

        /// Amount of time during running `fuzzer.init_vm`
        InitVm,

        /// Time spent in the VM
        InVm,

        /// Time spent before executing `vcpu.run`
        PreRunVm,

        /// Time spent after executing `vcpu.run`
        PostRunVm,

        /// Time spent scheduling a new input
        ScheduleInput,

        /// Time spent mutating input
        InputMutate,

        /// Time spent setting input
        InputSet,

        /// Time it takes to handle the vmexit
        HandleVmExit,

        /// Time spent getting dirty logs
        GetDirtyLogs,

        /// Time to for rapid stats sync
        StatsSync,

        /// Time to for stats coverage sync
        SyncCov1,

        /// Time to for stats coverage sync
        SyncCov2,

        /// Time taken to gather redqueen breakpoints
        Redqueen,

        /// Time spent in the VM during redqueen
        RedqueenInVm,

        /// Time spent syncing coverage
        MergeCoverageSync,

        /// Time spent checking if a new input is needed for redqueen
        RedqueenCheckNewInput,

        /// Time spent gathering coverage in redqueen
        RedqueenGatherCoverage,

        /// Time in the `fuzzvm::reset_and_run_with_redqueen` function
        ResetAndRunWithRedqueen,

        /// Time in the `fuzzvm::restore_dirty_pages` function
        RestoreDirtyPages,

        /// Time in the `fuzzvm::restore_custom_guest_memory` function
        RestoreCustomGuestMemory,

        /// Time spent elsewhere that is not currently being tracked
        Remaining,
    }
);

impl_enum!(
    /// TUI Performance Stats
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub enum TuiPerfStats {
        Poll,
        AccumulateStats,
        ClearTimeline,
        AccumulateTimeline,
        AccumulateTimelineDifference,
        AccumulateTimelineSource,
        AccumulateAppendCoverage,
        AccumulateCoverageDifference,
        RQClearTimeline,
        RQAccumulateAppendCoverage,
        RQAccumulateTimeline,
        NewInput,
        WriteGraphs,
        UpdateTotalStats,
        GatherCrashes,
        WriteStatsData,
        MergeCoverage,
        CoverageLighthouse,
        CoverageAddress,
        CoverageSource,
        Lcov,
        Total,
    }
);

impl GlobalStats {
    /// Display the stats in a tabular format
    fn display(&self) {
        let width = 120;

        // Print the header
        let title = " FUZZER STATS ";
        println!("+{title:-^width$}+", width = width - 2);

        let last_cov_elapsed = self.last_coverage;
        let last_cov_seconds = last_cov_elapsed % 60;
        let last_cov_minutes = (last_cov_elapsed / 60) % 60;
        let last_cov_hours = last_cov_elapsed / (60 * 60);

        let line = format!(
            " {} | {} | {} ",
            format!("{:>10}: {:>10}", "Time", self.time),
            format!(
                "{:>10}: {:10} (core {:6.2})",
                "Exec/sec",
                self.exec_per_sec,
                self.exec_per_sec as f64 / self.alive as f64
            ),
            format!(
                "{:>10}: {:10} (last seen {last_cov_hours:02}:{last_cov_minutes:02}:{last_cov_seconds:02})",
                "Coverage", self.coverage,
            )
        );
        println!("|{line: <width$}|", width = width - 2);

        let line = format!(
            " {} | {} | {}",
            format!("{:>10}: {:10}", "Iters", self.iterations),
            format!("{:>10}: {:24}", "Corpus", self.corpus),
            format!("{:>10}: {:10}", "Crashes", self.crashes),
        );
        println!("|{line: <width$}|", width = width - 2);

        let line = format!(
            " {} | {} | {} ",
            format!("{:>10}: {:10}", "Timeouts", self.timeouts),
            format!("{:>10}: {:24}", "Cov. Left", self.coverage_left),
            format!("{:>10}: {:10}", "Alive", self.alive),
        );
        println!("|{line: <width$}|", width = width - 2);

        let line = format!(
            " {} | {} | {} ",
            format!(
                "{:>10}: {:9} (K: {} F: {})",
                "Dirty Pages", self.dirty_pages, self.dirty_pages_kvm, self.dirty_pages_custom
            ),
            format!("{:>10}: {:?}", "Dead cores", self.dead),
            format!("{:>10}: {:?}", "Cores in Redqueen", self.in_redqueen),
        );
        println!("|{line: <width$}|", width = width - 2);

        // Print the footer
        println!("+{}+", "-".repeat(width - 2));

        // Print the header
        let title = " PERFORMANCE STATS ";
        println!("+{title:-^width$}+", width = width - 2);

        // Get the accumulated performance stats
        let (totals, total, remaining) = self.perfs;

        let mut line = String::new();

        line.push_str("| ");

        // Print the perf stats for each core
        // Display each marker as a percentage of total time
        for (i, elem) in PerfMark::elements().iter().enumerate() {
            // No need to print the total time
            if i == PerfMark::Total as usize {
                continue;
            }

            let curr_stat = totals[*elem as usize];

            // Print the percentage of time this marker was executed
            let segment = format!(
                "{:>25}: {:5.2}%",
                format!("{elem:?}"),
                curr_stat as f64 / total as f64 * 100.
            );

            if line.len() + segment.len() > width {
                println!("{line:width$}|", width = width - 1);
                line = String::new();
                line.push_str("| ");
            }

            if line.len() > 3 {
                line.push_str(" | ");
            }

            line.push_str(&segment);
        }

        // Print the percentage of time this marker was executed
        let segment = format!(
            "{:>25}: {:5.2}%",
            "Other",
            remaining as f64 / total as f64 * 100.
        );

        if line.len() + segment.len() > width {
            println!("{line:width$}|", width = width - 1);
            println!("| {segment:width$} |", width = width - 4);
        } else {
            if line.len() > 3 {
                line.push_str(" | ");
            }

            line.push_str(&segment);
            println!("{line:width$}|", width = width - 1);
        }

        // Print the footer
        println!("+{}+", "-".repeat(width - 2));

        // Print the header
        let title = " PERFORMANCE STATS (TSC / CORE / ITERATION) ";
        println!("+{title:-^width$}+", width = width - 2);

        // Get the accumulated performance stats
        let (totals, _, remaining) = self.perfs;

        let mut line = String::new();
        line.push_str("| ");

        // Ignore div by zero chances
        if self.alive == 0 || self.iterations == 0 {
            return;
        }

        // Write the InVm line
        println!("{line:width$}|", width = width - 1);
        line.clear();
        line.push_str("| ");

        // Print the perf stats for each core
        // Display each marker as a percentage of total time
        for (i, elem) in PerfMark::elements().iter().enumerate() {
            // No need to print the total time
            if i == PerfMark::Total as usize {
                continue;
            }

            let curr_stat = totals[*elem as usize];

            let segment = format!(
                "{:>25}: {:18}",
                format!("{elem:?}"),
                curr_stat / self.alive / self.iterations
            );

            // Print the percentage of time this marker was executed
            if line.len() + segment.len() > width {
                println!("{line:width$}|", width = width - 1);
                line = String::new();
                line.push_str("| ");
            }

            if line.len() > 2 {
                line.push_str(" | ");
            }

            line.push_str(&segment);
        }

        // Print the percentage of time this marker was executed
        let segment = format!(
            "{:>25}: {:5.2}",
            "Other",
            remaining / self.alive / self.iterations
        );

        if line.len() + segment.len() > width {
            println!("{line:width$}|", width = width - 1);
            println!("| {segment:width$} |", width = width - 4);
        } else {
            if line.len() > 3 {
                line.push_str(" | ");
            }

            line.push_str(&segment);
            println!("{line:width$}|", width = width - 1);
        }

        // Print the footer
        println!("+{}+", "-".repeat(width - 2));

        // Print the header
        let title = " VMEXITS ";
        println!("+{title:-^width$}+", width = width - 2);

        // Init the line String for this chart of vmexit stats
        line.clear();
        line.push_str("| ");

        for i in 0..std::mem::variant_count::<FuzzVmExit>() {
            let name = FuzzVmExit::name(i as usize);
            let val = self.vmexits[i as usize];

            // Print the percentage of time this marker was executed
            let segment = format!("{name:>30}: {val:18}");

            if line.len() + segment.len() > width {
                println!("{line:width$}|", width = width - 1);
                line = String::new();
                line.push_str("| ");
            }

            if line.len() > 2 {
                line.push_str(" | ");
            }

            line.push_str(&segment);
        }

        // Print the footer
        println!("+{}+", "-".repeat(width - 2));
    }
}

/// Get a [`Context`] for every known binary in the snapshot.
///
/// Search for all `.bin` files and vmlinux in the snapshot dir and open
/// a [`adddr2line::Context`] for all of them to retrieve symbols
#[allow(clippy::type_complexity)]
pub fn get_binary_contexts(
    project_dir: &Path,
) -> Result<Vec<Context<EndianReader<RunTimeEndian, Rc<[u8]>>>>> {
    // ) -> Result<Vec<u64>> {
    let mut contexts = Vec::new();

    // Check if the project contains a `vmlinux` file for kernel symbols
    let vmlinux = project_dir.join("vmlinux");
    if vmlinux.exists() {
        let file = File::open(vmlinux)?;
        let map = unsafe { memmap::Mmap::map(&file)? };
        let object = addr2line::object::File::parse(&*map)?;
        let tmp = addr2line::Context::new(&object)?;
        contexts.push(tmp);
        log::info!("Found vmlinux addr2line context");
    }

    for file in std::fs::read_dir(project_dir)? {
        let file = file?;
        if let Some(extension) = file.path().extension() {
            if matches!(extension.to_str(), Some("bin")) {
                let file = File::open(file.path())?;
                let map = unsafe { memmap::Mmap::map(&file)? };
                let object = addr2line::object::File::parse(&*map)?;
                let tmp = addr2line::Context::new(&object)?;
                contexts.push(tmp);
                log::info!("Found {file:?} addr2line context");
            }
        }
    }

    // Return the found binary contexts
    Ok(contexts)
}

/// Recursively search the given path for other directories. Returns `true` if the directory
/// has file children and `false` if it only has other directories.
fn get_subdirs(path: &PathBuf, crashes: &mut Vec<String>) -> bool {
    let mut has_file_children = false;

    if let Ok(crash_entries) = std::fs::read_dir(path) {
        for file in crash_entries {
            if let Ok(file) = file {
                if !file.path().is_dir() {
                    has_file_children = true;
                    continue;
                }

                let has_files = get_subdirs(&file.path(), crashes);
                if has_files {
                    crashes.push(file.path().to_str().unwrap().to_string());
                }
            }
        }
    }

    has_file_children
}

/// The worker function to display the statistics of the fuzzing cores
#[allow(clippy::too_many_lines)]
pub fn worker<FUZZER: Fuzzer>(
    stats: Arc<Vec<Arc<Mutex<Stats<FUZZER>>>>>,
    modules: &Modules,
    project_dir: &Path,
    prev_coverage: BTreeSet<VirtAddr>,
    prev_redqueen_coverage: BTreeSet<RedqueenCoverage>,
    input_corpus: &[FUZZER::Input],
    coverage_breakpoints: Option<BTreeSet<VirtAddr>>,
    symbols: &Option<VecDeque<Symbol>>,
    mut coverage_analysis: Option<CoverageAnalysis>,
    tui: bool,
    config: &Config, // redqueen_rules: BTreeMap<u64, BTreeSet<RedqueenRule>>
    stop_after_first_crash: bool,
) -> Result<()> {
    // Create the data directory if it doesn't exist to store raw data from the fuzzer
    let data_dir = project_dir.join("data");
    if !data_dir.exists() {
        std::fs::create_dir(&data_dir)?;
    }

    // Create the web directory for displaying stats via the browser
    let web_dir = project_dir.join("web");
    if !web_dir.exists() {
        std::fs::create_dir(&web_dir)?;
    }

    // Create the current corpus directory if it doesn't exist
    let corpus_dir = project_dir.join("current_corpus");
    if !corpus_dir.exists() {
        std::fs::create_dir(&corpus_dir)?;
    }

    // Populate the current corpus filenames for monitoring when a new file is dropped
    // into `current_corpus`
    let mut corpus_filenames = ahash::AHashSet::with_capacity(input_corpus.len() * 2);
    for entry in corpus_dir.read_dir()? {
        if let Ok(entry) = entry {
            if entry.file_type()?.is_dir() {
                continue;
            }

            if let Some(filename) = entry.path().file_name() {
                corpus_filenames.insert(filename.to_string_lossy().into_owned());
            }
        }
    }

    let contexts = get_binary_contexts(project_dir)?;

    // Create the web directory for displaying stats via the browser
    let crash_dir = project_dir.join("crashes");
    if !crash_dir.exists() {
        std::fs::create_dir(&crash_dir)?;
    }

    // Get the filenames for the various output files
    let lighthouse_file = project_dir.join("coverage.lighthouse");
    let coverage_addrs = project_dir.join("coverage.addresses");
    // let coverage_src = project_dir.join("coverage.src");
    let coverage_lcov = project_dir.join("coverage.lcov");
    let coverage_in_order = project_dir.join("coverage.in_order");
    let coverage_redqueen_in_order = project_dir.join("coverage.redqueen.in_order");
    let coverage_redqueen = project_dir.join("coverage.redqueen");
    // let redqueen_rules_path = project_dir.join("redqueen.rules");
    let plot_exec_per_sec = data_dir.join("exec_per_sec.plot");
    let plot_dirty_page_per_sec = data_dir.join("dirty_page_per_sec.plot");
    let plot_coverage = data_dir.join("coverage.plot");
    let plot_crash_groups = data_dir.join("crashes.plot");

    // Start the timer for the beginning of the fuzz run
    let start = std::time::Instant::now();

    // Average stats used for the stats TUI
    let mut exec_per_sec;
    let mut rq_exec_per_sec;
    let mut dirty_pages = 0;
    let mut dirty_pages_kvm = 0;
    let mut dirty_pages_custom = 0;

    // Init the coverage time to sync coverage between the cores
    let mut coverage_timer = std::time::Instant::now();

    let mut merge_coverage = false;

    let mut total_coverage = prev_coverage;
    let mut total_redqueen_coverage = prev_redqueen_coverage;
    // let mut total_redqueen_rules = redqueen_rules;

    let mut last_best_coverage = 0;
    let mut last_coverage = std::time::Instant::now();

    let mut total_iters: u64 = 0;
    let mut total_rq_iters: u64 = 0;

    // Rolling window to calculate most recent iterations
    let mut sum_iters = [0_u64; ITERS_WINDOW_SIZE];
    let mut sum_rq_iters = [0_u64; ITERS_WINDOW_SIZE];
    let mut sum_dirty_pages = [0_u64; ITERS_WINDOW_SIZE];
    let mut sum_dirty_pages_kvm = [0_u64; ITERS_WINDOW_SIZE];
    let mut sum_dirty_pages_custom = [0_u64; ITERS_WINDOW_SIZE];
    let mut iters_index = 0;
    let mut lighthouse_data = String::new();
    let mut cov_addrs = String::new();

    // Init graph data
    let mut graph_exec_per_sec = vec![0];
    let mut graph_coverage = vec![0];
    let mut graph_seconds = vec![0];
    let mut graph_iters = vec![0];
    let mut graph_crashes = vec![0];
    let mut graph_dirty_pages_per_sec = vec![[0u64, 0, 0]];

    // Init the total corpus across all cores
    let mut total_corpus = ahash::AHashSet::with_capacity(input_corpus.len() * 2);
    total_corpus.extend(input_corpus.iter().cloned());

    let mut rng = Rng::new();

    let mut dead = Vec::new();
    let mut in_redqueen = Vec::new();
    let mut perfs = vec![None; crate::MAX_CORES];
    let mut vmexits = [0_u64; std::mem::variant_count::<FuzzVmExit>()];
    let mut lcov = BTreeMap::new();

    // TUI log state
    let mut tui_log_state = TuiWidgetState::new();

    // Initialize all coverage breakpoints as not being hit
    if let Some(cov_bps) = coverage_breakpoints {
        for rip in cov_bps {
            let addr = rip.0;

            for context in &contexts {
                // Try to get the addr2line information for the current address
                if let Some(loc) = context.find_location(addr)? {
                    // Insert valid file:line into the BTreeMap for producing lcov
                    if let (Some(file), Some(line)) = (loc.file, loc.line) {
                        lcov.entry(file)
                            .or_insert_with(BTreeMap::new)
                            .insert(line, 0);

                        // Found the correct addr2line context, no need to go into other contextx
                        break;
                    }
                } else if let Some(module_start) = modules.get_module_start_containing(addr) {
                    // If not found, check if the module that contains this address
                    // is compiled with Position Independent code (PIE) and subtract
                    // the module start address to check for
                    if let Some(loc) = context.find_location(addr.saturating_sub(module_start))? {
                        // Insert valid file:line into the BTreeMap for producing lcov
                        if let (Some(file), Some(line)) = (loc.file, loc.line) {
                            lcov.entry(file)
                                .or_insert_with(BTreeMap::new)
                                .insert(line, 0);

                            // Found the correct addr2line context, no need to go into other contextx
                            break;
                        }
                    }
                }
            }
        }
    }

    // Call once to log the poll trace for crossterm so it doesn't clog the screen
    let _ = crossterm::event::poll(Duration::from_millis(1))?;

    // Initialize the terminal if using the TUI
    let mut terminal = None;
    if tui {
        terminal = Some(crate::stats_tui::init_terminal()?);
    }

    let mut coverage_timeline = Vec::new();
    let mut tab_index = 0_u8;

    let mut crashes: Vec<DirEntry> = Vec::new();
    let mut crash_path_strs: Vec<String> = Vec::new();
    let mut crash_paths: Vec<_> = Vec::new();
    let mut num_crashes = 0_u32;
    let mut num_interesting_crashes = 0_u32;

    // Initialize the coverage analysis with the current toal coverage
    let mut coverage_blockers = Vec::new();

    let mut scratch_string = String::new();

    let mut tui_perf_stats = [0_f64; std::mem::variant_count::<TuiPerfStats>()];

    let mut poll_start = std::time::Instant::now();
    let mut tui_start = std::time::Instant::now();
    let mut perf_stats = Vec::new();
    let mut curr_tui_perf_stats = Vec::new();
    let mut vmexit_stats = Vec::new();
    let mut diffs: Vec<VirtAddr> = Vec::new();
    let mut redqueen_diffs: Vec<_> = Vec::new();

    /// Time the $expr and return the result of $expr
    macro_rules! time {
        ($stat:ident, $expr:expr) => {{
            let start = std::time::Instant::now();

            // Execute the given expression
            let result = $expr;

            tui_perf_stats[TuiPerfStats::$stat as usize] += start.elapsed().as_secs_f64();

            // Return the result from the expression
            result
        }};
    }

    // Stats loop
    'finish: for iter in 0usize.. {
        tui_start = std::time::Instant::now();

        if iter == 0
            || coverage_timer.elapsed() > config.stats.merge_coverage_timer
                && !total_corpus.len() > 1
        {
            merge_coverage = true;
        }

        // Reset the time window stats for this iteration window
        sum_iters[iters_index] = 0;
        sum_rq_iters[iters_index] = 0;
        sum_dirty_pages[iters_index] = 0;
        sum_dirty_pages_custom[iters_index] = 0;
        sum_dirty_pages_kvm[iters_index] = 0;

        let mut sum_timeouts = 0;
        let mut coverage_left = 0_u64;
        let mut alive = 0;

        // Clear the list for the currently dead cores
        dead.clear();
        in_redqueen.clear();

        time!(
            AccumulateStats,
            // Calculate the current statistics
            for (core_id, core_stats) in stats.iter().enumerate() {
                // Attempt to get this core's stats. If it fails, continue the next core
                // and get the stats on the next loop iteration
                let Ok(mut stats) = core_stats.try_lock() else {
                    continue;
                };

                // If the core signaled a forced shutdown from Ctrl+C, immediately break out
                // of the stats loop
                if stats.forced_shutdown {
                    log::warn!("Core with forced shutdown.. bailing..");
                    break 'finish;
                }

                // Add the dirty pages per iteration
                if stats.iterations > 0 {
                    let stats_dirty_pages = stats.dirty_pages_kvm + stats.dirty_pages_custom;
                    sum_dirty_pages[iters_index] += stats_dirty_pages / stats.iterations;
                    sum_dirty_pages_kvm[iters_index] += stats.dirty_pages_kvm / stats.iterations;
                    sum_dirty_pages_custom[iters_index] +=
                        stats.dirty_pages_custom / stats.iterations;
                }

                // Add the core stats to the total stats across all cores
                total_iters += stats.iterations;
                total_rq_iters += stats.iterations;
                sum_iters[iters_index] += stats.iterations;
                sum_rq_iters[iters_index] += stats.rq_iterations;
                sum_timeouts += stats.timeouts;
                coverage_left += stats.cov_left as u64;

                // Reset the iterations for the core
                stats.iterations = 0;
                stats.rq_iterations = 0;
                stats.dirty_pages_kvm = 0;
                stats.dirty_pages_custom = 0;

                if stats.in_redqueen {
                    in_redqueen.push(core_id);
                } else if stats.alive {
                    alive += 1;
                } else {
                    dead.push(core_id);
                }

                // Reset the alive stat for this core
                stats.alive = false;
            }
        );

        // Clear the differences accumulator
        time!(ClearTimeline, {
            diffs.clear();
        });

        // Clear the differences accumulator
        time!(RQClearTimeline, {
            redqueen_diffs.clear();
        });

        // Calculate the current statistics
        for (core_id, core_stats) in stats.iter().enumerate() {
            // Attempt to get this core's stats. If it fails, continue the next core
            // and get the stats on the next loop iteration
            let Ok(mut stats) = core_stats.try_lock() else {
                // log::info!("Core {core_id} holding stats lock");
                continue;
            };

            // Gather the differences while holding the lock, and then process
            // the difference after releasing the lock
            time!(AccumulateTimelineDifference, {
                for addr in stats.coverage.difference(&total_coverage) {
                    diffs.push(*addr);
                }
            });

            // Gather the differences while holding the lock, and then process
            // the difference after releasing the lock
            time!(RQAccumulateTimeline, {
                for cov in stats.redqueen_coverage.difference(&total_redqueen_coverage) {
                    redqueen_diffs.push(*cov);
                }
            });

            // Collect the coverage for this core to the total coverage
            time!(AccumulateAppendCoverage, {
                total_coverage.append(&mut stats.coverage);
            });

            // Collect the redqueen coverage for this core to the total coverage
            time!(RQAccumulateAppendCoverage, {
                total_redqueen_coverage.append(&mut stats.redqueen_coverage);
            });

            time!(AccumulateCoverageDifference, {
                assert!(
                    stats.coverage.difference(&total_coverage).count() == 0,
                    "stats.coverage difference not applied properly"
                );
            });

            // Add this core's stats to the display table
            stats.perf_stats.elapsed[PerfMark::Total as usize] =
                crate::utils::rdtsc() - stats.perf_stats.start_time;
            perfs[core_id] = Some(stats.perf_stats.elapsed);

            // Add the vmexits to the total vmexits seen by the fuzzer
            for (i, val) in stats.vmexits.iter().enumerate() {
                vmexits[i] += val;
            }
        }

        // Add any new coverage to the timeline
        time!(AccumulateTimeline, {
            for addr in &diffs {
                let addr = addr.0;

                if let Some(sym_data) = symbols {
                    if let Some(symbol) = crate::symbols::get_symbol(addr, sym_data) {
                        let mut found = false;

                        for context in &contexts {
                            // Try to get the addr2line information for the current address
                            if let Some(loc) = context.find_location(addr)? {
                                let src = format!(
                                    "{addr:#x} {symbol} -- {}:{}:{}",
                                    loc.file.unwrap_or("??unknownfile??"),
                                    loc.line.unwrap_or(0),
                                    loc.column.unwrap_or(0)
                                );

                                coverage_timeline.push(src);
                                found = true;
                            } else if let Some(module_start) =
                                modules.get_module_start_containing(addr)
                            {
                                // If not found, check if the module that contains this address
                                // is compiled with Position Independent code (PIE) and subtract
                                // the module start address to check for
                                if let Some(loc) =
                                    context.find_location(addr.saturating_sub(module_start))?
                                {
                                    let src = format!(
                                        "{addr:#x} {symbol} -- {}:{}:{}",
                                        loc.file.unwrap_or("??unknownfile??"),
                                        loc.line.unwrap_or(0),
                                        loc.column.unwrap_or(0)
                                    );

                                    coverage_timeline.push(src);
                                    found = true;
                                }
                            }
                        }

                        // If the source code wasn't found, add the raw symbol instead
                        if !found {
                            // Add the found symbol the symbol timeline
                            coverage_timeline.push(format!("{addr:#x} {symbol}"));
                        }
                    } else {
                        // Symbol not found, add the address
                        coverage_timeline.push(format!("{addr:#x}"));
                    }
                } else {
                    // Symbol not found, add the address
                    coverage_timeline.push(format!("{addr:#x}"));
                }
            }
        });

        time!(RQAccumulateTimeline, {
            for rq_diff in &redqueen_diffs {
                coverage_timeline.push(format!("{rq_diff:x?}"));
            }
        });

        let time_window = ITERS_WINDOW_SIZE as u64 * PRINT_SLEEP.as_secs();

        exec_per_sec = sum_iters.iter().sum::<u64>() / time_window;
        rq_exec_per_sec = sum_rq_iters.iter().sum::<u64>() / time_window;
        if alive > 0 {
            dirty_pages = sum_dirty_pages.iter().sum::<u64>() / time_window / alive;
            dirty_pages_kvm = sum_dirty_pages_kvm.iter().sum::<u64>() / time_window / alive;
            dirty_pages_custom = sum_dirty_pages_custom.iter().sum::<u64>() / time_window / alive;
        }

        // Get the elapsed time in hours:minutes:seconds
        let elapsed = start.elapsed().as_secs();
        let seconds = elapsed % 60;
        let minutes = (elapsed / 60) % 60;
        let hours = elapsed / (60 * 60);

        // Update the last coverage seen timer if new coverage has been seen
        if last_best_coverage < total_coverage.len() {
            last_coverage = std::time::Instant::now();
            last_best_coverage = total_coverage.len();
        }

        // Accumulate the performance metrics
        let mut total = 0;
        let mut totals = [0_u64; PerfMark::Count as usize];
        let mut remaining = 0;

        // Accumulate the stats for all cores
        time!(UpdateTotalStats, {
            for curr_perf_stats in perfs.iter().flatten() {
                // Get the total cycles for this core
                let curr_total = curr_perf_stats[PerfMark::Total as usize];

                // Add the current total to the total across all cores
                total += curr_total;

                // Init the unaccounted for cycles to the total
                let mut curr_remaining = curr_total;

                // Display each marker as a percentage of total time
                for (i, elem) in PerfMark::elements().iter().enumerate() {
                    // No need to print the total time
                    if i == PerfMark::Total as usize || i == PerfMark::Remaining as usize {
                        continue;
                    }

                    // Get the current stat
                    let curr_stat = curr_perf_stats[*elem as usize];

                    // Add the stat for this core for this element into the totals
                    totals[*elem as usize] = totals[*elem as usize]
                        .checked_add(curr_stat)
                        .expect(&format!("FAILED {elem:?}"));

                    // Remove this stat from the total to display the percentage of work
                    // that hasn't been accomodated for
                    curr_remaining = curr_remaining.saturating_sub(curr_stat);
                }

                remaining += curr_remaining;
            }

            // Add the remaining
            totals[PerfMark::Remaining as usize] = remaining;
        });

        // Get the avg coverage left from all cores
        coverage_left /= std::cmp::max(alive, 1);

        // If the crash directory doesn't exist, or was deleted, create it
        time!(GatherCrashes, {
            if iter % 4 == 0 {
                num_crashes = 0;
                crash_paths.clear();

                crash_path_strs.clear();
                get_subdirs(&crash_dir, &mut crash_path_strs);
                crash_path_strs.sort();

                for path in &crash_path_strs {
                    if let Ok(dir) = std::fs::read_dir(path) {
                        num_crashes += dir.count() as u32;
                    }
                    if !path.starts_with("timeout") && !path.starts_with("misc") {
                        num_interesting_crashes += 1;
                    }
                }

                // Remove the crash_dir prefix from the found crash dirs
                let crash_dir_str = format!("{}/", crash_dir.to_str().unwrap());
                crash_paths = crash_path_strs
                    .iter()
                    .map(|path| ListItem::new(Span::raw(path.replace(&crash_dir_str, ""))))
                    .collect();
            }
        });

        if stop_after_first_crash && num_interesting_crashes > 0 {
            crate::FINISHED.store(true, Ordering::SeqCst);
        }

        // Calculate the performance stats for the totals that are >1%
        perf_stats.clear();
        for (index, &val) in totals.iter().enumerate() {
            if val == 0 {
                continue;
            }

            // Calculate the percentage for this value
            let res = (val as f64 / total as f64 * 100.).round();

            if res == 0.0 {
                continue;
            }

            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            perf_stats.push((PerfMark::names()[index], res as u64));
        }
        perf_stats.sort_by(|x, y| y.1.cmp(&x.1));

        // Calculate the performance stats for the totals that are >1%
        curr_tui_perf_stats.clear();
        let tui_total = tui_perf_stats[TuiPerfStats::Total as usize];
        let mut other = 100.0;
        let avg_tui_iter = tui_total / iter as f64;
        for (index, &val) in tui_perf_stats.iter().enumerate() {
            if index == TuiPerfStats::Total as usize {
                continue;
            }

            if val == 0.0 {
                continue;
            }

            // Calculate the percentage for this value
            let res = (val / tui_total * 100.).round();

            if res == 0.0 {
                continue;
            }

            // '_' denote a subcategory in a stat, don't subtract the subcategory
            // from the entire missing time
            if !TuiPerfStats::names()[index].contains(&"_") {
                other -= res;
            }

            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            curr_tui_perf_stats.push((TuiPerfStats::names()[index], res as u64));
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        curr_tui_perf_stats.push(("Other", other as u64));
        curr_tui_perf_stats.sort_by(|x, y| y.1.cmp(&x.1));

        vmexit_stats.clear();
        let total_vmexits: u64 = vmexits.iter().sum();
        for (index, &val) in vmexits.iter().enumerate() {
            if val == 0 {
                continue;
            }

            let name = FuzzVmExit::name(index);

            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            vmexit_stats.push((name, (val as f64 / total_vmexits as f64 * 100.0) as u64));
        }
        vmexit_stats.sort_by(|x, y| y.1.cmp(&x.1));

        // Add the graph data for this time sample
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        {
            graph_exec_per_sec.push(exec_per_sec);
            graph_coverage.push(total_coverage.len() as u64);
            graph_seconds.push(iter);
            graph_iters.push(total_iters);
            graph_crashes.push(crash_paths.len() as u64);
            graph_dirty_pages_per_sec.push([dirty_pages, dirty_pages_kvm, dirty_pages_custom]);
        }

        let coverage: Vec<(u64, u64)> = graph_iters
            .iter()
            .zip(graph_coverage.iter())
            .map(|(x, y)| (*x, *y))
            .collect();

        // Update the coverage blockers
        if let Some(cov_analysis) = &mut coverage_analysis {
            for addr in &total_coverage {
                cov_analysis.hit(addr.0);
            }

            coverage_blockers.clear();

            for (score, addr) in cov_analysis.best_options() {
                if coverage_blockers.len() > 200 {
                    break;
                }

                if let Some(sym_data) = symbols {
                    let addr = **addr;
                    if let Some(symbol) = crate::symbols::get_symbol(addr, sym_data) {
                        // Ignore asan/ubsan symbols
                        if symbol.contains("asan")
                            || symbol.contains("lsan")
                            || symbol.contains("ubsan")
                            || symbol.contains("sanitizer")
                        {
                            continue;
                        }

                        let mut line = format!("{score:>5?}: {addr:#x} {symbol}");

                        // Add the source line for this address in the coverage timeline
                        for context in &contexts {
                            // Write the source and lcov coverage files if vmlinux exists
                            for curr_addr in [addr, addr.saturating_sub(0x5555_5555_4000)] {
                                if let Some(loc) = context.find_location(curr_addr)? {
                                    line.push_str(&format!(
                                        " {}:{}:{}",
                                        loc.file.unwrap_or("??unknownfile??"),
                                        loc.line.unwrap_or(0),
                                        loc.column.unwrap_or(0)
                                    ));

                                    break;
                                }
                            }
                        }

                        coverage_blockers.push(line);
                    }
                }
            }
        }

        // If merge coverage timer has elapsed, set the total coverage across all cores
        // and give each core a new corpus to fuzz with
        time!(MergeCoverage, {
            if merge_coverage {
                // First, gather all the corpi from all cores
                for (core_id, core_stats) in stats.iter().enumerate() {
                    let Ok(mut curr_stats) = core_stats.try_lock() else {
                        continue;
                    };

                    if let Some(corpus) = curr_stats.old_corpus.take() {
                        // Check if any input in the current corpus is new by calculating the
                        // hash of each input
                        for input in corpus {
                            total_corpus.insert(input);
                        }
                    }
                }

                for (core_id, core_stats) in stats.iter().enumerate() {
                    // Attempt to lock this core's stats for updating. If the lock is taken,
                    // skip it and update the core on the next iteration
                    let Ok(mut curr_stats) = core_stats.try_lock() else {
                        continue;
                    };

                    // Update the total coverage for this core
                    curr_stats.coverage = total_coverage.clone();

                    // Update the redqueen rules and coverage for this core
                    total_redqueen_coverage.append(&mut curr_stats.redqueen_coverage);
                    curr_stats.redqueen_coverage = total_redqueen_coverage.clone();

                    let corpus_len = total_corpus.len();

                    // Give each new core a small percentage (between 10% and 50%) of the total corpus
                    let mut new_corpus_len = corpus_len;
                    if corpus_len > 100 {
                        // Get the minimum number of files to add for this new corpus
                        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                        let min = ((corpus_len as f64
                            * (config.stats.minimum_total_corpus_percentage_sync as f64 / 100.))
                            as usize)
                            .min(config.stats.maximum_new_corpus_size);

                        // Get the maximum number of files to add for this new corpus
                        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                        let max = ((corpus_len as f64
                            * (config.stats.maximum_total_corpus_percentage_sync as f64 / 100.))
                            as usize)
                            .min(config.stats.maximum_new_corpus_size + 1);

                        // Get a random number of files for this corpus from min to max
                        if min < max {
                            new_corpus_len = rng.gen_range(min..max);
                        }
                    }

                    // New corpus defaults to None. Set the Option to Some to start adding to
                    // the new corpus
                    if curr_stats.new_corpus.is_none() {
                        curr_stats.new_corpus = Some(Vec::with_capacity(new_corpus_len));
                    }

                    assert!(corpus_len > 0);

                    // Give the core worker a new corpus if it hasn't picked up the existing
                    // corpus already.
                    let in_redqueen = curr_stats.in_redqueen;

                    if let Some(ref mut new_corpus) = &mut curr_stats.new_corpus {
                        if !new_corpus.is_empty() && !in_redqueen {
                            log::info!("{core_id} hasn't picked up old corpus");

                            // Core hasn't yet picked up the old corpus
                            continue;
                        }

                        let cap = new_corpus.capacity();
                        if cap < new_corpus_len {
                            new_corpus.reserve_exact(new_corpus_len - cap);
                        }

                        // Add the new corpus to the core, this should be O(n)
                        new_corpus.extend(
                            total_corpus
                                .iter()
                                .choose_multiple(&mut rng, new_corpus_len)
                                .into_iter()
                                .cloned(),
                        );
                    }
                }

                // Reset the coverage timer if we merged coverage
                coverage_timer = std::time::Instant::now();

                // Reset the merge coverage flag
                merge_coverage = false;
            }
        });

        if iter % 4 == 0 {
            time!(CoverageLighthouse, {
                // Clear old lighthouse data
                lighthouse_data.clear();

                // Collect the lighthouse coverage data
                for addr in &total_coverage {
                    if let Some((module, offset)) = modules.contains(addr.0) {
                        lighthouse_data.push_str(&format!("{module}+{offset:x}\n"));
                    } else {
                        lighthouse_data.push_str(&format!("{:x}\n", addr.0));
                    }
                }

                // Write the lighthouse coverage data
                #[allow(clippy::needless_borrow)]
                std::fs::write(&lighthouse_file, &lighthouse_data)
                    .expect("Failed to write lighthouse file");
            });

            time!(CoverageAddress, {
                // Clear old address data
                cov_addrs.clear();

                for addr in &total_coverage {
                    cov_addrs.push_str(&format!("{:#x}\n", addr.0));
                }

                // Write the coverage raw addresses file (used with addr2line to get source cov)
                #[allow(clippy::needless_borrow)]
                std::fs::write(&coverage_addrs, &cov_addrs)
                    .expect("Failed to write coverage addresses");

                // Write the coverage raw addresses file (used with addr2line to get source cov)
                #[allow(clippy::needless_borrow)]
                std::fs::write(&coverage_in_order, coverage_timeline.join("\n"))
                    .expect("Failed to write coverage in order file");
            });

            #[cfg(feature = "redqueen")]
            {
                let redqueen_cov = total_redqueen_coverage
                    .iter()
                    .map(
                        |RedqueenCoverage {
                             virt_addr,
                             rflags,
                             hit_count,
                         }| {
                            format!("{:#x} {rflags:#x} {hit_count:#x}", virt_addr.0)
                        },
                    )
                    .collect::<Vec<_>>()
                    .join("\n");

                // Write the coverage raw addresses file (used with addr2line to get source cov)
                #[allow(clippy::needless_borrow)]
                std::fs::write(&coverage_redqueen, redqueen_cov)
                    .expect("Failed to write redqueen cov file");
            }
        }

        // Write the redqueen rules
        /*
        if let Ok(redqueen_bytes) = serde_json::to_vec(&total_redqueen_rules) {
            std::fs::write(&redqueen_rules_path, &redqueen_bytes);
        }
        */

        time!(CoverageSource, {
            for context in &contexts {
                // Write the source and lcov coverage files if vmlinux exists
                // let mut result = Vec::new();

                for rip in &total_coverage {
                    let addr = *rip;

                    // Try to get the addr2line information for the current address
                    if let Some(loc) = context.find_location(addr.0)? {
                        /*
                        let kernel_sym = format!(
                            "{}:{}:{} {:#x}",
                            loc.file.unwrap_or("??"),
                            loc.line.unwrap_or(0),
                            loc.column.unwrap_or(0),
                            addr.0,
                        );

                        result.push(kernel_sym);
                        */

                        // Insert valid file:line into the BTreeMap for producing lcov
                        if let (Some(file), Some(line)) = (loc.file, loc.line) {
                            lcov.entry(file)
                                .or_insert_with(BTreeMap::new)
                                .insert(line, 1);
                        }
                    } else if let Some(module_start) = modules.get_module_start_containing(addr.0) {
                        // If not found, check if the module that contains this address
                        // is compiled with Position Independent code (PIE) and subtract
                        // the module start address to check for
                        if let Some(loc) =
                            context.find_location(addr.saturating_sub(module_start))?
                        {
                            /*
                            let kernel_sym = format!(
                                "{}:{}:{} {:#x}",
                                loc.file.unwrap_or("??"),
                                loc.line.unwrap_or(0),
                                loc.column.unwrap_or(0),
                                addr.0,
                            );

                            result.push(kernel_sym);
                            */

                            // Insert valid file:line into the BTreeMap for producing lcov
                            if let (Some(file), Some(line)) = (loc.file, loc.line) {
                                lcov.entry(file)
                                    .or_insert_with(BTreeMap::new)
                                    .insert(line, 1);
                            }
                        }
                    }
                }

                // result.sort();
                // #[allow(clippy::needless_borrow)]
                // std::fs::write(&coverage_src, result.join("\n"))?;
            }
        });

        time!(Lcov, {
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
        });

        /*
        let (_, _write_corpus_elapsed) = time!(
            // Write the current corpus to disk
            for input in &total_corpus {
                save_input_in_dir(input, &corpus_dir)?;
            }
        );
        */

        // Check for a new file dropped into `current_corpus`
        /*
        let (_, _newinput_elapsed) = time!(for entry in corpus_dir.read_dir()? {
            // Limit how long we monitor the `current_corpus` for this iteration to not
            // lock the TUI for too long
            if start.elapsed() >= PRINT_SLEEP {
                break;
            }

            // Get the entry
            let Ok(entry) = entry else { continue; };

            let path = entry.path();

            // Get the filename from the entry
            let Some(filename) = path.file_name() else { continue; };

            // Only new filenames that we haven't seen before. Avoids having to
            // read every input file from disk just to check if we know about it.
            if corpus_filenames.insert(filename.to_string_lossy().into_owned()) {
                if let Ok(bytes) = std::fs::read(entry.path()) {
                    if let Ok(input) = FUZZER::Input::from_bytes(&bytes) {
                        if total_corpus.insert(input) {
                            log::info!("Inserting new input: {:?}", entry.path());
                        } else {
                            log::warn!("New input already found in corpus: {:?}", entry.path());
                        }
                    } else {
                        log::warn!(
                            "Failed to deserialize input based on Fuzzer: {:?}",
                            entry.path()
                        );
                    }
                }
            }
        });
        tui_perf_stats[TuiPerfStats::NewInput as usize] += _newinput_elapsed.as_secs_f64();
        */

        time!(WriteGraphs, {
            // Write the graph data to disk
            scratch_string.clear();
            graph_exec_per_sec
                .iter()
                .for_each(|val| scratch_string.push_str(&format!("{val}\n")));
            std::fs::write(&plot_exec_per_sec, &scratch_string)?;

            scratch_string.clear();
            graph_dirty_pages_per_sec.iter().for_each(|val| {
                scratch_string.push_str(&format!("{},{},{}\n", val[0], val[1], val[2]))
            });
            std::fs::write(&plot_dirty_page_per_sec, &scratch_string)?;

            // Write the coverage data to disk
            scratch_string.clear();
            graph_coverage
                .iter()
                .for_each(|val| scratch_string.push_str(&format!("{val}\n")));
            std::fs::write(&plot_coverage, &scratch_string)?;
        });

        // Get the current stats ready to print in tabular form
        let table = GlobalStats {
            time: format!("{hours:02}:{minutes:02}:{seconds:02}"),
            iterations: total_iters,
            coverage: total_coverage.len(),
            rq_coverage: total_redqueen_coverage.len(),
            last_coverage: last_coverage.elapsed().as_secs(),
            exec_per_sec,
            rq_exec_per_sec,
            timeouts: sum_timeouts,
            coverage_left,
            dirty_pages,
            dirty_pages_kvm,
            dirty_pages_custom,
            corpus: u32::try_from(total_corpus.len()).unwrap(),
            alive,
            crashes: num_crashes,
            dead: dead.clone(),
            in_redqueen: in_redqueen.clone(),
            perfs: (totals, total, remaining),
            vmexits,
        };

        time!(WriteStatsData, {
            if let Ok(data) = serde_json::to_string(&table) {
                let _ = std::fs::write(data_dir.join("stats.json"), &data);
            }
            if let Ok(data) = toml::to_string(&table) {
                let _ = std::fs::write(data_dir.join("stats.toml"), &data);
            }
        });

        // Sleep to pad for the rest of the frame
        let time_left = PRINT_SLEEP.saturating_sub(tui_start.elapsed());
        if time_left == std::time::Duration::from_secs(0) {
            log::info!("Missed stat time window!");
        }

        time!(Poll, {
            'draw: while crossterm::event::poll(time_left)? {
                let ev = crossterm::event::read()?;
                if let crossterm::event::Event::Key(key) = ev {
                    match key.code {
                        KeyCode::Char('q') => {
                            // Restore the terminal to the original state
                            crate::stats_tui::restore_terminal()?;

                            // Signal cores to terminate
                            for core_stats in stats.iter() {
                                core_stats.lock().unwrap().forced_shutdown = true;
                                core_stats.lock().unwrap().alive = false;
                            }

                            // Signal stats display to terminate
                            crate::FINISHED.store(true, Ordering::SeqCst);
                        }
                        KeyCode::Right | KeyCode::Char('l') => {
                            tab_index = tab_index.wrapping_add(1);
                            break 'draw;
                        }
                        KeyCode::Left | KeyCode::Char('h') => {
                            tab_index = tab_index.wrapping_sub(1);
                            break 'draw;
                        }
                        KeyCode::Char('H') => {
                            tui_log_state.transition(&TuiWidgetEvent::LeftKey);
                            break 'draw;
                        }
                        KeyCode::Char('L') => {
                            tui_log_state.transition(&TuiWidgetEvent::RightKey);
                            break 'draw;
                        }
                        KeyCode::Char('J') => {
                            tui_log_state.transition(&TuiWidgetEvent::DownKey);
                            break 'draw;
                        }
                        KeyCode::Char('K') => {
                            tui_log_state.transition(&TuiWidgetEvent::UpKey);
                            break 'draw;
                        }
                        _ => {
                            // log::info!("Not impl: {:?}", key);
                        }
                    }
                }
            }
        });

        // If something has triggered FINISH, close out all stats and return from this
        // thread
        if crate::FINISHED.load(Ordering::SeqCst) {
            // Restore the terminal to the original state
            crate::stats_tui::restore_terminal()?;

            // Sanity check all cores are dead before exiting
            let iters = 20;
            println!("Stats waiting for threads to terminate");
            for iter in 0..iters {
                alive = 0;

                // Calculate the current statistics
                for (_core_id, core_stats) in stats.iter().enumerate() {
                    let mut stats = core_stats.lock().unwrap();

                    // Add this core's corpus to the total corpus
                    if let Some(corpus) = stats.old_corpus.take() {
                        for input in corpus {
                            total_corpus.insert(input);
                        }
                    }

                    if stats.alive {
                        alive += 1;
                        continue;
                    }
                }

                if alive == 0 {
                    println!("All cores are dead..");
                    break;
                }

                println!("{iter}/{iters}: Cores still alive: {alive}");

                std::thread::sleep(std::time::Duration::from_millis(500));
            }

            println!("Stats breaking from finish..");

            break 'finish;
        }

        if tui {
            let app = StatsApp::new(
                perf_stats.as_slice(),
                coverage.as_slice(),
                vmexit_stats.as_slice(),
                &table,
                &coverage_timeline,
                &crash_paths,
                tab_index,
                &coverage_blockers,
                &mut tui_log_state,
                &curr_tui_perf_stats,
                avg_tui_iter,
            );

            if let Some(ref mut term) = terminal {
                term.draw(|f| crate::stats_tui::ui(f, &app))?;
            }

            tui_perf_stats[TuiPerfStats::Total as usize] += tui_start.elapsed().as_secs_f64();
        } else {
            // Ascii stats display
            table.display();

            // Display coverage blockers for ascii stats
            for line in coverage_blockers.iter().take(ASCII_COVERAGE_BLOCKERS) {
                println!("{line:?}");
            }
        }

        // Set the new index
        iters_index = (iters_index + 1) % ITERS_WINDOW_SIZE;
    } // Start of iteration loop

    // Restore the terminal to the original state
    crate::stats_tui::restore_terminal()?;

    println!("Writing graph data to disk..");
    // Write the graph data to disk
    std::fs::write(
        plot_exec_per_sec,
        graph_exec_per_sec
            .iter()
            .map(|x| format!("{x}"))
            .collect::<Vec<String>>()
            .join("\n"),
    )?;

    std::fs::write(
        plot_dirty_page_per_sec,
        graph_dirty_pages_per_sec
            .iter()
            .map(|x| format!("{},{},{}", x[0], x[1], x[2]))
            .collect::<Vec<String>>()
            .join("\n"),
    )?;

    std::fs::write(
        plot_coverage,
        graph_coverage
            .iter()
            .map(|x| format!("{x}"))
            .collect::<Vec<String>>()
            .join("\n"),
    )?;

    std::fs::write(
        plot_crash_groups,
        graph_crashes
            .iter()
            .map(|x| format!("{x}"))
            .collect::<Vec<String>>()
            .join("\n"),
    )?;

    let mut corpus_len = 0;

    for input in &total_corpus {
        corpus_len += save_input_in_dir(input, &corpus_dir)?;
    }

    println!(
        "Writing corpus ({}) to disk: {:4.2} MB",
        total_corpus.len(),
        corpus_len as f64 / 1024. / 1024.
    );

    drop(stats);

    println!("[stats] FINISHED!");

    Ok(())
}

/*
pub fn source_from_address(
    addr: u64,
    contexts: Vec<Context<EndianReader<RunTimeEndian, Rc<[u8]>>>>,
    modules: &Modules,
    lcov: &mut BTreeMap<usize, usize>,
) {
    for context in &contexts {
        // Write the source and lcov coverage files if vmlinux exists
        let mut result = Vec::new();

        // Try to get the addr2line information for the current address
        if let Some(loc) = context.find_location(addr.0)? {
            let kernel_sym = format!(
                "{}:{}:{} {:#x}",
                loc.file.unwrap_or("??"),
                loc.line.unwrap_or(0),
                loc.column.unwrap_or(0),
                addr.0,
            );

            result.push(kernel_sym);

            // Insert valid file:line into the BTreeMap for producing lcov
            if let (Some(file), Some(line)) = (loc.file, loc.line) {
                lcov.entry(file)
                    .or_insert_with(BTreeMap::new)
                    .insert(line, 1);
            }
        } else if let Some(module_start) = modules.get_module_start_containing(addr.0) {
            // If not found, check if the module that contains this address
            // is compiled with Position Independent code (PIE) and subtract
            // the module start address to check for
            if let Some(loc) = context.find_location(addr.saturating_sub(module_start))? {
                let kernel_sym = format!(
                    "{}:{}:{} {:#x}",
                    loc.file.unwrap_or("??"),
                    loc.line.unwrap_or(0),
                    loc.column.unwrap_or(0),
                    addr.0,
                );

                result.push(kernel_sym);

                // Insert valid file:line into the BTreeMap for producing lcov
                if let (Some(file), Some(line)) = (loc.file, loc.line) {
                    lcov.entry(file)
                        .or_insert_with(BTreeMap::new)
                        .insert(line, 1);
                }
            }
        }
    }
}
*/
