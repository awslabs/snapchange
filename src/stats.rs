//! Statistics gathered across all fuzzing cores
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::format_in_format_args)]

use addr2line::gimli::{EndianReader, RunTimeEndian};
use addr2line::Context;

use anyhow::Result;
use crossterm::event::KeyCode;

use ahash::{AHashMap, AHashSet};
use rand::seq::IteratorRandom;
use rand::Rng as _;
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use tui::text::Span;
use tui::widgets::ListItem;
use tui_logger::{TuiWidgetEvent, TuiWidgetState};

use std::collections::BTreeSet;
use std::convert::Into;
use std::fs::File;
use std::io::Write;
use std::mem::variant_count;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::addrs::VirtAddr;
use crate::cmdline::Modules;
use crate::config::Config;
use crate::coverage_analysis::{Blockers, CoverageAnalysis};
use crate::feedback::{FeedbackLog, FeedbackTracker};
use crate::fuzz_input::InputWithMetadata;
use crate::fuzzer::Fuzzer;
use crate::fuzzvm::FuzzVmExit;
use crate::rng::Rng;
use crate::stats_tui::StatsApp;
use crate::utils::save_input_in_project;
use crate::{FxIndexMap, FxIndexSet, SymbolList};

#[cfg(feature = "redqueen")]
use crate::cmp_analysis::RedqueenCoverage;

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

    /// Number of iterations (VM executions) this core has performed in redqueen
    pub rq_iterations: u64,

    /// Number of inputs this core has performed in redqueen
    pub rq_inputs: u64,

    /// Signals to a core to force exit
    pub forced_shutdown: bool,

    /// Signals that this core is alive
    pub alive: bool,

    /// Signals that this core is in redqueen
    pub in_redqueen: bool,

    /// Current coverage feedback
    pub feedback: FeedbackTracker,

    /// Current redqueen coverage seen by this core
    // pub redqueen_coverage: BTreeSet<RedqueenCoverage>,

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
    pub old_corpus: Option<Vec<Arc<InputWithMetadata<FUZZER::Input>>>>,

    /// A new corpus to be picked up by the fuzzer. This is populated by the main stats
    /// worker containing some random inputs from the total corpus.
    pub new_corpus: Option<Vec<Arc<InputWithMetadata<FUZZER::Input>>>>,

    /// Performance metrics for this core indexed by `PerfMark`
    pub perf_stats: PerfStats,

    /// Number of [`FuzzVmExit`] seen
    pub vmexits: [u64; variant_count::<FuzzVmExit>()],

    /// Toal number of [`FuzzVmExit`] seen
    pub total_vmexits: u64,

    /// Performance metrics for the stats loop itself
    pub tui_perf_stats: [f64; variant_count::<TuiPerfStats>()],

    /// Total input hashes that have been seen by redqueen cores
    pub redqueen_seen: Arc<Mutex<BTreeSet<u64>>>,
}

impl<FUZZER: Fuzzer> Stats<FUZZER> {
    /// Increment the hit count for the given [`FuzzVmExit`]
    pub fn inc_vmexit(&mut self, vmexit: &FuzzVmExit) {
        let index = vmexit.id();
        self.total_vmexits += 1;
        self.vmexits[index] += 1;
    }
}

/// Current stats to display to the screen
#[allow(clippy::module_name_repetitions)]
#[derive(Default, Serialize, Deserialize)]
pub struct GlobalStats {
    /// Elapsed time
    pub time: String,

    /// Number of iterations across all cores
    pub iterations: u64,

    /// Total coverage seen
    pub coverage: usize,

    /// Seconds since the last coverage
    pub last_coverage: u64,

    /// Executions per second (total)
    pub exec_per_sec: u64,

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
    pub perfs: (PerfMarks, u64, u64),

    /// Number of vmexits found across all cores
    pub vmexits: [u64; variant_count::<FuzzVmExit>()],

    /// Number of vmexits per iteration on average
    pub vmexits_per_iter: u64,

    /// Total coverage seen in redqueen
    #[cfg(feature = "redqueen")]
    pub rq_coverage: usize,

    /// Executions per second (total) in Redqueen
    #[cfg(feature = "redqueen")]
    pub rq_exec_per_sec: u64,
}

pub struct PerfMarks {
    timers: [u64; variant_count::<PerfMark>()],
}

impl std::default::Default for PerfMarks {
    fn default() -> Self {
        Self {
            timers: [0; variant_count::<PerfMark>()],
        }
    }
}

/// Performance statistics
#[derive(Clone)]
#[allow(clippy::module_name_repetitions)]
pub struct PerfStats {
    /// The start time of the performance metrics
    pub start_time: u64,

    /// Start times for the performance marks available
    starts: [u64; variant_count::<PerfMark>()],

    /// Time spent during child timers
    child_time: [u64; variant_count::<PerfMark>()],

    /// Elapsed times for the performance marks
    elapsed: [u64; variant_count::<PerfMark>()],

    /// Hit count for this timer
    hits: [u64; variant_count::<PerfMark>()],

    /// The current timer
    current: Option<PerfMark>,
}

impl std::default::Default for PerfStats {
    fn default() -> PerfStats {
        PerfStats {
            start_time: 0,
            starts: [0_u64; variant_count::<PerfMark>()],
            child_time: [0_u64; variant_count::<PerfMark>()],
            elapsed: [0_u64; variant_count::<PerfMark>()],
            hits: [0_u64; variant_count::<PerfMark>()],
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
        let mut stats = core_stats.lock().unwrap();
        let parent = stats.perf_stats.current;
        stats.perf_stats.current = Some(timer);
        drop(stats);

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
            .unwrap_or_else(|| {
                log::debug!(
                    "Failed on drop: {:?} curr elapsed {:#x} elapsed {:#x} child time {:#x}",
                    self.timer,
                    stats.elapsed[self.timer as usize],
                    elapsed,
                    child_time
                );

                0
            });

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

        /// Time to for stats coverage sync
        SyncCov3,

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

        ResetGuestState,
        InitGuest,
        ApplyRedqueenBreakpoints,
        RunUntilResetRedqueen,
        ClearDirtyLogs,
        ApplyResetBreakpoints,
        ApplyFuzzerBreakpoints,
        RQSyncCov,
        RqInVm,
        GatherRedqueen,
        RqRecordCodeCov,
        RqRecordBreakpoint,
        RqHandleVmexit,
        HandleBreakpoint,
        HandleBp1,
        HandleBp2,
        HandleBp3,
        HandleBp4,
        HandleBp5,
        HandleBp6,
        HandleBp7,
        GatherComparison,
        RQReadU8,
        RQReadU16,
        RQReadU32,
        RQReadU64,
        RQReadU128,
        RQReadF32,
        RQReadF64,
        RQReadX87,
        RQIncEntropy,
        SetRQRuleCandidates,
        GetRQRuleCandidates,
        AddRQRuleCandidates,
        AddDirtyPages,
        FuzzerInitVm,
        RemainingResetGuest,
        PostRunVmBp,
        PostRunVmCovBp,
        PostRunVmResetBp,
        ResetImmediateReturn,
        IncreaseInputEntropy,
        GetRQRuleEntry,
        InsertRQRuleEntry,

        /// time spent elsewhere that is not currently being tracked
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
        CoverageAnalysis,
        WriteCoverageAnalysis,
        WriteCoverageAll,
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
        let (totals, total, remaining) = &self.perfs;
        let totals = totals.timers;

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
                curr_stat as f64 / *total as f64 * 100.
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
            *remaining as f64 / *total as f64 * 100.
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
        let (totals, _, remaining) = &self.perfs;
        let totals = totals.timers;

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

        for i in 0..variant_count::<FuzzVmExit>() {
            let name = FuzzVmExit::name(i);
            let val = self.vmexits[i];

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

pub type ContextList = Vec<Context<EndianReader<RunTimeEndian, Rc<[u8]>>>>;
pub type ContextSlice = [Context<EndianReader<RunTimeEndian, Rc<[u8]>>>];

/// Get a [`Context`] for every known binary in the snapshot.
///
/// Search for all `.bin` files and vmlinux in the snapshot dir and open
/// a [`adddr2line::Context`] for all of them to retrieve symbols
#[allow(clippy::type_complexity)]
pub fn get_binary_contexts(project_dir: &Path) -> Result<ContextList> {
    // ) -> Result<Vec<u64>> {
    let mut contexts = Vec::new();

    for file in std::fs::read_dir(project_dir)? {
        let file = file?;
        if let Some(extension) = file.path().extension() {
            if matches!(extension.to_str(), Some("bin")) {
                let fd = File::open(file.path())?;
                let map = unsafe { memmap2::Mmap::map(&fd)? };
                let object = addr2line::object::File::parse(&*map)?;
                let tmp = addr2line::Context::new(&object)?;
                contexts.push(tmp);
                log::info!("Found {:?} addr2line context", file.path().file_name());
            }
        }
    }

    // Check if the project contains a `vmlinux` file for kernel symbols
    let vmlinux = project_dir.join("vmlinux");
    if vmlinux.exists() {
        let file = File::open(vmlinux)?;
        let map = unsafe { memmap2::Mmap::map(&file)? };
        let object = addr2line::object::File::parse(&*map)?;
        let tmp = addr2line::Context::new(&object)?;
        contexts.push(tmp);
        log::info!("Found vmlinux addr2line context");
    }

    // Return the found binary contexts
    Ok(contexts)
}

/// Recursively search the given path for other directories. Returns `true` if the directory
/// has file children and `false` if it only has other directories.
fn get_subdirs(path: &PathBuf, crashes: &mut Vec<String>) -> bool {
    let mut has_file_children = false;

    if let Ok(crash_entries) = std::fs::read_dir(path) {
        for file in crash_entries.into_iter().flatten() {
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

    has_file_children
}

/// The worker function to display the statistics of the fuzzing cores
#[allow(clippy::too_many_lines)]
pub fn worker<FUZZER: Fuzzer>(
    stats: Arc<Vec<Arc<Mutex<Stats<FUZZER>>>>>,
    project_state: &crate::ProjectState,
    project_dir: &Path,
    mut total_feedback: FeedbackTracker,
    input_corpus: &Vec<Arc<InputWithMetadata<FUZZER::Input>>>,
    symbols: Option<&SymbolList>,
    mut coverage_analysis: Option<CoverageAnalysis>,
    tui: bool,
    config: &Config, // redqueen_rules: BTreeMap<u64, BTreeSet<RedqueenRule>>
    stop_after_first_crash: bool,
    stop_after_time: Option<Duration>,
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

    log::info!(
        "starting with previously seen coverage/feedback with {} entries",
        total_feedback.len()
    );

    // Populate the current corpus filenames for monitoring when a new file is dropped
    // into `current_corpus`
    let mut corpus_filenames = ahash::AHashSet::with_capacity(input_corpus.len() * 2);
    for entry in corpus_dir.read_dir()?.flatten() {
        if entry.file_type()?.is_dir() {
            continue;
        }

        if let Some(filename) = entry.path().file_name() {
            corpus_filenames.insert(filename.to_string_lossy().into_owned());
        }
    }

    let debug_info = DebugInfo::new(project_state)?;
    log::info!(
        "loaded debug info with {} debug locations",
        debug_info.len()
    );
    let mut lcov = debug_info.lcov_info_from_feedback(&total_feedback);

    // Create the web directory for displaying stats via the browser
    let crash_dir = project_dir.join("crashes");
    if !crash_dir.exists() {
        std::fs::create_dir(&crash_dir)?;
    }

    // Get the filenames for the various output files
    let coverage_all = project_dir.join("coverage.all");
    let coverage_lighthouse = project_dir.join("coverage.lighthouse");
    let coverage_addrs = project_dir.join("coverage.addresses");
    let coverage_blockers_in_path_file = project_dir.join("coverage.blockers.in_path");
    let coverage_blockers_total_file = project_dir.join("coverage.blockers.total");
    // let coverage_src = project_dir.join("coverage.src");
    let coverage_lcov = project_dir.join("coverage.lcov");
    let coverage_in_order = project_dir.join("coverage.in_order");
    #[cfg(feature = "redqueen")]
    let coverage_redqueen = project_dir.join("coverage.redqueen");
    #[cfg(feature = "custom_feedback")]
    let coverage_custom = project_dir.join("coverage.custom.json");
    #[cfg(feature = "custom_feedback")]
    let coverage_max = project_dir.join("coverage.max.json");

    // let redqueen_rules_path = project_dir.join("redqueen.rules");
    let plot_exec_per_sec = data_dir.join("exec_per_sec.plot");
    let plot_dirty_page_per_sec = data_dir.join("dirty_page_per_sec.plot");
    let plot_coverage = data_dir.join("coverage.plot");
    let plot_crash_groups = data_dir.join("crashes.plot");

    // Start the timer for the beginning of the fuzz run
    let start = std::time::Instant::now();

    // Average stats used for the stats TUI
    let mut exec_per_sec;
    let mut dirty_pages = 0;
    let mut dirty_pages_kvm = 0;
    let mut dirty_pages_custom = 0;
    let mut vmexits_per_iter = 0;

    // Init the coverage time to sync coverage between the cores
    let mut coverage_timer = std::time::Instant::now();
    let mut corpus_timer = std::time::Instant::now();

    let mut merge_coverage = false;
    let mut merge_corpus = false;

    let mut last_best_coverage = 0;
    let mut last_coverage = std::time::Instant::now();

    let mut total_iters: u64 = 0;

    // Rolling window to calculate most recent iterations
    let mut sum_iters = [0_u64; ITERS_WINDOW_SIZE];
    let mut sum_rq_iters = [0_u64; ITERS_WINDOW_SIZE];
    let mut sum_dirty_pages = [0_u64; ITERS_WINDOW_SIZE];
    let mut sum_dirty_pages_kvm = [0_u64; ITERS_WINDOW_SIZE];
    let mut sum_dirty_pages_custom = [0_u64; ITERS_WINDOW_SIZE];
    let mut sum_vmexits = [0_u64; ITERS_WINDOW_SIZE];
    let mut iters_index = 0;
    let mut cov_addrs = String::new();

    // Init graph data
    let mut graph_exec_per_sec = vec![0];
    let mut graph_coverage = vec![0];
    let mut graph_seconds = vec![0];
    let mut graph_iters = vec![0];
    let mut graph_crashes = vec![0];
    let mut graph_dirty_pages_per_sec = vec![[0u64, 0, 0]];

    // Init the total corpus across all cores
    // let mut total_corpus: AHashSet<Arc<InputWithMetadata<FUZZER::Input>>> = AHashSet::with_capacity(input_corpus.len() * 2);
    let mut total_corpus = AHashSet::with_capacity(input_corpus.len() * 2);
    total_corpus.extend(input_corpus.iter().cloned());

    let mut rng = Rng::new();

    let mut dead = Vec::new();
    let mut in_redqueen = Vec::new();
    let mut perfs = vec![None; crate::MAX_CORES];
    let mut vmexits = [0_u64; variant_count::<FuzzVmExit>()];

    // TUI log state
    let mut tui_log_state = TuiWidgetState::new();

    // Call once to log the poll trace for crossterm so it doesn't clog the screen
    let _ = crossterm::event::poll(Duration::from_millis(1))?;

    // Initialize the terminal if using the TUI
    let mut terminal = None;
    if tui {
        terminal = Some(crate::stats_tui::init_terminal()?);
    }

    let mut coverage_timeline = if let Ok(data) = std::fs::read_to_string(&coverage_in_order) {
        data.split('\n').map(|x| x.to_string()).collect()
    } else {
        Vec::new()
    };

    let mut tab_index = 0_u8;

    let mut crash_path_strs: Vec<String> = Vec::new();
    let mut crash_paths: Vec<_> = Vec::new();
    let mut num_crashes = 0_u32;

    // Initialize the coverage analysis with the current toal coverage
    let mut coverage_blockers_in_path = Vec::new();
    let mut coverage_blockers_total = Vec::new();

    let mut scratch_string = String::new();

    let mut tui_perf_stats = [0_f64; variant_count::<TuiPerfStats>()];

    let mut tui_start;
    let mut perf_stats = Vec::new();
    let mut curr_tui_perf_stats = Vec::new();
    let mut vmexit_stats = Vec::new();

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
            || coverage_timer.elapsed() > config.stats.coverage_sync_timer
                && !total_corpus.len() > 1
        {
            merge_coverage = true;
            if corpus_timer.elapsed() > config.stats.merge_corpus_timer {
                merge_corpus = true;
            }
        }

        // Reset the time window stats for this iteration window
        sum_iters[iters_index] = 0;
        sum_rq_iters[iters_index] = 0;
        sum_dirty_pages[iters_index] = 0;
        sum_dirty_pages_custom[iters_index] = 0;
        sum_dirty_pages_kvm[iters_index] = 0;
        sum_vmexits[iters_index] = 0;

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
                    // log::info!("Core {core_id} holding stats lock 1");
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
                    sum_vmexits[iters_index] += stats.total_vmexits / stats.iterations;
                }

                // Add the core stats to the total stats across all cores
                total_iters += stats.iterations;
                total_iters += stats.rq_iterations;
                sum_iters[iters_index] += stats.iterations;
                sum_rq_iters[iters_index] += stats.rq_iterations;
                sum_timeouts += stats.timeouts;
                coverage_left += stats.cov_left as u64;

                // Reset the iterations for the core
                stats.iterations = 0;
                stats.rq_iterations = 0;
                stats.dirty_pages_kvm = 0;
                stats.dirty_pages_custom = 0;
                stats.total_vmexits = 0;

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

        // Calculate the current statistics
        for (core_id, core_stats) in stats.iter().enumerate() {
            // Attempt to get this core's stats. If it fails, continue the next core
            // and get the stats on the next loop iteration
            let Ok(mut stats) = core_stats.try_lock() else {
                // log::info!("Core {core_id} holding stats lock 2");
                continue;
            };

            // Add this core's stats to the display table
            stats.perf_stats.elapsed[PerfMark::Total as usize] =
                crate::utils::rdtsc() - stats.perf_stats.start_time;
            perfs[core_id] = Some(stats.perf_stats.elapsed);

            // Add the vmexits to the total vmexits seen by the fuzzer
            for (i, val) in stats.vmexits.iter().enumerate() {
                vmexits[i] += val;
            }
        }

        let time_window = ITERS_WINDOW_SIZE as u64 * PRINT_SLEEP.as_secs();

        exec_per_sec = sum_iters.iter().sum::<u64>() / time_window;
        if alive > 0 {
            dirty_pages = sum_dirty_pages.iter().sum::<u64>() / time_window / alive;
            dirty_pages_kvm = sum_dirty_pages_kvm.iter().sum::<u64>() / time_window / alive;
            dirty_pages_custom = sum_dirty_pages_custom.iter().sum::<u64>() / time_window / alive;
            vmexits_per_iter = sum_vmexits.iter().sum::<u64>() / time_window / alive;
        }

        // Get the elapsed time in hours:minutes:seconds
        let elapsed = start.elapsed().as_secs();
        let seconds = elapsed % 60;
        let minutes = (elapsed / 60) % 60;
        let hours = elapsed / (60 * 60);

        // Signal to finish if we've elapsed time
        if let Some(stop_time) = stop_after_time {
            if start.elapsed() > stop_time {
                crate::FINISHED.store(true, Ordering::SeqCst);
            }
        }

        // Update the last coverage seen timer if new coverage has been seen
        if last_best_coverage < total_feedback.code_cov.len() {
            last_coverage = std::time::Instant::now();
            last_best_coverage = total_feedback.code_cov.len();
        }

        // Accumulate the performance metrics
        let mut total = 0;
        let mut totals = [0_u64; variant_count::<PerfMark>()];
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
                        .unwrap_or_else(|| panic!("FAILED {elem:?}"));

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
                }

                // Remove the crash_dir prefix from the found crash dirs
                let crash_dir_str = format!("{}/", crash_dir.to_str().unwrap());
                crash_paths = crash_path_strs
                    .iter()
                    .map(|path| ListItem::new(Span::raw(path.replace(&crash_dir_str, ""))))
                    .collect();
            }
        });

        // Calculate the performance stats for the totals that are >1%
        perf_stats.clear();
        for (index, &val) in totals.iter().enumerate() {
            if val == 0 {
                continue;
            }

            // Calculate the percentage for this value
            let res = (val as f64 / total as f64 * 100.).round();

            if res < 2.0 {
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
            if !TuiPerfStats::names()[index].contains('_') {
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
            graph_coverage.push(total_feedback.code_cov.len() as u64);
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
        time!(CoverageAnalysis, {
            if let Some(cov_analysis) = &mut coverage_analysis {
                for addr in total_feedback.code_cov.keys() {
                    cov_analysis.hit(addr.0);
                }

                coverage_blockers_in_path.clear();
                coverage_blockers_total.clear();

                let Blockers { in_path, total } = cov_analysis.best_options();

                for (blockers, curr_collection) in [
                    (in_path, &mut coverage_blockers_in_path),
                    (total, &mut coverage_blockers_total),
                ] {
                    for (score, addr, parent_addrs) in blockers {
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

                                // Add the symbol source line if available
                                if let Some((loc_file, loc_line)) =
                                    debug_info.get_first_location(addr)
                                {
                                    line.push_str(&format!(" {loc_file}:{loc_line}"));
                                };

                                if !parent_addrs.is_empty() {
                                    line.push_str(" from ");
                                }

                                for addr in parent_addrs {
                                    line.push_str(&format!(" {addr:#x}"));

                                    if let Some(symbol) =
                                        crate::symbols::get_symbol(*addr, sym_data)
                                    {
                                        line.push_str(&format!(":{symbol}"));
                                    }

                                    /*
                                    if let Some((loc_file, loc_line)) = debug_info.get_first_location(&addr)
                                    {
                                        line.push_str(&format!(":{loc_file}:{loc_line}"));
                                    };
                                    */

                                    line.push(' ');
                                }

                                // Add the line to the collection
                                curr_collection.push(line);
                            }
                        }
                    }
                }
            }
        });

        // If merge coverage timer has elapsed, set the total coverage across all cores
        // and give each core a new corpus to fuzz with
        time!(MergeCoverage, {
            if merge_coverage {
                let mut locked_cores = [false; crate::MAX_CORES];

                // First, gather all the corpi from all cores
                for (core_id, core_stats) in stats.iter().enumerate() {
                    let Ok(mut curr_stats) = core_stats.try_lock() else {
                        // log::info!("Core {core_id} holding stats lock 3 (old_corpus)");
                        locked_cores[core_id] = true;
                        continue;
                    };

                    if let Some(corpus) = curr_stats.old_corpus.take() {
                        // Check if any input in the current corpus is new by calculating the
                        // hash of each input
                        for input in corpus {
                            let curr_metadata = input.metadata.read().unwrap();
                            if !curr_metadata.new_coverage.is_empty() {
                                total_feedback.ensure_clean();
                                let is_new =
                                    total_feedback.merge_from_log(&curr_metadata.new_coverage);
                                let new_entries = total_feedback.take_log();

                                if is_new {
                                    for entry in new_entries {
                                        match entry {
                                            FeedbackLog::VAddr((addr, hitcount)) => {
                                                let addr = *addr;

                                                let symbol =
                                                    get_symbol_str(addr, &debug_info, symbols)?;

                                                if !debug_info.is_empty() {
                                                    debug_info.update_single_lcov(
                                                        &mut lcov, addr, hitcount,
                                                    );
                                                }

                                                coverage_timeline.push(format!(
                                                    "Covbp | {addr:#x} | hits {hitcount:03} | {symbol}"
                                                ));
                                            }
                                            #[cfg(feature = "redqueen")]
                                            FeedbackLog::Redqueen(RedqueenCoverage {
                                                virt_addr,
                                                rflags: _,
                                                hit_count,
                                            }) => {
                                                let virt_addr = *virt_addr;

                                                let symbol = get_symbol_str(
                                                    virt_addr,
                                                    &debug_info,
                                                    symbols,
                                                )?;

                                                coverage_timeline.push(format!(
                                                    "RQ    | {virt_addr:#x} | hits {hit_count:03} | {symbol}"
                                                ));
                                            }
                                            #[cfg(feature = "custom_feedback")]
                                            FeedbackLog::Custom(val) => {
                                                coverage_timeline.push(format!("Custom {val:#x}"));
                                            }
                                            #[cfg(feature = "custom_feedback")]
                                            FeedbackLog::CustomMax((tag, val)) => {
                                                coverage_timeline.push(format!(
                                                    "Custom Max - Tag {tag:#x} Value {val:#x}"
                                                ));
                                            }
                                        }
                                    }

                                    if total_corpus.insert(input.clone()) {
                                        save_input_in_project(
                                            &input,
                                            project_dir,
                                            "current_corpus",
                                        )
                                        .unwrap();
                                    }
                                }
                            }
                        }
                    }
                }

                for (core_id, core_stats) in stats.iter().enumerate() {
                    // Do not reset the corpus for any cores that were locked before
                    if locked_cores[core_id] {
                        continue;
                    }
                    // Attempt to lock this core's stats for updating. If the lock is taken,
                    // skip it and update the core on the next iteration
                    let Ok(mut curr_stats) = core_stats.try_lock() else {
                        // log::info!("Core {core_id} holding stats lock 3");
                        continue;
                    };

                    // Update the total coverage for this core
                    curr_stats.feedback.merge(&total_feedback);

                    if merge_corpus {
                        let corpus_len = total_corpus.len();

                        // Give each new core a small percentage (between 10% and 50%) of the total corpus
                        let mut new_corpus_len = corpus_len;

                        // get the minimum number of files to add for this new corpus
                        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                        let min = ((corpus_len as f64
                            * (config.stats.minimum_total_corpus_percentage_sync as f64 / 100.))
                            as usize)
                            .min(config.stats.maximum_new_corpus_size);

                        // get the maximum number of files to add for this new corpus
                        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                        let max = ((corpus_len as f64
                            * (config.stats.maximum_total_corpus_percentage_sync as f64 / 100.))
                            as usize)
                            .min(config.stats.maximum_new_corpus_size + 1);

                        // get a random number of files for this corpus from min to max
                        if min < max {
                            new_corpus_len = rng.gen_range(min..max);
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
                                // log::info!("{core_id} hasn't picked up old corpus");

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
                }

                // Reset the coverage timer if we merged coverage
                coverage_timer = std::time::Instant::now();

                // Reset the merge coverage flag
                merge_coverage = false;

                if merge_corpus {
                    corpus_timer = std::time::Instant::now();
                    merge_corpus = false;
                }
            }
        });

        if iter % 4 == 0 {
            time!(CoverageLighthouse, {
                // Collect the lighthouse coverage data
                write_lighthouse_coverage(
                    &project_state.modules,
                    &total_feedback,
                    &coverage_lighthouse,
                )?;
            });

            time!(CoverageAddress, {
                // Clear old address data
                cov_addrs.clear();

                for addr in total_feedback.code_cov.keys() {
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

            time!(WriteCoverageAnalysis, {
                // Write the coverage raw addresses file (used with addr2line to get source cov)
                #[allow(clippy::needless_borrow)]
                std::fs::write(
                    &coverage_blockers_in_path_file,
                    coverage_blockers_in_path.join("\n"),
                )
                .expect("Failed to write coverage addresses");

                // Write the coverage raw addresses file (used with addr2line to get source cov)
                #[allow(clippy::needless_borrow)]
                std::fs::write(
                    &coverage_blockers_total_file,
                    coverage_blockers_total.join("\n"),
                )
                .expect("Failed to write coverage addresses");
            });

            time!(WriteCoverageAll, {
                // No need to write the current log to disk
                total_feedback.ensure_clean();
                std::fs::write(&coverage_all, serde_json::to_string(&total_feedback)?)
                    .expect("Failed to write all coverage");
            });

            #[cfg(feature = "redqueen")]
            {
                let redqueen_cov = total_feedback
                    .redqueen
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

            #[cfg(feature = "custom_feedback")]
            {
                // dump custom coverage as json
                let w = File::create(&coverage_custom).unwrap();
                serde_json::to_writer(w, &total_feedback.custom).unwrap();
                let w = File::create(&coverage_max).unwrap();
                serde_json::to_writer(w, &total_feedback.max).unwrap();
            }

            time!(CoverageSource, {
                if !debug_info.is_empty() {
                    // Write the source and lcov coverage files if vmlinux exists
                    // debug_info.write_coverage_to_lcov_info(&total_feedback, &coverage_lcov)?;
                    lcov.write_to_file(&coverage_lcov)?;
                }
            });
        }

        // Write the redqueen rules
        /*
        if let Ok(redqueen_bytes) = serde_json::to_vec(&total_redqueen_rules) {
            std::fs::write(&redqueen_rules_path, &redqueen_bytes);
        }
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
            coverage: total_feedback.code_cov.len(),
            last_coverage: last_coverage.elapsed().as_secs(),
            exec_per_sec,
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
            perfs: (PerfMarks { timers: totals }, total, remaining),
            vmexits,
            vmexits_per_iter,
            #[cfg(feature = "redqueen")]
            rq_coverage: total_feedback.redqueen.len(),
            #[cfg(feature = "redqueen")]
            rq_exec_per_sec: sum_rq_iters.iter().sum::<u64>() / time_window,
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
            if tui {
                // Restore the terminal to the original state
                crate::stats_tui::restore_terminal()?;
            }

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
                            let curr_metadata = input.metadata.read().unwrap();
                            if !curr_metadata.new_coverage.is_empty() {
                                total_feedback.ensure_clean();
                                let is_new =
                                    total_feedback.merge_from_log(&curr_metadata.new_coverage);

                                if is_new {
                                    drop(curr_metadata);
                                    total_corpus.insert(input);
                                }
                            }
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
                &coverage_blockers_in_path,
                &coverage_blockers_total,
                &mut tui_log_state,
                &curr_tui_perf_stats,
            );

            if let Some(ref mut term) = terminal {
                term.draw(|f| crate::stats_tui::ui(f, &app))?;
            }

            tui_perf_stats[TuiPerfStats::Total as usize] += tui_start.elapsed().as_secs_f64();
        } else {
            // Ascii stats display
            table.display();

            // Display coverage blockers for ascii stats
            for line in coverage_blockers_in_path
                .iter()
                .take(ASCII_COVERAGE_BLOCKERS)
            {
                println!("{line:?}");
            }

            // Display coverage blockers for ascii stats
            for line in coverage_blockers_total.iter().take(ASCII_COVERAGE_BLOCKERS) {
                println!("{line:?}");
            }
        }

        // Set the new index
        iters_index = (iters_index + 1) % ITERS_WINDOW_SIZE;
    } // Start of iteration loop

    let mut corpus_len = 0;
    for input in &total_corpus {
        corpus_len += save_input_in_project(input, project_dir, "current_corpus")?;
    }

    if tui {
        // Restore the terminal to the original state
        crate::stats_tui::restore_terminal()?;
    }

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

    std::fs::write(
        &coverage_blockers_in_path_file,
        coverage_blockers_in_path.join("\n"),
    )
    .expect("Failed to write coverage addresses");

    write_lighthouse_coverage(
        &project_state.modules,
        &total_feedback,
        &coverage_lighthouse,
    )?;

    std::fs::write(&coverage_addrs, &cov_addrs).expect("Failed to write coverage addresses");
    std::fs::write(&coverage_in_order, coverage_timeline.join("\n"))
        .expect("Failed to write coverage in order file");

    #[cfg(feature = "redqueen")]
    {
        let redqueen_cov = total_feedback
            .redqueen
            .iter()
            .map(
                |RedqueenCoverage {
                     virt_addr,
                     rflags,
                     hit_count,
                 }| { format!("{:#x} {rflags:#x} {hit_count:#x}", virt_addr.0) },
            )
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&coverage_redqueen, redqueen_cov)
            .expect("Failed to write redqueen cov file");
    }

    time!(CoverageSource, {
        if !debug_info.is_empty() {
            debug_info.write_coverage_to_lcov_info(&total_feedback, &coverage_lcov)?;
        }
    });

    println!(
        "Writing corpus ({}) to disk: {:4.2} MB",
        total_corpus.len(),
        corpus_len as f64 / 1024. / 1024.
    );

    drop(stats);

    println!("[stats] FINISHED!");

    Ok(())
}

/// Get the `str` for the given address using the symbols and modules of this project
fn get_symbol_str(
    addr: u64,
    debug_info: &DebugInfo,
    symbols: Option<&SymbolList>,
) -> Result<String> {
    let mut result = String::new();

    if let Some(sym_data) = symbols {
        if let Some(symbol) = crate::symbols::get_symbol(addr, sym_data) {
            if let Some((file, line)) = debug_info.get_first_location(addr) {
                result = format!("{symbol} -- {file}:{line}");
            } else {
                // if the source code wasn't found, add the raw symbol instead
                result = symbol.to_string();
            }
        }
    }

    Ok(result)
}

/// dump the coverage recorded in a `FeedbackTracker` into a lighthouse file.
pub fn write_lighthouse_coverage<P: std::convert::AsRef<std::path::Path>>(
    modules: &Modules,
    feedback: &FeedbackTracker,
    filepath: P,
) -> anyhow::Result<()> {
    write_lighthouse_coverage_addresses(modules, feedback.code_cov.keys().cloned(), filepath)
}

/// write a list of addresses as lighthouse coverage to file
pub fn write_lighthouse_coverage_addresses<
    T: Into<u64>,
    I: IntoIterator<Item = T>,
    P: std::convert::AsRef<std::path::Path>,
>(
    modules: &Modules,
    addresses: I,
    filepath: P,
) -> anyhow::Result<()> {
    let mut outfile = std::io::BufWriter::new(std::fs::File::create(filepath)?);

    for addr in addresses {
        let addr: u64 = addr.into();
        if let Some((module, offset)) = modules.contains(addr) {
            writeln!(outfile, "{module}+{offset:x}")?;
        } else {
            writeln!(outfile, "{addr:x}")?;
        }
    }
    outfile.flush()?;

    Ok(())
}

/// write a list of addresses to a file
pub fn write_text_coverage_addresses<
    T: Into<u64>,
    I: IntoIterator<Item = T>,
    P: std::convert::AsRef<std::path::Path>,
>(
    addresses: I,
    filepath: P,
) -> anyhow::Result<()> {
    let mut outfile = std::io::BufWriter::new(std::fs::File::create(filepath)?);

    for addr in addresses {
        let addr: u64 = addr.into();
        writeln!(outfile, "{addr:x}")?;
    }
    outfile.flush()?;

    Ok(())
}

/// write coverage as a text file - this is more or less machine readable
pub fn write_text_coverage<P: std::convert::AsRef<std::path::Path>>(
    feedback: &FeedbackTracker,
    filepath: P,
) -> anyhow::Result<()> {
    write_text_coverage_addresses(feedback.code_cov.keys().cloned(), filepath)
}

/// Write human readable coverage to a text file.
pub fn write_human_readable_text_coverage<P: std::convert::AsRef<std::path::Path>>(
    debug_info: &DebugInfo,
    symbols: Option<&SymbolList>,
    feedback: &FeedbackTracker,
    filepath: P,
) -> anyhow::Result<()> {
    let mut outfile = std::io::BufWriter::new(std::fs::File::create(filepath)?);

    for (&addr, &hitcount) in feedback.code_cov.iter() {
        let addr: u64 = addr.into();
        let symbol = get_symbol_str(addr, debug_info, symbols)?;
        writeln!(outfile, "{addr:x} | {hitcount} | {symbol}")?;
    }
    outfile.flush()?;

    Ok(())
}

/// Encapsulate debug info loaded from ELF files using the `addr2line` crate.
#[derive(Default, Clone)]
pub struct DebugInfo {
    /// A indexable set of `(filename, line)` tuples, where `filename` is a index into `files`
    locations: FxIndexSet<(u32, u32)>,
    /// custom interning of file strings. filenames are stored once in the `files` set and referred
    /// to by insertion index from `info`.
    files: crate::AIndexSet<String>, // using ahash because it is faster for strings
    /// maps virtual address to one or more debug locations. stores indicies into `locations`
    vaddrs: FxHashMap<VirtAddr, smallvec::SmallVec<[u32; 4]>>,
}

/// [`LcovInfo`] encapsulates source coverage data in the form `line:hitcount` needed to write to a
/// lcov info file. [`LcovInfo`] is always bound to a [`DebugInfo`] struct lifetime-wise as it
/// references the filenames stored in the [`DebugInfo`].
#[derive(Default, Clone)]
pub struct LcovInfo<'a> {
    pub(crate) data: AHashMap<&'a str, FxIndexMap<u32, u32>>,
}

impl DebugInfo {
    /// Create new [`DebugInfo`] and populate the coverage info from the enabled coverage basic blocks and the `addr2line` contexts that allow to map addresses to source code coverage.
    pub fn new<'a>(project_state: &crate::ProjectState) -> Result<Self> {
        let mut s = Self::default();
        let contexts = get_binary_contexts(&project_state.path)?;
        s.populate(project_state, &contexts)?;
        Ok(s)
    }

    /// check if no debug info was loaded.
    pub fn is_empty(&self) -> bool {
        self.locations.is_empty()
    }

    /// Return the number of debuginfo locations
    pub fn len(&self) -> usize {
        self.locations.len()
    }

    /// populate debug info given a project state and associated addr2line contexts.
    pub fn populate<'a>(
        &mut self,
        project_state: &crate::ProjectState,
        contexts: &'a ContextSlice,
    ) -> Result<()> {
        let cov_bps = project_state
            .coverage_basic_blocks
            .as_ref()
            .ok_or(anyhow::anyhow!(
                "Coverage breakpoints required for source coverage"
            ))?;
        'outer: for (bb_start, bb_len) in cov_bps.iter() {
            let mut start_addr = bb_start.0;

            // check vanilla start_addr and also module modified start address
            for _ in 0..2 {
                for context in contexts {
                    let mut found_some = false;

                    let bb_len = *bb_len as u64;
                    let end_addr = start_addr + bb_len;
                    for (_low, _high, loc) in context.find_location_range(start_addr, end_addr)? {
                        if let (Some(file), Some(line)) = (loc.file, loc.line) {
                            found_some = true;

                            let (file_index, _is_new) = self.files.insert_full(file.to_string());
                            let file_index: u32 = file_index.try_into().unwrap();
                            let (loc_index, _is_new) =
                                self.locations.insert_full((file_index, line));
                            let v = self.vaddrs.entry(*bb_start).or_default();
                            let loc_index: u32 = loc_index.try_into().unwrap();
                            if !v.contains(&loc_index) {
                                v.push(loc_index);
                            }
                        }
                    }
                    if found_some {
                        continue 'outer;
                    }
                }

                // TODO(mrodler): do we really need to check both contexts? wouldn't it suffice to
                // check only the one with the module start subtracted?
                if let Some(module_start) = project_state
                    .modules
                    .get_module_start_containing(start_addr)
                {
                    start_addr = start_addr - module_start;
                } else {
                    break;
                }
            }
        }

        Ok(())
    }

    /// Create an empty [`LcovInfo`] struct.
    pub fn empty_lcov_info<'a>(&'a self) -> LcovInfo<'a> {
        // Double hashmap:
        // filename -> line_num -> hitcount
        let mut data: AHashMap<&'a str, FxIndexMap<u32, u32>> = AHashMap::default();

        for (file_index, line) in self.locations.iter().copied() {
            let file = self.files[file_index as usize].as_str();
            data.entry(file).or_default().insert(line, 0_u32);
        }

        // sort the lcov info file according to line number
        for line_map in data.values_mut() {
            line_map.sort_unstable_keys();
        }

        LcovInfo { data }
    }

    /// Create an [`LcovInfo`] struct populated with the given recorded feedback
    pub fn lcov_info_from_feedback<'a>(&'a self, feedback: &FeedbackTracker) -> LcovInfo<'a> {
        let mut lcov = self.empty_lcov_info();
        if !self.is_empty() {
            self.update_lcov_with_feedback(&mut lcov, feedback);
        }
        lcov
    }

    /// Update a lcov given a single address/hitcount pair.
    pub fn update_single_lcov<'a, T: Into<VirtAddr>, U: Into<u32>>(
        &'a self,
        lcov: &mut LcovInfo<'a>,
        addr: T,
        hitcount: U,
    ) {
        let addr: VirtAddr = addr.into();
        let hitcount: u32 = hitcount.into();
        if let Some(locs) = self.vaddrs.get(&addr) {
            for loc_index in locs.iter().copied() {
                let (file_index, line) = self.locations[loc_index as usize];
                let file: &'a str = self.files[file_index as usize].as_str();

                lcov.data
                    .entry(file)
                    .or_default()
                    .entry(line)
                    .and_modify(|hits| *hits += hitcount)
                    .or_insert(hitcount);
            }
        }
    }

    /// Update [`LcovInfo`] struct with the given iterator over `(address, hitcount)`.
    pub fn update_lcov_addresses<
        'a,
        T: Into<VirtAddr>,
        U: Into<u32>,
        I: IntoIterator<Item = (T, U)>,
    >(
        &'a self,
        lcov: &mut LcovInfo<'a>,
        addresses: I,
    ) {
        for cov_entry in addresses {
            let addr: VirtAddr = cov_entry.0.into();
            let hitcount: u32 = cov_entry.1.into();
            self.update_single_lcov(lcov, addr, hitcount);
        }
    }

    /// Update [`LcovInfo`] struct with the recorded feedback.
    pub fn update_lcov_with_feedback<'a>(
        &'a self,
        lcov: &mut LcovInfo<'a>,
        feedback: &FeedbackTracker,
    ) {
        self.update_lcov_addresses(lcov, feedback.code_cov.iter().map(|(&x, &y)| (x, y)))
    }

    /// Write a lcov info file based on [`DebugInfo`] and a [`FeedbackTracker`].
    pub fn write_coverage_to_lcov_info<P: std::convert::AsRef<std::path::Path>>(
        &self,
        feedback: &FeedbackTracker,
        filepath: P,
    ) -> Result<()> {
        let mut lcov = self.empty_lcov_info();
        self.update_lcov_with_feedback(&mut lcov, feedback);
        lcov.write_to_file(filepath)?;
        Ok(())
    }

    /// Obtain the first debug location associated with the given address.
    pub fn get_first_location<'a, V: Into<VirtAddr>>(&'a self, addr: V) -> Option<(&'a str, u32)> {
        let addr: VirtAddr = addr.into();
        if let Some(locs) = self.vaddrs.get(&addr) {
            if let Some(loc_index) = locs.first().copied() {
                let (file_index, line) = self.locations[loc_index as usize];
                let file = self.files[file_index as usize].as_str();
                return Some((file, line));
            }
        }
        // oh no - nothing found
        None
    }
}

impl<'a> LcovInfo<'a> {
    /// Write source coverage data to a file in the lcov info format.
    pub fn write_to_file<P: std::convert::AsRef<std::path::Path>>(
        &self,
        filepath: P,
    ) -> anyhow::Result<()> {
        let mut outfile = std::io::BufWriter::new(std::fs::File::create(filepath)?);

        writeln!(outfile, "TN:")?;

        for (file, lines) in self.data.iter() {
            writeln!(outfile, "SF:{file}")?;
            for (line, hit_val) in lines {
                writeln!(outfile, "DA:{line},{hit_val}")?;
            }
            writeln!(outfile, "end_of_record")?;
        }
        // BufWriter needs manual flush
        outfile.flush()?;

        Ok(())
    }
}

// allow debug info to be dumped as json with serde_json
use serde::ser::{SerializeMap, Serializer};

impl Serialize for DebugInfo {
    /// Serialize [`DebugInfo`] as a map `VirtAddr -> ["file:linenum", ...]`
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut str_vec = vec![];
        let mut map = serializer.serialize_map(Some(self.vaddrs.len()))?;
        for (k, v) in self.vaddrs.iter() {
            // map.serialize_key(&k)?;
            // let mut seq = serializer.serialize_seq(Some(v.len()))?;
            str_vec.clear();
            for loc_index in v.iter().copied() {
                let (file_index, line) = self.locations[loc_index as usize];
                let file = self.files[file_index as usize].as_str();
                let e = format!("{}:{}", file, line);
                // seq.serialize_element(&e)?;
                str_vec.push(e);
            }
            // seq.end();
            let k_str = format!("{:#x}", k.0);
            map.serialize_entry(&k_str, &str_vec)?;
        }
        map.end()
    }
}
