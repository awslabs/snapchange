//! Command line arguments

use anyhow::{anyhow, ensure, Context, Result};
use clap::builder::ArgAction;
use clap::Parser;
use log::debug;
use smallvec::SmallVec;
use thiserror::Error;

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::addrs::{Cr3, VirtAddr};
use crate::cmp_analysis::{Conditional, Operand, RedqueenArguments, Size};
use crate::config::Config;
use crate::feedback::FeedbackTracker;

use crate::fuzzvm::ResetBreakpoints;
use crate::stack_unwinder::StackUnwinders;
use crate::symbols::{Symbol, LINUX_KERNEL_SYMBOLS, LINUX_USERLAND_SYMBOLS};
use crate::vbcpu::{VbCpu, VmSelector, X86FxState, X86XSaveArea, X86XSaveHeader, X86XsaveYmmHi};
use crate::SymbolList;

/// Custom errors [`FuzzVm`](crate::fuzzvm::FuzzVm) can throw
#[derive(Error, Debug)]
pub enum Error {
    /// Odd number of hex digits found in [`WriteMem`]
    #[error("Odd number of hex digits found in [`WriteMem`]")]
    WriteMemOddNumberOfHexDigits,

    /// Failed to parse the bytes for [`WriteMem`]
    #[error("Failed to parse the bytes for [`WriteMem`]: {0:#x?}")]
    WriteMemParseFail(String),

    /// Failed to parse the QEMU `info registers` output due to invalid form
    #[error("Failed to parse the QEMU `info registers` output due to invalid form")]
    InvalidQemuRegisterInput,

    /// Register state (.regs file) missing from project dir
    #[error("Register state (.regs file) missing from project dir")]
    RegisterStateMissing,

    /// Physical memory missing (.physmem file) missing from project dir
    #[error("Physical memory missing (.physmem file) missing from project dir")]
    PhysicalMemoryMissing,

    /// Invalid modules file format
    #[error("Modules (.modules file) contained an invalid line")]
    InvalidModulesFormat,

    /// Parsing symbols file failed
    #[error("Symbols (.symbols file) failed to parse with serde_json")]
    SymbolsFailedToParse(u64),

    /// Unknown timeout format given
    #[error("Unknown timeout format given. Valid types:  [0-9]+(ns|us|ms|s|m|h)")]
    InvalidTimeoutFormat(String),

    /// Module coverage breakpoint not found in module address range
    #[error(
        "Module ({1}) coverage breakpoint ({0:#x}) not found in module address range ({2:x?})"
    )]
    CoverageBreakpointNotFoundInModuleRange(u64, String, Range<u64>),

    /// Cmp Operand unable to be parsed
    #[error("Found a redqueen operand that couldn't be parsed: {0}")]
    UnimplementedCmpOperand(String),
}

/// Stores Basic Block Addresses and Sizes
pub type BasicBlockMap = crate::FxIndexMap<VirtAddr, usize>;

/// The files associated with the snapshot state
#[derive(Debug)]
pub struct ProjectState {
    /// The path to this project
    pub(crate) path: PathBuf,

    /// Parsed [`VbCpu`] from the register state
    pub vbcpu: VbCpu,

    /// Path to the physical memory backing of the snapshot
    pub(crate) physical_memory: PathBuf,

    /// Path to the json file containing mapping of addresses to symbol
    pub(crate) symbols: Option<PathBuf>,

    /// Addresses to apply single shot breakpoints for the purposes of coverage.
    /// Addresses assume the CR3 of the beginning of the snapshot.
    pub(crate) coverage_basic_blocks: Option<BasicBlockMap>,

    /// Module metadata containing where each module is loaded in the snapshot. Primarily
    /// used for dumping lighthouse coverage maps
    pub(crate) modules: Modules,

    /// The found `.bin` files found in the project directory used for gathering source
    /// information
    pub(crate) binaries: Vec<PathBuf>,

    /// The found `vmlinux` file found in the project directory used for gathering source
    /// information
    pub(crate) vmlinux: Option<PathBuf>,

    /// The configuration settings for this project
    pub(crate) config: Config,

    #[cfg(feature = "redqueen")]
    /// The redqueen breakpoints used to capture comparison arguments during runtime
    pub(crate) redqueen_breakpoints: Option<HashMap<u64, Vec<RedqueenArguments>>>,

    /// A stack unwinder that can be used to unwind stack
    pub(crate) unwinders: StackUnwinders,
}

/// Current coverage found in the project
#[derive(Default)]
pub struct ProjectCoverage {
    /// Previously seen coverage by the fuzzer
    pub prev_coverage: FeedbackTracker,

    /// Coverage left to be seen by the fuzzer
    pub coverage_left: crate::FxIndexSet<VirtAddr>,
}

impl ProjectState {
    /// Return the coverage remaining from the original coverage and the previously found
    /// coverage along with the previously found coverage itself.
    ///
    /// # Errors
    ///
    /// Can error during parsing the coverage.all project file
    #[allow(clippy::missing_panics_doc)]
    pub fn feedback(&self) -> Result<ProjectCoverage> {
        let prev_coverage_file = self.path.join("coverage.all");
        let mut prev_coverage: FeedbackTracker = FeedbackTracker::default();
        if let Ok(data) = std::fs::read_to_string(prev_coverage_file) {
            prev_coverage = serde_json::from_str(&data)?;
        }

        if let Some(breakpoints) = self.coverage_basic_blocks.as_ref() {
            // The coverage left to hit
            let coverage_left = breakpoints
                .keys()
                .filter(|a| prev_coverage.code_cov.get(&a).cloned().unwrap_or(0u16) == 0)
                .copied()
                .collect();

            // Get the current coverage not yet seen across previous runs
            Ok(ProjectCoverage {
                prev_coverage,
                coverage_left,
            })
        } else {
            Ok(ProjectCoverage {
                prev_coverage,
                coverage_left: crate::FxIndexSet::default(),
            })
        }
    }

    /// Parse sancov coverage breakpoints if they are available in this target. Use
    /// -fsanitize-coverage=-trace-pc-guard,pc-table to enable this.
    pub fn parse_sancov_breakpoints(&mut self) -> Result<Option<BasicBlockMap>> {
        if let Some(symbol_path) = &self.symbols {
            let mut new_covbps = BasicBlockMap::default();

            // Look for the symbols for the start of the breakpoint table from sancov
            for start_sancov_pcs in std::fs::read_to_string(symbol_path)?
                .split('\n')
                .filter(|x| x.contains("__start___sancov_pcs"))
            {
                // Sancov entry format
                #[repr(C)]
                struct SanCovBp {
                    // Address of the breakpoint
                    addr: u64,

                    // Type of breakpoint
                    typ: u64,
                }

                #[repr(u64)]
                #[derive(Debug)]
                #[allow(dead_code)]
                enum SanCovBpType {
                    // This basic block is not the start of a function
                    NonEntryBlock,

                    // This basic block is the start of a function
                    FunctionEntryBlock,
                }

                // Get the address for __start___sancov_pcs symbol for the start of the
                // known basic block addresses
                let address = start_sancov_pcs.split(" ").next().unwrap();
                let mut start_bps = u64::from_str_radix(&address.replace("0x", ""), 16)?;

                // Get a copy of the current memory to read the breakpoints
                let mut memory = self.memory()?;

                loop {
                    // Read the next sancov breakpoint
                    let new_bp =
                        memory.read::<SanCovBp>(VirtAddr(start_bps), Cr3(self.vbcpu.cr3))?;
                    let SanCovBp { addr, typ } = new_bp;

                    if addr == 0 || typ > 1 {
                        break;
                    }

                    // Add the new breakpoint
                    new_covbps.insert(addr.into(), 0);

                    // Increment the to the next breakpoint
                    start_bps += std::mem::size_of::<SanCovBp>() as u64;
                }

                log::info!("New breakpoints added from SanCov: {}", new_covbps.len());
            }

            Ok(Some(new_covbps))
        } else {
            Ok(None)
        }
    }
}

/// Module metadata containing where each module is loaded in the snapshot.
///
/// Any individual module data is found at the same index. Module 0 is found in
/// `starts[0], ends[0], names[0]`. Module 1 is found in `starts[1], ends[1], names[1]`,
/// ect
#[derive(Debug, Clone, Default)]
pub struct Modules {
    /// Starting address of the module
    starts: Vec<u64>,

    /// Ending address of the module
    ends: Vec<u64>,

    /// Name of the module
    pub names: Vec<String>,

    /// Number of modules in this metadata
    count: usize,
}

impl Modules {
    /// Checks if the given address is in the module list.
    /// Returns the (`module_name`, `offset_in_module`) if found.
    pub(crate) fn contains(&self, addr: u64) -> Option<(&str, u64)> {
        for index in 0..self.count {
            // Get the start and end address for the current module
            let start = self.starts[index];
            let end = self.ends[index];

            if start <= addr && addr <= end {
                let offset = addr - start;

                // Returned found module
                return Some((&self.names[index], offset));
            }
        }

        // Not found in the module list
        None
    }

    /// Returns the address range of the given module name
    pub(crate) fn get_module_range(&self, name: &str) -> Option<Range<u64>> {
        for id in 0..self.count {
            if self.names[id] == name {
                return Some(self.starts[id]..self.ends[id]);
            }
        }

        None
    }

    /// Returns the loaded address of the module containing `addr`, `None` otherwise
    pub(crate) fn get_module_start_containing(&self, addr: u64) -> Option<u64> {
        for index in 0..self.count {
            // Get the start and end address for the current module
            let start = self.starts[index];
            let end = self.ends[index];

            if start <= addr && addr <= end {
                // Returned found module starting address
                return Some(start);
            }
        }

        // Not found in the module list
        None
    }
}

/// Basic command line args for build.rs
#[derive(Parser, Debug)]
pub struct TemplateCommandLineArgs {
    /// Path to the directory containing the target snapshot state. See documentation for
    /// the necessary files
    #[clap(short, long, default_value = "./snapshot")]
    pub project: PathBuf,
}

/// Replay a given snapshot in KVM
#[derive(Parser, Debug)]
pub struct CommandLineArgs {
    /// Path to the directory containing the target snapshot state. See documentation for
    /// the necessary files
    #[clap(short, long, default_value = "./snapshot")]
    pub(crate) project: PathBuf,

    /// Verbosity to print information messages
    #[clap(flatten)]
    pub(crate) verbosity: clap_verbosity_flag::Verbosity,

    /// Command to execute
    #[clap(subcommand)]
    pub(crate) command: SubCommand,
}

/// Subcommands available for the command line
#[derive(Parser, Debug)]
pub enum SubCommand {
    /// Fuzz a project
    Fuzz(Fuzz),

    /// Gather data about the project
    Project(Project),

    /// Collect a single step trace for an input
    Trace(Trace),

    /// Minimize an input by size or trace length
    Minimize(Minimize),

    /// Gather coverage for an input
    Coverage(Coverage),

    /// Find an input that hits the given address or symbol
    FindInput(FindInput),

    /// Minimize the given corpus by moving files that don't add any new coverage to a trash directory
    CorpusMin(CorpusMin),

    /// Gather Redqueen coverage for an input
    #[cfg(feature = "redqueen")]
    Redqueen(RedqueenAnalysis),
}

/// Fuzz a project
#[derive(Parser, Debug, Clone)]
pub struct Fuzz {
    /// Number of cores to fuzz with. Negative numbers interpretted as MAX_CORES - CORES. Prefix
    /// with `/N` to specify a fraction of available cores.
    #[clap(short, long, allow_hyphen_values = true, value_parser = parse_cores)]
    pub(crate) cores: Option<NonZeroUsize>,

    /// Set the timeout (in seconds) of the execution of the VM. [0-9]+(ns|us|ms|s|m|h)
    #[clap(long, value_parser = parse_timeout, default_value = "1s")]
    pub(crate) timeout: Duration,

    /// Set a maximum duration that each core spends on fuzzing.
    #[clap(long, value_parser = parse_timeout)]
    pub(crate) stop_after_time: Option<Duration>,

    /// Stop after the first crash is found
    #[clap(long)]
    pub(crate) stop_after_first_crash: bool,

    /// Directory to populate the initial input corpus. Defaults to `<project_dir>/input`
    #[clap(short, long)]
    pub(crate) input_dir: Option<PathBuf>,

    /// Use the ASCII stats display instead of the TUI stats display
    #[clap(long)]
    pub(crate) ascii_stats: bool,
}

/// Project subcommand
#[derive(Parser, Debug)]
pub struct Project {
    /// Execute the project subcommand
    #[clap(subcommand)]
    pub(crate) command: ProjectSubCommand,
}

/// Trace subcommand
#[derive(Parser, Debug)]
pub struct Trace {
    /// Enable single step, single execution trace of the guest using the given file as
    /// the input
    pub(crate) input: Option<PathBuf>,

    /// Set the timeout (in seconds) of the execution of the VM. [0-9]+(ns|us|ms|s|m|h)
    #[clap(long, value_parser = parse_timeout, default_value = "60s")]
    pub(crate) timeout: Duration,

    /// Don't single step with the trace. Useful for quickly executing one single input
    #[clap(short, long)]
    pub(crate) no_single_step: bool,

    #[clap(short, long)]
    pub(crate) ignore_cov_bps: bool,
}

/// To which extent code coverage is considered when minimizing a testcase.
#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Copy, Clone, clap::ValueEnum)]
pub(crate) enum MinimizeCodeCovLevel {
    None = 0,
    Symbols = 1,
    BasicBlock = 2,
    Hitcounts = 3,
}

/// Minimize subcommand
#[derive(Parser, Debug)]
pub struct Minimize {
    /// Minimize the given file or alternatively, if a directory is passed, everything inside of the
    /// directory.
    pub(crate) path: PathBuf,

    /// Whether to replace the original file with the minimized file.
    #[clap(short = 'I', long)]
    pub(crate) in_place: bool,

    /// Set the timeout (in seconds) of the execution of the VM. [0-9]+(ns|us|ms|s|m|h)
    #[clap(long, value_parser = parse_timeout, default_value = "60s")]
    pub(crate) timeout: Duration,

    /// Set the number of iterations per minimization stage before moving onto the next
    /// stage
    #[clap(short, long, default_value_t = 50000)]
    pub(crate) iterations_per_stage: u32,

    /// Specify, which type of code coverage feedback should be considered, when minimizing
    /// the given input. `none` ignores all code coverage. `basic-blocks` is the regular fuzzing
    /// coverage. `symbols` is function-level coverage when symbols are available. `hitcounts`
    /// is basic-block coverage considering hitcounts.
    #[clap(long, value_enum)]
    pub(crate) consider_coverage: Option<MinimizeCodeCovLevel>,

    /// Only check the RIP register for checking if the register state is the same after
    /// minimizing an input
    #[clap(
        short, long,
        default_value("false"),
        default_missing_value("true"),
        num_args(0..=1),
        require_equals(true),
        action = ArgAction::Set,
    )]
    pub(crate) rip_only: bool,

    /// Ignore the feedback returned through coverage breakpoints and custom feedback,
    /// when checking for same state after minimizing an input.
    #[clap(
        long,
        default_value("false"),
        default_missing_value("true"),
        num_args(0..=1),
        require_equals(true),
        action = ArgAction::Set,
    )]
    pub(crate) ignore_feedback: bool,

    /// Ignore stack contents when checking for same state after minimizing an input.
    #[clap(
        long,
        default_value("true"),
        default_missing_value("true"),
        num_args(0..=1),
        require_equals(true),
        action = ArgAction::Set,
    )]
    pub(crate) ignore_stack: bool,

    /// Ignore the consoel output when checking for same state after minimizing an input.
    #[clap(
        long,
        default_value("true"),
        default_missing_value("true"),
        num_args(0..=1),
        require_equals(true),
        action = ArgAction::Set,
    )]
    pub(crate) ignore_console_output: bool,

    /// Dump the observed feedback into a file. Useful when debugging minimization according to
    /// observed feedback.
    #[clap(long)]
    pub(crate) dump_feedback_to_file: bool,
}

/// CorpusMin subcommand
#[derive(Parser, Debug)]
pub struct CorpusMin {
    /// Number of cores to fuzz with. Negative numbers interpretted as MAX_CORES - CORES. Prefix
    /// with `/N` to specify a fraction of available cores.
    #[clap(short, long, allow_hyphen_values = true, value_parser = parse_cores)]
    pub(crate) cores: Option<NonZeroUsize>,

    /// The path to the corpus containing input files to minimize
    #[clap(short, long, default_value = "./snapshot/current_corpus")]
    pub(crate) input_dir: PathBuf,

    /// The path to move the discarded inputs
    #[clap(short, long, default_value = "./snapshot/current_corpus.trash")]
    pub(crate) trash_dir: PathBuf,

    /// The number of input files, per core, to gather coverage for during a single iteration.
    ///
    /// For extremely large input corpi, storing the coverage for the entire corpus
    /// can be costly. This number can reduce the memory footprint by performing
    /// the corpus minimization algorithm over many subsets of the input.
    #[clap(long, default_value_t = 10000)]
    pub(crate) chunk_size: usize,

    /// Set the timeout (in seconds) of the execution of the VM. [0-9]+(ns|us|ms|s|m|h)
    #[clap(long, value_parser = parse_timeout, default_value = "60s")]
    pub(crate) timeout: Duration,
}

/// Coverage subcommand
#[derive(Parser, Debug)]
pub struct Coverage {
    /// The path to the input to gather coverage for
    pub(crate) path: PathBuf,

    /// The path where to store the inputs files
    #[clap(long)]
    pub(crate) coverage_path: Option<PathBuf>,

    /// Set the timeout (in seconds) of the execution of the VM. [0-9]+(ns|us|ms|s|m|h)
    #[clap(long, value_parser = parse_timeout, default_value = "1s")]
    pub(crate) timeout: Duration,

    /// Display the ending [`FuzzVm`](crate::fuzzvm::FuzzVm) context after gathering
    /// coverage
    #[clap(long)]
    pub(crate) context: bool,
}

/// `RedqueenAnalysis` subcommand
#[cfg(feature = "redqueen")]
#[derive(Parser, Debug)]
pub struct RedqueenAnalysis {
    /// The path to the input to gather coverage for
    pub(crate) path: PathBuf,
}

/// `FindInput` subcommand
#[derive(Parser, Debug)]
pub struct FindInput {
    /// The address or symbol to find an input for
    pub(crate) location: Option<String>,

    /// Set the timeout (in seconds) of the execution of the VM. [0-9]+(ns|us|ms|s|m|h)
    #[clap(long, value_parser = parse_timeout, default_value = "1s")]
    pub(crate) timeout: Duration,

    /// Number of cores to fuzz with. Negative numbers interpretted as MAX_CORES - CORES. Prefix
    /// with `/N` to specify a fraction of available cores. Use `/1` for all cores.
    /// Recommended: `/2` on systems with hyperthreading.
    #[clap(short, long, allow_hyphen_values = true, value_parser = parse_cores)]
    pub(crate) cores: Option<NonZeroUsize>,
}

/// Subcommands available for the command line specific to the project
#[derive(Parser, Debug)]
pub enum ProjectSubCommand {
    /// Translate an address using the project
    Translate(Translate),

    /// Hardcode breakpoints (0xcc) into the physical memory
    WriteBp(WriteBp),

    /// Permanently modify memory in the physical snapshot
    WriteMem(WriteMem),

    /// Dump the known symbols and their addresses
    Symbols,

    /// Initialize the configuration file for this project
    InitConfig,

    /// Write DebugInfo as json
    WriteDebugInfoJson,
}

/// Translate an address from the project
#[derive(Parser, Debug)]
pub struct Translate {
    /// Virtual Address to translate and dump information about
    pub(crate) virt_addr: Option<String>,

    /// Use a different cr3 than the original cr3 in the register state
    #[clap(long)]
    pub(crate) cr3: Option<VirtAddr>,

    /// Number of instructions to attempt to disassemble
    #[clap(short, long, default_value_t = 20)]
    pub(crate) instrs: u32,
}

/// Hard code a breakpoint to the physical memory in the project
#[derive(Parser, Debug)]
pub struct WriteBp {
    /// Virtual Address to translate and dump information about
    pub(crate) virt_addr: String,

    /// Use a different cr3 than the original cr3 in the register state
    #[clap(long)]
    pub(crate) cr3: Option<VirtAddr>,
}

/// Parse the given input string into bytes
///
/// Example:
///
/// ```
/// let res = parse_hex_bytes("41424344")?;
/// assert_eq!(res, vec![0x41, 0x42, 0x43, 0x44])
/// ```
///
/// # Errors
///
/// If the given `hex` string is an odd number of digits
pub fn parse_hex_bytes(hex: &str) -> Result<Vec<u8>, Error> {
    if hex.len() % 2 == 1 {
        return Err(Error::WriteMemOddNumberOfHexDigits);
    }

    let mut offset = 0;
    if hex.starts_with("0x") {
        offset = 2;
    }

    let mut res = Vec::new();
    for index in (offset..hex.len()).step_by(2) {
        res.push(
            u8::from_str_radix(&hex[index..index + 2], 16)
                .map_err(|_| Error::WriteMemParseFail(hex[index..index + 2].to_string()))?,
        );
    }

    Ok(res)
}

/// Write memory into the physical snapshot
#[derive(Parser, Debug)]
pub struct WriteMem {
    /// Virtual Address to translate and dump information about
    pub(crate) virt_addr: String,

    /// Bytes to write into the physial snapshot
    pub(crate) bytes: String,

    /// Use a different cr3 than the original cr3 in the register state
    #[clap(long)]
    pub(crate) cr3: Option<VirtAddr>,
}

/// Get the [`ProjectState`] from the given project directory
///
/// # Errors
///
/// * Parsing of the register state files, coverage breakpoints, or modules file
/// * Error getting context for addr2line
pub fn get_project_state(dir: &Path, cmd: Option<&SubCommand>) -> Result<ProjectState> {
    // Init the snapshot state variables
    let mut vbcpu = None;
    let mut physical_memory = None;
    let mut symbols = None;
    let mut modules = Modules::default();
    let mut binaries = Vec::new();
    let mut config = Config::default();
    let mut update_config = true;
    let mut covbps_paths = Vec::new();

    #[cfg(feature = "redqueen")]
    let mut cmps_paths = Vec::new();

    if !dir.exists() {
        panic!("Project dir {dir:?} not found.");
    }

    // Read the snapshot directory looking for the specific file extensions
    for file in dir.read_dir()? {
        let file = file?;

        if let Some(extension) = file.path().extension() {
            // If we find a config file, use this config instead of the default
            if matches!(file.file_name().to_str(), Some("config.toml")) {
                let data = &std::fs::read_to_string(file.path())?;
                config = toml::from_str(data)?;
                println!("Using project config: {config:#?}");

                // Check if we need to update the config if the configuration
                // format has changed
                let new_data = toml::to_string(&config)?;
                if &new_data == data {
                    update_config = false;
                }
                continue;
            }

            match extension.to_str() {
                Some("regs") => {
                    // Parse the snapshot register state
                    let reg_state = std::fs::read_to_string(file.path())?;
                    vbcpu = Some(serde_json::from_str(&reg_state)?);
                }
                Some("qemuregs") => {
                    // Parse the qemuregs file
                    let reg_state = std::fs::read_to_string(file.path())?;
                    vbcpu = Some(parse_qemu_regs(&reg_state)?);
                }
                Some("bin") => {
                    binaries.push(file.path());
                }
                Some("covbps") => {
                    // Ignore parsing coverage breakpoints for "project" commands, except for the one that
                    // dumps debug info as json
                    if let Some(SubCommand::Project(project_command)) = cmd {
                        if !matches!(
                            project_command.command,
                            ProjectSubCommand::WriteDebugInfoJson
                        ) {
                            continue;
                        }
                    }
                    covbps_paths.push(file.path());
                }
                #[cfg(feature = "redqueen")]
                Some("cmps") => {
                    cmps_paths.push(file.path());
                }
                Some("physmem") => physical_memory = Some(file.path()),
                Some("symbols") => {
                    ensure!(
                        symbols.is_none(),
                        "Already found a symbols file: {:?}",
                        symbols
                    );
                    symbols = Some(file.path());
                }
                Some("modules") => {
                    let module_data = std::fs::read_to_string(file.path())?;
                    for line in module_data.split('\n') {
                        // Ignore empty lines
                        if line.is_empty() {
                            continue;
                        }

                        // Split the module file
                        //
                        // Expected format: 0x1234 0x1234 NAME
                        let mut line = line.split(' ');

                        // Parse the first arg
                        let elem = line.next().ok_or(Error::InvalidModulesFormat)?;
                        let start_addr = u64::from_str_radix(&elem.replace("0x", ""), 16)?;

                        // Parse the second arg
                        let elem = line.next().ok_or(Error::InvalidModulesFormat)?;
                        let end_addr = u64::from_str_radix(&elem.replace("0x", ""), 16)?;

                        // Get the module name
                        let module_name =
                            line.next().ok_or(Error::InvalidModulesFormat)?.to_string();

                        // Add the module to the Modules database
                        modules.starts.push(start_addr);
                        modules.ends.push(end_addr);
                        modules.names.push(module_name);
                        modules.count += 1;
                    }
                }
                _ => {}
            }
        }
    }

    // Update the guest memory size to fit the current physical memory size
    let physical_memory = physical_memory.ok_or(Error::PhysicalMemoryMissing)?;
    config.guest_memory_size = std::fs::metadata(&physical_memory)?
        .len()
        .max(config.guest_memory_size);

    // Write the updated config if one wasn't found or if the configuration options
    // have changed
    if update_config {
        std::fs::write(dir.join("config.toml"), &toml::to_string(&config)?)?;
    }

    // Parse the available redqueen cmps files
    // Also gather the redqueen breakpoint addresses to remove them from the
    // coverage breakpoints
    #[cfg(feature = "redqueen")]
    let mut redqueen_breakpoints = None;

    #[cfg(feature = "redqueen")]
    let mut redqueen_bp_addrs: rustc_hash::FxHashSet<VirtAddr> = rustc_hash::FxHashSet::default();

    #[cfg(feature = "redqueen")]
    if !cmps_paths.is_empty() {
        let mut result = HashMap::new();

        for cmps_path in &cmps_paths {
            let rules = parse_cmps(cmps_path)?;
            for (addr, _) in &rules {
                redqueen_bp_addrs.insert(VirtAddr(*addr));
            }

            result.extend(rules);
        }

        redqueen_breakpoints = Some(result);
    }

    let mut coverage_breakpoints: Option<BasicBlockMap> = None;

    for covbps_path in &covbps_paths {
        let covbps = coverage_breakpoints.get_or_insert(BasicBlockMap::default());

        #[allow(unused_mut)]
        let mut bps = parse_coverage_breakpoints(covbps_path)?;

        // Ensure no coverage breakpoints are redqueen breakpoints as the
        // redqueen breakpoints are not one-shot and will be reapplied
        // even when they are hit
        #[cfg(feature = "redqueen")]
        bps.retain(|start, _len| !redqueen_bp_addrs.contains(start));

        let module = covbps_path
            .file_prefix()
            .ok_or_else(|| anyhow!("FilePrefix failed"))?
            .to_str()
            .ok_or_else(|| anyhow!("Failed to get file_prefix str"))?;

        if let Some(module_range) = modules.get_module_range(module) {
            // Get the smallest coverage breakpoint for this module
            let min_addr = bps
                .keys()
                .copied()
                .min()
                .ok_or_else(|| anyhow!("No smallest breakpoint found"))?;

            // If the smallest breakpoint isn't in the module range, then
            // the coverage breakpoints are probably invalid
            if !module_range.contains(&min_addr.0) {
                return Err(Error::CoverageBreakpointNotFoundInModuleRange(
                    *min_addr,
                    module.to_string(),
                    module_range,
                )
                .into());
            }
        }

        covbps.extend(bps);
    }

    // Check if the source lines for the coverage breakpoints has already been written
    // and write it if not

    // Check if the project contains a `vmlinux` file for kernel symbols
    let mut vmlinux = None;
    let vmlinux_path = dir.join("vmlinux");
    if vmlinux_path.exists() {
        // Also check for `vmlinux` file as well for looking into contexts
        binaries.push(dir.join("vmlinux"));
        vmlinux = Some(vmlinux_path);
    }

    let unwinders = {
        let start = std::time::Instant::now();

        let mut unwinders = StackUnwinders::default();

        for bin_file in &binaries {
            let Some(bin_name) = bin_file.file_name() else {
                continue;
            };
            let Some(bin_name) = bin_name.to_str() else {
                continue;
            };
            let bin_name = bin_name.replace(".bin", "");

            // Get the module range and rebase the stack unwinder if we have known module range
            let mut module_range = None;
            if let Some(range) = modules.get_module_range(&bin_name) {
                module_range = Some(range);
            };

            // Attempt to create an unwinder for this binary
            unwinders.create_unwinder(bin_file, module_range)?;
        }

        log::info!("Gathering unwinders took: {:?}", start.elapsed());

        unwinders
    };

    let vbcpu = vbcpu.ok_or(Error::RegisterStateMissing)?;

    let mut state = ProjectState {
        path: dir.to_owned(),
        vbcpu,
        physical_memory,
        symbols,
        coverage_basic_blocks: coverage_breakpoints,
        modules,
        binaries,
        vmlinux,
        config,
        unwinders,
        #[cfg(feature = "redqueen")]
        redqueen_breakpoints,
    };

    // Check for sancov basic blocks in the target
    if let Some(sancov_bps) = state.parse_sancov_breakpoints()? {
        // Write the coverage breakpoints found in sanitizer coverage
        let sancov_bps_file = Path::new("sancov.covbps");
        std::fs::write(
            state.path.join(sancov_bps_file),
            sancov_bps
                .keys()
                .map(|x| format!("{:#x}", x.0))
                .collect::<Vec<_>>()
                .join("\n"),
        )?;

        // Add the sancov breakpoints to the total coverage breakpoints
        if let Some(covbps) = state.coverage_basic_blocks.as_mut() {
            covbps.extend(sancov_bps);
        } else {
            state.coverage_basic_blocks = Some(sancov_bps);
        }
    }

    Ok(state)
}

/// Parse the symbols handed to the hypervisor into the form or a fuzzer to take. This
/// returns the symbols sorted in ascending order as well as the found crashing
/// breakpoint addresses found.
///
/// # Errors
///
/// * Failed to read symbols file
pub fn parse_symbols(
    symbols_arg: &Option<PathBuf>,
    cr3: Cr3,
) -> Result<(Option<SymbolList>, Option<ResetBreakpoints>)> {
    // Init the resulting values
    let mut symbols = None;
    let mut reset_breakpoints = Some(ResetBreakpoints::default());

    if let Some(ref syms) = symbols_arg {
        let mut curr_symbols = crate::SymbolList::new();

        // Parse the symbols file:
        // 0xdeadbeef example!main
        let data = std::fs::read_to_string(syms)?;
        for line in data.split('\n').filter(|line| !line.is_empty()) {
            // Split the (address, symbol)
            let line: Vec<&str> = line.split(' ').collect();

            // Remove the 0x for `from_str_radix`
            let address = line[0].replace("0x", "");
            let address = u64::from_str_radix(&address, 16)?;

            // Add the parsed symbol
            curr_symbols.push(Symbol {
                address,
                symbol: line[1].to_string(),
            });
        }

        let mut symbol_bps = ResetBreakpoints::default();

        // Sanity check the symbols are sorted
        for sym in &curr_symbols {
            // Check if this symbol matches a known reset symbol
            for (symbol, symbol_type) in LINUX_USERLAND_SYMBOLS {
                if sym.symbol.contains(symbol) {
                    log::info!(
                        "Linux user symbol: {} @ {:#x} {:#x} {:?}",
                        sym.symbol,
                        sym.address,
                        cr3.0,
                        symbol_type
                    );
                    symbol_bps.insert((VirtAddr(sym.address), cr3), *symbol_type);
                    break;
                }
            }

            // Calculate the kernel CR3 based on the instrutions from the single step of
            // the kernel
            //
            // 0x00007ffff7eac249 0x00000000ba693000 | libc-2.31.so!__getpid+0x9 | syscall
            // 0xffffffffa6200010 0x00000000ba693000 | entry_SYSCALL_64+0x0      | swapgs
            // 0xffffffffa6200013 0x00000000ba693000 | entry_SYSCALL_64+0x3      | mov qword ptr gs:[0x6014], rsp
            // 0xffffffffa620001c 0x00000000ba693000 | entry_SYSCALL_64+0xc      | nop
            // 0xffffffffa620001e 0x00000000ba693000 | entry_SYSCALL_64+0xe      | mov rsp, cr3
            // 0xffffffffa6200021 0x00000000ba693000 | entry_SYSCALL_64+0x11     | bts rsp, 0x3f
            // 0xffffffffa6200026 0x00000000ba693000 | entry_SYSCALL_64+0x16     | and rsp, 0xffffffffffffe7ff
            // 0xffffffffa620002d 0x00000000ba693000 | entry_SYSCALL_64+0x1d     | mov cr3, rsp
            let kern_cr3 = cr3.0 & 0xffff_ffff_ffff_e7ff;

            // Check if this symbol matches a known crashing symbol
            for (symbol, symbol_type) in LINUX_KERNEL_SYMBOLS {
                if sym.symbol == *symbol {
                    debug!(
                        "Linux kernel symbol: {} @ {:#x} {:#x} {:?}",
                        sym.symbol, sym.address, cr3.0, symbol_type
                    );

                    symbol_bps.insert((VirtAddr(sym.address), Cr3(kern_cr3)), *symbol_type);
                    symbol_bps.insert(
                        (VirtAddr(sym.address), crate::fuzzvm::WILDCARD_CR3),
                        *symbol_type,
                    );

                    break;
                }
            }
        }

        // we sort the symbols here, such that we can binary search the symbols afterwards
        curr_symbols.sort_unstable_by_key(|sym| sym.address);
        // Set the valid return fields
        symbols = Some(curr_symbols);
        reset_breakpoints = Some(symbol_bps);
    } else {
        log::warn!("No symbols file found..");
    }

    Ok((symbols, reset_breakpoints))
}

fn parse_hex_str(addr_str: &str) -> std::result::Result<u64, std::num::ParseIntError> {
    let hex_parse = if addr_str.starts_with("0x") {
        &addr_str[2..]
    } else {
        addr_str
    };
    u64::from_str_radix(hex_parse, 16)
}

/// Parse the coverage breakpoints command line argument. This will read the given path
/// and create a [`BTreeSet`] of the found coverage breakpoints
///
/// # Errors
///
/// * Failed to read coverage breakpoints file
pub fn parse_coverage_breakpoints(cov_bp_path: &Path) -> Result<BasicBlockMap> {
    // Read the breakpoints
    let data =
        std::fs::read_to_string(cov_bp_path).context("Failed to read coverage breakpoints file")?;

    // Init the result
    let mut cov_bps = BasicBlockMap::default();

    // Parse the addresses for the VM
    data.split('\n').for_each(|line| {
        // Parses lines of the kind as u64:
        // 0xdeadbeef
        // deadbeef
        // 12341234

        let line = line.trim();

        // Empty strings are always invalid
        if line.is_empty() {
            return;
        }
        // ignore "comments"
        if line.starts_with("# ") || line.starts_with("// ") {
            return;
        }

        let parts: SmallVec<[&str; 2]> = line.split(',').collect();
        if parts.is_empty() {
            return;
        }
        if parts.len() > 2 {
            eprintln!(
                "[COVBPS] failed to parse address from line: {:?} (reason: too many ',' chars)",
                line
            );
            return;
        }

        let addr_str = parts[0];
        match parse_hex_str(addr_str) {
            Ok(addr) => {
                let len = if parts.len() == 2 {
                    match parse_hex_str(parts[1]) {
                        Ok(addr) => addr,
                        Err(e) => {
                            eprintln!(
                                "[COVBPS] failed to parse address from line: {:?} (reason: {})",
                                line, e
                            );
                            return;
                        }
                    }
                } else {
                    0
                } as usize;
                cov_bps.insert(VirtAddr(addr), len);
            }
            Err(e) => {
                eprintln!(
                    "[COVBPS] failed to parse address from line: {:?} (reason: {})",
                    line, e
                );
            }
        }
    });

    // Return breakpoints
    Ok(cov_bps)
}

/// Parse the `info registers` output from the QEMU monitor
///
/// Example:
///
/// ```
/// RAX=0000555555555125 RBX=0000000000000000 RCX=00007ffff7fbf718 RDX=00007fffffffeca8
/// RSI=00007fffffffec98 RDI=0000000000000001 RBP=00007fffffffeba0 RSP=00007fffffffeba0
/// R8 =0000000000000000 R9 =00007ffff7fe21b0 R10=0000000000000000 R11=00000000000000c2
/// R12=0000555555555040 R13=0000000000000000 R14=0000000000000000 R15=0000000000000000
/// RIP=0000555555555129 RFL=00000246 [---Z-P-] CPL=3 II=0 A20=1 SMM=0 HLT=0
/// ES =0000 0000000000000000 000fffff 00000000
/// CS =0033 0000000000000000 ffffffff 00a0fb00 DPL=3 CS64 [-RA]
/// SS =002b 0000000000000000 ffffffff 00c0f300 DPL=3 DS   [-WA]
/// DS =0000 0000000000000000 000fffff 00000000
/// FS =0000 00007ffff7fc7540 ffffffff 00c00000
/// GS =0000 0000000000000000 000fffff 00000000
/// LDT=0000 0000000000000000 000fffff 00000000
/// TR =0040 fffffe000004a000 00004087 00008b00 DPL=0 TSS64-busy
/// GDT=     fffffe0000048000 0000007f
/// IDT=     fffffe0000000000 00000fff
/// CR0=80050033 CR2=000055be87f4bff0 CR3=0000000024557000 CR4=000006e0
/// DR0=0000000000000000 DR1=0000000000000000 DR2=0000000000000000 DR3=0000000000000000
/// DR6=00000000ffff0ff0 DR7=0000000000000400
/// EFER=0000000000000d01
/// FCW=037f FSW=0000 [ST=0] FTW=00 MXCSR=00001f80
/// FPR0=0000000000000000 0000 FPR1=0000000000000000 0000
/// FPR2=0000000000000000 0000 FPR3=0000000000000000 0000
/// FPR4=0000000000000000 0000 FPR5=0000000000000000 0000
/// FPR6=0000000000000000 0000 FPR7=0000000000000000 0000
/// XMM00=00000000000000000000ff00000000ff XMM01=2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f
/// XMM02=00000000000000000000000000000000 XMM03=0000000000ff00000000000000000000
/// XMM04=00030005000500050005000000455441 XMM05=00000000000000000000000000000000
/// XMM06=00000000000000000000000000000000 XMM07=00000000000000000000000000000000
/// XMM08=00000000000000000000000000000000 XMM09=00000000000000000000000000000000
/// XMM10=00000000000000000000000000000000 XMM11=00000000000000000000000000000000
/// XMM12=00000000000000000000000000000000 XMM13=00000000000000000000000000000000
/// XMM14=00000000000000000000000000000000 XMM15=00000000000000000000000000000000
/// ```
#[allow(clippy::similar_names)]
pub(crate) fn parse_qemu_regs(data: &str) -> Result<VbCpu> {
    // Parse the input line-by-line
    // Skip all starting lines until we come across the first line containing RAX
    let mut lines = data
        .split('\n')
        .skip_while(|line| !line.contains("RAX=") && !line.contains("RBX="));

    /// Get the next line of input or return error
    macro_rules! next_line {
        () => {
            lines.next().ok_or(Error::InvalidQemuRegisterInput)?
        };
    }

    let mut curr_line = next_line!().split(' ');

    /// Get the next element in the current line
    macro_rules! next_elem {
        () => {
            curr_line.next().ok_or(Error::InvalidQemuRegisterInput)?
        };
    }

    /// Parse the VM selector line
    macro_rules! next_selector {
        () => {{
            let tmp = next_line!().replace(" =", "_=");
            curr_line = tmp.split(' ');

            // CS =0033 0000000000000000 ffffffff 00a0fb00 DPL=3 CS64 [-RA]
            let sel = u16::from_str_radix(&next_elem!()[4..], 16)?;
            let base = u64::from_str_radix(&next_elem!(), 16)?;
            let limit = u32::from_str_radix(&next_elem!(), 16)?;
            let rights = u32::from_str_radix(&next_elem!(), 16)? >> 8;
            VmSelector {
                base,
                limit,
                access_rights: rights,
                selector: sel,
                reserved0: 0,
                reserved1: 0,
            }
        }};
    }

    // At this point, we assume the start of the info registers has been found

    // Example
    // RAX=0000555555555125 RBX=0000000000000000 RCX=00007ffff7fbf718 RDX=00007fffffffeca8
    let rax = u64::from_str_radix(&next_elem!()[4..], 16)?;
    let rbx = u64::from_str_radix(&next_elem!()[4..], 16)?;
    let rcx = u64::from_str_radix(&next_elem!()[4..], 16)?;
    let rdx = u64::from_str_radix(&next_elem!()[4..], 16)?;

    // RSI=00007fffffffec98 RDI=0000000000000001 RBP=00007fffffffeba0 RSP=00007fffffffeba0
    curr_line = next_line!().split(' ');
    let rsi = u64::from_str_radix(&next_elem!()[4..], 16)?;
    let rdi = u64::from_str_radix(&next_elem!()[4..], 16)?;
    let rbp = u64::from_str_radix(&next_elem!()[4..], 16)?;
    let rsp = u64::from_str_radix(&next_elem!()[4..], 16)?;

    // R8 =0000000000000000 R9 =00007ffff7fe21b0 R10=0000000000000000 R11=00000000000000c2
    let tmp = next_line!().replace(" =", "_=");
    curr_line = tmp.split(' ');
    let r8 = u64::from_str_radix(&next_elem!()[4..], 16)?;
    let r9 = u64::from_str_radix(&next_elem!()[4..], 16)?;
    let r10 = u64::from_str_radix(&next_elem!()[4..], 16)?;
    let r11 = u64::from_str_radix(&next_elem!()[4..], 16)?;

    // R12=0000555555555040 R13=0000000000000000 R14=0000000000000000 R15=0000000000000000
    curr_line = next_line!().split(' ');
    let r12 = u64::from_str_radix(&next_elem!()[4..], 16)?;
    let r13 = u64::from_str_radix(&next_elem!()[4..], 16)?;
    let r14 = u64::from_str_radix(&next_elem!()[4..], 16)?;
    let r15 = u64::from_str_radix(&next_elem!()[4..], 16)?;

    // RIP=0000555555555129 RFL=00000246 [---Z-P-] CPL=3 II=0 A20=1 SMM=0 HLT=0
    curr_line = next_line!().split(' ');
    let rip = u64::from_str_radix(&next_elem!()[4..], 16)?;
    let rflags = u64::from_str_radix(&next_elem!()[4..], 16)?;

    // ES =0000 0000000000000000 000fffff 00000000
    let es = next_selector!();

    // CS =0033 0000000000000000 ffffffff 00a0fb00 DPL=3 CS64 [-RA]
    let cs = next_selector!();

    // SS =002b 0000000000000000 ffffffff 00c0f300 DPL=3 DS   [-WA]
    let ss = next_selector!();

    // DS =0000 0000000000000000 000fffff 00000000
    let ds = next_selector!();

    // FS =0000 00007ffff7fc7540 ffffffff 00c00000
    let fs = next_selector!();

    // GS =0000 0000000000000000 000fffff 00000000
    let gs = next_selector!();

    // LDT=0000 0000000000000000 000fffff 00000000
    let ldtr = next_selector!();

    // TR =0040 fffffe000004a000 00004087 00008b00 DPL=0 TSS64-busy
    let mut tr = next_selector!();

    // Ensure TR.access rights has the 64-bit busy TSS enabled
    tr.access_rights |= 0xb;

    // GDT=     fffffe0000048000 0000007f
    let tmp = next_line!().replace("     ", " ");
    curr_line = tmp.split(' ');
    let _name = next_elem!();
    let gdtr_base = u64::from_str_radix(next_elem!(), 16)?;
    let gdtr_limit = u32::from_str_radix(next_elem!(), 16)?;

    // IDT=     fffffe0000000000 00000fff
    let tmp = next_line!().replace("     ", " ");
    curr_line = tmp.split(' ');
    let _name = next_elem!();
    let idtr_base = u64::from_str_radix(next_elem!(), 16)?;
    let idtr_limit = u32::from_str_radix(next_elem!(), 16)?;

    // CR0=80050033 CR2=000055be87f4bff0 CR3=0000000024557000 CR4=000006e0
    curr_line = next_line!().split(' ');
    let cr0 = u64::from_str_radix(&next_elem!()[4..], 16)?;
    let cr2 = u64::from_str_radix(&next_elem!()[4..], 16)?;
    let cr3 = u64::from_str_radix(&next_elem!()[4..], 16)?;
    let cr4 = u64::from_str_radix(&next_elem!()[4..], 16)?;

    // DR0=0000000000000000 DR1=0000000000000000 DR2=0000000000000000 DR3=0000000000000000
    curr_line = next_line!().split(' ');
    let dr0 = u64::from_str_radix(&next_elem!()[4..], 16)?;
    let dr1 = u64::from_str_radix(&next_elem!()[4..], 16)?;
    let dr2 = u64::from_str_radix(&next_elem!()[4..], 16)?;
    let dr3 = u64::from_str_radix(&next_elem!()[4..], 16)?;

    // DR6=00000000ffff0ff0 DR7=0000000000000400
    curr_line = next_line!().split(' ');
    let dr6 = u64::from_str_radix(&next_elem!()[4..], 16)?;
    let dr7 = u64::from_str_radix(&next_elem!()[4..], 16)?;

    // CCS=0000000000000000 CCD=0000000000000000 CCO=EFLAGS
    curr_line = next_line!().split(' ');
    let _ccs = u64::from_str_radix(&next_elem!()[4..], 16)?;
    let _ccd = u64::from_str_radix(&next_elem!()[4..], 16)?;
    //let _cc0 = u64::from_str_radix(&next_elem!()[4..], 16)?;

    // EFER=0000000000000d01
    curr_line = next_line!().split(' ');
    let msr_efer = u64::from_str_radix(&next_elem!()[5..], 16)?;

    // FCW=037f FSW=0000 [ST=0] FTW=00 MXCSR=00001f80
    curr_line = next_line!().split(' ');
    let fcw = u16::from_str_radix(&next_elem!()[4..], 16)?;
    let fsw = u16::from_str_radix(&next_elem!()[4..], 16)?;
    let _flag = next_elem!();
    let ftw = u16::from_str_radix(&next_elem!()[4..], 16)?;
    let mxcsr = u32::from_str_radix(&next_elem!()[6..], 16)?;

    // FPR0=0000000000000000 0000 FPR1=0000000000000000 0000
    curr_line = next_line!().split(' ');
    let fpr0_lower = u128::from_str_radix(&next_elem!()[5..], 16)?;
    let fpr0_upper = u128::from_str_radix(next_elem!(), 16)?;
    let fpr0 = fpr0_upper << 64 | fpr0_lower;
    let fpr1_lower = u128::from_str_radix(&next_elem!()[5..], 16)?;
    let fpr1_upper = u128::from_str_radix(next_elem!(), 16)?;
    let fpr1 = fpr1_upper << 64 | fpr1_lower;

    // FPR2=0000000000000000 0000 FPR3=0000000000000000 0000
    curr_line = next_line!().split(' ');
    let fpr2_lower = u128::from_str_radix(&next_elem!()[5..], 16)?;
    let fpr2_upper = u128::from_str_radix(next_elem!(), 16)?;
    let fpr2 = fpr2_upper << 64 | fpr2_lower;
    let fpr3_lower = u128::from_str_radix(&next_elem!()[5..], 16)?;
    let fpr3_upper = u128::from_str_radix(next_elem!(), 16)?;
    let fpr3 = fpr3_upper << 64 | fpr3_lower;

    // FPR4=0000000000000000 0000 FPR5=0000000000000000 0000
    curr_line = next_line!().split(' ');
    let fpr4_lower = u128::from_str_radix(&next_elem!()[5..], 16)?;
    let fpr4_upper = u128::from_str_radix(next_elem!(), 16)?;
    let fpr4 = fpr4_upper << 64 | fpr4_lower;
    let fpr5_lower = u128::from_str_radix(&next_elem!()[5..], 16)?;
    let fpr5_upper = u128::from_str_radix(next_elem!(), 16)?;
    let fpr5 = fpr5_upper << 64 | fpr5_lower;

    // FPR6=0000000000000000 0000 FPR7=0000000000000000 0000
    curr_line = next_line!().split(' ');
    let fpr6_lower = u128::from_str_radix(&next_elem!()[5..], 16)?;
    let fpr6_upper = u128::from_str_radix(next_elem!(), 16)?;
    let fpr6 = fpr6_upper << 64 | fpr6_lower;
    let fpr7_lower = u128::from_str_radix(&next_elem!()[5..], 16)?;
    let fpr7_upper = u128::from_str_radix(next_elem!(), 16)?;
    let fpr7 = fpr7_upper << 64 | fpr7_lower;

    curr_line = next_line!().split(' ');

    // Preallocate the string used to parse the XMM registers
    let mut xmm_str = String::new();

    /// Parse the XMM register line from the QEMU register file
    // XMM00=0000000000000000 0000ff00000000ff XMM01=2f2f2f2f2f2f2f2f 2f2f2f2f2f2f2f2f
    macro_rules! parse_xmm {
        () => {{
            xmm_str.clear();
            let xmm_hi = &next_elem!()[6..];
            let xmm_lo = next_elem!();
            xmm_str.push_str(xmm_hi);
            xmm_str.push_str(xmm_lo);
            u128::from_str_radix(&xmm_str, 16)?
        }};
    }

    let xmm0 = parse_xmm!();
    let xmm1 = parse_xmm!();

    curr_line = next_line!().split(' ');
    let xmm2 = parse_xmm!();
    let xmm3 = parse_xmm!();

    curr_line = next_line!().split(' ');
    let xmm4 = parse_xmm!();
    let xmm5 = parse_xmm!();

    curr_line = next_line!().split(' ');
    let xmm6 = parse_xmm!();
    let xmm7 = parse_xmm!();

    curr_line = next_line!().split(' ');
    let xmm8 = parse_xmm!();
    let xmm9 = parse_xmm!();

    curr_line = next_line!().split(' ');
    let xmm10 = parse_xmm!();
    let xmm11 = parse_xmm!();

    curr_line = next_line!().split(' ');
    let xmm12 = parse_xmm!();
    let xmm13 = parse_xmm!();

    curr_line = next_line!().split(' ');
    let xmm14 = parse_xmm!();
    let xmm15 = parse_xmm!();

    // Code=f8 02 00 00 00 c7 45 f4 03 00 00 00 c7 45 f0 0f 27 00 00 cc <0f> 01 c1 8b
    // Ignore the code bytes for now
    let _ = next_line!().split(' ');

    // Create the xsave area
    let xsave_state = X86XSaveArea {
        x87: X86FxState {
            fcw,
            fsw,
            ftw,
            opcode: 0,
            fpuip: 0,
            cs: 0,
            reserved_1: 0,
            fpudp: 0,
            ds: 0,
            reserved_2: 0,
            mxcsr,
            mxcsr_mask: 0,
            fpu_regs: [fpr0, fpr1, fpr2, fpr3, fpr4, fpr5, fpr6, fpr7],
            xmm_regs: [
                xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm9, xmm10, xmm11, xmm12,
                xmm13, xmm14, xmm15,
            ],
            reserved_rest: [0; (464 - 416) / std::mem::size_of::<u32>()],
            reserved_rest2: [0; (512 - 464) / std::mem::size_of::<u32>()],
        },
        header: X86XSaveHeader {
            xstate: 0,
            xcomp: 0,
            reserved: [0; 6],
        },
        ymm_hi: X86XsaveYmmHi { regs: [0; 16] },
    };

    // APIC_BASE=fee00d00
    let tmp = next_line!();
    assert!(
        tmp.contains("APIC_BASE"),
        "Expected APIC_BASE. Found: {tmp}",
    );
    let msr_apic_base = u64::from_str_radix(&tmp[0xa..], 16)?;

    // EFER=d01
    let tmp = next_line!();
    assert!(tmp.contains("EFER"), "Expected EFER. Found: {tmp}");
    let _msr_efer = u64::from_str_radix(&tmp[0x5..], 16)?;

    // STAR=23001000000000
    let tmp = next_line!();
    assert!(tmp.contains("STAR"), "Expected STAR. Found: {tmp}");
    let msr_star = u64::from_str_radix(&tmp[0x5..], 16)?;

    // LSTAR=ffffffff83e00000
    let tmp = next_line!();
    assert!(tmp.contains("LSTAR"), "Expected LSTAR. Found: {tmp}");
    let msr_lstar = u64::from_str_radix(&tmp[0x6..], 16)?;

    // CSTAR=ffffffff83e01680
    let tmp = next_line!();
    assert!(tmp.contains("CSTAR"), "Expected CSTAR. Found: {tmp}");
    let msr_cstar = u64::from_str_radix(&tmp[0x6..], 16)?;

    // SFMASK=257fd5
    let tmp = next_line!();
    assert!(tmp.contains("SFMASK"), "Expected SFMASK. Found: {tmp}");
    let msr_sfmask = u64::from_str_radix(&tmp[0x7..], 16)?;

    // KERNELGSBASE=0
    let tmp = next_line!();
    assert!(
        tmp.contains("KERNELGSBASE"),
        "Expected KERNELGSBASE. Found: {tmp}",
    );
    let msr_kernel_gs_base = u64::from_str_radix(&tmp[0xd..], 16)?;

    Ok(VbCpu {
        rax,
        rbx,
        rcx,
        rdx,
        rsi,
        rdi,
        r8,
        r9,
        r10,
        r11,
        r12,
        r13,
        r14,
        r15,
        rip,
        rsp,
        rbp,
        rflags,
        cs,
        ds,
        es,
        fs,
        gs,
        ss,
        cr0,
        cr2,
        cr3,
        // cr4: 0x706f0, // OLD
        cr4,
        dr0,
        dr1,
        dr2,
        dr3,
        dr4: 0,
        dr5: 0,
        dr6,
        dr7,
        gdtr_base,
        gdtr_limit,
        gdtr_reserved: 0,
        idtr_base,
        idtr_limit,
        idtr_reserved: 0,
        ldtr,
        tr,
        sysenter_cs: 0,
        sysenter_eip: 0,
        sysenter_esp: 0,
        msr_efer,
        msr_star,
        msr_pat: 0x0,
        msr_lstar,
        msr_cstar,
        // msr_sfmask: 0x47700, // OLD
        msr_sfmask,
        msr_kernel_gs_base,
        msr_apic_base,
        xcr0: 0x7,
        xcr1: 0x0,
        cbext: 0x340,
        padding0: 0,
        xsave_state,
    })
}

/// Number of seconds in a minute
const SECONDS_IN_MINUTE: u64 = 60;

/// Number of seconds in an hour.
const SECONDS_IN_HOUR: u64 = 60 * SECONDS_IN_MINUTE;

/// Number of seconds in a full day (24h).
const SECONDS_IN_DAY: u64 = 24 * SECONDS_IN_HOUR;

/// Number of seconds in a week.
const SECONDS_IN_WEEK: u64 = 7 * SECONDS_IN_DAY;

/// Parse the command line timeout argument into a [`Duration`]
///
/// Value example:
///
/// * 10ns - 10 nanoseconds
/// * 25us - 25 microseconds
/// * 05ms - 10 milliseconds
/// * 01s  - 1 second
/// * 10m  - 10 minutes
/// * 2h   - 2 hours
/// * 2d   - 2 days
/// * 1w   - 1 week
///
/// # Errors
///
/// * Fails to parse the given timeout number as a `u64`
pub fn parse_timeout(input: &str) -> anyhow::Result<Duration> {
    // Default duration form to seconds
    let mut number = String::new();
    let mut format = String::new();
    let mut non_digits = false;
    for curr_char in input.chars() {
        if non_digits || !curr_char.is_numeric() {
            non_digits = true;
            format.push(curr_char.to_ascii_lowercase());
        } else {
            number.push(curr_char);
        }
    }

    // Parse the number for the given format
    let number = number.parse::<u64>()?;

    // Parse the format into the durations known by `Duration`
    let res = match format.as_str() {
        "ns" => Duration::from_nanos(number),
        "us" => Duration::from_micros(number),
        "ms" => Duration::from_millis(number),
        "s" => Duration::from_secs(number),
        "m" => Duration::from_secs(number * SECONDS_IN_MINUTE),
        "h" => Duration::from_secs(number * SECONDS_IN_HOUR),
        "d" => Duration::from_secs(number * SECONDS_IN_DAY),
        "w" => Duration::from_secs(number * SECONDS_IN_WEEK),
        _ => return Err(Error::InvalidTimeoutFormat(format).into()),
    };

    // Return the found duration
    Ok(res)
}

fn parse_cores(str: &str) -> Result<NonZeroUsize, anyhow::Error> {
    let num_cores = core_affinity::get_core_ids().unwrap().len();

    let cores = if let Some(cores) = str.strip_prefix('/') {
        let i = cores.parse::<NonZeroUsize>()?;
        num_cores / i
    } else {
        let i = str.parse::<i64>()?;
        if i < 0 {
            ((num_cores as i64) + i).try_into()?
        } else {
            i.try_into()?
        }
    };
    Ok(cores.try_into()?)
}

/// Parse the cmp analysis breakpoints. This will read the given path and parse
/// the redqueen breakpoints from binary ninja.
///
/// Example:
///
/// 0x555555555268,0x4,reg eax,CMP_SLT,load_from add reg rbp -0x1c
///
/// (0x555555555268, RedqueenArguments {
///     size: Size::U32,
///     operation: Operation::SignedLessThan,
///     left_op: Operand::Register(EAX),
///     right_op: Operand::Memory {
///         register: RBP,
///         displacement: -0x1c,
///     },
/// })
///
/// # Errors
///
/// * Failed to read cmps file
pub fn parse_cmps(cmps_path: &Path) -> Result<HashMap<u64, Vec<RedqueenArguments>>> {
    // Read the breakpoints
    let data = std::fs::read_to_string(cmps_path).context("Failed to read cmps file")?;
    let lines: Vec<_> = data.lines().collect();

    let mut result: HashMap<u64, Vec<RedqueenArguments>> = HashMap::new();

    let mut index = 0;
    let mut invalid = 0;

    while index < lines.len() {
        let line = lines[index].to_string();
        index += 1;

        // Ignore empty lines
        if line.is_empty() {
            continue;
        }

        if line.contains("x87") {
            println!("[CMP] Not impl - x87 line: {line}");
            invalid += 1;
            continue;
        }

        if line.contains("recurs") {
            println!("[CMP] Skipping recursion error: {line}");
            invalid += 1;
            continue;
        }

        if line.contains("unknown") {
            println!("[CMP] unknown operand found: {line}");
            invalid += 1;
            continue;
        }

        // Expected rule format: 0x555555555246,4,load_from add rbp -0x10,NE,0x11111111
        let Some([addr, cmp_size, left_op_str, operation, right_op_str]) =
            line.split(',').array_chunks().next()
        else {
            // panic!("Invalid cmp analysis rule found: {line}");
            println!("[CMP] ERROR: invalid cmp analysis rule found: {line:?}");
            invalid += 1;
            index += 1;
            continue;
        };

        let addr = u64::from_str_radix(&addr.replace("0x", ""), 16)
            .expect("Failed to parse cmp analysis address");

        let mut size = match cmp_size {
            "0x1" => Size::U8,
            "0x2" => Size::U16,
            "0x4" => Size::U32,
            "0x8" => Size::U64,
            "0x10" => Size::U128,
            "f0x4" => Size::F32,
            "f0x8" => Size::F64,
            size => {
                if let Some(reg) = size.strip_prefix("reg ") {
                    Size::Register(try_parse_register(reg)?)
                } else {
                    Size::Bytes(usize::from_str_radix(&size.replace("0x", ""), 16)?)
                }
            }
        };

        let operation = match operation {
            "CMP_E" => Conditional::Equal,
            "CMP_NE" => Conditional::NotEqual,
            "CMP_SLT" => Conditional::SignedLessThan,
            "CMP_ULT" => Conditional::UnsignedLessThan,
            "CMP_SLE" => Conditional::SignedLessThanEqual,
            "CMP_ULE" => Conditional::UnsignedLessThanEqual,
            "CMP_SGT" => Conditional::SignedGreaterThan,
            "CMP_UGT" => Conditional::UnsignedGreaterThan,
            "CMP_SGE" => Conditional::SignedGreaterThanEqual,
            "CMP_UGE" => Conditional::UnsignedGreaterThanEqual,
            "FCMP_E" => Conditional::FloatingPointEqual,
            "FCMP_NE" => Conditional::FloatingPointNotEqual,
            "FCMP_LT" => Conditional::FloatingPointLessThan,
            "FCMP_LE" => Conditional::FloatingPointLessThanEqual,
            "FCMP_GT" => Conditional::FloatingPointGreaterThan,
            "FCMP_GE" => Conditional::FloatingPointGreaterThanEqual,
            "strcmp" => {
                // strcmp's size should just be a Size::Bytes regardless of the given size
                size = Size::Bytes(0x1234);
                Conditional::Strcmp
            }
            "memcmp" => {
                size = if let Some(reg) = cmp_size.strip_prefix("reg ") {
                    Size::Register(try_parse_register(reg)?)
                } else {
                    Size::Bytes(usize::from_str_radix(&cmp_size.replace("0x", ""), 16)?)
                };

                Conditional::Memcmp
            }
            "memchr" => {
                size = if let Some(reg) = cmp_size.strip_prefix("reg ") {
                    Size::Register(try_parse_register(reg)?)
                } else {
                    Size::Bytes(usize::from_str_radix(&cmp_size.replace("0x", ""), 16)?)
                };

                Conditional::Memchr
            }
            _ => {
                println!("[CMP] skipping unknown operation: {operation}");
                continue;
            }
        };

        // Adjust the floating point sizes if invalid in the cmp line
        if matches!(
            operation,
            Conditional::FloatingPointEqual
                | Conditional::FloatingPointNotEqual
                | Conditional::FloatingPointLessThan
                | Conditional::FloatingPointLessThanEqual
                | Conditional::FloatingPointGreaterThan
                | Conditional::FloatingPointGreaterThanEqual
        ) {
            match size {
                Size::F32 | Size::F64 => {
                    // Good floating point size, nothing to do
                }
                Size::U32 => size = Size::F32,
                Size::U64 => size = Size::F64,
                Size::Bytes(0xa) => size = Size::X87,
                _ => panic!("Invalid floating point size: {line} {size:?}"),
            }
        }

        // Parse the left and right operands
        match (
            parse_cmp_operand(left_op_str),
            parse_cmp_operand(right_op_str),
        ) {
            (Ok((left_op, _left_remaining)), Ok((right_op, _right_remaining))) => {
                let arg = RedqueenArguments {
                    size,
                    operation,
                    left_op,
                    right_op,
                };

                result.entry(addr).or_default().push(arg);
            }
            (Err(e), _) => {
                println!(
                    "[CMP] skipping rule due to failure parsing LHS: {:?} {e:?}",
                    left_op_str
                );
                invalid += 1;
            }
            (Ok(_), Err(e)) => {
                println!(
                    "[CMP] skipping rule due to failure parsing RHS: {:?} {e:?}",
                    right_op_str
                );
                invalid += 1;
            }
        }
        // let (left_op, remaining_str) = parse_cmp_operand(left_op_str)?;
        // let (right_op, remaining_str) = parse_cmp_operand(right_op_str)?;
    }

    if invalid > 0 {
        println!("Skipped {invalid}/{} invalid cmp breakpoints", lines.len());
    }

    Ok(result)
}

/// Parse a number string and return the parsed value
fn parse_number(num: &str) -> Result<i64> {
    // Remove 0x or -0x prefixes
    let without_prefix = num.trim_start_matches("0x").trim_start_matches("-0x");

    // Return parsed number
    Ok(u64::from_str_radix(without_prefix, 16).map(|n| n as i64)?)
}

/// Parse the cmp line given by the binja plugin and return how to retrieve
/// the information from a `fuzzvm`.
///
/// Example:
///
/// BP Address,Size,Operand 1,Operation,Operand 2
///
/// 0x555555555514,0x4,reg eax,E,0x912f2593
/// 0x55555555557e,0x4,load_from add reg rax 0x4,SLT,0x41414141
///
/// Operand examples:
///
/// reg eax -> eax
/// load_from add reg rax 0x4 -> [rax + 0x4]
/// load_from 0xdeadbeef -> [0xdeadbeef]
/// 0x12341234 -> 0x12341234
///
/// Function calls:
///
/// 0x55555555582c,0x30,reg rdi,memcmp,reg rsi -> memcmp(rdi, rsi)
fn parse_cmp_operand(input: &str) -> Result<(Operand, &str)> {
    if let Some(args) = input.strip_prefix("load_from ") {
        let (address, remaining) = parse_cmp_operand(args)?;

        Ok((
            Operand::Load {
                address: Box::new(address),
            },
            remaining,
        ))
    } else if let Some(args) = input.strip_prefix("and ") {
        // Parses and <operation>
        let (left, remaining) = parse_cmp_operand(args)?;
        let (right, remaining) = parse_cmp_operand(remaining)?;

        Ok((
            Operand::And {
                left: Box::new(left),
                right: Box::new(right),
            },
            remaining,
        ))
    } else if let Some(args) = input.strip_prefix("neg ") {
        // Parses neg <operation>

        // Parse the register
        let (src, remaining) = parse_cmp_operand(args)?;

        Ok((Operand::Neg { src: Box::new(src) }, remaining))
    } else if let Some(args) = input.strip_prefix("not ") {
        // Parses not <operation>

        // Parse the register
        let (src, remaining) = parse_cmp_operand(args)?;

        Ok((Operand::Not { src: Box::new(src) }, remaining))
    } else if let Some(args) = input.strip_prefix("add ") {
        // Parses add <operation>
        let (left, remaining) = parse_cmp_operand(args)?;
        let (right, remaining) = parse_cmp_operand(remaining)?;

        Ok((
            Operand::Add {
                left: Box::new(left),
                right: Box::new(right),
            },
            remaining,
        ))
    } else if let Some(args) = input.strip_prefix("mul ") {
        // Parses mul <operation>
        let (left, remaining) = parse_cmp_operand(args)?;
        let (right, remaining) = parse_cmp_operand(remaining)?;

        Ok((
            Operand::Mul {
                left: Box::new(left),
                right: Box::new(right),
            },
            remaining,
        ))
    } else if let Some(args) = input.strip_prefix("div ") {
        // Parses div <operation>
        let (left, remaining) = parse_cmp_operand(args)?;
        let (right, remaining) = parse_cmp_operand(remaining)?;

        Ok((
            Operand::Div {
                left: Box::new(left),
                right: Box::new(right),
            },
            remaining,
        ))
    } else if let Some(args) = input
        .strip_prefix("logical_shift_left ")
        .or_else(|| input.strip_prefix("lsl "))
    {
        // Parses lsl <operation>
        let (left, remaining) = parse_cmp_operand(args)?;
        let (right, remaining) = parse_cmp_operand(remaining)?;

        Ok((
            Operand::LogicalShiftLeft {
                left: Box::new(left),
                right: Box::new(right),
            },
            remaining,
        ))
    } else if let Some(args) = input.strip_prefix("sub ") {
        // Parses sub <operation>
        let (left, remaining) = parse_cmp_operand(args)?;
        let (right, remaining) = parse_cmp_operand(remaining)?;

        Ok((
            Operand::Sub {
                left: Box::new(left),
                right: Box::new(right),
            },
            remaining,
        ))
    } else if let Some(args) = input
        .strip_prefix("arithmetic_shift_right ")
        .or_else(|| input.strip_prefix("lsr "))
    {
        // Parses arithmetic_shift_right <operation>
        let (left, remaining) = parse_cmp_operand(args)?;
        let (right, remaining) = parse_cmp_operand(remaining)?;

        Ok((
            Operand::ArithmeticShiftRight {
                left: Box::new(left),
                right: Box::new(right),
            },
            remaining,
        ))
    } else if let Some(args) = input.strip_prefix("sign_extend ") {
        // Parses sign_extend <operation>
        let (left, remaining) = parse_cmp_operand(args)?;

        Ok((
            Operand::SignExtend {
                src: Box::new(left),
            },
            remaining,
        ))
    } else if let Some(args) = input.strip_prefix("reg ") {
        // Parses reg <reg>

        // Split on the first space if there is one
        let (reg_str, remaining) = args.split_once(' ').unwrap_or((args, ""));

        // Parse the register
        let reg = try_parse_register(reg_str)?;

        Ok((Operand::Register(reg), remaining))
    } else if let Some(args) = input.strip_prefix("0x") {
        // Parses 0x<value>
        let (value_str, remaining) = args.split_once(' ').unwrap_or((args, ""));

        // Parse the value
        let value = parse_number(value_str)?;

        Ok((Operand::ConstU64(value as u64), remaining))
    } else if let Some(args) = input.strip_prefix("-0x") {
        // Parses -0x<value>
        let (value_str, remaining) = args.split_once(' ').unwrap_or((args, ""));

        // Parse the value
        let value = parse_number(value_str)?;

        Ok((Operand::ConstU64(-value as u64), remaining))
    } else if let Ok(float_num) = input.parse::<f64>() {
        // Parses <f64>
        Ok((Operand::ConstF64(float_num), "NOTHERE_f64"))
    } else if let Some([num, remaining]) = input.splitn(2, ' ').array_chunks().next() {
        if let Ok(num_u64) = num.parse::<u64>() {
            // Parses <u64>
            Ok((Operand::ConstU64(num_u64), remaining))
        } else if let Ok(num_f64) = num.parse::<f64>() {
            // Parses <f64>
            Ok((Operand::ConstF64(num_f64), remaining))
        } else {
            Err(Error::UnimplementedCmpOperand(input.to_string()).into())
        }
    } else {
        Err(Error::UnimplementedCmpOperand(input.to_string()).into())
    }
}

fn try_parse_register(reg: &str) -> Result<iced_x86::Register> {
    use iced_x86::Register;

    Ok(match reg.to_ascii_lowercase().as_str() {
        "al" => Register::AL,
        "bl" => Register::BL,
        "cl" => Register::AL,
        "dl" => Register::DL,
        "ch" => Register::CH,
        "dh" => Register::DH,
        "bh" => Register::BH,
        "spl" => Register::SPL,
        "bpl" => Register::BPL,
        "sil" => Register::SIL,
        "dil" => Register::DIL,
        "r8b" => Register::R8L,
        "r9b" => Register::R9L,
        "r10b" => Register::R10L,
        "r11b" => Register::R11L,
        "r12b" => Register::R12L,
        "r13b" => Register::R13L,
        "r14b" => Register::R14L,
        "r15b" => Register::R15L,
        "ax" => Register::AX,
        "cx" => Register::CX,
        "dx" => Register::DX,
        "bx" => Register::BX,
        "sp" => Register::SP,
        "bp" => Register::BP,
        "si" => Register::SI,
        "di" => Register::DI,
        "r8w" => Register::R8W,
        "r9w" => Register::R9W,
        "r10w" => Register::R10W,
        "r11w" => Register::R11W,
        "r12w" => Register::R12W,
        "r13w" => Register::R13W,
        "r14w" => Register::R14W,
        "r15w" => Register::R15W,
        "eax" => Register::EAX,
        "ecx" => Register::ECX,
        "edx" => Register::EDX,
        "ebx" => Register::EBX,
        "esp" => Register::ESP,
        "ebp" => Register::EBP,
        "esi" => Register::ESI,
        "edi" => Register::EDI,
        "r8d" => Register::R8D,
        "r9d" => Register::R9D,
        "r10d" => Register::R10D,
        "r11d" => Register::R11D,
        "r12d" => Register::R12D,
        "r13d" => Register::R13D,
        "r14d" => Register::R14D,
        "r15d" => Register::R15D,
        "rax" => Register::RAX,
        "rcx" => Register::RCX,
        "rdx" => Register::RDX,
        "rbx" => Register::RBX,
        "rsp" => Register::RSP,
        "rbp" => Register::RBP,
        "rsi" => Register::RSI,
        "rdi" => Register::RDI,
        "r8" => Register::R8,
        "r9" => Register::R9,
        "r10" => Register::R10,
        "r11" => Register::R11,
        "r12" => Register::R12,
        "r13" => Register::R13,
        "r14" => Register::R14,
        "r15" => Register::R15,
        "eip" => Register::EIP,
        "rip" => Register::RIP,
        "es" => Register::ES,
        "cs" => Register::CS,
        "ss" => Register::SS,
        "ds" => Register::DS,
        "fs" => Register::FS,
        "gs" => Register::GS,
        "xmm0" => Register::XMM0,
        "xmm1" => Register::XMM1,
        "xmm2" => Register::XMM2,
        "xmm3" => Register::XMM3,
        "xmm4" => Register::XMM4,
        "xmm5" => Register::XMM5,
        "xmm6" => Register::XMM6,
        "xmm7" => Register::XMM7,
        "xmm8" => Register::XMM8,
        "xmm9" => Register::XMM9,
        "xmm10" => Register::XMM10,
        "xmm11" => Register::XMM11,
        "xmm12" => Register::XMM12,
        "xmm13" => Register::XMM13,
        "xmm14" => Register::XMM14,
        "xmm15" => Register::XMM15,
        "xmm16" => Register::XMM16,
        "xmm17" => Register::XMM17,
        "xmm18" => Register::XMM18,
        "xmm19" => Register::XMM19,
        "xmm20" => Register::XMM20,
        "xmm21" => Register::XMM21,
        "xmm22" => Register::XMM22,
        "xmm23" => Register::XMM23,
        "xmm24" => Register::XMM24,
        "xmm25" => Register::XMM25,
        "xmm26" => Register::XMM26,
        "xmm27" => Register::XMM27,
        "xmm28" => Register::XMM28,
        "xmm29" => Register::XMM29,
        "xmm30" => Register::XMM30,
        "xmm31" => Register::XMM31,
        "ymm0" => Register::YMM0,
        "ymm1" => Register::YMM1,
        "ymm2" => Register::YMM2,
        "ymm3" => Register::YMM3,
        "ymm4" => Register::YMM4,
        "ymm5" => Register::YMM5,
        "ymm6" => Register::YMM6,
        "ymm7" => Register::YMM7,
        "ymm8" => Register::YMM8,
        "ymm9" => Register::YMM9,
        "ymm10" => Register::YMM10,
        "ymm11" => Register::YMM11,
        "ymm12" => Register::YMM12,
        "ymm13" => Register::YMM13,
        "ymm14" => Register::YMM14,
        "ymm15" => Register::YMM15,
        "ymm16" => Register::YMM16,
        "ymm17" => Register::YMM17,
        "ymm18" => Register::YMM18,
        "ymm19" => Register::YMM19,
        "ymm20" => Register::YMM20,
        "ymm21" => Register::YMM21,
        "ymm22" => Register::YMM22,
        "ymm23" => Register::YMM23,
        "ymm24" => Register::YMM24,
        "ymm25" => Register::YMM25,
        "ymm26" => Register::YMM26,
        "ymm27" => Register::YMM27,
        "ymm28" => Register::YMM28,
        "ymm29" => Register::YMM29,
        "ymm30" => Register::YMM30,
        "ymm31" => Register::YMM31,
        "zmm0" => Register::ZMM0,
        "zmm1" => Register::ZMM1,
        "zmm2" => Register::ZMM2,
        "zmm3" => Register::ZMM3,
        "zmm4" => Register::ZMM4,
        "zmm5" => Register::ZMM5,
        "zmm6" => Register::ZMM6,
        "zmm7" => Register::ZMM7,
        "zmm8" => Register::ZMM8,
        "zmm9" => Register::ZMM9,
        "zmm10" => Register::ZMM10,
        "zmm11" => Register::ZMM11,
        "zmm12" => Register::ZMM12,
        "zmm13" => Register::ZMM13,
        "zmm14" => Register::ZMM14,
        "zmm15" => Register::ZMM15,
        "zmm16" => Register::ZMM16,
        "zmm17" => Register::ZMM17,
        "zmm18" => Register::ZMM18,
        "zmm19" => Register::ZMM19,
        "zmm20" => Register::ZMM20,
        "zmm21" => Register::ZMM21,
        "zmm22" => Register::ZMM22,
        "zmm23" => Register::ZMM23,
        "zmm24" => Register::ZMM24,
        "zmm25" => Register::ZMM25,
        "zmm26" => Register::ZMM26,
        "zmm27" => Register::ZMM27,
        "zmm28" => Register::ZMM28,
        "zmm29" => Register::ZMM29,
        "zmm30" => Register::ZMM30,
        "zmm31" => Register::ZMM31,
        "k0" => Register::K0,
        "k1" => Register::K1,
        "k2" => Register::K2,
        "k3" => Register::K3,
        "k4" => Register::K4,
        "k5" => Register::K5,
        "k6" => Register::K6,
        "k7" => Register::K7,
        "bnd0" => Register::BND0,
        "bnd1" => Register::BND1,
        "bnd2" => Register::BND2,
        "bnd3" => Register::BND3,
        "cr0" => Register::CR0,
        "cr1" => Register::CR1,
        "cr2" => Register::CR2,
        "cr3" => Register::CR3,
        "cr4" => Register::CR4,
        "cr5" => Register::CR5,
        "cr6" => Register::CR6,
        "cr7" => Register::CR7,
        "cr8" => Register::CR8,
        "cr9" => Register::CR9,
        "cr10" => Register::CR10,
        "cr11" => Register::CR11,
        "cr12" => Register::CR12,
        "cr13" => Register::CR13,
        "cr14" => Register::CR14,
        "cr15" => Register::CR15,
        "dr0" => Register::DR0,
        "dr1" => Register::DR1,
        "dr2" => Register::DR2,
        "dr3" => Register::DR3,
        "dr4" => Register::DR4,
        "dr5" => Register::DR5,
        "dr6" => Register::DR6,
        "dr7" => Register::DR7,
        "dr8" => Register::DR8,
        "dr9" => Register::DR9,
        "dr10" => Register::DR10,
        "dr11" => Register::DR11,
        "dr12" => Register::DR12,
        "dr13" => Register::DR13,
        "dr14" => Register::DR14,
        "dr15" => Register::DR15,
        "st0" => Register::ST0,
        "st1" => Register::ST1,
        "st2" => Register::ST2,
        "st3" => Register::ST3,
        "st4" => Register::ST4,
        "st5" => Register::ST5,
        "st6" => Register::ST6,
        "st7" => Register::ST7,
        "mm0" => Register::MM0,
        "mm1" => Register::MM1,
        "mm2" => Register::MM2,
        "mm3" => Register::MM3,
        "mm4" => Register::MM4,
        "mm5" => Register::MM5,
        "mm6" => Register::MM6,
        "mm7" => Register::MM7,
        "tr0" => Register::TR0,
        "tr1" => Register::TR1,
        "tr2" => Register::TR2,
        "tr3" => Register::TR3,
        "tr4" => Register::TR4,
        "tr5" => Register::TR5,
        "tr6" => Register::TR6,
        "tr7" => Register::TR7,
        "tmm0" => Register::TMM0,
        "tmm1" => Register::TMM1,
        "tmm2" => Register::TMM2,
        "tmm3" => Register::TMM3,
        "tmm4" => Register::TMM4,
        "tmm5" => Register::TMM5,
        "tmm6" => Register::TMM6,
        "tmm7" => Register::TMM7,

        #[allow(deprecated)]
        "fsbase" => Register::DontUseFA,
        x => anyhow::bail!("Unknown register value: {x:?}"),
    })
}
