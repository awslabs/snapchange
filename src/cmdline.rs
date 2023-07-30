//! Command line arguments

use anyhow::{anyhow, ensure, Context, Result};
use clap::Parser;
use log::debug;
use thiserror::Error;
use x86_64::registers::rflags::RFlags;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::File;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::addrs::{Cr3, VirtAddr};
use crate::config::Config;
use crate::fuzzer::ResetBreakpointType;
use crate::stack_unwinder::StackUnwinders;
use crate::symbols::{Symbol, LINUX_KERNEL_SYMBOLS, LINUX_USERLAND_SYMBOLS};
use crate::vbcpu::{VbCpu, VmSelector, X86FxState, X86XSaveArea, X86XSaveHeader, X86XsaveYmmHi};

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
}

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
    pub(crate) coverage_breakpoints: Option<BTreeSet<VirtAddr>>,

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

    /// Project has `.cmps` file for redqueen
    ///
    /// Used to decide whether or not to map a second clean physical snapshot used exclusively
    /// for redqueen breakpoints without applying coverage breakpoints
    #[cfg(feature = "redqueen")]
    pub(crate) redqueen_available: bool,

    /// A stack unwinder that can be used to unwind stack
    pub(crate) unwinders: StackUnwinders,
}

/// Current coverage found in the project
#[derive(Default)]
pub struct ProjectCoverage {
    /// Previously seen coverage by the fuzzer
    pub prev_coverage: BTreeSet<VirtAddr>,

    /// Coverage left to be seen by the fuzzer
    pub coverage_left: BTreeSet<VirtAddr>,

    /// Previously seen redqueen coverage by the fuzzer
    pub prev_redqueen_coverage: BTreeSet<(VirtAddr, RFlags)>,
}

impl ProjectState {
    /// Return the coverage remaining from the original coverage and the previously found
    /// coverage along with the previously found coverage itself. Also adds breakpoints
    /// for basic blocks as seen in SanitiverCoverage when compiling a target with
    /// `-fsanitize-coverage=trace-pc-guard,pc-table`.
    ///
    /// # Errors
    ///
    /// Can error during parsing the coverage.addresses project file
    #[allow(clippy::missing_panics_doc)]
    pub fn coverage_left(&self) -> Result<ProjectCoverage> {
        // If there was previous coverage seen, remove that from the total coverage
        // breakpoints
        let mut prev_coverage = BTreeSet::new();
        let prev_coverage_file = self.path.join("coverage.addresses");
        if prev_coverage_file.exists() {
            prev_coverage = std::fs::read_to_string(prev_coverage_file)
                .context("Failed to read coverage.addresses file")?
                .split('\n')
                .filter_map(|x| u64::from_str_radix(x.trim_start_matches("0x"), 16).ok())
                .map(VirtAddr)
                .collect();
        }

        let mut prev_redqueen_coverage = BTreeSet::new();
        let prev_rq_coverage_file = self.path.join("coverage.redqueen");
        if prev_rq_coverage_file.exists() {
            prev_redqueen_coverage = std::fs::read_to_string(prev_rq_coverage_file)
                .context("Failed to read coverage.redqueen file")?
                .split('\n')
                .filter_map(|line| {
                    let mut iter = line.split(' ');
                    let Some(addr) = iter.next() else {
                        return None;
                    };
                    let Some(rflags) = iter.next() else {
                        return None;
                    };

                    let addr = u64::from_str_radix(addr.trim_start_matches("0x"), 16);
                    let rflags = u64::from_str_radix(rflags.trim_start_matches("0x"), 16);
                    if let (Ok(addr), Ok(rflags)) = (addr, rflags) {
                        let rflags = RFlags::from_bits_truncate(rflags);
                        Some((VirtAddr(addr), rflags))
                    } else {
                        None
                    }
                })
                .collect();
        }

        if self.coverage_breakpoints.is_none() {
            return Ok(ProjectCoverage {
                prev_coverage,
                prev_redqueen_coverage,
                coverage_left: BTreeSet::new(),
            });
        }

        log::info!(
            "Total coverage: {} Coverage seen: {} Redqueen coverage: {}",
            self.coverage_breakpoints.as_ref().unwrap().len(),
            prev_coverage.len(),
            prev_redqueen_coverage.len()
        );

        // The coverage left to hit
        let coverage_left = self
            .coverage_breakpoints
            .as_ref()
            .unwrap()
            .difference(&prev_coverage)
            .copied()
            .collect();

        // Get the current coverage not yet seen across previous runs
        Ok(ProjectCoverage {
            prev_coverage,
            coverage_left,
            prev_redqueen_coverage,
        })
    }

    /// Parse sancov coverage breakpoints if they are available in this target
    pub fn parse_sancov_breakpoints(&mut self) -> Result<Option<BTreeSet<VirtAddr>>> {
        if let Some(symbol_path) = &self.symbols {
            let mut new_covbps = BTreeSet::new();

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
                    new_covbps.insert(VirtAddr(addr));

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
    pub(crate) cores: Option<usize>,

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
}

/// Minimize subcommand
#[derive(Parser, Debug)]
pub struct Minimize {
    /// Enable single step, single execution trace of the guest using the given file as
    /// the input
    pub(crate) path: PathBuf,

    /// Set the timeout (in seconds) of the execution of the VM. [0-9]+(ns|us|ms|s|m|h)
    #[clap(long, value_parser = parse_timeout, default_value = "60s")]
    pub(crate) timeout: Duration,

    /// Set the number of iterations per minimization stage before moving onto the next
    /// stage
    #[clap(short, long, default_value_t = 50000)]
    pub(crate) iterations_per_stage: u32,

    /// Only check the RIP register for checking if the register state is the same after
    /// minimizing an input
    #[clap(long)]
    pub(crate) rip_only: bool,
}

/// CorpusMin subcommand
#[derive(Parser, Debug)]
pub struct CorpusMin {
    /// Number of cores to fuzz with. Negative numbers interpretted as MAX_CORES - CORES. Prefix
    /// with `/N` to specify a fraction of available cores.
    #[clap(short, long, allow_hyphen_values = true, value_parser = parse_cores)]
    pub(crate) cores: Option<usize>,

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
    /// with `/N` to specify a fraction of available cores.
    #[clap(short, long, allow_hyphen_values = true, value_parser = parse_cores)]
    pub(crate) cores: Option<usize>,
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

/// List of [`Symbol`] sorted in order by address
pub type SymbolList = VecDeque<Symbol>;

/// Set of addresses that, if hit, signal a crash in the guest
pub type ResetBreakpoints = BTreeMap<(VirtAddr, Cr3), ResetBreakpointType>;

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

    #[cfg(feature = "redqueen")]
    let mut redqueen_available = false;

    let mut covbps_paths = Vec::new();

    // Read the snapshot directory looking for the specific file extensions
    for file in dir.read_dir()? {
        let file = file?;

        if let Some(extension) = file.path().extension() {
            // Ignore parsing coverage breakpoints for "project" commands
            if matches!(cmd, Some(SubCommand::Project(_)))
                && matches!(extension.to_str(), Some("covbps"))
            {
                continue;
            }

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
                    covbps_paths.push(file.path());
                }
                #[cfg(feature = "redqueen")]
                Some("cmps") => {
                    redqueen_available = true;
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

    // Write the updated config if one wasn't found or if the configuration options
    // have changed
    if update_config {
        std::fs::write(dir.join("config.toml"), &toml::to_string(&config)?)?;
    }

    let mut coverage_breakpoints: Option<BTreeSet<VirtAddr>> = None;
    let mut coverage_breakpoints_src = None;

    for covbps_path in &covbps_paths {
        let covbps = coverage_breakpoints.get_or_insert(BTreeSet::new());

        let bps = parse_coverage_breakpoints(&covbps_path)?;

        let module = covbps_path
            .file_prefix()
            .ok_or_else(|| anyhow!("FilePrefix failed"))?
            .to_str()
            .ok_or_else(|| anyhow!("Failed to get file_prefix str"))?;

        if let Some(module_range) = modules.get_module_range(module) {
            // Get the smallest coverage breakpoint for this module
            let VirtAddr(min_addr) = bps
                .iter()
                .min()
                .ok_or_else(|| anyhow!("No smallest breakpoint found"))?;

            // If the smallest breakpoint isn't in the module range, then
            // the coverage breakpoints are probably invalid
            if !module_range.contains(min_addr) {
                return Err(Error::CoverageBreakpointNotFoundInModuleRange(
                    *min_addr,
                    module.to_string(),
                    module_range,
                )
                .into());
            }
        }

        covbps.extend(bps);
        coverage_breakpoints_src = Some(covbps_path.with_extension("covbps_src"));
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

    if let (Some(covbps), Some(covbps_src)) = (&coverage_breakpoints, coverage_breakpoints_src) {
        if !covbps_src.exists() {
            let mut contexts = Vec::new();

            for bin_file in &binaries {
                if !bin_file.exists() {
                    continue;
                }

                let file = File::open(bin_file)?;
                let map = unsafe { memmap::Mmap::map(&file)? };
                let object = addr2line::object::File::parse(&*map)?;
                let ctx = addr2line::Context::new(&object)?;
                contexts.push(ctx);
            }

            let mut res = String::new();

            // For each coverage breakpoint, write its source line
            'next_addr: for addr in covbps.iter() {
                for ctx in &contexts {
                    if let Some(loc) = ctx.find_location(addr.0)? {
                        let symbol = format!(
                            "{:#x} {}:{}:{}\n",
                            addr.0,
                            loc.file.unwrap_or("??"),
                            loc.line.unwrap_or(0),
                            loc.column.unwrap_or(0)
                        );

                        res.push_str(&symbol);

                        continue 'next_addr;
                    }
                }
            }

            // Write the coverage breakpoint source lines
            std::fs::write(covbps_src, res)?;
        }
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
    let physical_memory = physical_memory.ok_or(Error::PhysicalMemoryMissing)?;

    let mut state = ProjectState {
        path: dir.to_owned(),
        vbcpu,
        physical_memory,
        symbols,
        coverage_breakpoints,
        modules,
        binaries,
        vmlinux,
        config,
        unwinders,
        #[cfg(feature = "redqueen")]
        redqueen_available,
    };

    // Check for sancov basic blocks in the target
    if let Some(sancov_bps) = state.parse_sancov_breakpoints()? {
        // Write the coverage breakpoints found in sanitizer coverage
        let sancov_bps_file = Path::new("sancov.covbps");
        std::fs::write(
            state.path.join(sancov_bps_file),
            sancov_bps
                .iter()
                .map(|x| format!("{:#x}", x.0))
                .collect::<Vec<_>>()
                .join("\n"),
        )?;

        // Add the sancov breakpoints to the total coverage breakpoints
        if let Some(covbps) = state.coverage_breakpoints.as_mut() {
            covbps.extend(sancov_bps);
        } else {
            state.coverage_breakpoints = Some(sancov_bps);
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
    let mut reset_breakpoints = Some(BTreeMap::new());

    if let Some(ref syms) = symbols_arg {
        let mut curr_symbols: VecDeque<Symbol> = VecDeque::new();

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
            curr_symbols.push_back(Symbol {
                address,
                symbol: line[1].to_string(),
            });
        }

        let mut symbol_bps = BTreeMap::new();

        // Sanity check the symbols are sorted
        let mut last = 0;
        let mut re_sort = false;
        for sym in &curr_symbols {
            if sym.address < last {
                re_sort = true;
            }

            last = sym.address;

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

        // If we've manually inserted a symbol, resort the symbols to be in order
        if re_sort {
            curr_symbols.make_contiguous().sort();
        }

        // Set the valid return fields
        symbols = Some(curr_symbols);
        reset_breakpoints = Some(symbol_bps);
    } else {
        log::warn!("No symbols file found..");
    }

    Ok((symbols, reset_breakpoints))
}

/// Parse the coverage breakpoints command line argument. This will read the given path
/// and create a [`BTreeSet`] of the found coverage breakpoints
///
/// # Errors
///
/// * Failed to read coverage breakpoints file
pub fn parse_coverage_breakpoints(cov_bp_path: &Path) -> Result<BTreeSet<VirtAddr>> {
    // Read the breakpoints
    let data =
        std::fs::read_to_string(cov_bp_path).context("Failed to read coverage breakpoints file")?;

    // Init the result
    let mut cov_bps = BTreeSet::new();

    // Parse the addresses for the VM
    data.split('\n').for_each(|line| {
        // Parses lines of the kind as u64:
        // 0xdeadbeef
        // deadbeef
        // 12341234

        // Empty strings are always invalid
        if line.is_empty() {
            return;
        }

        // Parse each line
        if let Ok(addr) = u64::from_str_radix(&line.replace("0x", ""), 16) {
            cov_bps.insert(VirtAddr(addr));
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

/// Number of minutes in an hour
const MINUTES_IN_HOUR: u64 = 60;

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
        "h" => Duration::new(number * MINUTES_IN_HOUR, 0),
        _ => return Err(Error::InvalidTimeoutFormat(format).into()),
    };

    // Return the found duration
    Ok(res)
}

fn parse_cores(str: &str) -> Result<usize, anyhow::Error> {
    let ncores = core_affinity::get_core_ids().unwrap().len();
    let cores = if str.starts_with('/') {
        let i = str[1..].parse::<usize>()?;
        ncores / i
    } else {
        let i = str.parse::<i64>()?;
        if i < 0 {
            ((ncores as i64) + i) as usize
        } else {
            i as usize
        }
    };
    Ok(cores)
}
