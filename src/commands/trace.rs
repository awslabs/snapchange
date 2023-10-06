//! Executing the `trace` command

use anyhow::{anyhow, ensure, Context, Result};

use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use core_affinity::CoreId;
use kvm_bindings::CpuId;
use kvm_ioctls::VmFd;

use crate::fuzz_input::FuzzInput;
use crate::fuzzer::Fuzzer;
use crate::fuzzvm::{FuzzVm, FuzzVmExit};
use crate::interrupts::IdtEntry;
use crate::memory::Memory;
use crate::{cmdline, fuzzvm, symbols, unblock_sigalrm, THREAD_IDS};
use crate::{handle_vmexit, init_environment, KvmEnvironment, ProjectState};
use crate::{Cr3, Execution, ResetBreakpointType, Symbol, VbCpu, VirtAddr};

/// Number of iterations to execute the same input through the VM (for debugging)
const NUMBER_OF_ITERATIONS: usize = 1;

/// Thread worker to execute a single input and write the single step trace for that
/// input
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
    input_case: &Option<PathBuf>,
    vm_timeout: Duration,
    single_step: bool,
    project_state: &ProjectState,
) -> Result<()> {
    // Get the options from the project state
    let ProjectState {
        vmlinux,
        binaries,
        modules,
        config,
        unwinders,
        ..
    } = project_state;

    // Store the thread ID of this thread used for passing the SIGALRM to this thread
    let thread_id = unsafe { libc::pthread_self() };
    *THREAD_IDS[core_id.id].lock().unwrap() = Some(thread_id);

    // Unblock SIGALRM to enable this thread to handle SIGALRM
    unblock_sigalrm()?;

    // Set the core affinity for this core
    core_affinity::set_for_current(core_id);

    // Create a default fuzzer for single shot, tracing execution with the given input
    let mut fuzzer = FUZZER::default();

    log::info!("Fuzzer: {:#x} RIP: {:#x}", FUZZER::START_ADDRESS, vbcpu.rip);

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
        coverage_breakpoints,
        symbol_breakpoints,
        symbols,
        config.clone(),
        unwinders.clone(),
        #[cfg(feature = "redqueen")]
        redqueen_rules,
    )?;

    // Enable single step for tracing
    if single_step {
        log::info!("Single step trace");
        fuzzvm.enable_single_step()?;
    } else {
        log::info!("No single step trace");
        fuzzvm.disable_single_step()?;
    }

    // If the trace input name is `testcase`, allow the fuzzer to do something ahead of
    // time
    if let Some(input) = &input_case {
        if input
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .contains("testcase")
        {
            fuzzer.test_trace(&mut fuzzvm)?;
        }
    }

    log::info!("Tracing timeout: {:?}", vm_timeout);

    // Add all of the interrupt routines as also function start locations since they
    // aren't a `call` site
    let mut interrupt_routines = Vec::new();
    for vector in 0..255 {
        let addr = fuzzvm.vbcpu.idtr_base + vector * std::mem::size_of::<IdtEntry>() as u64;
        let entry = fuzzvm.read::<IdtEntry>(VirtAddr(addr), fuzzvm.cr3())?;
        let isr = entry.isr();
        interrupt_routines.push(isr);
    }

    // If we are tracing an input, set that input in the guest
    let input = if let Some(input_path) = input_case {
        <FUZZER::Input as FuzzInput>::from_bytes(&std::fs::read(input_path)?)?
    } else {
        FUZZER::Input::default()
    };

    for iter in 0..NUMBER_OF_ITERATIONS {
        // Init single allocation for symbol creation and the final resulting trace
        let mut symbol = String::new();
        let mut result = String::new();
        let mut funcs = Vec::new();

        let mut execution = Execution::Continue;

        // Init timer to mark how long the tracing took
        let start = std::time::Instant::now();

        // Set the input into the VM as per the fuzzer
        fuzzer.set_input(&input, &mut fuzzvm)?;

        let mut contexts = Vec::new();

        log::info!("Getting vmlinux");
        if let Some(vmlinux_path) = vmlinux {
            let file = File::open(vmlinux_path)?;
            let map = unsafe { memmap::Mmap::map(&file)? };
            let object = addr2line::object::File::parse(&*map)?;
            let tmp = addr2line::Context::new(&object)?;
            contexts.push(tmp);
        }

        log::info!("Getting binary contexts");
        for binary in binaries {
            let file = File::open(binary)?;
            let map = unsafe { memmap::Mmap::map(&file)? };
            let object = addr2line::object::File::parse(&*map)?;
            let tmp = addr2line::Context::new(&object)?;
            contexts.push(tmp);
        }

        // Initialize the performance counters for executing a VM
        let mut perf = crate::fuzzvm::VmRunPerf::default();

        let mut at_call = false;
        let mut indent = 4;
        let mut func_indexes = Vec::new();

        // Top of the run iteration loop for the current fuzz case
        for index in 0.. {
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
                let curr_symbol =
                    symbols::get_symbol(rip, sym_data).unwrap_or_else(|| "UnknownSym".to_string());
                symbol.push_str(&curr_symbol.to_string());
            }

            // Write the current line to the trace
            result.push_str(&format!(
                "INSTRUCTION {:03} {:#018x} {:#010x} | {:60} \n    {}\n",
                index,
                rip,
                u64::try_from(cr3.0).unwrap(),
                symbol,
                instr,
            ));

            let mut source_line = None;

            // Find the module starting address for this symbol
            let mut module_start = None;
            if let Some(module) = symbol.split('!').next() {
                if let Some(range) = modules.get_module_range(module) {
                    module_start = Some(range.start);
                }
            }

            for context in &contexts {
                if let Some(loc) = context.find_location(rip)? {
                    let mut src: Option<String> = None;
                    if let (Some(file), Some(line)) = (loc.file, loc.line) {
                        if let Ok(data) = std::fs::read_to_string(file) {
                            let mut lines = data.lines();
                            src = Some(
                                lines
                                    .nth(line.saturating_sub(1) as usize)
                                    .unwrap_or("")
                                    .to_string(),
                            );
                        }
                    }

                    let curr_line = format!(
                        "    {}:{}:{}\n    CODE: {src:?}\n",
                        loc.file.unwrap_or("??"),
                        loc.line.unwrap_or(0),
                        loc.column.unwrap_or(0)
                    );

                    result.push_str(&curr_line);

                    source_line = Some(curr_line);
                    break;
                } else if let Some(module_start) = module_start {
                    /*
                    println!(
                        "RIP {rip:#x}  Module Start {module_start:#x} Addr: {:#x}",
                        rip.saturating_sub(module_start)
                    );
                    */

                    // If the original RIP is not found in the context, naively check
                    // if the module was built as PIE by subtracting the module start from
                    // the RIP and checking addr2line for the address
                    if let Some(loc) = context.find_location(rip.saturating_sub(module_start))? {
                        let curr_line = format!(
                            "    {}:{}:{}\n",
                            loc.file.unwrap_or("??"),
                            loc.line.unwrap_or(0),
                            loc.column.unwrap_or(0)
                        );

                        result.push_str(&curr_line);

                        source_line = Some(curr_line);
                        break;
                    }
                }
            }

            // At a new call site, write the call arguments
            // If the call site was a jmp, go to the next instruction instead of the jmp site
            if fuzzvm.single_step && at_call && !instr.contains("jmp") {
                let symbol = symbol
                    .replace("+0x0", "")
                    .replace("UnknownSym", &format!("{:#x}", fuzzvm.rip()));

                let arg1 = fuzzvm.rdi();
                let arg2 = fuzzvm.rsi();
                let arg3 = fuzzvm.rdx();
                let arg4 = fuzzvm.rcx();
                let call_indent = " ".repeat(indent);

                let mut curr_res = String::new();
                curr_res.push_str(&format!("{call_indent}{symbol}("));
                if let Ok(a1) = fuzzvm.read_c_string(VirtAddr(arg1), fuzzvm.cr3()) {
                    if a1.len() > 2 {
                        curr_res.push_str(&format!("{a1:?}, "));
                    } else {
                        curr_res.push_str(&format!("{arg1:#x}, "));
                    }
                } else {
                    curr_res.push_str(&format!("{arg1:#x}, "));
                }
                if let Ok(a2) = fuzzvm.read_c_string(VirtAddr(arg2), fuzzvm.cr3()) {
                    if a2.len() > 2 {
                        curr_res.push_str(&format!("{a2:?}, "));
                    } else {
                        curr_res.push_str(&format!("{arg2:#x}, "));
                    }
                } else {
                    curr_res.push_str(&format!("{arg2:#x}, "));
                }
                if let Ok(a3) = fuzzvm.read_c_string(VirtAddr(arg3), fuzzvm.cr3()) {
                    if a3.len() > 2 {
                        curr_res.push_str(&format!("{a3:?}, "));
                    } else {
                        curr_res.push_str(&format!("{arg3:#x}, "));
                    }
                } else {
                    curr_res.push_str(&format!("{arg3:#x}, "));
                }
                if let Ok(a4) = fuzzvm.read_c_string(VirtAddr(arg4), fuzzvm.cr3()) {
                    if a4.len() > 2 {
                        curr_res.push_str(&format!("{a4:?}, "));
                    } else {
                        curr_res.push_str(&format!("{arg4:#x}, "));
                    }
                } else {
                    curr_res.push_str(&format!("{arg4:#x}"));
                }

                curr_res.push(')');

                if let Some(source) = source_line {
                    curr_res.push_str(&format!(" : {source:?}"));
                }

                // func_index += 1;
                func_indexes.push(funcs.len());

                funcs.push((curr_res, None));

                at_call = false;
            }

            // Mark that the next instruction is a call site to write to the function trace
            if fuzzvm.single_step && instr.contains("call") {
                at_call = true;
                indent += 1;
            }

            // Mark that the next instruction is a call site to write to the function trace
            if fuzzvm.single_step && interrupt_routines.contains(&rip) {
                at_call = true;
                indent += 1;
            }

            // Mark that the next instruction is a call site to write to the function trace
            if fuzzvm.single_step && instr.contains("ret") {
                indent = indent.saturating_sub(1);

                let ret = fuzzvm.rax();
                let curr_index = func_indexes.pop().unwrap_or(0xdead);
                if let Some(item) = funcs.get_mut(curr_index) {
                    item.1 = Some(ret);
                }
            }

            // Check if we hit the ASAN error reporter and parse the ASAN data if so
            if symbol.contains("ReportGenericError") {
                let pc = fuzzvm.rdi() - 1;
                let sp = fuzzvm.rsi();
                let bp = fuzzvm.rdx();
                let crashing_addr = fuzzvm.rcx();
                let is_write = fuzzvm.r8b();
                let size = fuzzvm.r9b();
                let _fatal = fuzzvm.read::<u64>(VirtAddr(fuzzvm.rsp() + 0x10), fuzzvm.cr3())? == 1;

                // Get the current symbol at the current instruction
                let sym = fuzzvm
                    .get_symbol(pc)
                    .unwrap_or_else(|| "Unknown symbol".to_string());

                // Get the instruction message
                let instr_msg = if let Ok((instr, _)) = fuzzvm
                    .memory
                    .get_instruction_string_at(VirtAddr(pc), fuzzvm.cr3())
                {
                    instr
                } else {
                    String::from("???")
                };

                result.push_str("AddressSanitizer\n");
                result.push_str(&format!(
                    "{} {} PC: {:#x} {} {} SP: {:#x} BP: {:#x} CRASHING: {:#x}",
                    if is_write > 0 { "WRITE" } else { "READ" },
                    size,
                    pc,
                    sym,
                    instr_msg,
                    sp,
                    bp,
                    crashing_addr
                ));

                let offset = i64::try_from(crashing_addr & 0xf).unwrap();

                // Print a hexdump around the crashing address, highlighting the crashing
                // address
                for index in -0x40_i64 - offset..0x40_i64 + offset {
                    let addr = i64::try_from(crashing_addr);
                    if addr.is_err() {
                        break;
                    }

                    let addr = i64::try_from(crashing_addr).unwrap() + index;

                    if addr % 0x10 == 0 {
                        result.push_str(&format!("\n{addr:#x}: "));
                    }

                    let addr = u64::try_from(addr).unwrap_or(0x1337_1337_1337_1337);

                    let byte = fuzzvm.read::<u8>(VirtAddr(addr), fuzzvm.cr3());

                    match byte {
                        Ok(val) => result.push_str(&format!(
                            "{}{:02x}{}",
                            if crashing_addr == addr { "[" } else { " " },
                            val,
                            if crashing_addr == addr { "]" } else { " " },
                        )),
                        Err(_) => result.push_str(&format!(
                            "{}??{}",
                            if crashing_addr == addr { "[" } else { " " },
                            if crashing_addr == addr { "]" } else { " " }
                        )),
                    }
                }

                // Add the finishing newline
                result.push('\n');
            }

            // Reset the VM if the vmexit handler says so
            if matches!(execution, Execution::Reset | Execution::CrashReset { .. }) {
                break;
            }

            // Execute the VM
            let ret = fuzzvm.run(&mut perf)?;

            match ret {
                FuzzVmExit::KasanRead { ip, size, addr } => {
                    // Write the current line to the trace
                    result.push_str(&format!(
                        "INSTRUCTION KASAN READ ip: {ip:#x} size: {size:#x} addr {addr:#x}\n",
                    ));
                }
                FuzzVmExit::KasanWrite { ip, size, addr } => {
                    // Write the current line to the trace
                    result.push_str(&format!(
                        "INSTRUCTION KASAN WRITE ip: {ip:#x} size: {size:#x} addr {addr:#x}\n",
                    ));
                }
                _ => {}
            }

            // Handle the FuzzVmExit to determine
            let ret = handle_vmexit(&ret, &mut fuzzvm, &mut fuzzer, None, &input, None);

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
                if let Ok(new_execution) = fuzzvm.handle_breakpoint(&mut fuzzer, &input, None) {
                    execution = new_execution;
                } else {
                    // Ignore the unknown breakpoint case since we check every instruction due to
                    // single stepping here.
                }
            }

            // Check if the VM needs to be timed out
            if fuzzvm.start_time.elapsed() > vm_timeout {
                log::warn!("Tracing VM Timed out.. exiting");
                execution = Execution::Reset;
            }
        }

        log::info!("Tracing took {:4.2?}", start.elapsed());

        // Write the trace file to disk
        let mut trace_file = if let Some(input_case) = input_case {
            let traces_dir = project_state.path.join("traces");
            if !traces_dir.exists() {
                std::fs::create_dir(&traces_dir)?;
            }

            let orig_file_name = input_case
                .file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new("UNKNOWNFILENAME"))
                .to_string_lossy();

            let mut trace_file = traces_dir.join(format!("{orig_file_name:?}_{iter}"));
            if single_step {
                trace_file.set_file_name(format!("{orig_file_name}_trace"));
            } else {
                trace_file.set_file_name(&format!("{orig_file_name}_trace.no_single_step"));
            }

            trace_file
        } else {
            // No input file given. Just executing the snapshot as is.
            PathBuf::from("default.trace")
        };

        let func_trace_file = trace_file.with_extension(format!("func_trace_{iter}"));

        log::info!("Writing trace file: {:?}", trace_file);
        std::fs::write(&trace_file, result)?;

        if single_step {
            log::info!("Writing func trace file: {:?}", func_trace_file);
            let mut result = String::new();
            for (func, ret) in funcs {
                let ret = if let Some(ret) = ret {
                    format!("{ret:#x}")
                } else {
                    "NORET".to_string()
                };

                result.push_str(&format!("{func} = {ret}\n"));
            }
            std::fs::write(&func_trace_file, result)?;
        }

        // Dump the finishing context
        fuzzvm.print_context()?;

        // If there was console output, write that alongside the trace file
        if !fuzzvm.console_output.is_empty() {
            trace_file.set_extension("console_output");
            log::info!("Writing console_output file: {:?}", trace_file);
            std::fs::write(trace_file, &fuzzvm.console_output)?;
        }

        // Reset the guest state
        let _guest_reset_perf = fuzzvm.reset_guest_state(&mut fuzzer)?;

        // Reset the fuzzer state
        fuzzer.reset_fuzzer_state();
    }

    Ok(())
}
/// Execute the Trace subcommand to gather a single step trace over an input
pub(crate) fn run<FUZZER: Fuzzer>(
    project_state: &ProjectState,
    args: &cmdline::Trace,
) -> Result<()> {
    if let Some(input) = &args.input {
        log::info!("Gathering single step trace of {:?}", input);
    } else {
        log::info!("Gathering single step trace of the starting snapshot");
    }

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

    let mut covbp_bytes = BTreeMap::new();

    /*
    // Apply coverage breakpoints or not
    let mut mem = crate::memory::Memory::from_addr(clean_snapshot_addr);
    {
        let curr_clean_snapshot = clean_snapshot.write().unwrap();
        let cr3 = Cr3(project_state.vbcpu.cr3);
        for addr in project_state.coverage_breakpoints.as_ref().unwrap() {
            if let Ok(orig_byte) = curr_clean_snapshot.read::<u8>(*addr, cr3) {
                covbp_bytes.insert(*addr, orig_byte);
                curr_clean_snapshot.write::<u8>(*addr, cr3, 0xcc, crate::memory::WriteMem::Dirty);
            }
        }
    }
    */

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
        Some(covbp_bytes), // No need to apply coverage breakpoints for tracing
        &args.input,
        args.timeout,
        !args.no_single_step,
        project_state,
    )?;

    // Exit the program
    Ok(())
}
