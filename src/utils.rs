//! Various utility functions

use anyhow::Result;
use thiserror::Error;

use std::collections::hash_map::DefaultHasher;
use std::collections::VecDeque;
use std::hash::Hash;
use std::hash::Hasher;
use std::path::Path;
use std::str::FromStr;

use crate::fuzz_input::FuzzInput;
use crate::{Symbol, VirtAddr};

/// Print a hexdump representation of given data bytes
///
/// Example:
///
/// ```
/// hexdump([0x41, 0x42, 0x43, 0x44], 0xdead0000)
/// 0xdead0000: 41 42 43 44 | ABCD
/// ```
///
use crate::colors::Colorized;

/// Prints a hexdump representation of the given `data` assuming the data starts at
/// `starting_address`
pub fn hexdump(data: &[u8], starting_address: u64) {
    println!(
        "{:-^18}   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F    0123456789ABCDEF",
        " address "
    );

    let mut prev_chunk: &[u8] = &[2_u8; 0x10];
    let mut prev_chunk_id = 0;

    for (i, chunk) in data.chunks(0x10).enumerate() {
        if chunk == prev_chunk {
            if i - prev_chunk_id == 1 {
                println!(
                    "{:#018x}: {}",
                    starting_address + i as u64 * 0x10,
                    "** repeated line(s) **".red()
                );
            }
            continue;
        }

        // Store the current chunk as the most recent unique line
        prev_chunk = chunk;
        prev_chunk_id = i;

        // Display the current address
        print!("{:#018x}: ", starting_address + i as u64 * 0x10);

        // Display the bytes
        for b in chunk {
            match b {
                0x00 => print!("{:02x} ", b.green()),
                0x0a | 0xff => print!("{:02x} ", b.red()),
                0x21..0x7e => print!("{:02x} ", b.yellow()),
                0x7f => print!("{:02x} ", b.blue()),
                _ => print!("{:02x} ", b.white()),
            }
        }

        // Pad chunks that are not 16 bytes wide
        if chunk.len() < 16 {
            print!("{}", " ".repeat((16 - chunk.len()) * 3));
        }

        // Add the separation
        print!(" | ");

        // Display the bytes as characters
        for b in chunk {
            match b {
                0x00 => print!("{}", '.'.green()),
                0x0a | 0xff => print!("{}", '.'.red()),
                0x21..0x7e => print!("{}", (*b as char).yellow()),
                0x7f => print!("{}", '.'.blue()),
                _ => print!("{}", '.'.white()),
            }
        }

        // Go to the next line
        println!();
    }
}

/// Wrapper around `rdtsc`
#[must_use]
pub fn rdtsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// Returns the hash of the given input using [`DefaultHasher`]
pub fn calculate_hash<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

/// Returns the formatted hash of the given input as hexadecimal digits
pub fn hexdigest<T: Hash>(t: &T) -> String {
    let h = calculate_hash(t);
    format!("{h:016x}")
}

/// Save the [`FuzzInput`] into the directory using the hash of input as the filename
///
/// # Errors
///
/// * Given `input.to_bytes()` failed
/// * Failed to write the bytes to disk
pub fn save_input_in_dir(input: &impl FuzzInput, dir: &Path) -> Result<usize> {
    let mut input_bytes: Vec<u8> = vec![];
    input.to_bytes(&mut input_bytes)?;
    let length = input_bytes.len();

    // Create the filename for this input
    let filename = hexdigest(&input);

    // Write the input
    let filepath = dir.join(filename);
    if !filepath.exists() {
        std::fs::write(filepath, input_bytes)?;
    }

    Ok(length)
}

/// Errors that can be triggered during `project` subcommand
#[derive(Error, Debug)]
pub enum Error {
    /// Invalid symbol format: `symbol`, `symbol!offset`, `symbol+offset`
    #[error("Invalid symbol format: `symbol`, `symbol!offset`, `symbol+offset`")]
    InvalidSymbolFormat(String),

    /// Symbol offset failed to parse to a `u64`
    #[error("Symbol offset failed to parse to a `u64`")]
    InvalidSymbolOffset(String),

    /// Did not find symbol
    #[error("Invalid symbol format: `symbol`, `symbol!offset`, `symbol+offset`")]
    SymbolNotFound,
}

/// Parse the given `argument` as a `VirtAddr`
///
/// Examples:
///
/// ```
/// deadbeef
/// 0xdeadbeef
/// main
/// main+123
/// main+0x123
/// ```
///
/// # Errors
///
/// * Attempted to parse an unknown symbol format
/// * Requested symbol is not found
pub fn parse_cli_symbol(
    possible_virt_addr: &str,
    symbols: &Option<VecDeque<Symbol>>,
) -> Result<VirtAddr> {
    // Parse the given translation address or default to the starting RIP of the snapshot
    let parsed = VirtAddr::from_str(possible_virt_addr);

    if let Ok(addr) = parsed {
        Ok(addr)
    } else {
        let Some(symbols) = symbols.as_ref() else {
            return Err(Error::SymbolNotFound.into());
        };

        // Failed to parse the argument as a `VirtAddr`. Try to parse it as a
        // symbol of the following forms
        // `symbol`
        // `symbol+offset`
        let mut offset = 0;
        let virt_addr = possible_virt_addr;
        let mut symbol = virt_addr.to_string();
        let mut addr = None;

        if virt_addr.contains('+') {
            let mut iter = virt_addr.split('+');
            symbol = iter
                .next()
                .ok_or_else(|| Error::InvalidSymbolFormat(virt_addr.to_string()))?
                .to_string();

            let curr_offset = iter
                .next()
                .ok_or(Error::InvalidSymbolFormat(virt_addr.to_string()))?;

            let no_prefix = curr_offset.trim_start_matches("0x");

            // Attempt to parse the hex digit
            offset = u64::from_str_radix(no_prefix, 16)
                .map_err(|_| Error::InvalidSymbolOffset(offset.to_string()))?;
        }

        log::info!("Checking for symbol: {symbol}+{offset:#x}");

        let mut subsymbols = Vec::new();

        // Add the fuzzer specific symbols
        for Symbol {
            address,
            symbol: curr_symbol,
        } in symbols
        {
            if *curr_symbol == symbol {
                addr = Some(VirtAddr(*address).offset(offset));
            } else if curr_symbol.contains(&symbol) {
                subsymbols.push((curr_symbol, VirtAddr(*address).offset(offset)));
            }
        }

        if let Some(found) = addr {
            Ok(found)
        } else {
            if subsymbols.len() == 1 {
                log::info!("Did not find symbol {symbol}, but found 1 subsymbol.. using this one");
                return Ok(subsymbols[0].1);
            }

            log::error!("Did not find symbol {symbol}");
            if !subsymbols.is_empty() {
                log::error!("Did find symbols containing {symbol}. One of these might be a more specific symbol:");

                let min = subsymbols.len().min(50);
                if subsymbols.len() > 50 {
                    log::info!(
                        "Here are the first {min}/{} symbols containing {symbol}",
                        subsymbols.len()
                    );
                }

                for (subsymbol, _) in subsymbols.iter().take(min) {
                    log::info!("- {subsymbol}");
                }
            }

            Err(Error::SymbolNotFound.into())
        }
    }
}


/// helper functions for directly using libfuzzer binaries as harness.
pub mod libfuzzer {
    use crate::fuzzvm::FuzzVm;
    use crate::fuzzer::Fuzzer;
    use crate::addrs::VirtAddr;

    /// sets a input for libfuzzers LLVMFuzzerTestOneInput
    pub fn set_input<F: Fuzzer>(input: &[u8], fuzzvm: &mut FuzzVm<F>) -> anyhow::Result<()> {
        // Restore RIP to before the `int3 ; vmcall` snapshot point
        fuzzvm.set_rip(fuzzvm.rip() - 4);

        // Set the data buffer to the current mutated input
        let buffer = fuzzvm.rdi();
        fuzzvm.write_bytes_dirty(VirtAddr(buffer), fuzzvm.cr3(), input)?;

        // Set the length of the input
        fuzzvm.set_rsi(input.len() as u64);

        Ok(())
    }

    /// apply reset breakpoints at return address of libfuzzer's LLVMFuzzerTestOneInput
    pub fn init_vm<F: Fuzzer>(fuzzvm: &mut FuzzVm<F>) -> anyhow::Result<()> {
        let rsp = fuzzvm.rsp();
        let cr3 = fuzzvm.cr3();
        let retaddr = fuzzvm.read::<u64>(VirtAddr(rsp), cr3)?;
        fuzzvm.set_breakpoint(
            VirtAddr(retaddr),
            cr3,
            crate::fuzzer::BreakpointType::Repeated,
            crate::fuzzvm::BreakpointMemory::NotDirty,
            crate::fuzzvm::BreakpointHook::None,
        )?;
        if let Some(ref mut reset_bps) = fuzzvm.reset_breakpoints {
            reset_bps.insert((VirtAddr(retaddr), cr3), crate::fuzzer::ResetBreakpointType::Reset);
        }
        Ok(())
    }
}
