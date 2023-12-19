//! Utilites for obtaining symbols for a given address for a variety of operating systems

use serde::{Deserialize, Serialize};

use crate::fuzzer::ResetBreakpointType;

/// List of partial linux userland symbols that, if hit, signifies a crash
///
/// Each symbol given to the hypervisor is checked against this list. If there is a
/// partial match, the address of the symbol is set as a permanent breakpoint
pub(crate) const LINUX_USERLAND_SYMBOLS: &[(&str, ResetBreakpointType)] = &[
    // ASAN generic error reporting (asan_report_* functions)
    (
        "ReportGenericError",
        ResetBreakpointType::ReportGenericError,
    ),
    // ASAN out of memory report error
    ("ReportOutOfMemory", ResetBreakpointType::Crash),
    ("::Report", ResetBreakpointType::Crash),
    // StackDepotPut would crash sometimes. We don't need ASAN stack traces, so we can
    // always ignore this
    ("StackDepotPut", ResetBreakpointType::ImmediateReturn),
    // Crash on a raise call
    ("__GI_raise", ResetBreakpointType::Crash),
    // Reset when we hit exit
    ("__GI_exit", ResetBreakpointType::Reset),
    ("ld-musl-x86_64.so.1!exit", ResetBreakpointType::Reset),
    // This one is something we see with musl/static linking
    ("__libc_exit_fini", ResetBreakpointType::Reset),
    // Crash on assert()
    ("__assert_fail", ResetBreakpointType::Crash),
];

/// List of FULL linux kernel symbols that, if hit, signifies a special case to handle.
/// These symbols are exact matches vs the userland symbols which are partial matches.
/// This is separate from the userland symbols because a different CR3 is needed to check
/// if this symbol is in the guest.
///
/// Each symbol given to the hypervisor is checked against this list. If there is a
/// partial match, the address of the symbol is set as a permanent breakpoint
pub(crate) const LINUX_KERNEL_SYMBOLS: &[(&str, ResetBreakpointType)] = &[
    ("force_sig_fault", ResetBreakpointType::ForceSigFault),
    ("__die_body", ResetBreakpointType::KernelDie),
    ("do_idle", ResetBreakpointType::Reset),
    // ("notify_die", ResetBreakpointType::Reset),
    ("kasan_report", ResetBreakpointType::KasanReport),
    ("univ8250_console_write", ResetBreakpointType::ConsoleWrite),
    // ("vprintk_emit", ResetBreakpointType::ImmediateReturn),
    // ("__asan_report_load8_noabort", ResetBreakpointType::ImmediateReturn),
    // ("switch_fpu_return", ResetBreakpointType::ImmediateReturn),
    // ("write_comp_data", ResetBreakpointType::Reset),
    // ("__sanitizer_cov_trace_pc", ResetBreakpointType::ImmediateReturn),
    // ("__sanitizer_cov_trace_const_cmp4", ResetBreakpointType::ImmediateReturn),
    // ("handle_invalid_op", ResetBreakpointType::HandleInvalidOp),
    // ("handle_bug", ResetBreakpointType::HandleInvalidOp),
];

/// Symbol mapping to an address
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
pub struct Symbol {
    /// Starting address for this symbol
    pub(crate) address: u64,

    /// The name of this symbol
    pub(crate) symbol: String,
}

/// Get the symbol for the given `addr` using the given `symbols`
pub fn get_symbol(addr: u64, symbols: &crate::SymbolList) -> Option<String> {
    // Get the index to where this address can be found
    let index = symbols.binary_search_by_key(&addr, |Symbol { address, .. }| *address);

    if matches!(index, Err(0)) {
        return None;
    }

    // Get the symbol containing the address
    let Symbol {
        address: symbol_addr,
        symbol,
    } = match index {
        Ok(index) => &symbols[index],
        Err(index) => &symbols[index - 1],
    };

    // Calculate the offset into the symbol
    let offset = addr - symbol_addr;

    // Only output symbols with less than 0x100000 offset to avoid ambiguous symbols
    if offset < 0x10_0000 {
        // Return the symbol with offset
        Some(format!("{symbol}+{offset:#x}"))
    } else {
        None
    }
}
