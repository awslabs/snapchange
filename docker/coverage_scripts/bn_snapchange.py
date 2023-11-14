#!/usr/bin/env python3
"""
Snapchange Analysis for Binary Ninja - doubles as plugin and command line script

* `python3 bn_snapchange.py --analysis --bps ./examples/01_getpid/example1`
* Copy/Symlink to your binary ninja plugins directory

"""

import enum
import json
import math
import os
import string
import struct
import sys
from pathlib import Path

if __name__ == "__main__":
    # disable plugin loading etc. if we are in headless script mode - need to
    # do this before importing binaryninja
    os.environ["BN_DISABLE_USER_SETTINGS"] = "True"
    os.environ["BN_DISABLE_USER_PLUGINS"] = "True"
    os.environ["BN_DISABLE_REPOSITORY_PLUGINS"] = "True"

from typing import List, Optional

import binaryninja as bn
import binaryninja._binaryninjacore as core
from binaryninja import (
    BackgroundTaskThread,
    BranchType,
    HighLevelILOperation,
    LowLevelILInstruction,
    LowLevelILOperation,
    MediumLevelILInstruction,
    MediumLevelILOperation,
)

# from binaryninja.log import log_debug, log_error, log_info, log_warn
from binaryninja.lowlevelil import LowLevelILFlag

LOG_ID = "snapchange"


def log_debug(msg, rtype=LOG_ID):
    return bn.log.log_debug(msg, rtype)


def log_warn(msg, rtype=LOG_ID):
    return bn.log.log_warn(msg, rtype)


def log_info(msg, rtype=LOG_ID):
    return bn.log.log_info(msg, rtype)


def log_error(msg, rtype=LOG_ID):
    return bn.log.log_error(msg, rtype)


DEFAULT_IGNORE = ["asan", "ubsan", "msan", "lcov", "sanitizer", "interceptor"]

ALPHANUM = set(string.ascii_letters + string.digits)
STR_LEN_THRESHOLD = 128


class FunctionAlias(enum.Enum):
    """
    Used to identify aliases of common comparison functions,
    e.g., strcmp and curl_strequal, which are essentially the same.
    """

    MEMCMP = 1
    STRCMP = 2
    STRNCMP = 3
    STRCASECMP = 4
    STRNCASECMP = 5
    MEMCHR = 6
    RETURN_STATUS_FUNCTION = 100


FUNCTION_ALIASES = {
    # essentially strcmp
    "strcmp": FunctionAlias.STRCMP,
    "xmlStrcmp": FunctionAlias.STRCMP,
    "xmlStrEqual": FunctionAlias.STRCMP,
    "g_strcmp0": FunctionAlias.STRCMP,
    "curl_strequal": FunctionAlias.STRCMP,
    "strcsequal": FunctionAlias.STRCMP,
    # essentially memcmp
    "memcmp": FunctionAlias.MEMCMP,
    "bcmp": FunctionAlias.MEMCMP,
    "CRYPTO_memcmp": FunctionAlias.MEMCMP,
    "OPENSSL_memcmp": FunctionAlias.MEMCMP,
    "memcmp_const_time": FunctionAlias.MEMCMP,
    "memcmpct": FunctionAlias.MEMCMP,
    # essentially strncmp
    "strncmp": FunctionAlias.STRNCMP,
    "xmlStrncmp": FunctionAlias.STRNCMP,
    "curl_strnequal": FunctionAlias.STRNCMP,
    # strcasecmp
    "strcasecmp": FunctionAlias.STRCASECMP,
    "stricmp": FunctionAlias.STRCASECMP,
    "ap_cstr_casecmp": FunctionAlias.STRCASECMP,
    "OPENSSL_strcasecmp": FunctionAlias.STRCASECMP,
    "xmlStrcasecmp": FunctionAlias.STRCASECMP,
    "g_strcasecmp": FunctionAlias.STRCASECMP,
    "g_ascii_strcasecmp": FunctionAlias.STRCASECMP,
    "Curl_strcasecompare": FunctionAlias.STRCASECMP,
    "Curl_safe_strcasecompare": FunctionAlias.STRCASECMP,
    "cmsstrcasecmp": FunctionAlias.STRCASECMP,
    # strncasecmp
    "strncasecmp": FunctionAlias.STRNCASECMP,
    "strnicmp": FunctionAlias.STRNCASECMP,
    "ap_cstr_casecmpn": FunctionAlias.STRNCASECMP,
    "OPENSSL_strncasecmp": FunctionAlias.STRNCASECMP,
    "xmlStrncasecmp": FunctionAlias.STRNCASECMP,
    "g_ascii_strncasecmp": FunctionAlias.STRNCASECMP,
    "Curl_strncasecompare": FunctionAlias.STRNCASECMP,
    "g_strncasecmp": FunctionAlias.STRNCASECMP,
    "memchr": FunctionAlias.MEMCHR,
}

errored_functions = set()


class SnapchangeTask(BackgroundTaskThread):

    TASK_NAME = "Snapchange Analysis"

    def __init__(
        self,
        bv: bn.BinaryView,
        ignore: Optional[List[str]] = None,
        location: Optional[Path] = None,
    ):
        """

        bv:
            binaryview to work on - provided by the GUI or needs to be manually opened
        location:
            file location to save the result to
        """
        BackgroundTaskThread.__init__(self, self.TASK_NAME, True)
        self.bv = bv
        self.ignore = ignore
        self.location = location


class SnapchangeCoverageBreakpoints(SnapchangeTask):
    TASK_NAME = "Snapchange Coverage Breakpoints"

    def run(self):
        bv = self.bv
        binary = Path(bv.file.filename)
        # binary_name = binary.with_suffix("").name

        blacklist = DEFAULT_IGNORE
        if self.ignore:
            blacklist.extend(self.ignore)
        log_info(f"Ignore functions: {blacklist}", LOG_ID)

        ignored_functions = set()

        # Collect functions not in the blacklist
        funcs = []
        for i, func in enumerate(bv.functions):
            if self.cancelled:
                return

            self.progress = f"{self.TASK_NAME} - {i + 1} / {len(bv.functions)} funcs"
            # If any of the blacklist substrings are found in the function name, ignore it
            if any(black for black in blacklist if black in func.name):
                log_debug(f"Ignoring {func.name}", LOG_ID)
                ignored_functions.add(str(func))
                continue

            funcs.append(func)

        # Looking to specifically ignore basic blocks of the `jmp` after an `asan_report` call
        # This is due to that `jmp` being seen as the next source line in DWARF, making the .lcov
        # coverage file inconsisent

        #        ┌─────────────────────────────────────────────────────────┐
        #        │  0x5936e6 [og]                                          │
        #        │ mov rax, qword [rbx + 0x260]                            │
        #        │ and rax, 7                                              │
        #        │ add rax, 1                                              │
        #        │ mov cl, byte [rbx + 0x257]                              │
        #        │ cmp al, cl                                              │
        #        │ jl 0x593713                                             │
        #        └─────────────────────────────────────────────────────────┘
        #                       f t
        #                       │ │
        #                       │ └────────────────────┐
        #       ┌───────────────┘                      │
        #       │                                      │
        #   ┌───────────────────────────────────────┐  │
        #   │ [0x593707]                            │  │
        #   │ mov rdi, qword [rbx + 0x260]          │  │
        #   │ call sym.__asan_report_store2_noabort │  │
        #   └───────────────────────────────────────┘  │
        #       v                                      │
        #       │                                      │
        #       └────────────────┐ ┌───────────────────┘
        #                        │ │
        #                        │ │
        #                ┌────────────────────┐  <-- IGNORE THIS BLOCK
        #                │  0x593713 [oj]     │
        #                │ jmp 0x593718       │
        #                └────────────────────┘
        bad_blocks = []
        for func in funcs:
            if self.cancelled:
                return
            for bb in func:
                if (
                    bb.instruction_count == 1
                    and len(bb.outgoing_edges) == 1
                    and len(bb.incoming_edges) == 2
                ):
                    text = []
                    for edge in bb.incoming_edges:
                        block_text = [
                            str(x) for x in edge.source.get_disassembly_text()
                        ]
                        text.extend(block_text)

                    text = " ".join(text)
                    if "asan_report" in text:
                        bad_blocks.append(bb.start)

        # Get all basic block and block edges that aren't that asan_report finish basic block
        blocks = [
            hex(bb.start) for func in funcs for bb in func if bb.start not in bad_blocks
        ]

        if ignored_functions:
            log_info(f"ignored the following functions: {ignored_functions}", LOG_ID)

        log_info(f"found {len(blocks)} basic blocks", LOG_ID)

        if self.location:
            location = self.location
        else:
            location = binary.parent / (binary.name + ".covbps")
        log_info(f"Writing coverage breakpoints to '{location}'", LOG_ID)
        with open(location, "w") as f:
            f.write("\n".join(blocks))


class SnapchangeCovAnalysis(SnapchangeTask):
    """
    Background task for coverage analysis consumable by snapchange.
    """

    TASK_NAME = "Snapchange Coverage Analysis"

    def run(self):
        bv = self.bv
        binary = Path(bv.file.filename)
        binary_name = binary.with_suffix("").name

        blacklist = DEFAULT_IGNORE
        if self.ignore:
            blacklist.extend(self.ignore)
        log_info(f"Ignore functions: {blacklist}", LOG_ID)

        # Lookup table from address to index into the list of basic blocks
        lookup = {}

        # All basic block nodes
        nodes = []

        # Found cross references from functions. Used identify "parent" edges to functions to
        # allow for inter-functional updates of scores.
        function_calls = []

        ignored_functions = set()

        for i, func in enumerate(bv.functions):
            if self.cancelled:
                return

            self.progress = f"{self.TASK_NAME} - {i + 1} / {len(bv.functions)} funcs"

            # If any of the blacklist substrings are found in the function name, ignore it
            if any(black for black in blacklist if black in func.name):
                log_debug(f"Ignoring {func.name}", LOG_ID)
                ignored_functions.add(str(func))
                continue

            # if func.analysis_skipped:
            #     fn = str(func)
            #     if fn not in errored_functions:
            #         skip_reason = str(func.analysis_skip_reason)
            #         log_warn(f"Analysis skipped for {func} | {skip_reason}")
            #         errored_functions.add(func)

            # If this function doesn't have LLIL, display the warning only once
            if func.low_level_il is None:
                fn = str(func)
                if fn not in errored_functions:
                    log_warn(f"Analysis skipped for {func} | missing LLIL")
                    errored_functions.add(func)

            for bb in func:
                # Get the starting address for this basic block
                start = bb.start

                # Cache this node for easy lookup by address
                lookup[start] = len(nodes)

                # Initialize this node's data
                node = {}
                node["address"] = start
                node["children"] = list(set(x.target.start for x in bb.outgoing_edges))
                node["dominator_tree_children"] = set(
                    x.start for x in bb.dominator_tree_children
                )
                node["parents"] = set()

                # Add incoming edges that are not in a loop
                for edge in bb.incoming_edges:
                    incoming_block = edge.source
                    in_loop = False

                    # Check if the current basic block is in the incoming edge's dominator
                    # If so, it is part of a loop and should not be considered when backtracking
                    # information through the incoming edges
                    for dom in incoming_block.dominators:
                        if bb.start == dom.start:
                            # log_warn(f"Ignoring loop basic block! {incoming_block.start:#x} in loop {dom.start:#x}")
                            in_loop = True
                    if not in_loop:
                        node["parents"].add(incoming_block.start)

                node["function"] = func.name
                node["function_offset"] = start - func.start
                node["called_funcs"] = []
                node["dominators"] = list(
                    set(x.start for x in bb.dominators if x.start != start)
                )

                if func.llil:
                    # Check if there is a constant function in the block. If so, add the function as child.
                    llil = func.get_low_level_il_at(start)
                    if not hasattr(llil, "il_basic_block"):
                        continue

                    if llil.il_basic_block is None:
                        continue

                    for il in llil.il_basic_block:
                        if not il.operation == LowLevelILOperation.LLIL_CALL:
                            continue

                        if not il.dest.operation == LowLevelILOperation.LLIL_CONST_PTR:
                            continue

                        # Ensure the called function isn't on the blacklist
                        called_func = bv.get_function_at(il.dest.constant)

                        # If any of the blacklist substrings are found in the function name, ignore it
                        if hasattr(called_func, "name") and any(
                            [black for black in blacklist if black in called_func.name]
                        ):
                            # log_warn(f"Ignoring called {called_func.name} from {func.name}")
                            continue

                        # Do not recurse into the current function
                        if called_func == func:
                            continue

                        # Found a function that is called in this basic block. Add this function
                        # to the node to add the score of the entire function to this basic block
                        node["called_funcs"].append(il.dest.constant)
                        function_calls.append((start, il.dest.constant))

                node["dominator_tree_children"] = list(node["dominator_tree_children"])

                # Add the node to the list of all nodes
                nodes.append(node)

        # Add the found function cross references as parents for each function to allow
        # inter-funtion score updates
        for (caller, callee) in function_calls:
            node_index = lookup.get(callee, None)
            if node_index is None:
                # node_addr = node['address']
                callee = int(callee)
                caller = int(caller)
                log_error(
                    f"ERROR: Check this called function! Function call not found: {caller:#x} -> {callee:#x}",
                    LOG_ID,
                )
            else:
                nodes[node_index]["dominators"].append(caller)

        if ignored_functions:
            log_info(f"ignored the following functions: {ignored_functions}", LOG_ID)

        # Make the `parents` a list to allow for JSON serialization
        for node in nodes:
            node["parents"] = list(node["parents"])

        filename = binary.parent / f"{binary_name}.coverage_analysis"
        if self.location:
            location = self.location
        else:
            location = filename
        log_info(f"Writing coverage analysis to '{location}'", LOG_ID)
        with open(location, "w") as f:
            f.write(json.dumps(nodes))


class SnapchangeCmpAnalysis(SnapchangeTask):
    TASK_NAME = "Snapchange Cmp Analysis"

    def __init__(
        self,
        bv: bn.BinaryView,
        ignore: Optional[List[str]] = None,
        cmp_location: Optional[Path] = None,
        dict_location: Optional[Path] = None,
    ):
        """

        bv:
            binaryview to work on - provided by the GUI or needs to be manually opened
        location:
            file location to save the result to
        """
        BackgroundTaskThread.__init__(self, self.TASK_NAME, True)
        self.bv = bv
        self.ignore = ignore
        self.cmp_location = None
        if cmp_location:
            self.cmp_location = Path(cmp_location)
        self.dict_location = None
        if dict_location:
            self.dict_location = Path(dict_location)

    def run(self):
        cmps, autodict = run_cmp_analysis(self.bv, self.ignore, self)
        if self.cancelled or (cmps is None and autodict is None):
            return
        if self.cmp_location:
            with self.cmp_location.open("w") as f:
                f.write("\n".join(map(lambda c: str(c).strip(), cmps)))
        if self.dict_location:
            self.dict_location.mkdir(parents=True, exist_ok=True)
            for entry in autodict:
                write_dict_entry(entry, self.dict_location)


def write_dict_entry(entry, location: Path):
    if isinstance(entry, int):
        entry = abs(entry)
        # identify the size of constant - we always use the smallest possible one
        if entry < (1 << 8):
            # we don't bother with byte-size constants
            return
        if entry < (1 << 16):
            size = 2
        elif entry < (1 << 32):
            size = 4
        elif entry < (1 << 64):
            size = 8
        elif entry < (1 << 128):
            size = 16
        elif entry < (1 << 256):
            size = 32
        elif entry < (1 << 512):
            size = 64
        else:
            log_warn("unsupported int constant is too big: " + hex(entry))

        # emit both endian - who knows.
        for endian in ("little", "big"):
            data = entry.to_bytes(size, endian)
            fname = endian + "_" + hex(entry)
            with (location / fname).open("wb") as f:
                f.write(data)

        # emit as ascii str
        fname = "int_str_" + str(entry).replace("-", "neg")
        with (location / fname).open("w") as f:
            f.write(str(entry))

    elif isinstance(entry, float):
        # emit using struct.pack in various formats
        for float_fmt in ("e", "f", "d"):
            for endian in (("<", "le"), (">", "be")):
                fmt = endian[0] + float_fmt
                try:
                    buf = struct.pack(fmt, entry)
                    # don't write all 0 buffers to dict
                    if all(b == 0 for b in buf):
                        continue
                    fname = "_".join([float_fmt, endian[1], hex(hash(entry))[2:]])
                    with (location / fname).open("wb") as f:
                        f.write(buf)
                except (ValueError, OverflowError):
                    pass

        # emit as ascii str
        fname = "float_str_" + str(entry).replace(".", "_").replace("-", "neg")
        with (location / fname).open("w") as f:
            str_entry = str(entry)
            if str_entry not in ("0.0"):
                f.write(str_entry)

    elif isinstance(entry, (bytes, str)):
        fname = hex(abs(hash(entry)))
        if isinstance(entry, str):
            fname += "_" + "".join(e if e in ALPHANUM else "_" for e in entry[:8])
            entry = entry.encode()
        else:
            if all(chr(b) in ALPHANUM for b in entry):
                fname += "_" + entry.decode()[:8]
            else:
                fname += "_" + entry.hex()[:8]

        with (location / fname).open("wb") as f:
            f.write(entry)

        entry_stripped = entry.strip(b"\x00\t \n\r")
        if entry_stripped != entry:
            with (location / (str(fname) + "_trimmed")).open("wb") as f:
                f.write(entry_stripped)
    else:
        log_warn(f"cannot deal with {type(entry)} in auto-dict {entry!r}")


def int_is_interesting_for_dict(i, size, _bv=None):
    if i == 0:
        return False
    if i < 256:
        return False
    if size == 0:
        size = 4
    # convert to signed
    i_s = i
    if i_s & (1 << (size - 1)):
        i_s = -(1 << size) + i_s
    if abs(i_s) < 256:  # small signed constant
        return False
    for bits in (8, 16, 32, 64, 128, 256, 512):
        if bits > size:
            break
        shift = 1 << bits
        if i in (shift, shift - 1):
            return False
        # check if negative power
        if abs(i) in (shift, shift - 1):
            return False
    # check for some bitmask-like things to weed out.
    mask = 0
    for shift in range(0, 60, 4):
        mask = mask << 4
        mask |= 0xF
        if i == mask:
            return False
    try:
        if all(b in (0, 0xFF, 0xF0, 0x0F) for b in i.to_bytes(size, "little")):
            return False
    except OverflowError:
        pass

    # TODO: check if address -> ignore
    # if bv and bv.start <= i and i <= bv.end:
    #     return False

    # ok we found no reason to not find it interesting.
    return True


def float_is_interesting_for_dict(f, size):
    if math.isnan(f):  # ignore NaN
        return False

    if size < 4:  # ignore tiny floats
        return False

    if f == 0.0:  # ignore 0
        return False

    # ok we found no reason to not find it interesting.
    return True


def add_memory_to_dict(
    dictionary, bv, addr, memlen=STR_LEN_THRESHOLD, null_term=False, both_cases=False
):
    if addr is None or memlen is None:
        return
    if isinstance(memlen, str):
        return False
    if memlen <= 2:
        return False
    if isinstance(addr, int):
        pass  # all good
    elif isinstance(addr, str):
        if "reg" in addr:
            return False

        try:
            addr = int(addr, 0)
        except ValueError:
            s = f"cannot convert addr str {addr!r} to concrete address (type int)"
            log_error(s)
            return
    else:
        s = f"require addr to bye of type int; got {addr!r}"
        log_error(s)
        raise ValueError(s)
    if memlen > STR_LEN_THRESHOLD:
        return
    log_debug(f"auto-dict read memory @ '{addr:#x}' len {memlen}")
    data = bv.read(addr, memlen)
    if not data:
        log_debug(f"auto-dict found no data at addr  @ {addr:#x}")
        return
    if null_term:
        term = data.find(0)
        if term > 0:
            data = data[:term]
    if len(data) <= 2:  # ignore short strings
        return
    dictionary.add(data)
    log_debug(f"added data to dictionary: {data!r}")
    if both_cases:
        dictionary.add(data.upper())
        dictionary.add(data.lower())


def add_const_to_dict(bv, dictionary, c, c_size, is_float=False):
    real_size = 0
    # is_float = False
    if isinstance(c_size, str):
        if c_size[0] == "f":
            is_float = True
            c_size = c_size[1:]
        real_size = int(c_size, 0)
    else:
        real_size = c_size

    if not c_size and isinstance(c, bytes):
        real_size = len(c)

    if isinstance(c, bytes):  # was given raw bytes
        assert len(c) >= real_size
        if real_size in (2, 4, 8, 16) and not is_float:
            c = int.from_bytes(c, "little")
        elif is_float and real_size in (2, 4, 8):
            dictionary.add(c)
            if real_size == 4:
                c = struct.unpack("@f", c)[0]
            elif real_size == 8:
                c = struct.unpack("@d", c)[0]
            elif real_size == 2:
                c = struct.unpack("@e", c)[0]

    elif isinstance(c, str):
        if c.startswith("load_from"):
            x = c.split(" ")
            addr = None
            if len(x) > 1:
                try:
                    addr = int(x[1], 0)
                except ValueError:
                    addr = None

            if addr is not None:
                if not is_float:
                    try:
                        c = bv.read_int(addr, real_size)
                    except ValueError:
                        pass
                else:
                    # for floating points, we read the data as bytes
                    data = bv.read(addr, real_size)
                    # add the float bytes to the dictionary
                    dictionary.add(c)
                    # but we also attempt to convert to an actual float value using struct
                    # not sure this is always accurate.
                    try:
                        if real_size == 4:
                            c = struct.unpack("@f", data)[0]
                        elif real_size == 8:
                            c = struct.unpack("@d", data)[0]
                        elif real_size == 2:
                            c = struct.unpack("@e", data)[0]
                    except ValueError:
                        return
            else:
                # can't load non-constant from memory...
                return
        elif c.startswith("reg"):
            # not a constant
            return
        else:
            try:
                if is_float or "." in c:
                    c = float(c)
                else:
                    c = int(c, 0)
            except ValueError:
                # log_warn(f"failed to convert {c!r} into number")
                return

    if isinstance(c, int):
        if int_is_interesting_for_dict(c, real_size, bv):
            dictionary.add(c)
    elif isinstance(c, float):
        if float_is_interesting_for_dict(c, real_size):
            dictionary.add(c)
    else:
        # is there something else?
        dictionary.add(c)


def run_cmp_analysis(bv, ignore=None, taskref=None):
    blacklist = DEFAULT_IGNORE
    if ignore:
        blacklist.extend(ignore)
    log_info(f"Ignore functions: {blacklist}", LOG_ID)

    ignored_functions = set()

    cmps = []
    dictionary = set()

    ignored_addresses = []

    for _i, func in enumerate(bv.functions):
        if taskref and taskref.cancelled:
            return (None, None)
        # If any of the blacklist substrings are found in the function name, ignore it
        if any(black for black in blacklist if black in func.name):
            log_debug(f"Ignoring {func.name}", LOG_ID)
            ignored_functions.add(str(func))
            continue

        if func.low_level_il is None:
            log_warn(f"skipping func {func!r}, because of missing LLIL")
            continue

        # Get the number of LLIL expressions (not instructions) for this function
        num_exprs = core.BNGetLowLevelILExprCount(func.llil.handle)

        # Iterate over the expressions specifically
        for expr_index in range(num_exprs):
            instr = LowLevelILInstruction.create(func.llil, expr_index, None)

            # If this instruction uses the result of a memcmp/strcmp, ignore the
            # condition as a rule has already been added from the strcmp/memcmp call site
            if instr.address in ignored_addresses:
                log_warn(f"Ignoring instruction found in ignored_addresses: {instr}")
                continue

            if instr.operation == LowLevelILOperation.LLIL_CALL:
                # Only interested in const pointer function calls
                if instr.dest.operation != LowLevelILOperation.LLIL_CONST_PTR:
                    continue

                s = bv.get_symbol_at(instr.dest.constant)
                if not s:  # check that there is a symbol
                    continue
                func_name = s.name
                func_alias = FUNCTION_ALIASES.get(func_name)
                if func_alias is not None:
                    # Get the registers used for the calling convention
                    param_regs = (
                        instr.function.source_function.calling_convention.int_arg_regs
                    )

                    # Create the register parameters
                    params = [f"reg {param_reg}" for param_reg in param_regs]

                    log_debug(
                        f"cmp function {instr.address:#x} {func_name} -> {func_alias!r} params: {params!r}"
                    )
                    strcmps = (
                        FunctionAlias.STRCMP,
                        FunctionAlias.STRCASECMP,
                        FunctionAlias.STRNCMP,
                        FunctionAlias.STRNCASECMP,
                    )
                    if func_alias in strcmps and len(params) >= 2 and all(params[:2]):
                        res = f"{instr.address:#x},0x0,{params[0]},strcmp,{params[1]}\n"
                        cmps.append(res)

                        memlen = STR_LEN_THRESHOLD
                        if (
                            len(params) >= 3
                            and params[2]
                            and func_alias
                            in (FunctionAlias.STRNCMP, FunctionAlias.STRNCASECMP)
                        ):
                            if isinstance(params[2], int):
                                memlen = params[2]
                            elif isinstance(params[2], str):
                                try:
                                    memlen = int(params[2], 0)
                                except ValueError:
                                    memlen = params[2]
                        both_cases = func_alias in (
                            FunctionAlias.STRNCASECMP,
                            FunctionAlias.STRCASECMP,
                        )
                        for p in params[:2]:
                            add_memory_to_dict(
                                dictionary,
                                bv,
                                p,
                                null_term=True,
                                memlen=memlen,
                                both_cases=both_cases,
                            )

                    if len(params) >= 3 and func_alias == FunctionAlias.MEMCMP:
                        cmp_len = None
                        if isinstance(params[2], int):
                            cmp_len = params[2]
                        elif isinstance(params[2], str):
                            try:
                                cmp_len = int(params[2], 0)
                            except ValueError:
                                cmp_len = params[2]
                        if cmp_len is not None:
                            res = f"{instr.address:#x},{cmp_len},{params[0]},memcmp,{params[1]}\n"
                            if "flag" not in res:
                                cmps.append(res)
                            else:
                                log_warn(f"Flag found! {res}")
                        for p in params[:2]:
                            add_memory_to_dict(
                                dictionary,
                                bv,
                                p,
                                null_term=False,
                                memlen=(cmp_len if cmp_len else STR_LEN_THRESHOLD),
                            )
                    if len(params) >= 3 and func_alias == FunctionAlias.MEMCHR:
                        cmp_len = None
                        if isinstance(params[2], int):
                            cmp_len = params[2]
                        elif isinstance(params[2], str):
                            try:
                                cmp_len = int(params[2], 0)
                            except ValueError:
                                cmp_len = params[2]
                        if cmp_len is not None:
                            res = f"{instr.address:#x},{cmp_len},{params[0]},memchr,{params[1]}\n"
                            if "flag" not in res:
                                cmps.append(res)

            if instr.operation in [
                LowLevelILOperation.LLIL_CMP_E,
                LowLevelILOperation.LLIL_CMP_NE,
                LowLevelILOperation.LLIL_CMP_SLT,
                LowLevelILOperation.LLIL_CMP_ULT,
                LowLevelILOperation.LLIL_CMP_SLE,
                LowLevelILOperation.LLIL_CMP_ULE,
                LowLevelILOperation.LLIL_CMP_SGE,
                LowLevelILOperation.LLIL_CMP_UGE,
                LowLevelILOperation.LLIL_CMP_SGT,
                LowLevelILOperation.LLIL_CMP_UGT,
                LowLevelILOperation.LLIL_FCMP_E,
                LowLevelILOperation.LLIL_FCMP_NE,
                LowLevelILOperation.LLIL_FCMP_LT,
                LowLevelILOperation.LLIL_FCMP_LE,
                LowLevelILOperation.LLIL_FCMP_GE,
                LowLevelILOperation.LLIL_FCMP_GT,
                LowLevelILOperation.LLIL_INTRINSIC,
            ]:
                is_float = False
                if instr.operation in (
                    LowLevelILOperation.LLIL_FCMP_E,
                    LowLevelILOperation.LLIL_FCMP_NE,
                    LowLevelILOperation.LLIL_FCMP_LT,
                    LowLevelILOperation.LLIL_FCMP_LE,
                    LowLevelILOperation.LLIL_FCMP_GE,
                    LowLevelILOperation.LLIL_FCMP_GT,
                ):
                    is_float = True

                find_ssa_defs = []
                if instr.operation != LowLevelILOperation.LLIL_INTRINSIC:
                    for curr_instr in (instr.left, instr.right):
                        find_ssa_defs.append(curr_instr)
                elif instr.operation == LowLevelILOperation.LLIL_INTRINSIC:
                    if "cmp" in str(curr_instr) and len(curr_instr.params) == 2:
                        find_ssa_defs.append(curr_instr.params[0])
                        find_ssa_defs.append(curr_instr.params[1])

                # this is a non-exhaustive ssa backtracking thing. it is mostly to cover patterns like:
                # ```
                # reg0 = [constptr]
                # if (reg0 == reg1) ...
                # ```
                while find_ssa_defs:
                    curr_instr = find_ssa_defs.pop()
                    if is_instr_const(curr_instr):
                        add_const_to_dict(
                            bv,
                            dictionary,
                            curr_instr.constant,
                            curr_instr.size,
                            is_float,
                        )
                    elif curr_instr.operation == LowLevelILOperation.LLIL_REG:
                        ssa_reg = curr_instr.ssa_form
                        if hasattr(ssa_reg, "full_reg"):
                            ssa_reg = ssa_reg.full_reg
                        elif hasattr(ssa_reg, "src"):
                            ssa_reg = ssa_reg.src
                        if (
                            hasattr(ssa_reg, "operation")
                            and ssa_reg.operation == LowLevelILOperation.LLIL_CONST
                        ):
                            add_const_to_dict(
                                bv, dictionary, ssa_reg.constant, ssa_reg.size, is_float
                            )
                        else:
                            definition = (
                                curr_instr.function.ssa_form.get_ssa_reg_definition(
                                    ssa_reg
                                )
                            )
                            if definition:
                                if hasattr(definition, "non_ssa_form"):
                                    find_ssa_defs.append(definition.non_ssa_form)
                                else:
                                    log_warn(f"{curr_instr} -> definition {definition} -> has no non-ssa-form ")
                    elif curr_instr.operation == LowLevelILOperation.LLIL_SET_REG:
                        find_ssa_defs.append(curr_instr.src)
                    elif curr_instr.operation == LowLevelILOperation.LLIL_LOAD:
                        iload = curr_instr
                        if iload.src.operation == LowLevelILOperation.LLIL_CONST_PTR:
                            add_const_to_dict(
                                bv,
                                dictionary,
                                bv.read(iload.src.constant, iload.size),
                                iload.size,
                                is_float,
                            )

                # Get the comparison rule for this instruction, using the address of the
                # full instruction
                res = get_collapsed_rule(bv, instr)

                if res is not None:
                    # Continue if the collapsed rule was ignored (like the return value comparison case)
                    if len(res) == 0:
                        continue

                    cmps.append(f"{res}\n")
                    continue

                # Get the comparison rule for this instruction, using the address of the
                # full instruction
                res = get_cmp_analysis_from_instr_llil(instr)

                # If we found a comparison rule write it to the log
                if res is not None:
                    cmps.append(f"{res}\n")
                    res_split = res.split(",")
                    size = res_split[1]
                    op1 = res_split[-1]
                    op2 = res_split[-3]
                    for op in (op1, op2):
                        is_float = False
                        if "FCMP" in res:
                            is_float = True
                        add_const_to_dict(bv, dictionary, op, size, is_float)

            # Special case unimplemented instructions
            if instr.operation == LowLevelILOperation.LLIL_UNIMPL:
                disasm = bv.get_disassembly(instr.address).replace(",", "").split()
                if disasm[0] == "sbb":
                    instr_length = bv.get_instruction_length(instr.address, bv.arch)
                    next_addr = instr.address + instr_length
                    next_instr = bv.get_disassembly(next_addr)
                    print(next_instr)
                    comparison = "CMP_SLT"
                    if "jb" in next_instr:
                        comparison = "CMP_SLT"
                    if "jae" in next_instr:
                        comparison = "CMP_SGE"

                    reg_size = bv.arch.regs[disasm[1]].size

                    res = f"{instr.address:#x},{reg_size:#x},reg {disasm[1]},{comparison},reg {disasm[2]}\n"
                    cmps.append(res)

    return (cmps, dictionary)


def get_config(bv, more_fields=None):
    """
    Helper method to get relocation address and ignorelist via the binary ninja
    GUI interaction components.
    """

    rebase_field = bn.interaction.AddressField("Image Base Address", view=bv, default=0)
    ignore_field = bn.interaction.TextLineField("Ignore Functions")

    fields = [
        f"Specify the base address for the image. BN image base is {bv.start:#x}.\n(leave empty or `0` for no relocation or if already rebased)",
        rebase_field,
        "Configure functions to ignore containing the following strings\n(`,` delimited):",
        ignore_field,
    ]
    if more_fields:
        fields.extend(more_fields)
    user_cancelled = not bn.interaction.get_form_input(
        fields, "Snapchange Analysis Export"
    )
    if user_cancelled:
        log_debug("user cancelled")
        return None

    base_addr = rebase_field.result
    ignore = ignore_field.result

    # configure base addr
    if base_addr is None:
        base_addr = 0

    # update functions to ignore
    nopelist = []
    if ignore:
        if "," in ignore:
            nopelist.extend(s.strip() for s in ignore.split(","))
        else:
            nopelist.append(ignore.strip())

    return (base_addr, nopelist)


def _dump(bv, analysis=True, bps=True, cmps=False, autodict=False):
    """
    Helper function to create prompt to configur exports and then launch the respective tasks.
    """
    assert analysis or bps or cmps or autodict

    # Get the path to the binary
    binary = Path(bv.file.filename)

    # Remove the extension to retrieve the base name of the file
    binary_name = binary.with_suffix("").name

    more_fields = []
    cov_analysis_field_location = None
    if analysis:
        filename = binary.parent / (binary_name + ".coverage_analysis")
        cov_analysis_field_location = bn.interaction.SaveFileNameField(
            "Coverage Analysis File", ext="coverage_analysis", default=str(filename)
        )
        more_fields.append(cov_analysis_field_location)

    covbps_field_location = None
    if bps:
        filename = binary.parent / (binary_name + ".covbps")
        covbps_field_location = bn.interaction.SaveFileNameField(
            "Coverage Breakpoints File", ext="covbps", default=str(filename)
        )
        more_fields.append(covbps_field_location)

    if cmps:
        filename = binary.parent / (binary_name + ".cmps")
        cmps_field_location = bn.interaction.SaveFileNameField(
            "Comparison Analysis File", ext="cmps", default=str(filename)
        )
        more_fields.append(cmps_field_location)

    if autodict:
        filename = binary.parent / "dict/"

        autodict_field_location = bn.interaction.DirectoryNameField(
            "Path to auto-generated dict/ dir", default=str(filename)
        )
        more_fields.append(autodict_field_location)

    r = get_config(bv, more_fields=more_fields)
    if r is None:  # user cancelled
        return
    base_addr, nopelist = r
    if base_addr:
        bv = bv.rebase(base_addr)

    if (
        analysis
        and cov_analysis_field_location is not None
        and cov_analysis_field_location.result
    ):
        location = Path(cov_analysis_field_location.result)
        a_task = SnapchangeCovAnalysis(bv, ignore=nopelist, location=location)
        a_task.start()

    if bps and covbps_field_location is not None and covbps_field_location.result:
        location = Path(covbps_field_location.result)
        b_task = SnapchangeCoverageBreakpoints(
            bv, ignore=nopelist, location=Path(location)
        )
        b_task.start()

    if cmps or autodict:
        cmp_location = None
        dict_location = None
        if cmps and cmps_field_location is not None and cmps_field_location.result:
            cmp_location = Path(cmps_field_location.result)

        if autodict and autodict_field_location and autodict_field_location.result:
            dict_location = Path(autodict_field_location.result)

        if cmp_location or dict_location:
            c_task = SnapchangeCmpAnalysis(
                bv,
                ignore=nopelist,
                cmp_location=cmp_location,
                dict_location=dict_location,
            )
            c_task.start()


def dump_covanalyis(bv):
    """
    Coverage analysis plugin command - registered with the GUI and exposes launching the coverage analysis task.
    """
    _dump(bv, analysis=True, bps=False)


def dump_covbps(bv):
    """
    Coverage breakpoint plugin command - registered with the GUI and exposes launching the task for dumping the coverage breakpoints.
    """
    _dump(bv, analysis=False, bps=True)


def dump_both(bv):
    """
    Plugin command registered with the GUI to start both snapchange analysis
    tasks at once. This only queries the rebase address and ignorelist for
    functions once.
    """
    _dump(bv, analysis=True, bps=True)


def dump_cmp(bv):
    """
    Start only cmp dumping analysis task.
    """
    _dump(bv, bps=False, analysis=False, cmps=True, autodict=False)


def dump_autodict(bv):
    """
    Start only autodict analysis task.
    """
    _dump(bv, bps=False, analysis=False, cmps=False, autodict=True)


def dump_cmp_autodict(bv):
    """
    Start only autodict analysis task.
    """
    _dump(bv, bps=False, analysis=False, cmps=True, autodict=True)


def dump_all(bv):
    """
    Start all analysis tasks and dump to the respective files.
    """
    _dump(bv, bps=True, analysis=True, cmps=True, autodict=True)


def get_cmp_analysis_from_instr_llil(curr_instr):
    if not hasattr(curr_instr, "operation"):
        return curr_instr

    if curr_instr.operation == LowLevelILOperation.LLIL_IF:
        return get_cmp_analysis_from_instr_llil(curr_instr.condition)
    elif curr_instr.operation in [
        LowLevelILOperation.LLIL_CMP_E,
        LowLevelILOperation.LLIL_CMP_NE,
        LowLevelILOperation.LLIL_CMP_SLT,
        LowLevelILOperation.LLIL_CMP_ULT,
        LowLevelILOperation.LLIL_CMP_SLE,
        LowLevelILOperation.LLIL_CMP_ULE,
        LowLevelILOperation.LLIL_CMP_SGE,
        LowLevelILOperation.LLIL_CMP_UGE,
        LowLevelILOperation.LLIL_CMP_SGT,
        LowLevelILOperation.LLIL_CMP_UGT,
        LowLevelILOperation.LLIL_FCMP_E,
        LowLevelILOperation.LLIL_FCMP_NE,
        LowLevelILOperation.LLIL_FCMP_LT,
        LowLevelILOperation.LLIL_FCMP_LE,
        LowLevelILOperation.LLIL_FCMP_GE,
        LowLevelILOperation.LLIL_FCMP_GT,
        LowLevelILOperation.LLIL_FCMP_O,
        LowLevelILOperation.LLIL_FCMP_UO,
    ]:
        # log_warn(f'{pad}TRACE {str(curr_instr.left):20} {str(curr_instr.right):20}')
        left = get_cmp_analysis_from_instr_llil(curr_instr.left)
        right = get_cmp_analysis_from_instr_llil(curr_instr.right)
        # result = {"left": left, "right": right}
        op = "_".join(str(curr_instr.operation).split("_")[1:])

        output = f"{curr_instr.address:#x},{curr_instr.size:#x},{left},{op},{right}\n"
        return output
    elif curr_instr.operation == LowLevelILOperation.LLIL_FLAG:
        if isinstance(curr_instr, LowLevelILFlag):
            # Base case for a particular bit in the flag register
            # if 'cond' in str(curr_instr.src) or 'flag' in str(curr_instr.src) or 'temp' in str(curr_instr.src):
            # Condition variable in use. Find the definition of the condition
            cond_ssa = curr_instr.ssa_form.src
            cond = curr_instr.function.get_ssa_flag_definition(cond_ssa)
            assert cond.operation == LowLevelILOperation.LLIL_SET_FLAG
            # log_warn(f'{pad}TRACE FLAG {cond}')
            res = get_cmp_analysis_from_instr_llil(cond.src)
            return f"flag {res}"
            # else:
            # log_warn(f"{address:#x} UNKNOWN FLAG: {curr_instr.src}")
            # return ['unknown']
    elif curr_instr.operation == LowLevelILOperation.LLIL_LOAD:
        # log_warn(f'{pad}TRACE {curr_instr} {str(curr_instr.operation)}')
        res = get_cmp_analysis_from_instr_llil(curr_instr.src)
        if isinstance(res, list) and len(res) == 3:
            res = " ".join(res)

        return f"load_from {res}"
    elif curr_instr.operation == LowLevelILOperation.LLIL_REG:

        # If temp if in this register, attempt to find it's definition
        if str(curr_instr.src.name) not in curr_instr.function.arch.regs:
            ssa_reg = curr_instr.ssa_form.src
            definition = curr_instr.function.ssa_form.get_ssa_reg_definition(ssa_reg)
            curr_instr = get_cmp_analysis_from_instr_llil(definition.src.non_ssa_form)
            return curr_instr

        # print(f'{pad}TRACE {curr_instr} {str(curr_instr.operation)}')
        # res = get_cmp_analysis_from_instr_llil(curr_instr.src, address, iters + 1)
        result = f"reg {curr_instr.src.name}"
        return result
    elif curr_instr.operation == LowLevelILOperation.LLIL_NOT:
        src = get_cmp_analysis_from_instr_llil(curr_instr.src)
        return f"not {src}"
    elif curr_instr.operation == LowLevelILOperation.LLIL_NEG:
        src = get_cmp_analysis_from_instr_llil(curr_instr.src)
        return f"neg {src}"
    elif curr_instr.operation == LowLevelILOperation.LLIL_OR:
        left = get_cmp_analysis_from_instr_llil(curr_instr.left)
        right = get_cmp_analysis_from_instr_llil(curr_instr.right)

        # Force constants to be the right to help the type checker
        if left.startswith("0x"):
            (left, right) = (right, left)

        return f"or {left} {right}"
    elif curr_instr.operation == LowLevelILOperation.LLIL_ADD:
        left = get_cmp_analysis_from_instr_llil(curr_instr.left)
        right = get_cmp_analysis_from_instr_llil(curr_instr.right)

        # Force constants to be the right to help the type checker
        if left.startswith("0x"):
            (left, right) = (right, left)

        return f"add {left} {right}"
    elif curr_instr.operation == LowLevelILOperation.LLIL_SUB:
        left = get_cmp_analysis_from_instr_llil(curr_instr.left)
        right = get_cmp_analysis_from_instr_llil(curr_instr.right)

        return f"sub {left} {right}"
    elif curr_instr.operation == LowLevelILOperation.LLIL_AND:
        left = get_cmp_analysis_from_instr_llil(curr_instr.left)
        right = get_cmp_analysis_from_instr_llil(curr_instr.right)

        # Force constants to be the right to help the type checker
        if left.startswith("0x"):
            (left, right) = (right, left)

        return f"and {left} {right}"
    elif curr_instr.operation == LowLevelILOperation.LLIL_LSL:
        left = get_cmp_analysis_from_instr_llil(curr_instr.left)
        right = get_cmp_analysis_from_instr_llil(curr_instr.right)

        # Force constants to be the right to help the type checker
        if left.startswith("0x"):
            (left, right) = (right, left)

        return f"lsl {left} {right}"
    elif curr_instr.operation == LowLevelILOperation.LLIL_CONST:
        # log_warn(f'{pad}TRACE CONST {curr_instr.constant:x}')
        return hex(curr_instr.constant)
    elif curr_instr.operation == LowLevelILOperation.LLIL_CONST_PTR:
        # log_warn(f'{pad}TRACE CONST_PTR {curr_instr.constant:x}')
        return f"{hex(curr_instr.constant)}"
    elif curr_instr.operation == LowLevelILOperation.LLIL_INTRINSIC:
        # TODO: Need a decent way of grouping all of the cmp mmx/sse/avx operations
        # for this check
        if "cmp" in str(curr_instr) and len(curr_instr.params) == 2:
            log_debug(f"INTRINSIC compare `{curr_instr}` @ {curr_instr.address:#x}")
            left = get_cmp_analysis_from_instr_llil(curr_instr.params[0])
            right = get_cmp_analysis_from_instr_llil(curr_instr.params[1])
            op = "CMP_E"
            if "neq" in str(curr_instr.intrinsic):
                op = "CMP_NE"
            size = 16
            if "ymm" in str(curr_instr):
                size = 32
            elif "zmm" in str(curr_instr):
                size = 64

            output = f"{curr_instr.address:#x},{size:#x},{left},{op},{right}\n"
            return output

        log_debug(
            f"{curr_instr.address:#x} UNKNOWN intrinsic @ {curr_instr.address:#x}: `{curr_instr.operation}` | {curr_instr!r}"
        )
        return None
    elif curr_instr.operation == LowLevelILOperation.LLIL_FLOAT_CONV:
        return get_cmp_analysis_from_instr_llil(curr_instr.src)

    log_warn(
        f"{curr_instr.address:#x} UNKNOWN instr @ {curr_instr.address:#x}: `{curr_instr}` ({curr_instr!r})"
    )
    return None


def is_instr_const(instr):
    """
    Returns True if this instruction is not dynamic for the purposes of compare analysis
    """
    STATIC_INSTRS = [
        LowLevelILOperation.LLIL_CONST,
        LowLevelILOperation.LLIL_CONST_PTR,
        MediumLevelILOperation.MLIL_IMPORT,
        MediumLevelILOperation.MLIL_CONST,
        MediumLevelILOperation.MLIL_CONST_PTR,
        MediumLevelILOperation.MLIL_FLOAT_CONST,
    ]

    return instr.operation in STATIC_INSTRS


def get_collapsed_rule(bv, instr):
    """
    This common pattern compares the result of an operation. We
    want to create a rule that would actually produce the result,
    and not a rule that compares the result itself

    Example:
    eax = eax & ecx
    al = eax != 0

    Would produce the rule: reg eax,CMP_NE,0x0
    Want to produce:        reg eax,CMP_E,reg ecx

    TODO: This only goes back one step for now. Look into how to solve the following:
    rsi = rsi - rdi
    rax = rsi
    rsi = rsi u>> 0x3f
    rax = rax s>> 3
    rsi = rsi + rax
    rsi = rsi s>> 1
    if (rsi == 0) then 10 @ 0x5555555551d8 else 11 @ 0x5555555551c4
    """
    if not hasattr(instr, "left") or not hasattr(instr, "right"):
        return None

    left = instr.left
    right = instr.right

    if (
        left.operation == LowLevelILOperation.LLIL_REG
        and right.operation == LowLevelILOperation.LLIL_CONST
    ):
        ssa_reg = left.ssa_form
        if hasattr(ssa_reg, "full_reg"):
            ssa_reg = ssa_reg.full_reg
        elif hasattr(ssa_reg, "src"):
            ssa_reg = ssa_reg.src

        # Get the definition of the variable being used in the comparison
        definition = instr.function.get_ssa_reg_definition(ssa_reg)
        if definition is None:  # ssa definition outside current function.
            return None

        # Ignore the following pattern. We don't want to add a redqueen rule that
        # compares against a known status code function
        #
        # rax = strcmp(..)
        # rax = rax == 0
        if definition.operation == LowLevelILOperation.LLIL_CALL:
            if hasattr(definition.dest, "constant"):
                func_name = bv.get_symbol_at(definition.dest.constant)
            else:
                log_warn(f"Call with no constant? Possibly by register? {definition}")
                func_name = "unknown_func"

            func_alias = FUNCTION_ALIASES.get(func_name)
            if func_alias in (
                FunctionAlias.MEMCMP,
                FunctionAlias.STRCMP,
                FunctionAlias.STRNCMP,
                FunctionAlias.STRCASECMP,
                FunctionAlias.STRNCASECMP,
            ):
                return ""

            # If this function return isn't known to be a status code,
            # we should check the result. For example:
            # result = checksum(..)
            # if (result == 0x1234) { .. }
            return None

        if definition.operation == LowLevelILOperation.LLIL_IF:
            # encountered a PHI in SSA. We don't backtrack any further.
            return None

        if definition.operation == LowLevelILOperation.LLIL_INTRINSIC:
            return get_cmp_analysis_from_instr_llil(definition)

        if not hasattr(definition, "src"):
            log_warn(
                f"failed to get ssa definition source for `{instr}` @ {instr.address:#x} for reg {ssa_reg} - def: ({definition!r})"
            )
            return None

        # Found a valid definition, get the src of the definition
        definition = definition.src
        if definition is None:
            return None

        # Ignore any operation that doesn't have 'left' and 'right' operands
        if not hasattr(definition, "left") or not hasattr(definition, "right"):
            return None

        # Finally, convert the left and right operands into the correct format for the rules
        left = get_cmp_analysis_from_instr_llil(definition.left)
        right = get_cmp_analysis_from_instr_llil(definition.right)
        op = "_".join(str(instr.operation).split("_")[1:])
        # def_op = "_".join(str(definition.operation).split("_")[1:]).lower()
        return f"{definition.address:#x},{instr.size:#x},{left},{op},{right}"

    return None


def is_isa_register(bv, regname):
    return regname.lower() in bv.arch.regs


def register_in_bn_ui():
    """register command in BN GUI"""
    bn.PluginCommand.register(
        "Snapchange\\Save Coverage Analysis",
        "Save Coverage Analysis for snapchange",
        dump_covanalyis,
    )
    bn.PluginCommand.register(
        "Snapchange\\Save Coverage Breakpoints",
        "Save a list of breakpoints used for coverage feedback in snapchange",
        dump_covbps,
    )
    bn.PluginCommand.register(
        "Snapchange\\Save Cov Analysis + Breakpoints",
        "Save both coverage analysis and breakpoints",
        dump_both,
    )
    bn.PluginCommand.register(
        "Snapchange\\Comparison Analysis",
        "Perform comparison analysis (redqueen)",
        dump_cmp,
    )
    bn.PluginCommand.register(
        "Snapchange\\Auto-dictionary Analysis",
        "Perform comparison analysis (auto-dict)",
        dump_autodict,
    )
    bn.PluginCommand.register(
        "Snapchange\\Comparison Analysis and Auto-Dict",
        "Perform comparison analysis (redqueen + auto-dict)",
        dump_cmp_autodict,
    )
    bn.PluginCommand.register(
        "Snapchange\\Full Analysis",
        "Perform breakpoint dump, coverage analysis, comparison analysis (cmp + autodict)",
        dump_all,
    )


def cli_main():
    """headless processing"""
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("binary", help="Path to the binary file to analyze", type=Path)
    parser.add_argument(
        "--base-addr",
        default=0,
        help="Address to rebase the binary to - check `gdb.vmmap` for base address",
        type=lambda i: int(i, 0),
    )
    parser.add_argument(
        "--ignore",
        default=[],
        nargs="+",
        help="Ignore functions with the given names (e.g., '--ignore asan')",
    )
    parser.add_argument(
        "--bn-max-function-size",
        default=65_000,
        type=int,
        help="set binary ninja analysis limit for max function size",
    )
    parser.add_argument(
        "--bn-max-analysis-time",
        default=(60 * 1000),
        type=int,
        help="set binary ninja analysis limit for max function analysis time (in ms)",
    )
    parser.add_argument(
        "--bps", action="store_true", help="dump coverage breakpoint addresses"
    )
    parser.add_argument(
        "--analysis", action="store_true", help="dump coverage analysis data"
    )
    parser.add_argument(
        "--cmp", action="store_true", help="dump comparision analysis data"
    )
    parser.add_argument(
        "--auto-dict",
        action="store_true",
        help="automatically create a dict/ directory for snapchange",
    )

    args = parser.parse_args()

    # Set the default log level to Info
    bn.log.log_to_stdout(bn.log.LogLevel.InfoLog)

    # Honor environment license information
    license_file = os.environ.get("BINARY_NINJA_LICENSE_FILE")
    license_data = os.environ.get("BINARY_NINJA_LICENSE_DATA")
    try:
        if license_file or license_data:
            if license_file:
                with open(license_file) as f:
                    license_data = f.read()
                log_info(f"Using license information from {license_file}")
            else:
                log_info("Using license information from BINARY_NINJA_LICENSE_DATA")

            bn.core_set_license(license_data)
    except Exception as e:
        log_warn(
            "Error while using environemnt license. Falling back on the system license."
        )
        log_warn(f"{e}")

    if not args.binary.exists():
        log_error(f"non-existing file passed to script {args.binary}", LOG_ID)
        sys.exit(1)

    if not args.bps and not args.analysis and not args.cmp:
        log_error("you must choose either --bps or --analysis or --cmp")
        sys.exit(1)

    log_info(
        f"starting analysis with max function size {args.bn_max_function_size} and max function analysis time {args.bn_max_analysis_time}"
    )
    # Get the BinaryView for the given binary
    options = {
        "analysis.limits.maxFunctionSize": args.bn_max_function_size,
        "analysis.limits.maxFunctionAnalysisTime": args.bn_max_analysis_time,
        "analysis.mode": "basic",
    }

    with bn.load(str(args.binary), options=options, update_analysis=True) as bv:
        # If given a different base address, rebase the BinaryView
        if args.base_addr != 0:
            bv = bv.rebase(args.base_addr)

        bv.update_analysis_and_wait()

        binary = Path(bv.file.filename)
        tasks = []

        task1 = None
        if args.analysis:
            log_info("launching coverage analysis")
            filename = binary.parent / (binary.name + ".coverage_analysis")
            task1 = SnapchangeCovAnalysis(bv, ignore=args.ignore, location=filename)
            task1.start()
            tasks.append(task1)

        task2 = None
        if args.bps:
            log_info("launching breakpoint dump")
            filename = binary.parent / (binary.name + ".covbps")
            task2 = SnapchangeCoverageBreakpoints(
                bv, ignore=args.ignore, location=filename
            )
            task2.start()
            tasks.append(task2)

        task3 = None
        if args.cmp or args.auto_dict:
            log_info("launching comparison analysis")
            filename = None
            dict_path = None
            if args.cmp:
                filename = binary.parent / (binary.name + ".cmps")
            if args.auto_dict:
                dict_path = binary.parent / "dict"
            task3 = SnapchangeCmpAnalysis(
                bv, ignore=args.ignore, cmp_location=filename, dict_location=dict_path
            )
            task3.start()
            tasks.append(task3)

        # Wait for all threads to finish
        for task in tasks:
            task.join()

    log_info("done. bye!")
    bn.shutdown()


if __name__ == "__main__":
    # run as headless script
    cli_main()
else:
    # bn imported this script as plugin
    register_in_bn_ui()
