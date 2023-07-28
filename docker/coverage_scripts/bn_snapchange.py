#!/usr/bin/env python3
"""
Snapchange Analysis for Binary Ninja - doubles as plugin and command line script

* `python3 bn_snapchange.py --analysis --bps ./examples/01_getpid/example1`
* Copy/Symlink to your binary ninja plugins directory

"""

import os
import sys
import json
from pathlib import Path

if __name__ == "__main__":
    # disable plugin loading etc. if we are in headless script mode - need to
    # do this before importing binaryninja
    os.environ["BN_DISABLE_USER_SETTINGS"] = "True"
    os.environ["BN_DISABLE_USER_PLUGINS"] = "True"
    os.environ["BN_DISABLE_REPOSITORY_PLUGINS"] = "True"

import binaryninja as bn
from binaryninja import BackgroundTaskThread
from binaryninja import LowLevelILOperation, MediumLevelILOperation, MediumLevelILInstruction, LowLevelILInstruction
from binaryninja import LowLevelILOperation, MediumLevelILOperation, HighLevelILOperation
from binaryninja.log import log_info, log_debug, log_warn, log_error
from binaryninja.lowlevelil import LowLevelILFlag
from binaryninja import BranchType

from typing import Optional, List

LOG_ID = "snapchange"

DEFAULT_IGNORE = ['asan', 'ubsan', 'msan', 'lcov', 'sanitizer', 'interceptor']

errored_functions = set()

class SnapchangeTask(BackgroundTaskThread):

    TASK_NAME = "Snapchange Analysis"

    def __init__(self,
                 bv: bn.BinaryView,
                 ignore: Optional[List[str]] = None,
                 location: Optional[Path] = None):
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
        binary_name = binary.with_suffix('').name

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
                if bb.instruction_count == 1 and len(
                        bb.outgoing_edges) == 1 and len(
                            bb.incoming_edges) == 2:
                    text = []
                    for edge in bb.incoming_edges:
                        block_text = [
                            str(x) for x in edge.source.get_disassembly_text()
                        ]
                        text.extend(block_text)

                    text = ' '.join(text)
                    if "asan_report" in text:
                        bad_blocks.append(bb.start)

        # Get all basic block and block edges that aren't that asan_report finish basic block
        blocks = [
            hex(bb.start) for func in funcs for bb in func
            if bb.start not in bad_blocks
        ]

        if ignored_functions:
            log_info(f"ignored the following functions: {ignored_functions}",
                     LOG_ID)

        log_info(f"found {len(blocks)} basic blocks", LOG_ID)

        if self.location:
            location = self.location
        else:
            location = binary.parent / (binary.name + '.covbps')
        log_info(f"Writing coverage breakpoints to '{location}'", LOG_ID)
        with open(location, 'w') as f:
            f.write('\n'.join(blocks))


class SnapchangeCovAnalysis(SnapchangeTask):
    """
    Background task for coverage analysis consumable by snapchange.
    """

    TASK_NAME = "Snapchange Coverage Analysis"

    def run(self):
        bv = self.bv
        binary = Path(bv.file.filename)
        binary_name = binary.with_suffix('').name

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

                
            # If this function doesn't have LLIL, display the warning only once
            if func.analysis_skipped:
                fn = str(func)
                if fn not in errored_functions:
                    skip_reason = str(func.analysis_skip_reason)
                    log_warn(
                        f"Analysis skipped for {func} | {skip_reason}",
                        LOG_ID)
                    errored_functions.add(func)

            for bb in func:
                # Get the starting address for this basic block
                start = bb.start

                # Cache this node for easy lookup by address
                lookup[start] = len(nodes)

                # Initialize this node's data
                node = {}
                node['address'] = start
                node['children'] = list(
                    set(x.target.start for x in bb.outgoing_edges))
                node['dominator_tree_children'] = set(
                    x.start for x in bb.dominator_tree_children)
                node['parents'] = set()

                # Add incoming edges that are not in a loop
                for edge in bb.incoming_edges:
                    incoming_block = edge.source
                    in_loop = False

                    # Check if the current basic block is in the incoming edge's dominator
                    # If so, it is part of a loop and should not be considered when backtracking
                    # information through the incoming edges
                    for dom in incoming_block.dominators:
                        if bb.start == dom.start:
                            # print(f"Ignoring loop basic block! {incoming_block.start:#x} in loop {dom.start:#x}")
                            in_loop = True
                    if not in_loop:
                        node['parents'].add(incoming_block.start)

                node['function'] = func.name
                node['function_offset'] = start - func.start
                node['called_funcs'] = []
                node['dominators'] = list(
                    set(x.start for x in bb.dominators if x.start != start))

                if func.llil:
                    # Check if there is a constant function in the block. If so, add the function as child.
                    llil =  func.get_low_level_il_at(start)
                    if not hasattr(llil,  'il_basic_block'):
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
                        if hasattr(called_func, 'name') and any([
                                black for black in blacklist
                                if black in called_func.name
                        ]):
                            # print(f"Ignoring called {called_func.name} from {func.name}")
                            continue

                        # Do not recurse into the current function
                        if called_func == func:
                            continue

                        # Found a function that is called in this basic block. Add this function
                        # to the node to add the score of the entire function to this basic block
                        node['called_funcs'].append(il.dest.constant)
                        function_calls.append((start, il.dest.constant))
                    
                node['dominator_tree_children'] = list(node['dominator_tree_children'])

                # Add the node to the list of all nodes
                nodes.append(node)

        # Add the found function cross references as parents for each function to allow
        # inter-funtion score updates
        for (caller, callee) in function_calls:
            node_index = lookup.get(callee, None)
            if node_index is None:
                log_error(
                    f"ERROR: Check this called function! Function call not found: {node_addr:#x}",
                    LOG_ID)
            else:
                nodes[node_index]['dominators'].append(caller)

        if ignored_functions:
            log_info(f"ignored the following functions: {ignored_functions}",
                     LOG_ID)

        # Make the `parents` a list to allow for JSON serialization
        for node in nodes:
            node['parents'] = list(node['parents'])

        filename = binary.parent / f'{binary_name}.coverage_analysis'
        if self.location:
            location = self.location
        else:
            location = filename
        log_info(f"Writing coverage analysis to '{location}'", LOG_ID)
        with open(location, 'w') as f:
            f.write(json.dumps(nodes))


class SnapchangeCmpAnalysis(SnapchangeTask):
    TASK_NAME = "Snapchange Cmp Analysis"

    def run(self):
        bv = self.bv
        run_cmp_analysis(bv, self.location, self.ignore)

def run_cmp_analysis(bv, cmpfile, ignore=None):
    blacklist = DEFAULT_IGNORE
    if ignore:
        blacklist.extend(ignore)
    log_info(f"Ignore functions: {blacklist}", LOG_ID)

    ignored_functions = set()

    # Collect functions not in the blacklist
    funcs = []
  
    with open(cmpfile, 'w') as f:
        ignored_addresses = []

        for i, func in enumerate(bv.functions):
            # If any of the blacklist substrings are found in the function name, ignore it
            if any(black for black in blacklist if black in func.name):
                log_debug(f"Ignoring {func.name}", LOG_ID)
                ignored_functions.add(str(func))
                continue

           
            # Initialize the seen expr_indexes so that we don't query CMP instructions
            # that are a part of the IF instructions
            expr_indexes = []

            # Keep track of the instr_indexes of MLIL_NOT conditions
            negations = []

            if func.medium_level_il is None:
                continue

            for instr in func.mlil_instructions:
                # Failed to find an instruction here. Found the end of the instructions.
                if instr.operation == MediumLevelILOperation.MLIL_NOP:
                    break

                # If this instruction uses the result of a memcmp/strcmp, ignore the 
                # condition as a rule has already been added from the strcmp/memcmp call site
                if instr.address in ignored_addresses:
                    print(f"Ignoring instruction found in ignored_addresses: {instr}")
                    continue

                if instr.operation == MediumLevelILOperation.MLIL_IF:
                    address = instr.address
                    # instr = instr.condition

                    # If the instruction is if(true) or if(false), there is nothing our input
                    # can do to affect the comparison, so continue
                    if instr.condition.operation == MediumLevelILOperation.MLIL_CONST:
                        continue

                    inverted = False
                    if instr.condition.operation == MediumLevelILOperation.MLIL_NOT:
                        # print(f'SKIPPING IF_NOT {address:#x}')
                        negations.append(address)
                        continue

                    if instr.condition.operation in [MediumLevelILOperation.MLIL_OR, MediumLevelILOperation.MLIL_AND]:
                        if instr.condition.left.operation == MediumLevelILOperation.MLIL_NOT and \
                                instr.condition.right.operation == MediumLevelILOperation.MLIL_NOT:
                            negations.append(address)

                        print(f'SKIPPING IF_[AND|OR] {address:#x}')
                        continue
                        
                    # Get the comparison rule for this instruction
                    res = get_cmp_analysis_from_instr_mlil(instr.condition, address, expr_indexes, cmp_size=None, iters=0)

                    # If we found a comparison rule write it to the log
                    if res != None:
                        if 'flag' not in res:
                            f.write(f'{address:#x},{res}\n')
                        else:
                            log_warn(f'Flag found! {res}')

                if instr.operation == MediumLevelILOperation.MLIL_CALL:
                    # Only interested in const pointer function calls 
                    if instr.dest.operation != MediumLevelILOperation.MLIL_CONST_PTR:
                        continue

                    func_name = bv.get_symbol_at(instr.dest.constant).name
                    if func_name == 'strcmp':
                        params = []
                        for param in instr.params:
                            # Get the comparison rule for this instruction
                            res = get_cmp_analysis_from_instr_mlil(param, address, expr_indexes, cmp_size=None, iters=0)

                            # If we found a comparison rule write it to the log
                            if res != None:
                                params.append(res)

                        print(f'strcmp {instr.address:#x}')
                        if len(params) > 0:
                            res = f"{instr.address:#x},0x8,{params[0]},strcmp,{params[1]}\n"
                            if 'flag' not in res:
                                f.write(res)
                            else:
                                log_warn(f'Flag found! {res}')

                    if func_name == 'memcmp':
                        params = []
                        for param in instr.params[:2]:
                            # Get the comparison rule for this instruction
                            res = get_cmp_analysis_from_instr_mlil(param, address, expr_indexes, cmp_size=None, iters=0)

                            # If we found a comparison rule write it to the log
                            if res != None:
                                params.append(res)

                        if len(params) > 0:
                            cmp_len = get_cmp_analysis_from_instr_mlil(instr.params[2], address, expr_indexes, cmp_size=None, iters=0)
                            if not cmp_len.startswith("0x"):
                                print(f"Found memcmp with dynamic size: {instr.address:#x}. Look into this!")
                            else:
                                res = f"{instr.address:#x},{cmp_len},{params[0]},memcmp,{params[1]}\n"
                                if 'flag' not in res:
                                    f.write(res)
                                else:
                                    log_warn(f'Flag found! {res}')

                    # For these functions, we are adding the rules at the call site and not the
                    # condition site. Ignore where the result of these functions is being used
                    # in a future condition
                    # 
                    # Example:
                    #   # Rule added here (at the call site)
                    #   rax_6 = strcmp(rdi_1, "password1234567") 
                    #   # Condition ignored here (at the cmp site)
                    #   if (rax_6.eax == 0) then 35 @ 0x1395 else 36 @ 0x12cd 
                    if func_name in ['memcmp', 'strcmp']:
                        ssa_func = instr.ssa_form.function
                        output = instr.ssa_form.output
                        if len(output) > 0:
                            output = output[0]
                            for use in ssa_func.get_ssa_var_uses(output):
                                if use.operation == MediumLevelILOperation.MLIL_IF:
                                    ignored_addresses.append(use.address)

            # Look for specific CMP instructions that are not in an IF explicitly
            for expr_index in range(0, 0x10000):
                if expr_index in expr_indexes:
                    continue

                instr = MediumLevelILInstruction.create(func.medium_level_il, expr_index)

                # Failed to find an instruction here. Found the end of the instructions.
                if instr.operation == MediumLevelILOperation.MLIL_NOP:
                    break

                if instr.operation in [ \
                        MediumLevelILOperation.MLIL_CMP_E, \
                        MediumLevelILOperation.MLIL_CMP_NE, \
                        MediumLevelILOperation.MLIL_CMP_SLT, \
                        MediumLevelILOperation.MLIL_CMP_ULT, \
                        MediumLevelILOperation.MLIL_CMP_SLE, \
                        MediumLevelILOperation.MLIL_CMP_ULE, \
                        MediumLevelILOperation.MLIL_CMP_SGE, \
                        MediumLevelILOperation.MLIL_CMP_UGE, \
                        MediumLevelILOperation.MLIL_CMP_SGT, \
                        MediumLevelILOperation.MLIL_CMP_UGT]:

                    # Assumption:
                    # If a CMP instruction is found via expr_index, then it is the actual 
                    # instruction. We want to query the result of the compare and not before the 
                    # compare. The instruction we want to add to the cmp list is the instruction 
                    # after this compare. 

                    ## Example:
                    ## 55555555528a  cmp     eax, ecx <- Found by expr_index
                    ## 55555555528c  sete    al       <- Instruction we want to actually break on
                    ## 
                    ## MLIL
                    ## 6 @ 55555555528c  rax_2.al = rax_2 == 0xf7ce60a9
                    full_instr = instr.function[instr.instr_index]

                    # Get the instruction following the CMP instruction.
                    # Since there could be multiple instructions for the same address, we walk the 
                    # basic block looking for a different address than the current instruction
                    basic_block = [bb for bb in instr.function if bb.start <= instr.instr_index < bb.end]

                    # Blocks might be split such that a `cmp` is the last instruction in a basic 
                    # block. Grab the next basic block in case we need it to find the instruction
                    # after the cmp instruction.
                    if len(basic_block[0].outgoing_edges) > 0:
                        edge = basic_block[0].outgoing_edges[0]
                        if edge.type == BranchType.UnconditionalBranch:
                            basic_block.append(edge.target)
                                               
                    check_address = full_instr.address

                    # If the instruction address is the comparison address, we need to go to the 
                    # next instruction for the correct address to check the comparison result
                    if instr.address == check_address:
                        for bb in basic_block:
                            for temp_instr in bb:
                                if temp_instr.instr_index <= instr.instr_index:
                                    continue

                                if temp_instr.address != check_address:
                                    check_address = temp_instr.address
                                    break

                            # If we found the correct next instruction, break out of trying future 
                            # block
                            if instr.address != check_address:
                                break

                    # print(f'here: {instr.address:#x} {expr_index} {instr} instr index: {instr.instr_index} -> {full_instr.address:#x} {full_instr}')

                    # Sanity check the larger instruction is not the same as the cmp instruction
                    if instr.address == check_address:
                        print(f"Error: {instr.address:#x}")
                        print(full_instr)
                        assert(instr.address != check_address)
                    else:
                        # Get the comparison rule for this instruction, using the address of the 
                        # full instruction
                        res = get_cmp_analysis_from_instr_mlil(instr, check_address, expr_indexes, cmp_size=None, iters=0)

                        # If we found a comparison rule write it to the log
                        if res != None:
                            if 'flag' not in res:
                                f.write(f'{check_address:#x},{res}\n')
                            else:
                                log_warn(f'Flag found! {res}')

                if instr.operation in [
                        MediumLevelILOperation.MLIL_FCMP_E, \
                        MediumLevelILOperation.MLIL_FCMP_NE, \
                        MediumLevelILOperation.MLIL_FCMP_LT, \
                        MediumLevelILOperation.MLIL_FCMP_LE, \
                        MediumLevelILOperation.MLIL_FCMP_GE, \
                        MediumLevelILOperation.MLIL_FCMP_GT]:
                        # MediumLevelILOperation.MLIL_FCMP_O, \
                        # MediumLevelILOperation.MLIL_FCMP_UO]:

                    full_instr = instr.function[instr.instr_index]

                    # Get the instruction following the FCMP instruction.
                    # Since there could be multiple instructions for the same address, we walk the 
                    # basic block looking for a different address than the current instruction
                    basic_block = [bb for bb in instr.function if bb.start <= instr.instr_index < bb.end][0]
                    check_address = full_instr.address

                    # If the instruction address is the comparison address, we need to go to the next instruction
                    # for the correct address to check the comparison result
                    if instr.address == check_address:
                        for temp_instr in basic_block:
                            if temp_instr.instr_index <= instr.instr_index:
                                continue

                            if temp_instr.address != check_address:
                                check_address = temp_instr.address
                                break

                    assert(instr.address != check_address)

                    # Get the comparison rule for this instruction, using the address of the 
                    # full instruction
                    res = get_cmp_analysis_from_instr_mlil(instr, check_address, expr_indexes, cmp_size=None, iters=0)

                    # Found a negated operation. Negate the operation before writing it
                    if check_address in negations:                        
                        if 'FCMP_E' in res:
                            res = res.replace("FCMP_E", "FCMP_NE")
                        elif 'FCMP_NE' in res:
                            res = res.replace("FCMP_NE", "FCMP_E")
                        elif 'FCMP_LE' in res:
                            res = res.replace("FCMP_LE", "FCMP_GT")
                        elif 'FCMP_LT' in res:
                            res = res.replace("FCMP_LT", "FCMP_GE")
                        elif 'FCMP_GE' in res:
                            res = res.replace("FCMP_GE", "FCMP_LT")
                        elif 'FCMP_GT' in res:
                            res = res.replace("FCMP_GT", "FCMP_LE")
                        else:
                            log_error(f"Unknown condition to negate! {res}")
                            assert(1 == 2)
                            
                    # If we found a comparison rule write it to the log
                    if res != None:
                        if 'flag' not in res:
                            f.write(f'{check_address:#x},{res}\n')
                        else:
                            log_warn(f'Flag found! {res}')


def get_config(bv, more_fields=None):
    """
    Helper method to get relocation address and ignorelist via the binary ninja
    GUI interaction components.
    """
    binary = Path(bv.file.filename)
    binary_name = binary.with_suffix('').name

    rebase_field = bn.interaction.AddressField("Image Base Address",
                                               view=bv,
                                               default=0)
    ignore_field = bn.interaction.TextLineField("Ignore Functions")

    fields = [
        f"Specify the base address for the image. BN image base is {bv.start:#x}.\n(leave empty or `0` for no relocation or if already rebased)",
        rebase_field,
        "Configure functions to ignore containing the following strings\n(`,` delimited):",
        ignore_field
    ]
    if more_fields:
        fields.extend(more_fields)
    user_cancelled = not bn.interaction.get_form_input(
        fields, "Snapchange Analysis Export")
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


def _dump(bv, analysis=True, bps=True):
    """
    Helper function to create prompt to configur exports and then launch the respective tasks.
    """
    assert (analysis or bps)

    # Get the path to the binary
    binary = Path(bv.file.filename)

    # Remove the extension to retrieve the base name of the file
    binary_name = binary.with_suffix('').name

    more_fields = []
    cov_analysis_field_location = None
    if analysis:
        filename = binary.parent / (binary_name + '.coverage_analysis')
        cov_analysis_field_location = bn.interaction.SaveFileNameField(
            "Coverage Analysis File",
            ext="coverage_analysis",
            default=str(filename))
        more_fields.append(cov_analysis_field_location)

    covbps_field_location = None
    if bps:
        filename = binary.parent / (binary_name + '.covbps')
        covbps_field_location = bn.interaction.SaveFileNameField(
            "Coverage Breakpoints File", ext="covbps", default=str(filename))
        more_fields.append(covbps_field_location)

    r = get_config(bv, more_fields=more_fields)
    if r is None:  # user cancelled
        return
    base_addr, nopelist = r

    if analysis and cov_analysis_field_location is not None and cov_analysis_field_location.result:
        location = Path(cov_analysis_field_location.result)
        a_task = SnapchangeCovAnalysis(bv,
                                       rebase=base_addr,
                                       ignore=nopelist,
                                       location=location)
        a_task.start()

    if bps and covbps_field_location is not None and covbps_field_location.result:
        location = Path(covbps_field_location.result)
        b_task = SnapchangeCoverageBreakpoints(bv,
                                               rebase=base_addr,
                                               ignore=nopelist,
                                               location=Path(location))
        b_task.start()


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

def get_cmp_analysis_from_instr(instr):
    print(f'Cmp Analysis {instr}')
    print(f'{instr.left} | {str(instr.operation)} | {instr.right}')
    print(f'{type(instr.left)} | {str(instr.operation)} | {type(instr.right)}')

    size = 0
    curr_instr = instr.left
    while True:
        if curr_instr.operation == MediumLevelILOperation.MLIL_VAR:
            # Convert a <mlil: var_18> to llil
            # <llil: [rbp#1 - 0x10 {var_18}].d @ mem#8>
            print(f'TRACE {curr_instr} {str(curr_instr.operation)}')
            curr_instr = curr_instr.llil
            continue
        elif curr_instr.operation == LowLevelILOperation.LLIL_LOAD_SSA:
            size = curr_instr.size
            print(f'TRACE {curr_instr} {str(curr_instr.operation)} {size}')
            curr_instr = curr_instr.src
            continue
        elif curr_instr.operation == LowLevelILOperation.LLIL_ADD:
            size = curr_instr.size
            print(f'TRACE {curr_instr} {str(curr_instr.operation)} {curr_instr.left} {curr_instr.right}')
            break
        else:
            break

def get_cmp_analysis_from_instr_llil(curr_instr, address, iters):
    if not hasattr(curr_instr, 'operation'):
        return curr_instr

    size = 0
    operation = None
    not_condition = False
    result = None
    flags = []

    pad = f'i {iters} | '
    if curr_instr.operation == LowLevelILOperation.LLIL_IF:
        return get_cmp_analysis_from_instr_llil(curr_instr.condition, address, iters + 1)
    elif curr_instr.operation in [ \
            LowLevelILOperation.LLIL_CMP_E, \
            LowLevelILOperation.LLIL_CMP_NE, \
            LowLevelILOperation.LLIL_CMP_SLT, \
            LowLevelILOperation.LLIL_CMP_ULT, \
            LowLevelILOperation.LLIL_CMP_SLE, \
            LowLevelILOperation.LLIL_CMP_ULE, \
            LowLevelILOperation.LLIL_CMP_SGE, \
            LowLevelILOperation.LLIL_CMP_UGE, \
            LowLevelILOperation.LLIL_CMP_SGT, \
            LowLevelILOperation.LLIL_CMP_UGT, \
            LowLevelILOperation.LLIL_FCMP_E, \
            LowLevelILOperation.LLIL_FCMP_NE, \
            LowLevelILOperation.LLIL_FCMP_LT, \
            LowLevelILOperation.LLIL_FCMP_LE, \
            LowLevelILOperation.LLIL_FCMP_GE, \
            LowLevelILOperation.LLIL_FCMP_GT, \
            LowLevelILOperation.LLIL_FCMP_O, \
            LowLevelILOperation.LLIL_FCMP_UO]:
        # print(f'{pad}TRACE {str(curr_instr.left):20} {str(curr_instr.right):20}')
        left = get_cmp_analysis_from_instr_llil(curr_instr.left, address, iters + 1)
        right = get_cmp_analysis_from_instr_llil(curr_instr.right, address, iters + 1)
        result = {'left': left, 'right': right}
        op = '_'.join(str(curr_instr.operation).split("_")[1:])

        data = ''
        if is_instr_const(curr_instr.left) and is_instr_const(curr_instr.right):
            data = 'CONST_INSTR'

        output = f"{address:#x} {left} {op} {curr_instr.size} {right}\n"
        return output
    elif curr_instr.operation == LowLevelILOperation.LLIL_FLAG:
        if isinstance(curr_instr, LowLevelILFlag):
            # Base case for a particular bit in the flag register
            # if 'cond' in str(curr_instr.src) or 'flag' in str(curr_instr.src) or 'temp' in str(curr_instr.src):
            # Condition variable in use. Find the definition of the condition
            cond_ssa = curr_instr.ssa_form.src
            cond = curr_instr.function.get_ssa_flag_definition(cond_ssa)
            assert(cond.operation == LowLevelILOperation.LLIL_SET_FLAG)
            # print(f'{pad}TRACE FLAG {cond}')
            res = get_cmp_analysis_from_instr_llil(cond.src, address, iters + 1)
            return ['flag', res, '']
            # else:
                # print(f"{address:#x} UNKNOWN FLAG: {curr_instr.src}")
                # return ['unknown']
    elif curr_instr.operation == LowLevelILOperation.LLIL_LOAD:
        # print(f'{pad}TRACE {curr_instr} {str(curr_instr.operation)}')
        res = get_cmp_analysis_from_instr_llil(curr_instr.src, address, iters + 1)
        if isinstance(res, list) and len(res) == 3:
            res = ' '.join(res)

        return ' '.join([f'load_from', res])
    elif curr_instr.operation == LowLevelILOperation.LLIL_REG:
        # print(f'{pad}TRACE {curr_instr} {str(curr_instr.operation)}')
        res = get_cmp_analysis_from_instr_llil(curr_instr.src, address, iters + 1)
        return f'reg {res.name}'
    elif curr_instr.operation == LowLevelILOperation.LLIL_NOT:
        src = get_cmp_analysis_from_instr_llil(curr_instr.src, address, iters + 1)
        return ['not', src, '']
    elif curr_instr.operation == LowLevelILOperation.LLIL_OR:
        left = get_cmp_analysis_from_instr_llil(curr_instr.left, address, iters + 1)
        right = get_cmp_analysis_from_instr_llil(curr_instr.right, address, iters + 1)

        # Force constants to be the right to help the type checker 
        if left.startswith('0x'):
            (left, right) = (right, left)

        return ['or', left, right]
    elif curr_instr.operation == LowLevelILOperation.LLIL_ADD:
        left = get_cmp_analysis_from_instr_llil(curr_instr.left, address, iters + 1)
        right = get_cmp_analysis_from_instr_llil(curr_instr.right, address, iters + 1)

        # Force constants to be the right to help the type checker 
        if left.startswith('0x'):
            (left, right) = (right, left)

        return ['add', left, right]
    elif curr_instr.operation == LowLevelILOperation.LLIL_SUB:
        left = get_cmp_analysis_from_instr_llil(curr_instr.left, address, iters + 1)
        right = get_cmp_analysis_from_instr_llil(curr_instr.right, address, iters + 1)

        return ['sub', left, right]
    elif curr_instr.operation == LowLevelILOperation.LLIL_AND:
        left = get_cmp_analysis_from_instr_llil(curr_instr.left, address, iters + 1)
        right = get_cmp_analysis_from_instr_llil(curr_instr.right, address, iters + 1)

        # Force constants to be the right to help the type checker 
        if left.startswith('0x'):
            (left, right) = (right, left)

        return ['and', left, right]
    elif curr_instr.operation == LowLevelILOperation.LLIL_CONST:
        # print(f'{pad}TRACE CONST {curr_instr.constant:x}')
        return hex(curr_instr.constant)
    elif curr_instr.operation == LowLevelILOperation.LLIL_CONST_PTR:
        # print(f'{pad}TRACE CONST_PTR {curr_instr.constant:x}')
        return ['const_ptr', hex(curr_instr.constant)]
    else:
        print(f"{address:#x} UNKNOWN: {str(curr_instr.operation)} | {type(curr_instr)}")
        return

def is_instr_const(instr):
    '''
    Returns True if this instruction is not dynamic for the purposes of compare analysis
    '''
    STATIC_INSTRS = [
        LowLevelILOperation.LLIL_CONST,
        LowLevelILOperation.LLIL_CONST_PTR,
        MediumLevelILOperation.MLIL_IMPORT,
        MediumLevelILOperation.MLIL_CONST,
        MediumLevelILOperation.MLIL_CONST_PTR,
        MediumLevelILOperation.MLIL_FLOAT_CONST,
    ]
        
    return instr.operation in STATIC_INSTRS


def get_cmp_analysis_from_instr_mlil(curr_instr, address, expr_indexes, cmp_size=None, iters=0):
    '''
    Walk the MLIL graph looking for the memory or register values to read in preparation for
    CMP analysis
    '''
    # if iters == 0:
        # print(f'START {address:#x} {iters} -- MLIL CMP Analysis {str(curr_instr)}')

    expr_indexes.append(curr_instr.expr_index)

    if not hasattr(curr_instr, 'operation'):
        return curr_instr

    size = 0
    operation = None
    not_condition = False
    result = None
    flags = []

    pad = f'i {iters} | '
    if curr_instr.operation == MediumLevelILOperation.MLIL_IF:
        # print(f'{pad}TRACE {curr_instr} {str(curr_instr.operation)}')
        res = get_cmp_analysis_from_instr_mlil(curr_instr.condition, address, expr_indexes, cmp_size, iters + 1)
        # print(f'{pad}TRACE {res}')
        return res
    elif curr_instr.operation in [ \
            MediumLevelILOperation.MLIL_CMP_E, \
            MediumLevelILOperation.MLIL_CMP_NE, \
            MediumLevelILOperation.MLIL_CMP_SLT, \
            MediumLevelILOperation.MLIL_CMP_ULT, \
            MediumLevelILOperation.MLIL_CMP_SLE, \
            MediumLevelILOperation.MLIL_CMP_ULE, \
            MediumLevelILOperation.MLIL_CMP_SGE, \
            MediumLevelILOperation.MLIL_CMP_UGE, \
            MediumLevelILOperation.MLIL_CMP_SGT, \
            MediumLevelILOperation.MLIL_CMP_UGT, \
            MediumLevelILOperation.MLIL_FCMP_E, \
            MediumLevelILOperation.MLIL_FCMP_NE, \
            MediumLevelILOperation.MLIL_FCMP_LT, \
            MediumLevelILOperation.MLIL_FCMP_LE, \
            MediumLevelILOperation.MLIL_FCMP_GE, \
            MediumLevelILOperation.MLIL_FCMP_GT, \
            MediumLevelILOperation.MLIL_FCMP_O,
            MediumLevelILOperation.MLIL_FCMP_UO]:
            
        # print(f'{pad}TRACE {str(curr_instr.left):20} {str(curr_instr.right):20}')
        cmp_size = curr_instr.size
        left = get_cmp_analysis_from_instr_mlil(curr_instr.left, address, expr_indexes, cmp_size, iters + 1)
        right = get_cmp_analysis_from_instr_mlil(curr_instr.right, address, expr_indexes, cmp_size, iters + 1)
        result = {'left': left, 'right': right}
        op = '_'.join(str(curr_instr.operation).split("_")[1:])

        data = ''
        if is_instr_const(curr_instr.left) and is_instr_const(curr_instr.right):
            data = 'CONST_INSTR'

        # Only write a rule for dynamic comparisions
        if data != 'CONST_INSTR':
            with open("/tmp/cmps_mlil", "a") as f:
                if isinstance(left, list):
                    left = ' '.join(left)
                if isinstance(right, list):
                    right = ' '.join(right)
                    
                # Manually change cmp size if using xmm
                isfloat = ''
                if 'xmm' in str(left) or 'xmm' in str(right):
                    isfloat = 'f'

                return f"{isfloat}{cmp_size:#x},{left},{op},{right}"
                # output = f"{address:#x},{cmp_size:#x},{left},{op},{right}"
                # return output
        else:
            return None
            
        # return [op, left, right]
    elif curr_instr.operation == MediumLevelILOperation.MLIL_LOAD:
        # Reset the compare size when going into a load instruction to keep the original
        # register and not alias based on the compare size
        res = get_cmp_analysis_from_instr_mlil(curr_instr.src, address, expr_indexes, 8, iters + 1)

        if isinstance(res, list) and len(res) == 3:
            res = ' '.join(res)

        return ' '.join([f'load_from', res])
    elif curr_instr.operation == MediumLevelILOperation.MLIL_NOT:
        # print(f'{pad}TRACE {curr_instr} {str(curr_instr.operation)}')
        src = get_cmp_analysis_from_instr_mlil(curr_instr.src, address, expr_indexes, cmp_size, iters + 1)
        return ' '.join(['not', src])
    elif curr_instr.operation == MediumLevelILOperation.MLIL_OR:
        left = get_cmp_analysis_from_instr_mlil(curr_instr.left, address, expr_indexes, cmp_size, iters + 1)
        right = get_cmp_analysis_from_instr_mlil(curr_instr.right, address, expr_indexes, cmp_size, iters + 1)
        # Force constants to be the right to help the type checker 
        if left.startswith('0x'):
            (left, right) = (right, left)

        return ' '.join(['or', left, right])
    elif curr_instr.operation == MediumLevelILOperation.MLIL_ADD:
        left = get_cmp_analysis_from_instr_mlil(curr_instr.left, address, expr_indexes, cmp_size, iters + 1)
        right = get_cmp_analysis_from_instr_mlil(curr_instr.right, address, expr_indexes, cmp_size, iters + 1)
        # Force constants to be the right to help the type checker 
        if left.startswith('0x'):
            (left, right) = (right, left)

        # No need to generate a rule for this since x+0 is x
        if left == '0x0':
            return right
        if right == '0x0':
            return left

        return ' '.join(['add', left, right])
    elif curr_instr.operation == MediumLevelILOperation.MLIL_SUB:
        left = get_cmp_analysis_from_instr_mlil(curr_instr.left, address, expr_indexes, cmp_size, iters + 1)
        right = get_cmp_analysis_from_instr_mlil(curr_instr.right, address, expr_indexes, cmp_size, iters + 1)
        return ' '.join(['sub', left, right])
    elif curr_instr.operation == MediumLevelILOperation.MLIL_AND:
        left = get_cmp_analysis_from_instr_mlil(curr_instr.left, address, expr_indexes, cmp_size, iters + 1)
        right = get_cmp_analysis_from_instr_mlil(curr_instr.right, address, expr_indexes, cmp_size, iters + 1)
        # Force constants to be the right to help the type checker 
        if left.startswith('0x'):
            (left, right) = (right, left)

        return ' '.join(['and', left, right])
    elif curr_instr.operation == MediumLevelILOperation.MLIL_LSL:
        left = get_cmp_analysis_from_instr_mlil(curr_instr.left, address, expr_indexes, cmp_size, iters + 1)
        right = get_cmp_analysis_from_instr_mlil(curr_instr.right, address, expr_indexes, cmp_size, iters + 1)
        return ' '.join(['left_shift_left', left, right])
    elif curr_instr.operation == MediumLevelILOperation.MLIL_CONST:
        return hex(curr_instr.constant)
    elif curr_instr.operation == MediumLevelILOperation.MLIL_FLOAT_CONST:
        return curr_instr.constant
    elif curr_instr.operation == MediumLevelILOperation.MLIL_CONST_PTR:
        return hex(curr_instr.constant)
    elif curr_instr.operation == MediumLevelILOperation.MLIL_IMPORT:
        return hex(curr_instr.constant)
    elif curr_instr.operation == MediumLevelILOperation.MLIL_SET_VAR:
        return get_cmp_analysis_from_instr_mlil(curr_instr.src, address, expr_indexes, cmp_size, iters + 1)
    elif curr_instr.operation == MediumLevelILOperation.MLIL_ZX:
        return get_cmp_analysis_from_instr_mlil(curr_instr.src, address, expr_indexes, cmp_size, iters + 1)
    elif curr_instr.operation == MediumLevelILOperation.MLIL_SX:
        return get_cmp_analysis_from_instr_mlil(curr_instr.src, address, expr_indexes, cmp_size, iters + 1)
    elif curr_instr.operation == MediumLevelILOperation.MLIL_FLOAT_CONV:
        return get_cmp_analysis_from_instr_mlil(curr_instr.src, address, expr_indexes, cmp_size, iters + 1)
    elif curr_instr.operation in [MediumLevelILOperation.MLIL_VAR, MediumLevelILOperation.MLIL_VAR_FIELD]:
        # If we see an MLIL variable, use the LLIL version to get the stack address
        # MLIL version - 82 @ 0043013a  if (var_38 == 0) 
        # >> var_38 used, not quite useful.. Let's check the LLIL
        # LLIL version - 105 @ 0043013a  if ([rbp - 0x30 {var_38}].q == 0) 
        # [rbp - 0x30] is must easier to use 
        if 'var_' in str(curr_instr.src):
            # mlil_func = curr_instr.function
            # ssa_var = mlil_func.get_ssa_var_definition(curr_instr.ssa_form.src)
            # var = get_cmp_analysis_from_instr_mlil(ssa_var, address, iters + 1)
            # return ['unknown_mlil_var', var]

            # Grab the LLIL version of this variable since it's a bit easier to work with
            this_llil = get_cmp_analysis_from_instr_llil(curr_instr.llil.non_ssa_form, address, 0)
            # return ['llil_var', this_llil]
            return this_llil
        if 'temp' in str(curr_instr.src) or 'cond' in str(curr_instr.src): # or str(curr_instr.src.type) == 'bool':
            mlil_func = curr_instr.function
            ssa_var = mlil_func.get_ssa_var_definition(curr_instr.ssa_form.src)
            var = get_cmp_analysis_from_instr_mlil(ssa_var, address, expr_indexes, cmp_size, iters + 1)
            return var
        else:
            # Replace the arg values with the registers
            name = str(curr_instr.src)
            if 'arg' in name:
                name = get_cmp_analysis_from_instr_llil(curr_instr.llil.non_ssa_form, address, 0)
            else:
                # Remove the versioning index of this register
                # rcx_1 -> rcx
                # rsi_9 -> rsi
                name = name.split('_')[0]
                if name in ['z', 'p', 'c', 's', 'o', 'a']:
                    return f'flag here | {curr_instr.address:#x} {curr_instr}'
                    
                # ssa_var = curr_instr.ssa_form
                # ssa_func = curr_instr.function.ssa_form
                # var_def = ssa_func.get_ssa_var_definition(ssa_var.src).non_ssa_form
                # orig_name = name
                # print(hex(address), var_def)
                # name = get_cmp_analysis_from_instr_mlil(var_def, address, 0)
                # print(hex(address), f'{orig_name} -> {name}')

            new_name = get_register_alias(name, cmp_size)
            # print(hex(address), new_name)

            if 'zmm' in new_name or 'ymm' in new_name:
                new_name = new_name.replace('zmm', 'xmm').replace('ymm', 'xmm')
            elif '256' in str(curr_instr.src.type) or '512' in str(curr_instr.src.type):
                log_warn(f"{curr_instr.address:#x} Discovered ymm or zmm register in use. Cannot handle those at this point. Ignoring")
                
            # return f'{name} ({cmp_size}) -> {new_name}'
            if new_name.startswith('reg '):
                old_name = new_name
                new_name = new_name.replace('reg ', '')
                log_warn(f"{curr_instr.address:#x} Replacing {old_name} to {new_name}")

            if 'load_from' in new_name:
                return f'{new_name}'
            else:
                return f'reg {new_name}'
    else:
        # print(dir(curr_instr))
        print(f"{address:#x} UNKNOWN: {str(curr_instr.operation)} | {type(curr_instr)}")
        return ['unknown', str(curr_instr.operation)]

    return ['realbad', result]

def get_register_alias(register, size):
    '''
    Get the register alias for the given register based on the requested size
    '''
    REGISTERS = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", "r8", "r9", "r10", \
        "r11", "r12", "r13", "r14", "r15", "rip"]

    # Based on the comparison size, return the correct register alias
    if register in REGISTERS:
        alias = {
            ('rax', 4): 'eax',
            ('rax', 2): 'ax',
            ('rax', 1): 'al',
            ('rbx', 4): 'ebx',
            ('rbx', 2): 'bx',
            ('rbx', 1): 'bl',
            ('rcx', 4): 'ecx',
            ('rcx', 2): 'cx',
            ('rcx', 1): 'cl',
            ('rdx', 4): 'edx',
            ('rdx', 2): 'dx',
            ('rdx', 1): 'dl',
            ('rsi', 4): 'esi',
            ('rsi', 2): 'si',
            ('rsi', 1): 'sil',
            ('rdi', 4): 'edi',
            ('rdi', 2): 'di',
            ('rdi', 1): 'dil',
            ('rsp', 4): 'esp',
            ('rsp', 2): 'sp',
            ('rsp', 1): 'spl',
            ('rbp', 4): 'ebp',
            ('rbp', 2): 'bp',
            ('rbp', 1): 'bpl',
            ('r8', 4): 'r8d',
            ('r8', 2): 'r8w',
            ('r8', 1): 'r8b',
            ('r9', 4): 'r9d',
            ('r9', 2): 'r9w',
            ('r9', 1): 'r9b',
            ('r10', 4): 'r10d',
            ('r10', 2): 'r10w',
            ('r10', 1): 'r10b',
            ('r11', 4): 'r11d',
            ('r11', 2): 'r11w',
            ('r11', 1): 'r11b',
            ('r12', 4): 'r12d',
            ('r12', 2): 'r12w',
            ('r12', 1): 'r12b',
            ('r13', 4): 'r13d',
            ('r13', 2): 'r13w',
            ('r13', 1): 'r13b',
            ('r14', 4): 'r14d',
            ('r14', 2): 'r14w',
            ('r14', 1): 'r14b',
            ('r15', 4): 'r15d',
            ('r15', 2): 'r15w',
            ('r15', 1): 'r15b',
            ('rip', 4): 'eip',
            ('rip', 2): 'ip',
            ('rflags', 4): 'eflags',
        }.get((register, size), register)
    else:
        alias = register

    return alias
    

# only if imported by binaryninja UI
if __name__ != "__main__":
    bn.PluginCommand.register("Snapchange\\Save Coverage Analysis",
                              "Save Coverage Analysis for snapchange",
                              dump_covanalyis)
    bn.PluginCommand.register(
        "Snapchange\\Save Coverage Breakpoints",
        "Save a list of breakpoints used for coverage feedback in snapchange",
        dump_covbps)
    bn.PluginCommand.register("Snapchange\\Save Cov Analysis + Breakpoints",
                              "Save both coverage analysis and breakpoints",
                              dump_both)
# if run from command line
else:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("binary",
                        help="Path to the binary file to analyze",
                        type=Path)
    parser.add_argument(
        "--base-addr",
        default=0,
        help=
        "Address to rebase the binary to - check `gdb.vmmap` for base address",
        type=lambda i: int(i, 0))
    parser.add_argument(
        "--ignore",
        default=[],
        nargs='+',
        help="Ignore functions with the given names (e.g., '--ignore asan')")
    parser.add_argument(
        "--bn-max-function-size",
        default=65_000,
        type=int,
        help="set binary ninja analysis limit for max function size")
    parser.add_argument(
        "--bn-max-analysis-time",
        default=(60 * 1000),
        type=int,
        help="set binary ninja analysis limit for max function analysis time (in ms)")
    parser.add_argument('--bps',
                        action='store_true',
                        help="dump coverage breakpoint addresses")
    parser.add_argument('--analysis',
                        action='store_true',
                        help="dump coverage analysis data")
    parser.add_argument('--cmp',
                        action='store_true',
                        help="dump comparision analysis data")

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
                log_info(f"Using license information from BINARY_NINJA_LICENSE_DATA")

            bn.core_set_license(license_data)
    except Exception as e:
        log_warn(f"Error while using environemnt license. Falling back on the system license.")
        log_warn(f"{e}")

    if not args.binary.exists():
        log_error("non-existing file passed to script", LOG_ID)
        sys.exit(1)

    if not args.bps and not args.analysis and not args.cmp:
        log_error("you must choose either --bps or --analysis or --cmp")
        sys.exit(1)

    log_info(
        f"starting analysis with max function size {args.bn_max_function_size} and max function analysis time {args.bn_max_analysis_time}"
    )
    # Get the BinaryView for the given binary
    options = {
        'analysis.limits.maxFunctionSize': args.bn_max_function_size,
        'analysis.limits.maxFunctionAnalysisTime': args.bn_max_analysis_time
    }

    with bn.open_view(str(args.binary), options=options,
                      update_analysis=True) as bv:
        # If given a different base address, rebase the BinaryView
        if args.base_addr != 0:
            bv = bv.rebase(args.base_addr)

        bv.update_analysis_and_wait()

        # import IPython; shell = IPython.terminal.embed.InteractiveShellEmbed(); shell.mainloop();
        # sys.exit(1)

        binary = Path(bv.file.filename)
        binary_name = binary.with_suffix('').name

        tasks = []

        task1 = None
        if args.analysis:
            log_info("launching coverage analysis")
            filename = binary.parent / (binary.name + '.coverage_analysis')
            task1 = SnapchangeCovAnalysis(bv,
                                          ignore=args.ignore,
                                          location=filename)
            task1.start()
            tasks.append(task1)

        task2 = None
        if args.bps:
            log_info("launching breakpoint dump")
            filename = binary.parent / (binary.name + '.covbps')
            task2 = SnapchangeCoverageBreakpoints(bv,
                                                  ignore=args.ignore,
                                                  location=filename)
            task2.start()
            tasks.append(task2)

        task3 = None
        if args.cmp:
            log_info("launching comparison dump")
            filename = binary.parent / (binary.name + '.cmps')
            task3 = SnapchangeCmpAnalysis(bv,
                                          ignore=args.ignore,
                                          location=filename)
            task3.start()
            tasks.append(task3)

        # Wait for all threads to finish
        for task in tasks:
            task.join()

    log_info("done. bye!")
    bn.shutdown()