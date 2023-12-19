# ghidra scripting uses jython2

from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.address import Address
from ghidra.app.decompiler import *
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.lang import Register, OperandType
from ghidra.program.model.scalar import Scalar
from ghidra.program.model.address import GenericAddress
from ghidra.program.model.symbol.RefType import READ
from ghidra.program.model.pcode.PcodeOp import *
from ghidra.program.model.pcode import Varnode, VarnodeAST
from ghidra.program.flatapi import FlatProgramAPI

import sys

"""
Used to identify aliases of common comparison functions,
e.g., strcmp and curl_strequal, which are essentially the same.
"""
FunctionAlias = {
    'MEMCMP': 1,
    'STRCMP': 2,
    'STRNCMP': 3,
    'STRCASECMP': 4,
    'STRNCASECMP': 5,
    'MEMCHR': 6,
    'RETURN_STATUS_FUNCTION': 100
}


FUNCTION_ALIASES = {
    # essentially strcmp
    "strcmp": 'STRCMP',
    "xmlStrcmp": 'STRCMP',
    "xmlStrEqual": 'STRCMP',
    "g_strcmp0": 'STRCMP',
    "curl_strequal": 'STRCMP',
    "strcsequal": 'STRCMP',

    # essentially memcmp
    "memcmp": 'MEMCMP',
    "bcmp": 'MEMCMP',
    "CRYPTO_memcmp": 'MEMCMP',
    "OPENSSL_memcmp": 'MEMCMP',
    "memcmp_const_time": 'MEMCMP',
    "memcmpct": 'MEMCMP',

    # essentially strncmp
    "strncmp": 'STRNCMP',
    "xmlStrncmp": 'STRNCMP',
    "curl_strnequal": 'STRNCMP',

    # strcasecmp
    "strcasecmp": 'STRCASECMP',
    "stricmp": 'STRCASECMP',
    "ap_cstr_casecmp": 'STRCASECMP',
    "OPENSSL_strcasecmp": 'STRCASECMP',
    "xmlStrcasecmp": 'STRCASECMP',
    "g_strcasecmp": 'STRCASECMP',
    "g_ascii_strcasecmp": 'STRCASECMP',
    "Curl_strcasecompare": 'STRCASECMP',
    "Curl_safe_strcasecompare": 'STRCASECMP',
    "cmsstrcasecmp": 'STRCASECMP',

    # strncasecmp
    "strncasecmp": 'STRNCASECMP',
    "strnicmp": 'STRNCASECMP',
    "ap_cstr_casecmpn": 'STRNCASECMP',
    "OPENSSL_strncasecmp": 'STRNCASECMP',
    "xmlStrncasecmp": 'STRNCASECMP',
    "g_ascii_strncasecmp": 'STRNCASECMP',
    "Curl_strncasecompare": 'STRNCASECMP',
    "g_strncasecmp": 'STRNCASECMP',

    # memchr
    "memchr": 'MEMCHR',
}

ALIAS_NAME = {
    'MEMCMP': 'memcmp',
    'STRCMP': 'strcmp',
    'STRNCMP': 'strcmp',
    'STRCASECMP': 'strcmp',
    'STRNCASECMP': 'strcmp',
    'MEMCHR': 'memchr',
}

args = getScriptArgs()
if len(args) > 0:
    base_address = int(args[0], 16)
    println("Base 0x%x" % base_address)
    base_address = currentProgram.getImageBase().getAddress(args[0])
    currentProgram.setImageBase(base_address, False)
    analyzeAll(currentProgram)

# Get the base address of the module
base = currentProgram.getMinAddress()
name = currentProgram.getExecutablePath()

block_model = BasicBlockModel(currentProgram)

# Get a function manager for getting the names of the functions containing
# the basic blocks
func_manager = currentProgram.getFunctionManager()

# Create the output file for these basic blocks
outfile = '{}.ghidra.covbps'.format(name)
rq_outfile = '{}.ghidra.cmps'.format(name)
seen = []

# Bad function substrings
bad_funcs = ["asan", "msan", "ubsan", "sanitizer", "lsan", "lcov", "intercept", "sancov", "ioctl_table_fill"]

# Write the basic blocks to the outfile
with open(outfile, 'w') as f:
    def write_blocks(blocks):
        while blocks.hasNext():
            block = blocks.next()
            if block:
                # Write the starting address of the basic block
                address = block.getMinAddress().getOffset()
                length = block.getMaxAddress().getOffset() - address
                s = "0x%x,0x%x\n" % (address, length)
                f.write(s)

    # Get the symbol table
    symbolTable = currentProgram.getSymbolTable()
    seen = []
    # Iterate over all symbols in the symbol table
    for symbol in symbolTable.getAllSymbols(True):
        # Only keep function symbols
        if symbol.getSymbolType() != ghidra.program.model.symbol.SymbolType.FUNCTION:
            continue

        # Get the function name
        func_name = str(symbol)

        seen.append(symbol.getAddress())

        # Ignore this basic block if its function is in the bad list
        if any(bad for bad in bad_funcs if bad in str(symbol.getObject()).lower()):
            println("Ignoring bad func %s\n" % func_name)
            continue

        # Get the function entry for this symbol
        func_entry = symbol.getProgramLocation().getAddress()

        # Ensure there is actually a function for this symbol
        func = func_manager.getFunctionAt(func_entry)
        if func is None:
            println("NO FUNC FOUND! %s\n" % func_name)
            continue

        # Found a valid function, dump the basic blocks for this function
        println("Good func! %s\n" % func_name)
        blocks = block_model.getCodeBlocksContaining(func.getBody(), monitor)
        write_blocks(blocks)
         

listing = currentProgram.getListing()
instrs = listing.getInstructions(True)
       

def get_register_name_and_size(varnode):
    ''' Given a Register Varnode, return the name of the register '''
    assert(isinstance(varnode, Varnode))
    assert(varnode.getAddress().isRegisterAddress())

    varnode_addr = varnode.getAddress()
    # println("        Addr    %s" % varnode_addr)
    # println("        Size    %s" % varnode_addr.getSize())
    # println("        PtrSize %s" % varnode_addr.getPointerSize())
    # println("        Offset  %s" % varnode_addr.getOffset())
    if varnode_addr.isRegisterAddress():
        reg_name = currentProgram.getRegister(varnode_addr).getName()
        return (reg_name.lower(), varnode_addr.getPointerSize())
    else:
        assert(None)

# Flags for determining whether to set the breakpoint on or after the given instruction
# For example, we can't set the breakpoint on fucomip since it pops off the register stack,
# corrupting the floating point register to check against
BREAK_AFTER = 0x1
BREAK_ON = 0x2

cmps = {}

# Generic comparisons
cmps['CMP'] = BREAK_AFTER
cmps['TEST'] = BREAK_AFTER

# f32/f64 comparison
cmps['UCOMISS'] = BREAK_AFTER
cmps['UCOMISD'] = BREAK_AFTER
cmps['FCOMI']  = BREAK_AFTER
cmps['FUCOMI'] = BREAK_AFTER
cmps['FCOMIP'] = BREAK_ON
cmps['FUCOMIP'] = BREAK_ON

REGISTER_CALLING_CONVENTION = {
    'reg rdi', 'reg rsi', 'reg rdx', 'reg rcx', 'reg r8', 'reg r9'
}


def get_emulated_pcode(instr):
    ''' 
    Emulate the pcode for a given instruction and return the ending emulated state.
    The goal is to calculate the total equation for setting status flags.
    '''
    emu = {'pf': ''}

    for pcode in instr.getPcode():
        # Convert the PCode operation to the binja operation used in the redqueen impl
        operation = {
            'LOAD': 'load_from',
            'COPY': '',
            'INT_MULT': 'mul',
            'INT_ADD': 'add',
            'INT_SUB': 'sub',
            'INT_AND': 'and',
            'INT_EQUAL': 'CMP_E',
            'INT_NOTEQUAL': 'CMP_NE',
            'INT_LESS': 'CMP_ULT',
            'INT_LESSEQUAL': 'CMP_ULE',
            'INT_SLESS': 'CMP_SLT',
            'INT_SLESSEQUAL': 'CMP_SLe',
            'INT_SBORROW': 'CMP_SLT',
            'FLOAT_EQUAL': 'FCMP_E',
            'FLOAT_LESS': 'FCMP_LT',

            # Probably useless
            'POPCOUNT': 'UNUSEDpopcount',
            'FLOAT_NAN': 'UNUSEDfloat_nan',
            'BOOL_OR': 'UNUSEDor',
            'INT_OR': 'UNUSEDintor'
        }[pcode.getMnemonic()]
        curr_inputs = [operation]

        inputs = pcode.getInputs()

        # NOTE(corydu): The first argument for the LOAD operation is the address space
        #               which we don't need in the resulting instruction
        if curr_inputs[0] == 'load_from':
            inputs = inputs[1:]

        for input in inputs:
            if input.isRegister():
                (name, reg_size) = get_register_name_and_size(input)
                if name == 'pf':
                    continue

                curr_inputs.append("reg %s" % name)
            elif input.isConstant():
                num = "0x%x" % input.getOffset()
                num = num.replace("0x-", "-0x")
                curr_inputs.append(num)
            elif input.isUnique():
                data = emu[input]
                curr_inputs.append(data)
            elif input.isAddress():
                curr_inputs.append('0x%x' % input.getAddress().getOffset())
            else:
                raise Exception("Unknown pcode input: %s" % input)
            
        output = pcode.getOutput()
        if output.isRegister():
            (name, reg_size) = get_register_name_and_size(output)
            output = name

        if output == 'pf':
            continue
            
        emu[output] = curr_inputs

    return emu

def flatten(x):
    '''
    Flatten a list of lists to a single list

    Example:
    Input  ['sub', ['load_from', ['add', u'reg rbp', '-0x20']], '0x4000'] 
    Output ['sub', 'load_from', 'add', u'reg rbp', '-0x20', '0x4000'] 
    '''
    res = []
    for items in x:
        if isinstance(items, list):
            res += flatten(items)
        else:
            res.append(items)
    return res

flat_api = FlatProgramAPI(currentProgram)
      
# Gather redqueen comparison rules
with open(rq_outfile, 'w') as f:
    instrs = listing.getInstructions(True)

    for instr in instrs:
        func_name = ''
        func = func_manager.getFunctionContaining(instr.getAddress())
        if func != None:
            func_name = func.getName()
        else:
            println("FINDME Instr not in func?! %s %s" % (instr, instr.getAddress()))

        if any(bad for bad in bad_funcs if bad in func_name):
            println("Skipping %s since it's in %s" % (instr, func_name))
            continue

        # Cache the original instruction
        orig_instr = instr

        op_str = instr.getMnemonicString()
        # Ignore comparison instructions
        if op_str not in cmps and op_str != 'CALL':
            continue

        if op_str == "CALL":
            # Check if this call is a hooked call like strcmp, memcmp, and memchr
            target = instr.getOpObjects(0)[0]
            if isinstance(target, Address):
                symbol = flat_api.getSymbolAt(target).getName()
                alias = FUNCTION_ALIASES.get(symbol)
                if alias == None:
                    continue

                alias_name = ALIAS_NAME.get(alias)
                size = "reg rdx"
                if alias_name == "strcmp":
                    size = "0x0"

                f.write("0x%s,%s,reg rdi,%s,reg rsi\n" % (instr.getAddressString(False, False), size, alias_name))

            continue

        println("-- Checking %s %s --" % (instr, instr.getAddressString(False, False)))

        # Get the addresses for this instruction and the next
        bp_addr = instr.getAddressString(False, False)
        next_bp_addr = instr.getNext().getAddressString(False, False)

        # Get the pcode objects for the left and right operands
        left_objs  = instr.getOpObjects(0)
        right_objs = instr.getOpObjects(1)

        # Get the operand type for each operand
        left_op_type = instr.getOperandType(0)
        right_op_type = instr.getOperandType(1)

        # Check if the operands are an address or dynamic operand type to mark it as 'load_from'
        left_is_addr = OperandType.isAddress(left_op_type) or OperandType.isDynamic(left_op_type)
        right_is_addr = OperandType.isAddress(right_op_type) or OperandType.isDynamic(right_op_type)

        '''
        for (name, bit) in [
                ('ADDRESS', 0x2000),
                ('BIT', 0x8000),
                ('BYTE', 0x10000),
                ('CODE', 0x40),
                ('COP', 0x200000),
                ('DATA', 0x80),
                ('DYNAMIC', 0x400000),
                ('FLAG', 0x800),
                ('FLOAT', 0x100000),
                ('IMMEDIATE', 0x8),
                ('IMPLICIT', 0x20),
                ('INDIRECT', 0x4),
                ('LIST', 0x400),
                ('PORT', 0x100),
                ('QUADWORD', 0x40000),
                ('READ', 0x1),
                ('REGISTER', 0x200),
                ('RELATIVE', 0x10),
                ('SCALAR', 0x4000),
                ('SIGNED', 0x80000),
                ('TEXT', 0x1000),
                ('WORD', 0x20000),
                ('WRITE', 0x2)
        ]:
            if left_op_type & bit > 0:
                println("LEFT %s %s" % (left_op_type, name))

        for (name, bit) in [('ADDRESS', 0x2000),
                ('BIT', 0x8000),
                ('BYTE', 0x10000),
                ('CODE', 0x40),
                ('COP', 0x200000),
                ('DATA', 0x80),
                ('DYNAMIC', 0x400000),
                ('FLAG', 0x800),
                ('FLOAT', 0x100000),
                ('IMMEDIATE', 0x8),
                ('IMPLICIT', 0x20),
                ('INDIRECT', 0x4),
                ('LIST', 0x400),
                ('PORT', 0x100),
                ('QUADWORD', 0x40000),
                ('READ', 0x1),
                ('REGISTER', 0x200),
                ('RELATIVE', 0x10),
                ('SCALAR', 0x4000),
                ('SIGNED', 0x80000),
                ('TEXT', 0x1000),
                ('WORD', 0x20000),
                ('WRITE', 0x2)]:
            if right_op_type & bit > 0:
                println("RIGHT %s %s" % (right_op_type, name))
        '''
       
        pcode_conditionals = [
            "INT_EQUAL",
            "INT_NOTEQUAL",
            "INT_LESS",
            "INT_SLESS",
            "INT_LESSEQUAL",
            "INT_SLESSEQUAL",
            "INT_CARRY",
            "INT_SCARRY",
            "INT_BORROW",
            "INT_SBORROW",
        ]

        is_float = False

        # Use the maximal size found by the operands as the size for this comparison
        size = 0

        # Get the size for the operation
        # If floating point, hard code the size based on the operation,
        # otherwise, use the largest size of the pcode
        if 'UCOMISD' in op_str:
            is_float = True
            size = 0x8
        elif 'UCOMISS' in op_str:
            is_float = True
            size = 0x4
        elif op_str in ['FUCOMI', 'FUCOMIP', 'FCOMI', 'FCOMIP']:
            is_float = True
            size = 0xa
        else:
            for pcode in instr.getPcode():
                if pcode.getMnemonic() in pcode_conditionals:
                    for input in pcode.getInputs():
                        size = max(size, input.getSize())
        
        # Look forward to the next instruction that uses the status flags
        checked_flags = []
        for _ in range(4):
            next_instr = instr.getNext()
            for pcode in next_instr.getPcode():
                println("  PCODE: %s" % pcode)
                for input in pcode.getInputs():
                    println("  INPUT: %s" % input)
                    if input.isRegister():
                        (name, reg_size) = get_register_name_and_size(input)
                        println("    -->: %s %s" % (name, size))
                        if name in ['zf', 'cf', 'sf', 'of']:     # Is PF needed?
                            println("    --> FOUND: %s" % name)
                            checked_flags.append(name)


            # Found an instruction that uses the status flags. Use these
            # flags as the conditions to use for this compare instruction
            if len(checked_flags) > 0:
                break

            # Not found, go to the next instruction
            instr = next_instr

        if size > 0:
            when_to_break = cmps[op_str]
            if when_to_break & BREAK_ON > 0:
                bp_addr = bp_addr
            elif when_to_break & BREAK_AFTER > 0:
                bp_addr = next_bp_addr
       
            # For each checked flag, add a specific rule for this
            emu = get_emulated_pcode(orig_instr)
            for flag in checked_flags:
                println("  EMU: %s" % (emu[flag]))
                curr_value = emu[flag]
                if 'UNUSED' in curr_value[0]:
                    curr_value = curr_value[1]

                [cmp, left, right] = curr_value
                println("  CMP: %s -- %s" % (cmp, flag))
                println("  left: %s" % left)
                println("  right: %s %s" % (right, type(right)))
                assert('CMP' in cmp)

                if right == 0x0 or right == '0x0':
                    # For the case of comparing: 'rax & rbx == 0' or 'rax - rbx == 0'
                    # Convert the equation just rax == rbx
                    [new_cmp, new_left, new_right] = left
                    if new_cmp in ['and', 'sub']:
                        left = new_left
                        right = new_right

                if not isinstance(left, list):
                    left = [left]
                left = ' '.join(flatten(left))

                if not isinstance(right, list):
                    right = [right]
                right = ' '.join(flatten(right))

                assert('CMP' in cmp)
                line =  "0x%s,0x%x,%s,%s,%s" % (bp_addr, size, left, cmp, right)

                # TODO(corydu): Is there a better way of finding xmm vs ymm in ghidra?
                if size in [4, 8] and 'ymm' in line:
                    line = line.replace("ymm", "xmm")

                println("   %s" % line)
                f.write("%s\n" % line)
        else:
            raise Exception("ERROR: NO SIZE FOUND: %s" % bp_addr)
    
println("Basic blocks written to %s" % outfile)
println("Redqueen rules written to %s" % rq_outfile)
