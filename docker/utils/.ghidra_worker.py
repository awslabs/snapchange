from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.address import Address
import sys

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
# blocks = model.getCodeBlocks(monitor)

# Get a function manager for getting the names of the functions containing
# the basic blocks
func_manager = currentProgram.getFunctionManager()

# Create the output file for these basic blocks
outfile = '{}.ghidra.covbps'.format(name)

seen = []

# Bad function substrings
bad_funcs = ["asan", "msan", "ubsan", "sanitizer", "lsan", "lcov", "intercept", "sancov", "ioctl_table_fill"]

# Write the basic blocks to the outfile
with open(outfile, 'w') as f:
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
        while blocks.hasNext():
            block = blocks.next()
            if block:
                # Write the starting address of the basic block
                address = block.getMinAddress().getOffset()
                f.write("0x%x\n" % address)


    # Go through all the functions that were not seen while looking at symbols
    for func in func_manager.getFunctions(True):
        if func.getEntryPoint() in seen:
            continue

        # Found a valid function, dump the basic blocks for this function
        println("Newfunc! 0x%x\n" % func.getEntryPoint())
        blocks = block_model.getCodeBlocksContaining(func.getBody(), monitor)
        while blocks.hasNext():
            block = blocks.next()
            if block:
                # Write the starting address of the basic block
                address = block.getMinAddress().getOffset()
                f.write("0x%x\n" % address)
        
    

println("Basic blocks written to %s" % outfile)
   