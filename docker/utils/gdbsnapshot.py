import gdb
import os
import subprocess
from collections import defaultdict
import json
import sys
from pathlib import Path

print("[gdbsnapshot.py loaded]")

symbols = defaultdict(list)


def collect_kernel_symbols():
    ''' Attempt to dump the kernel symbols. Fails if GDB is not ran as root '''
    if os.geteuid() != 0:
        print("ERROR: Kernel symbols not available.. GDB not executed as root")
    else:
        kallsyms_file = "gdb.kallsyms"

        with open("/proc/kallsyms", "r") as f:
            kallsyms = f.read()

        # Parse the kallsyms output
        parse_kallsyms(kallsyms)

def parse_kallsyms(data):
    ''' Parse the /proc/kallsyms output and return the symbol addresses '''
    global symbols

    for line in data.split('\n'):
        # Ignore (addr, __key*) line
        if '__key' in line:
             continue

        # Example line
        # ffffffffc0b2bb50 t btrfs_calculate_inode_block_rsv_size	[btrfs]
        line = line.split()
        if len(line) < 2:
            continue

        # Add the symbol address and symbol name to the symbols database
        addr = int(line[0], 16)
        symbols[addr].append(line[2])

def collect_process_memory_map():
    ''' Dump the process memory map '''
    vmmap_file = "/tmp/gdb.vmmap"
    print("Memory written to {}".format(vmmap_file))
    with open(vmmap_file, 'w') as f:
        vmmap = gdb.execute('info proc mappings', to_string=True)
        print(vmmap)
        f.write(vmmap)

    found_files = set()
    started = False
    modules = {}

    for line in vmmap.split('\n'):
        # Skip all lines until the header
        if not started and 'Start Addr' not in line:
            continue

        # Found the header, skip it and start parsing the following lines
        if not started and 'Start Addr' in line:
            started = True

            # Expecting
            # Start Addr           End Addr       Size     Offset  Perms  objfile
            #   0x400000           0x41d000    0x1d000        0x0  r--p   /root/sudo
            if 'Start Addr' not in line or \
               'End Addr' not in line or \
               'Size' not in line or \
               'Offset' not in line or \
               'Perms' not in line or  \
               'objfile' not in line:
                   print("Unknown GDB memory map.. Bailing early")
                   print(line)
                   print("Unknown GDB memory map.. Bailing early")
                   return
            continue

        line = line.split()

        # Skip lines that don't have 6 members
        if len(line) != 6:
            continue

        # Parse the split line
        (start_addr, end_addr, size, offset, perms, filepath) = line

        # Ignore [vvar], [vdso], [stack], [vsyscall], ect
        if '[' in filepath and ']' in filepath:
            continue

        # Already processed this file, no need to process it again
        if filepath in found_files:
            # Sanity check the filename was initialized properly
            assert('end' in modules[filename])

            modules[filename]['end'] = end_addr
            continue

        # New file
        found_files.add(filepath)

        # Get the filename from the filepath
        filename = os.path.basename(filepath)

        # Add the filename to the total module list if it doesn't exist
        print("Inserting first time in modules: {}".format(filename))
        modules[filename] = {"start": start_addr, "end": end_addr}

        # Parse the string into an int
        start_addr = int(start_addr, 16)

        # Init the module to parse with `nm` as False
        found = filepath

        if filepath == '/sys/kernel/debug/kcov':
            continue

        # If the module is a library, search the /usr/lib/debug for the debug build.
        # Otherwise, attempt to just get the symbols from the given binary 
        if '/usr/lib' in filepath or filepath.startswith('/lib'):
            if not os.path.exists("/usr/lib/debug/.build-id"):
                print(".build_id not exist")
                if os.path.exists("/usr/lib/debug"):
                    debug_path = "/usr/lib/debug/" + filepath + ".debug"
                    print("trying path for .debug", debug_path)
                    if os.path.exists(debug_path):
                        found = debug_path
                    for (root, dirs, files) in os.walk("/usr/lib/debug"):
                        if filename in files and "libc6-prof" not in root and "x86_64" in root:
                            found = os.path.join(root, filename)
                            break
            else:
                print("debug", filepath)
                try:
                    output = subprocess.check_output(["readelf", "-n", filepath])
                    
                    for line in output.split(b"\n"):
                        if b'Build ID' not in line:
                            continue

                        # Parse the build_id
                        build_id = line.split()[2].decode("utf-8")
                        dir1 = build_id[:2]
                        dir2 = build_id[2:]

                        print('build_id', build_id) 
                        debug_path = "/usr/lib/debug/.build-id/{}/{}.debug".format(dir1, dir2)
                        print('debug_path', debug_path)
                        if not os.path.exists(debug_path):
                            print("{} not found in .build-id with id: {}".format(filepath, build_id))
                            continue

                        found = debug_path
                        break
                except Exception as e:
                    print(f"ERROR readelf: {filepath} -- {e}")

        if found and os.path.exists(found):
            print("FOUND: {}".format(found))
            try:
                output = subprocess.check_output(["/usr/bin/objdump", "-x", found])

                for line in output.split(b"\n"):
                    if b'LOAD off' not in line:
                        continue

                    # [b'LOAD', b'off', b'0x0000000000000000', b'vaddr', b'0x0000000000000000', b'paddr', b'0x0000000000000000'..

                    # Check if the virtual address is the starting address of this module
                    # If so, `nm` will be dumping symbols from that offset, so we don't need
                    # to add the starting address here
                    vaddr = int(line.split()[4], 16)
                    if start_addr == vaddr:
                        start_addr = 0
                    elif vaddr == 0:
                        start_addr =  int(modules[filename]['start'], 16)

                    break

                print("Gathering symbols for {} @ starting addr {}".format(filename,
                    hex(start_addr)))
                try:
                    output = subprocess.check_output(["nm", found])
                    add_nm_output(output, start_addr, filename)
                except Exception as e:
                    print(f"ERROR nm: {found} -- {e}")

            except Exception as e:
                print(f"ERROR objdump: {found} -- {e}")


    for x in modules.items():
        print(x)

    # Force page in all memory in all found modules
    for (_filename, addrs) in modules.items():
        start = int(addrs['start'], 16) & ~0xfff
        end = (int(addrs['end'], 16) + 0xfff) & ~0xfff
        addrs = range(start, end, 0x1000)
        for (i, page) in enumerate(addrs):
            if i % 10 == 0:
                print("Page: {}/{}: {:x}".format(i, len(addrs), page))
            # Dump bytes from this page in order to force this memory to be paged in
            try:
                gdb.execute('x/4b {}'.format(page), to_string=True)
            except:
                print("Addr {} for {} not found: {}".format(hex(page), filename, addrs))


    # Write the specific modules file
    modules_file = "/tmp/gdb.modules"
    print("Modules found written to {}".format(modules_file))
    with open(modules_file, 'w') as f:
        for (filename, addrs) in modules.items():
            f.write("{} {} {}\n".format(addrs['start'], addrs['end'], filename))

def add_nm_output(data, start_addr, module):
    ''' 
    Parse `nm` output of `module` and add the resulting symbols to the symbol database
    using the `start_addr` as the starting address
    '''
    for line in data.split(b"\n"):
        line = line.split()

        # Ignore line with not 3 elements
        if len(line) != 3:
            continue

        (offset, type_, symbol) = line

        offset = int(offset, 16)
        # print(hex(start_addr + offset), "{}!{}".format(module, bytes.decode(symbol)))

        symbol = "{}!{}".format(module, bytes.decode(symbol))
        symbol_addr = start_addr + offset

        # Naive assumption that if the symbol starts with __ and there is already a key
        # there, that the current one is probably correct
        if symbol.startswith("_") and len(symbols[symbol_addr]) > 0:
            continue

        symbols[symbol_addr].append(symbol)

def write_symbols(symbols_file):
    '''
    Write the found symbols from the process to the given `symbols_file`
    '''
    
    collect_kernel_symbols()
    collect_process_memory_map()

    sorted_items = sorted(symbols.items())

    final_results = []

    for index in range(0, len(sorted_items) - 1):
        # Get the current and next symbol to calculate how 
        (curr_addr, s) = sorted_items[index]

        # Somehow no symbols for this address were added
        if len(s) == 0:
            continue

        # Add the symbol to the final database 
        final_results.append((curr_addr, s[0]))

    print("Writing symbols to {}".format(symbols_file))
    with open(symbols_file, 'w') as f:
        for (addr, sym) in sorted(final_results):
            f.write(f"{addr:#x} {sym}\n")

print("[gdbsnapshot.py] writing symbols")
write_symbols("/tmp/gdb.symbols")
print("[gdbsnapshot.py] done")
