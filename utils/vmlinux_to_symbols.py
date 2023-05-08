import os
import sys
import subprocess
from pathlib import Path

if len(sys.argv) < 2:
    print("USAGE: python3 vmlinux_to_symbols.py <VMLINUX>")
    sys.exit(0)

for p in os.environ['PATH'].split(":"):
    check_path = Path(p) / "nm"
    if check_path.exists():
        break
else:
    print("`nm` not found in path")
    sys.exit(0)

# Get the vmlinux path
vmlinux_path = sys.argv[1]

# Write out to vmlinux_path.symbols
out_path = Path(vmlinux_path).with_suffix(".symbols")

# Gather symbols from vmlinux from `nm`
data = subprocess.check_output(["nm", vmlinux_path])

symbols = []

# Gather the (address, symbol) for each symbol found in `nm`
for line in data.split(b'\n'):
    if len(line) < 2:
        continue

    (addr, _, symbol) = line.split()
    symbols.append((int(addr, 16), symbol))

# Sort the symbols and dump in the {"address": addr, "symbol": sym} format 
result = []
for (addr, sym) in sorted(symbols):
    result.append({"address": addr, "symbol": sym})

# Write out the file
with open(out_path, 'w') as f:
    f.write(str(result).replace("'", '"').replace('b"', '"'))

print(f"vmlinux symbols written to {out_path}")
