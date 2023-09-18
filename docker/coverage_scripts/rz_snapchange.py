#!/usr/bin/env python
"""
Use rizin/rzpipe to identify a set of basic blocks.

requirements:
    rizin
    pip3 install rzpipe
"""

import sys
import logging
import argparse

from pathlib import Path

# setup logging
try:
    import coloredlogs
    coloredlogs.install(level='DEBUG')
except ImportError:
    logging.basicConfig(level=logging.INFO)

logger = logging.getLogger(Path(__file__).name)

import rzpipe


# Prepare command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("binary", help="The binary to analyze", type=Path)
parser.add_argument("--base-addr", help="Base address to rebase the binary", type=lambda i: int(i, 0), default=0)
parser.add_argument("--auto-dict", help="automatically generate a dictionary", action="store_true")
args = parser.parse_args()

binary_path = args.binary
binary_name = binary_path.name
base_addr = args.base_addr

bb_addrs = set()

p = rzpipe.open(str(binary_path), flags=["-B", hex(base_addr)])
p.cmd("aa")  # analyze all
funcs = p.cmdj("aflj")
for func in funcs:
    blocks = p.cmdj("afbj @ " + hex(func['offset']))
    bb_addrs.update(b['addr'] for b in blocks)

outfile = args.binary.parent / f"{binary_name}.rz.covbps"
with outfile.open("w") as f:
    f.write("\n".join(map(hex, sorted(bb_addrs))))
