#!/usr/bin/env python

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

import angr
import pyvex

# Prepare command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("binary", help="The binary to analyze", type=Path)
parser.add_argument("--base-addr", help="Base address to rebase the binary", type=lambda i: int(i, 0), default=0)
parser.add_argument("--auto-dict", help="automatically generate a dictionary", action="store_true")
args = parser.parse_args()

binary_path = args.binary
binary_name = binary_path.name
base_addr = args.base_addr

logger.info("loading binary in angr")
p = angr.Project(binary_path, load_options={'auto_load_libs': False}, main_opts={'base_addr': base_addr})
logger.info("angr CFGFast")
cfg = p.analyses.CFGFast(normalize=True, data_references=True)
logger.info("CFG recovered with %d nodes and %d edges", len(cfg.graph.nodes()), len(cfg.graph.edges()))

addrs = set()
with open(f"{binary_name}.angr.covbps", "w") as f:
    # angr/vex splits BBs after call instructions, so we have a couple of unnecessary breakpoints using this.
    # `addrs = sorted([bb.addr for bb in cfg.graph.nodes()])`
    # alternative:
    for func in cfg.functions.values():
        addrs.extend(func.block_addrs)
    f.write("\n".join(map(hex, sorted(addrs))))

# check if we are done and exit
if not args.auto_dict:
    sys.exit(0)

auto_dictionary = set()

compares = []


# first use vex
# for block_addr in addrs:
for func in cfg.functions.values():
    for block in func.blocks:
        irsb = block.vex
        for stmt in irsb.statements:
            exprs = list(stmt.expressions)
            if not exprs:
                continue
            if isinstance(exprs[0], pyvex.expr.Binop):
                for e in exprs[1:]:
                    if isinstance(e, pyvex.expr.Const):
                       auto_dictionary.add(const.con.value)


sys.exit(0)


# TODO: use the decompiler to get better constants?

for func in cfg.functions:
    dec = p.analyses.Decompiler(func)
    if not (dec and dec.codegen):
        logger.warn("failed to decompile %s", func)
