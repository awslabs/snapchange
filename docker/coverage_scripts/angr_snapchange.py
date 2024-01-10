#!/usr/bin/env python
"""
angr-based analysis of binaries.

1. Generate coverage breakpoints with angr.
2. [optional] Generate dictionary based on VEX constants.
3. [optional][experimental] Generate dcitionary based on decompiled code.

for decompiler better to use pypy
```
sudo apt install pypy3 pypy3-dev pypy3-venv
pypy3 -m pip install angr coloredlogs
```
"""

import sys
import logging
import argparse
import string
import json
import math
import struct

from pathlib import Path

# setup logging <= also done by angr
try:
    import coloredlogs

#    coloredlogs.install(level="WARN", logger=logger)
except ImportError:
    logging.basicConfig(level=logging.WARN)

import angr
import angr.analyses.decompiler.structured_codegen.c as angrc
import pyvex
import claripy

logger = logging.getLogger(Path(__file__).name)
# logger.setLevel(logging.DEBUG)
logger.setLevel(logging.INFO)

STR_LEN_THRESHOLD = 128


# Prepare command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("binary", help="The binary to analyze", type=Path)
parser.add_argument(
    "--base-addr",
    help="Base address to rebase the binary",
    type=lambda i: int(i, 0),
    default=0,
)
parser.add_argument(
    "--auto-dict", help="automatically generate a dictionary", action="store_true"
)
parser.add_argument(
    "--use-decompiler",
    help=(
        "use the angr decompiler analysis to identify constants (strings, integers) "
        "in decompiled code. WARNING: slow and potentially broken"
    ),
    action="store_true",
)
parser.add_argument(
    "--dict-path", help="path to store dict files", default=Path("./dict"), type=Path
)
parser.add_argument(
    "--load-from-physmem-offset",
    help=(
        "switch to loading from physmem dump at given offset. "
        "`binary` arg should be path to physmem file. "
        "Use --base-addr to specify virt addr offset."
    ),
    type=lambda i: int(i, 0),
    default=-1,
)
parser.add_argument(
    "--physmem-num-pages",
    default=1,
    type=int,
    help="number of code pages to analyze in physmem",
)
parser.add_argument(
    "--physmem-segments",
    default=[],
    type=lambda b: json.loads(b),
    help="A json-formatted list of `[[file_offset, mem_addr, size], ...]` - hex ints must be strings!",
)
cliargs = parser.parse_args()

binary_path = cliargs.binary
binary_name = binary_path.name
base_addr = cliargs.base_addr

logger.info("loading binary in angr")

p = None
if cliargs.load_from_physmem_offset in (None, -1):
    p = angr.Project(
        binary_path,
        load_options={"auto_load_libs": False},
        main_opts={"base_addr": base_addr},
    )
else:
    segments = [
        (
            cliargs.load_from_physmem_offset,
            cliargs.base_addr,
            cliargs.physmem_num_pages * 4096,
        )
    ]
    if cliargs.physmem_segments:

        def ensure_int(s):
            if isinstance(s, int):
                return s
            return int(s, 0)

        # override defaults segments arg
        segments = [
            (ensure_int(o), ensure_int(a), ensure_int(s))
            for (o, a, s) in cliargs.physmem_segments
        ]
    p = angr.Project(
        binary_path,
        main_opts={
            "backend": "blob",
            "arch": "x86_64",
            "segments": segments,
            "base_addr": cliargs.base_addr,
            "entry_point": cliargs.base_addr,
        },
    )

logger.info("angr CFGFast")
cfg = p.analyses.CFGFast(normalize=True, data_references=True)
logger.info(
    "CFG recovered with %d nodes and %d edges",
    len(cfg.graph.nodes()),
    len(cfg.graph.edges()),
)

# easy mode...
addrs = set()
outfile = cliargs.binary.parent / f"{binary_name}.angr.covbps"
with outfile.open("w") as f:
    # angr/vex splits BBs after call instructions, so we have a couple of unnecessary breakpoints using this.
    # addrs = sorted([(bb.addr, bb.block.size) for bb in cfg.graph.nodes()])
    for node in cfg.graph.nodes():
        block = node.block
        if block:
            addrs.add((node.addr, block.size))
        else:
            logger.debug(f"odd: cfg node {node} without block")
    # # alternative:
    # for func in cfg.functions.values():
    #     addrs.update(func.block_addrs)
    f.write("\n".join(map(lambda bb: f"{bb[0]:#x},{bb[1]:#x}", sorted(list(addrs)))))

logger.info("covbps done")

# check if we are done and exit
if not cliargs.auto_dict:
    logger.warning("not doing auto-dict")
    sys.exit(0)

auto_dictionary = set()

ALPHANUM = set(string.ascii_letters + string.digits)


def int_is_interesting(i, size):
    if i == 0:
        return False
    if i < 256:
        return False
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
    # check if address -> ignore
    if p.loader.main_object.contains_addr(i):
        return False

    # ok we found no reason to not find it interesting.
    return True


def add_vex_const(c):
    if isinstance(c.value, int):
        if int_is_interesting(c.value, c.size):
            auto_dictionary.add(c.value)
    elif isinstance(c.value, float):
        if not math.isnan(c.value):
            auto_dictionary.add(c.value)
    else:
        # is there something else?
        auto_dictionary.add(c.value)


def add_vex_memory(addr, memlen=STR_LEN_THRESHOLD, null_term=False, both_cases=False):
    if addr is None or memlen is None:
        return
    if isinstance(addr, int):
        pass  # all good
    elif isinstance(addr, pyvex.expr.Const):
        addr = addr.value
    if memlen > STR_LEN_THRESHOLD:
        return
    # worklist = []
    logger.debug("add_vex_memory('%r', %d)", addr, memlen)
    if addr >= 0 and p.loader.main_object.contains_addr(addr):
        p.loader.memory.seek(addr)
        data = p.loader.memory.read(memlen)
        if null_term:
            term = data.find(0)
            if term > 0:
                data = data[:term]
        auto_dictionary.add(data)
        logger.debug("added data %r", data)
        if both_cases:
            auto_dictionary.add(data.upper())
            auto_dictionary.add(data.lower())
    else:
        logger.debug("add_memory found invalid address %d", addr)


def get_function_args(irsb, func, num_args):
    prop = p.analyses.Propagator(block=irsb, func=func)
    args = []
    regs = {}
    # if num_args == 1:
    # 24: 'rcx',
    # 32: 'rdx',
    # 40: 'rbx',
    # 48: 'rsp',
    # 56: 'rbp',
    # 64: 'rsi',
    # 72: 'rdi',
    for repl in prop.replacements.values():
        # logger.debug("%r", repl)
        for k, v in repl.items():
            if isinstance(k, angr.analyses.propagator.vex_vars.VEXReg) and isinstance(
                v, claripy.ast.bv.BV
            ):
                # ok we know how to handle this...
                if k.offset == 72:
                    regs["rdi"] = v.args[0]
                elif k.offset == 64:
                    regs["rsi"] = v.args[0]
                elif k.offset == 32:
                    regs["rdx"] = v.args[0]
                elif k.offset == 24:
                    regs["rcx"] = v.args[0]
    if num_args >= 1:
        args.append(regs.get("rdi"))
    if num_args >= 2:
        args.append(regs.get("rsi"))
    if num_args >= 3:
        args.append(regs.get("rdx"))
    if num_args >= 4:
        args.append(regs.get("rcx"))
    if len(args) != num_args:
        return None
    return args


# first use vex to identify constants - this is quite fast, but also a bit limited.
for func in cfg.functions.values():
    for block in func.blocks:
        try:
            irsb = block.vex
        except (pyvex.errors.PyVEXError, angr.errors.SimTranslationError):
            logger.warning("failed to translate block to vex")
            continue
        worklist = []
        for stmt in irsb.statements:
            exprs = list(stmt.child_expressions)
            if not exprs:
                continue
            op = exprs[0]
            if isinstance(op, pyvex.expr.Binop) and (
                op.op.startswith("Iop_Cmp")
                or op.op.startswith("Iop_CasCmp")
                or op.op.startswith("Iop_ExpCmp")
            ):
                # op.pp()
                for child_expr in op.child_expressions:
                    for c in child_expr.constants:
                        add_vex_const(c)
                    if isinstance(child_expr, pyvex.expr.RdTmp):
                        worklist.append(child_expr.tmp)
        # basic backtracking to identify constants that are contained within
        # the IRSB
        visited = set()
        while worklist:
            tmp = worklist.pop(0)
            if tmp in visited:
                continue
            visited.add(tmp)
            for stmt in irsb.statements:
                if isinstance(stmt, pyvex.stmt.WrTmp):
                    if stmt.tmp == tmp:  # we found our assignment
                        for child_expr in stmt.child_expressions:
                            if isinstance(child_expr, pyvex.expr.RdTmp):
                                worklist.append(child_expr.tmp)
                        for c in stmt.constants:
                            add_vex_const(c)

        if irsb.jumpkind == "Ijk_Call":
            next_addr = irsb.next
            if isinstance(next_addr, int):
                pass
            elif isinstance(next_addr, pyvex.expr.Const):
                next_addr = next_addr.con.value
            else:
                continue
            call_target = cfg.functions.get(next_addr)
            if call_target and call_target.name:
                fname = call_target.name
                if fname in [
                    "strcmp",
                    "xmlStrcmp",
                    "xmlStrEqual",
                    "g_strcmp0",
                    "curl_strequal",
                    "strcsequal",
                ]:
                    logger.info("found strcmp")
                    args = get_function_args(irsb, func, 2)
                    if args:
                        add_vex_memory(args[0], null_term=True)
                        add_vex_memory(args[1], null_term=True)
                    else:
                        logger.warning("failed to get args")
                elif fname in [
                    "memcmp",
                    "CRYPTO_memcmp",
                    "OPENSSL_memcmp",
                    "memcmp_const_time",
                    "memcmpct",
                ]:
                    logger.info("found memcmp")
                    args = get_function_args(irsb, func, 3)
                    if args:
                        add_vex_memory(args[0], args[2])
                        add_vex_memory(args[1], args[2])
                    else:
                        logger.warning("failed to get args")

                elif fname in ["strncmp", "xmlStrncmp", "curl_strnequal"]:
                    logger.info("found strncmp")
                    args = get_function_args(irsb, func, 3)
                    if args:
                        add_vex_memory(args[0], args[2], True)
                        add_vex_memory(args[1], args[2], True)
                    else:
                        logger.warning("failed to get args")
                elif fname in [
                    "strcasecmp",
                    "stricmp",
                    "ap_cstr_casecmp",
                    "OPENSSL_strcasecmp",
                    "xmlStrcasecmp",
                    "g_strcasecmp",
                    "g_ascii_strcasecmp",
                    "Curl_strcasecompare",
                    "Curl_safe_strcasecompare",
                    "cmsstrcasecmp",
                ]:
                    logger.info("found strcasecmp")
                    args = get_function_args(irsb, func, 2)
                    if args:
                        add_vex_memory(args[0], null_term=True, both_cases=True)
                        add_vex_memory(args[1], null_term=True, both_cases=True)
                    else:
                        logger.warning("failed to get args")
                elif fname in [
                    "strncasecmp",
                    "strnicmp",
                    "ap_cstr_casecmpn",
                    "OPENSSL_strncasecmp",
                    "xmlStrncasecmp",
                    "g_ascii_strncasecmp",
                    "Curl_strncasecompare",
                    "g_strncasecmp",
                ]:
                    logger.info("found strncasecmp")
                    args = get_function_args(irsb, func, 3)
                    if args:
                        add_vex_memory(
                            args[0], args[2], null_term=True, both_cases=True
                        )
                        add_vex_memory(
                            args[1], args[2], null_term=True, both_cases=True
                        )
                    else:
                        logger.warning("failed to get args")

# TODO: can we use VEX to identify calls with constants?


# next we use angr's decompiler to generate pseuo-c and check the AST for constants
# this is quite slow and might also be a bit broken.


def add_dec_c_const(c):
    if isinstance(c.value, int):
        if int_is_interesting(c.value, c.type.size):
            auto_dictionary.add(c.value)
    elif isinstance(c.value, float):
        if not math.isnan(c.value):
            auto_dictionary.add(c.value)
    else:
        # is there something else?
        auto_dictionary.add(c.value)


def check_dec_function(func, dec):
    logger.info("checking function %r", func)
    stmt_worklist = [dec.codegen.cfunc.statements]
    logger.debug("%r", stmt_worklist)

    def check_condition(cond):
        if isinstance(cond, angrc.CBinaryOp):
            stmt_worklist.append(cond.lhs)
            stmt_worklist.append(cond.rhs)
        elif isinstance(cond, angrc.CUnaryOp):
            stmt_worklist.append(cond.operand)
        elif isinstance(cond, angrc.CTypeCast):
            stmt_worklist.append(cond.expr)

    def check_for_constant(c):
        if isinstance(c, angrc.CConstant):
            add_dec_c_const(c)
        else:
            check_condition(c)

    def add_memory(op, memlen=STR_LEN_THRESHOLD, null_term=False):
        if memlen > STR_LEN_THRESHOLD:
            return
        # worklist = []
        logger.debug("add_memory('%s' (%r), %d)", op.c_repr(), op, memlen)
        if isinstance(op, angrc.CUnaryOp):
            if op.op == "Reference":
                if isinstance(op.operand, angrc.CVariable):
                    addr = op.operand.variable.addr
                else:
                    logger.warning(
                        "add_memory CUnaryOp branch can't handle %r", op.operand
                    )
                    return
                if addr > 0 and p.loader.main_object.contains_addr(addr):
                    p.loader.memory.seek(addr)
                    data = p.loader.memory.read(memlen)
                    if null_term:
                        term = data.find(0)
                        if term > 0:
                            data = data[:term]
                    auto_dictionary.add(data)
                    logger.debug("added data %r", data)
                else:
                    logger.debug("add_memory found invalid address %d", addr)
                return
            else:
                logger.warning("oh no unimplemented handling of unary op %s", op.op)
                return

        logger.warning("add_memory can't handle %r", op)

    while stmt_worklist:
        stmt = stmt_worklist.pop(0)
        # check basic expressions for constants and recurse otherwise
        if isinstance(stmt, angrc.CBinaryOp):
            check_for_constant(stmt.lhs)
            check_for_constant(stmt.rhs)
        elif isinstance(stmt, angrc.CUnaryOp):
            check_for_constant(stmt.operand)
        elif isinstance(stmt, angrc.CTypeCast):
            check_for_constant(stmt.expr)
        elif isinstance(stmt, angrc.CStatements):
            logger.debug("recurse into statements")
            stmt_worklist.extend(stmt.statements)
            logger.debug("%r", stmt_worklist)
        elif isinstance(stmt, angrc.CAssignment):
            # only RHS of an assignment
            stmt_worklist.append(stmt.rhs)
        elif isinstance(stmt, (angrc.CForLoop, angrc.CDoWhileLoop, angrc.CWhileLoop)):
            # we check the loop condition
            check_condition(stmt.condition)
            # and recurse into the body
            stmt_worklist.append(stmt.body)
        elif isinstance(stmt, angrc.CIfElse):
            for (cond, substmts) in stmt.condition_and_nodes:
                stmt_worklist.append(substmts)
                check_condition(cond)
            if stmt.else_node:
                stmt_worklist.append(stmt.else_node)
        elif isinstance(stmt, angrc.CIfBreak):
            pass
        elif isinstance(stmt, angrc.CSwitchCase):
            pass
        elif isinstance(stmt, angrc.CFunctionCall):
            logger.info("callee target: %r at %s", stmt.callee_target, stmt.c_repr())
            fname = None
            if isinstance(stmt.callee_target, angrc.CConstant):
                faddr = stmt.callee_target.value
                func = cfg.functions.get(faddr)
                if not func:
                    continue
                fname = func.name
            elif isinstance(stmt.callee_target, angrc.CFunction):
                fname = stmt.callee_target.name
            else:
                logger.warn("can't handle callee_target: %r", stmt.callee_target)
                continue

            if fname in [
                "strcmp",
                "xmlStrcmp",
                "xmlStrEqual",
                "g_strcmp0",
                "curl_strequal",
                "strcsequal",
            ]:
                logger.info("found strcmp")
                if len(stmt.args) >= 2:
                    lhs = stmt.args[0]
                    rhs = stmt.args[1]
                    add_memory(lhs, null_term=True)
                    add_memory(rhs, null_term=True)
                else:
                    logger.warning(
                        "strcmp with too few args: %r at %s", stmt, stmt.c_repr()
                    )
            elif fname in [
                "memcmp",
                "CRYPTO_memcmp",
                "OPENSSL_memcmp",
                "memcmp_const_time",
                "memcmpct",
            ]:
                logger.info("found memcmp")
                if len(stmt.args) >= 3:
                    lhs = stmt.args[0]
                    rhs = stmt.args[1]
                    memlen = stmt.args[2]
                    if isinstance(memlen, angrc.CConstant):
                        memlen = memlen.value
                        add_memory(lhs, memlen)
                        add_memory(rhs, memlen)
                    else:
                        logger.warning(
                            "cannot handle memcpy with non-constant length: %s",
                            stmt.c_repr(),
                        )
                else:
                    logger.warning(
                        "memcmp with too few args: %r at %s", stmt, stmt.c_repr()
                    )
            elif fname in ["strncmp", "xmlStrncmp", "curl_strnequal"]:
                logger.info("found strncmp")
                if len(stmt.args) >= 3:
                    lhs = stmt.args[0]
                    rhs = stmt.args[1]
                    memlen = stmt.args[2]
                    if isinstance(memlen, angrc.CConstant):
                        memlen = memlen.value
                        add_memory(lhs, memlen, null_term=True)
                        add_memory(rhs, memlen, null_term=True)
                    else:
                        logger.warning(
                            "cannot handle memcpy with non-constant length: %s",
                            stmt.c_repr(),
                        )
                else:
                    logger.warning(
                        "memcmp with too few args: %r at %s", stmt, stmt.c_repr()
                    )
            elif fname in [
                "strcasecmp",
                "stricmp",
                "ap_cstr_casecmp",
                "OPENSSL_strcasecmp",
                "xmlStrcasecmp",
                "g_strcasecmp",
                "g_ascii_strcasecmp",
                "Curl_strcasecompare",
                "Curl_safe_strcasecompare",
                "cmsstrcasecmp",
            ]:
                pass
            elif fname in [
                "strncasecmp",
                "strnicmp",
                "ap_cstr_casecmpn",
                "OPENSSL_strncasecmp",
                "xmlStrncasecmp",
                "g_ascii_strncasecmp",
                "Curl_strncasecompare",
                "g_strncasecmp",
            ]:
                pass


if cliargs.use_decompiler:
    for func in cfg.functions.values():
        # for debugging:
        # if not (func.name and func.name == "fuzzme"):
        #     continue

        logger.info("decompiling function %r name", func)
        dec = None
        try:
            dec = p.analyses.Decompiler(func)
        except Exception as exc:
            logger.warn("failed to decompile %s", func, exc_info=exc)
            continue
        if not (dec and dec.codegen):
            logger.warn("failed to decompile %s", func)
            continue

        check_dec_function(func, dec)


auto_dict_files = {}
for entry in auto_dictionary:
    if isinstance(entry, int):
        entry = abs(entry)
        # identify the size of constant - we always use the smallest possible one
        if entry < (1 << 8):
            # we don't bother with byte-size constants
            continue
        elif entry < (1 << 16):
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
            logger.warning("unsupported int constant is too big: %s", hex(entry))

        # emit both endian - who knows.
        for endian in ("little", "big"):
            data = entry.to_bytes(size, endian)
            fname = endian + "_" + hex(entry)
            auto_dict_files[fname] = data

        fname = "int_str_" + str(entry).replace("-", "neg")
        auto_dict_files[fname] = str(entry).encode()

    elif isinstance(entry, float):
        # emit using struct.pack in various formats
        for float_fmt in ("e", "f", "d"):
            for endian in (("<", "le"), (">", "be")):
                fmt = endian[0] + float_fmt
                try:
                    buf = struct.pack(fmt, entry)
                    fname = "_".join([float_fmt, endian[1], hex(hash(entry))[2:]])
                    auto_dict_files[fname] = buf
                except (ValueError, OverflowError):
                    pass

        # emit as ascii str
        fname = "float_str_" + str(entry).replace(".", "_").replace("-", "neg")
        with (location / fname).open("w") as f:
            auto_dict_files[fname] = str(entry)

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

        auto_dict_files[fname] = entry

        entry_stripped = entry.strip(b"\x00\t \n\r")
        if entry_stripped != entry:
            auto_dict_files[fname + "_trimmed"] = entry_stripped
    else:
        logger.warning("cannot deal with %s in auto-dict %s", type(entry), repr(entry))


dict_path = cliargs.dict_path
logger.info(f"writing auto-dict entries to {dict_path}")
dict_path.mkdir(parents=True, exist_ok=True)
written = 0
for fname, content in auto_dict_files.items():
    with (dict_path / fname).open("wb") as f:
        f.write(content)
        written += 1

logger.info(f"wrote {written} auto-dict entries")


sys.exit(0)
