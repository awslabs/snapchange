#!/usr/bin/env python

import tempfile
import subprocess
import os
import sys
import argparse
from pathlib import Path

ghidra_dir_guess = None
if "SNAPCHANGE_ROOT" in os.environ:
    ghidra_dir_guess = Path(os.environ["SNAPCHANGE_ROOT"]) / "ghidra"
else:
    ghidra_dir_guess = Path(__file__).parent.parent / "ghidra"
ghidra_dir_guess = ghidra_dir_guess.resolve()

# Prepare command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("binary", help="The binary to analyze with Ghidra", type=Path)
parser.add_argument(
    "--ghidra-dir",
    help="The path to the Ghidra directory",
    default=ghidra_dir_guess,
    type=Path,
)
parser.add_argument(
    "--base-addr", help="Base address to rebase the binary", type=lambda i: int(i, 0)
)

# Parse command line arguments
args = parser.parse_args()

# Get the path to the headless binary
headless = Path(args.ghidra_dir) / "support" / "analyzeHeadless"
if not headless.exists():
    print(
        "Couldn't find ghidra directory... please specify with --ghidra-dir",
        file=sys.stderr,
    )
    sys.exit(1)

if not args.binary.exists():
    print("non-existing binary path:", args.binary, file=sys.stderr)
    sys.exit(1)

# Analyze the binary using a temp directory
with tempfile.TemporaryDirectory() as tempdir:
    project_dir = tempfile.TemporaryDirectory(dir=tempdir)
    # output_dir = tempfile.TemporaryDirectory(dir=tempdir)
    this_dir = Path(__file__).resolve().parent
    # output_file = output_dir.name + "/output"

    # print(f"This dir {this_dir}")

    # Create the command to execute the python script
    command = [
        headless,
        project_dir.name,
        "temp",
        "-import",
        args.binary.resolve(),
        "-scriptPath",
        this_dir,
        "-postScript",
        "ghidra_script_bb_worker.py",
    ]

    # If there is a new base address via command line, add it to the command
    # to be picked up by Ghidra
    if args.base_addr:
        command.append(hex(args.base_addr))

    command = list(map(str, command))
    # Execute the command
    output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # print(output.stdout.decode())
    print(output.stderr.decode(), file=sys.stderr)

    # Only print lines from Ghidra for our executed script
    for line in output.stdout.decode().split("\n"):
        if "bb_worker.py>" not in line:
            continue

        print(line)
