import tempfile
import subprocess
import os
import sys
import argparse
from pathlib import Path

# Prepare command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("binary", help="The binary to analyze with Ghidra")
parser.add_argument("--ghidra-dir", help="The path to the Ghidra directory", default="ghidra")
parser.add_argument("--base-addr", help="Base address to rebase the binary")

# Parse command line arguments
args = parser.parse_args()

# Get the path to the headless binary
headless = Path(args.ghidra_dir) / 'support' / 'analyzeHeadless'

# Analyze the binary using a temp directory
with tempfile.TemporaryDirectory() as tempdir:
    project_dir = tempfile.TemporaryDirectory(dir=tempdir)
    output_dir = tempfile.TemporaryDirectory(dir=tempdir)
    this_dir = Path(__file__).resolve()
    output_file = output_dir.name + "/output"

    print(f"This dir {this_dir}")

    # Create the command to execute the python script
    command = [
        f'{headless}',
        project_dir.name,
        "temp",
        "-import",
        os.path.abspath(args.binary),
        "-scriptPath",
        f'{this_dir}',
        "-postScript",
        ".ghidra_worker.py",
    ]

    # If there is a new base address via command line, add it to the command
    # to be picked up by Ghidra
    if args.base_addr:
        command.append(args.base_addr)

    # Execute the command
    output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    print(f'{output.stdout.decode()}')
    print(f'{output.stderr.decode()}')

    # Only print lines from Ghidra for our executed script
    for line in output.stdout.decode().split("\n"):
        if 'bb.py>' not in line:
            continue

        print(f'{line}')
 
