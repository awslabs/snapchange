#!/usr/bin/env python

import string
import sys

entries = set()

for line in open(sys.argv[1]).readlines():
    line = line.strip()
    entries.add(line)


for lin in entries:
    fname = hex(hash(line))[2:] + "_"
    if all(c in string.ascii_letters for c in line):
        fname += line
    with open("./dict/" + fname, "w") as f:
        f.write(line)
