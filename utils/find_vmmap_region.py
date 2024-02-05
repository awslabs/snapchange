#!/usr/bin/env python

import sys

vmmap = sys.argv[1]
target = int(sys.argv[2], 0)

regions = []

found = False
with open(vmmap, "r") as f:
    for line in f.readlines():
        line = line.strip()
        if not line.startswith("0x"):
            continue

        line = line.split()
        start = int(line[0], 0)
        end = int(line[1], 0)

        regions.append((start, end, line[2:]))
        if start <= target and target <= end:
            print("target address", hex(target), "is within memory region:")
            print(*line)
            found = True
            break

regions = sorted(regions, key=lambda x: x[0])
region_before = None
region_after = None
if not found:
    for region in regions:
        start, end, _ = region
        if target > end:
            region_before = region
        if target < start:
            if region_after is None:
                region_after = region
            else:
                if start < region_after[0]:
                    region_after = region

    print("target address", hex(target), "is between two memory regions:")
    print(hex(region_before[0]), hex(region_before[1]), *region_before[2])
    print(hex(region_after[0]), hex(region_after[1]), *region_after[2])
