#!/usr/bin/env python
"""
Plot two runs of snapchange side-by-side for comparison.

e.g.,
```
cargo run -r -- fuzz ...
cp -r snapshot/data first
cargo run -r -- fuzz ...
cp -r snapshot/data second
python /path/to/snapchange/plot_stats_diff.py first second
```
"""

import sys
try:
    import plotext as plt
except ImportError as e:
    print(e)
    print()
    print("please do: pip install --user plotext")
    sys.exit(-1)

if len(sys.argv) != 3:
    print("usage:", sys.argv[0], "./path/to/first/data", "./path/to/second/data")
    sys.exit(1)


def read_data(dir):
    with open(f"./{dir}/exec_per_sec.plot") as f:
        execs = [int(x.strip(), 0) for x in f.read().splitlines() if x.strip()]
    with open(f"./{dir}/dirty_page_per_sec.plot") as f:
        dirty_pages = [[int(y.strip(), 0) for y in x.strip().split(",") if y.strip()] for x in f.read().splitlines() if x.strip()]

    assert execs
    assert dirty_pages

    execs_describe = " ".join(map(str, 
                                  ["execs/sec", 
                                   "max:", max(execs), 
                                   "min (!= 0):", min(d for d in execs if d > 0), 
                                   "avg:", sum(execs) // len(execs)]))

    split_dirty_pages = [
        [ x[0] for x in dirty_pages ],  # total
        [ x[1] for x in dirty_pages ],  # kvm
        [ x[2] for x in dirty_pages ],  # fuzzer/custom
    ]
    min_f = 0
    min_f_seq = [d for d in split_dirty_pages[2] if d > 0]
    if min_f_seq:
        min_f = min(min_f_seq)
    dirty_pages_describe = "".join(map(str, 
                                  ["dirty_pages/sec (T/K/F) ", 
                                   "max: ", max(split_dirty_pages[0]), 
                                   "/", max(split_dirty_pages[1]), 
                                   "/", max(split_dirty_pages[2]), 
                                   " min: ", min(d for d in split_dirty_pages[0] if d > 0), 
                                   "/", min(d for d in split_dirty_pages[1] if d > 0), 
                                   "/", min_f, 
                                   " avg: ", sum(split_dirty_pages[0]) // len(dirty_pages),
                                   "/", sum(split_dirty_pages[1]) // len(dirty_pages),
                                   "/", sum(split_dirty_pages[2]) // len(dirty_pages),
                                   ]))
    return execs, execs_describe, split_dirty_pages, dirty_pages_describe


first = read_data(sys.argv[1])
second = read_data(sys.argv[2])

plt.subplots(2, 2)

# plot execs
plt.subplot(1, 1)
plt.plot(first[0])
plt.title(first[1])

plt.subplot(1, 2)
plt.plot(second[0])
plt.title(second[1])

# plot dirty pages
plt.subplot(2, 1)
plt.plot(first[2][0], label = "total")
plt.plot(first[2][1], label = "kvm")
plt.plot(first[2][2], label = "custom")
plt.title(first[3])

plt.subplot(2, 2)
plt.plot(second[2][0], label = "total")
plt.plot(second[2][1], label = "kvm")
plt.plot(second[2][2], label = "custom")
plt.title(second[3])


plt.show()
