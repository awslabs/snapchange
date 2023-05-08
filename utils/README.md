# Utility functions

## vmlinux_to_symbols.py

Dumps the symbols found in a given `vmlinux` to the same `.symbols` format expected by
the fuzzer

```
python3 vmlinux_to_symbols.py vmlinux
```

```
[
  {"address": 0, "symbol": "__per_cpu_start"}, 
  {"address": 0, "symbol": "fixed_percpu_data"},
]
```
