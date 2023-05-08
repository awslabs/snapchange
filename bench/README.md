# Snapchange benchmark

This is the basic snapchange benchmark for gathering performance data across several factors:

* Instructions per iteration
* Breakpoints triggered per iteration
* Dirty Pages restored per iteration
* Number of cores used

Building the benchmark is a script:

```sh
$ ./make_bench_target.sh
```

Executing the benchmark is also a simple script:

```sh
$ ./bench.sh
```

This will generate a `data_120s` directory containing all of a `stats` file for each benchmark 
configuration. There is a small utility used to convert the data to be used for generating 
the comparison graphs.

```sh
$ cd gather_data
$ cargo run -r -- ../data_120s
$ cd ..
```

This will create a `data_120s.dat` data file with the extracted data ready for [seaborn](https://seaborn.pydata.org/)
to generate several graphs.

```sh
$ pip3 install seaborn
$ python3 generate_graph.py ./data_120.dat
```

## Benchmark harness

The benchmark harness is a small [assembly snippet](./bench_harness/src/main.rs):

```
  // Execute the dirty pages and instructions for this benchmark
  // R9 - Memory that can be dirtied (should NOT have to be set in the benchmark fuzzer)
  // R10 - Number of pages to dirty (at least 1)
  // RCX - Number of instructions to execute (not including dirtying pages)
  unsafe {
      std::arch::asm!(
          r#"
          4:
          mov byte ptr [r9], 0x41
          add r9, 0x1000
          dec r10
          jnz 4b

          2:
          dec rcx
          jnz 2b
      "#,
          in("r9") scratch,
          options(nostack)
      );
  }
```

This section will dirty pages by writing a single byte to each page. The number of pages to dirty
is set in `rdi` 

```
4:
mov byte ptr [r9], 0x41
add r9, 0x1000
dec r10
jnz 4b
```

For number of instructions, there is a tight loop that executes. The number of instructions is stored in `rcx`.

```
2:
dec rcx
jnz 2b
```

The number of instructions and dirty pages cores are given to the harness via environment variables.

For running the benchmark with `1000` pages, `1000000` instructions, and `8` cores.

```PAGES=1000 INSTRS=1000000 timeout 120s cargo run -r -- fuzz -c 8 --timeout 120s```

For running the benchmark with `1000` pages, `1000000` breakpoints, and `8` cores.

```PAGES=1000 VMEXITS=1000000 timeout 120s cargo run -r -- fuzz -c 8 --timeout 120s```
