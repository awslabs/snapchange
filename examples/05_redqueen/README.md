# Example 5 - Redqueen implementation

This example will demonstrate the redqueen implementation in Snapchange. [Redqueen](https://www.ndss-symposium.org/ndss-paper/redqueen-fuzzing-with-input-to-state-correspondence/) 
aims to help solve difficult branches during fuzzing by analyzing runtime information of the target.

_NOTE: Redqueen is built on top of a Binary Ninja analysis plugin. The output
of the plugin is in this example in case you don't have a copy of Binary Ninja.
A license to Binary Ninja would be required to use Redqueen for other targets_

## Target

The [target](./harness/test_redqueen.c#L68) for this example is a series of "hard" fuzz 
blockers. The target exercises comparisons (`==`, `>=`, `<=`, `<`, and `>`) for the 
following types:

* `int`
* `unsigned int`
* `short`
* `unsigned short`
* `long long`
* `unsigned long long`
* `float`
* `double`

There are also sections of branchless code and `strcmp` and `memcmp`. The goal of
the fuzzer is to get past these checks. 

The fuzzer achieves this by breaking at the instruction after every known comparison 
operation. Each breakpoint knows which registers/memory to compare against. The fuzzer
checks if the operands of the comparison and creates a rule to attempt to invert the
current state of the comparison. If either operand is found in the input, the rule will
attempt to replace the found bytes with bytes that will invert the comparison.

For example, this comparison will return true if eax and ebx are equal. 

```
Comparison: eax == ebx
EAX = AAAA
EBX = BBBB
```

Rules will be created to attempt to replace instances of AAAA in the input with BBBB in order
to satisfy the comparison.

The [redqueen documention](../../docs/REDQUEEN.md) has further details on the implementation.

## Usage

Create the example snapshot using the supplied script

```
./make_example.sh
```

Fuzz the example

```
cargo run -r -- fuzz -c 8
```

Like in example 1, the fuzzer will pass through the required checks and set the result of `getpid`
to the required value in order to cause the bug to be triggered.

## Configuration knobs

The project contains a configuration at `./snapshot/config.toml`. There are a few configuration 
options that are worth mentioning:

```
[redqueen]
# Number of cores that will execute redqueen
cores = 8

# How long to allow any core to stay executing redqueen before exiting the current fuzz iteration
[redqueen.timeout]
secs = 2
nanos = 0
```
