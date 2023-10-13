# Tutorial 6 - Custom Feedback

Snapchange does not only support code coverage, but also supports providing custom feedback to guide the fuzzer towards interesting program states.
This requires to add some domain knowledge to the fuzzer on what is considered interesting. 
We can do that using the usual breakpoint hooks provided by snapchange.

For more information on the techniques we use in snapchange, we would like to point out to the [IJON paper](https://nyx-fuzz.com/papers/ijon.pdf), which proposed many of the techniques we use here.

In this tutorial, we will solve a well-known challenge for automated test-case
generators: a simple maze game. Note that a specialized solver for the maze
would be more efficient, but we want to demonstrate how a snapchange fuzzer can
be adapted to essentially become a solver for the maze.


```
+-+---+---+
|X|     |#|
| | --+ | |
| |   | | |
| +-- | | |
|     |   |
+-----+---+
```

The maze code is taken from Felipe Andres Manzano's blog: http://feliam.wordpress.com/2010/10/07/the-symbolic-maze/
And is adapted according to the changes from the ijon paper: https://github.com/RUB-SysSec/ijon-data/tree/master/maze

Note that we build several variants of the maze code, with two different sizes
and with backtracking enabled or not. The directory already provides several
convenience wrappers around the different maze variants: `./fuzz.sh
maze.variant`, `./run.sh maze.variant`, etc.

We will use the `maze.small` variant throughout this tutorial, but the exact
same code can be used to solve the other variants, although with a bit more
fuzzing time.

## Program state feedback

The maze walking code has one important program state that we want to explore
with the fuzzer: the `(x, y)` coordinates of the player. We want the fuzzer to know about the current position of the maze, so need to identify a point in the program. Fortunately, there are various function calls that receive the current positions of the player as arguments, such as `win`, `lose`, and `log_pos`. We can place breakpoint hooks in the fuzzer to gather feedback. For example, we can hook the `log_pos` function to observe every position that the player visits. We obtain the `(x, y)` values from the registers `rsi` and `rdx` (second and third parameter). We then use the `feedback.record_pair` function to record the `(x, y)` values as custom feedback.

```rust
Breakpoint {
    lookup: AddressLookup::SymbolOffset(constants::TARGET_LOG_POS, 0x0),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<Self>, _input, _fuzzer, feedback| {
        if let Some(feedback) = feedback {
            let x = (fuzzvm.rsi() & 0xffff) as u32;
            let y = (fuzzvm.rdx() & 0xffff) as u32;
            if feedback.record_pair(x, y) {
                log::debug!("found new position: {:?}", (x, y));
            }
        }
        fuzzvm.fake_immediate_return()?;
        Ok(Execution::Continue)
    },
},
```

However, we can see that this induces significant performance overhead. Every
iteration of the target's maze walking loop, will trigger a breakpoint that is
handled by snapchange. Breakpoints are quite expensive, since they require
context switching from the virtualized userspace, to KVM, to snapchange, and
back.

However, we can apply a similar breakpoint only to the `lose` function. This
function is executed at the end of the execution and also is a good point for a
reset breakpoint. We will combine the reset breakpoint and the custom feedback
breakpoint into a single one. Most of the time we only care about the last
position that a player visits with a certain input and not about every
intermediate position. This allows us to significantly speed up the fuzzing.


## Custom Input Format

We analyze the game's code and see that there are only a couple of allowed input bytes: `wasdxy`, i.e., similar to a gamepad. 
The `wasd` keys move the player through the maze, while `xy` only print the players current position and re-draws the maze.

So first, we will implement a restricted version of the `Vec<u8>` input, the
`WasdArray`. 
This is more efficient as using a standard byte vector, that will use many
unnecessary mutations that produce invalid bytes.

```rust
#[repr(u8)]
pub enum Wasd {
    W = b'w',
    A = b'a',
    S = b's',
    D = b'd',
    X = b'x',
    Y = b'y',
    Stop = 0,
}

pub struct WasdArray {
    data: Vec<Wasd>,
}
```

Using a `repr(u8)` enum, we can create a `Vec<Wasd>`, which we can safely transmute into a `Vec<u8>`. This makes it easy to write a `WasdArray` into the target's address space. While mutating the input, we can take advantage of the guarantee that the input only contains valid `Wasd` bytes.

Next we define several mutation operations:

```rust
pub enum WasdFuzzOperation {
    Insert,       // insert a single Wasd at a random index
    Replace,      // replace a random Wasd at a random index, e.g., "aaww" -> "adww"
    Remove,       // remove a single Wasd at a random index
    Append,       // append a random Wasd at the end, e.g., "aaww" -> "aawwd"
    AppendMany,   // append a random Wasd multiple times, e.g., "a" -> "awwww"
    ReplaceLast,  // replace the last direction with a different one, e.g. "aa" -> "ad"
    ReplaceLastMany, // replace the last direction with many, e.g. "aa" -> "addddd"
    Splice,       // insert parts of another testcase from the corpus
}
```

As you can see, we already tweaked the input and mutations such that they
better fit our fuzzing target. We have several standard mutation operations,
such as insert, replace, remove. Additionally we also implement several
mutations that focus at the end of the input, i.e., the append and replace last
variants. This kind of mutations favor making incremental progress with the
fuzzer towards the maze exit.


## Modifying the input scheduling

We want to set up our fuzzer such that it makes incremental progress. In our
case, the last input that is found, is the input that made the farthest
progress in the maze, i.e., it discovered a new `(x, y)` position. So in this
case it makes sense to make it more likely to schedule the last input again for
mutation. We do this by using the `WeightedIndex` from the `rand` crate. This
allows us to assign weights to every corpus entry, with the lowest weight being
assigned to the first corpus entry, and the highest weight having the last corpus entry. 
We will simply use the index of the corpus entry + 1 as the weight for selecting
the corpus entry as next input.

We change the `schedule_next_input` function that is provided as a default
implementation in the `Fuzzer` trait to perform roughly the following code:

```rust
// we create the weights array simply by collecting a range into a Vec
let weights = (1u32..((corpus.len() + 1) as u32)).collect();
// then we sample the index of the next input
let dist = rand::distributions::WeightedIndex::new(&self.weights).unwrap();
let idx = dist.sample(rng) as usize;
corpus.get(idx).unwrap().clone()
```

## Solving the Maze

We can now run the fuzzer to find the exit of the maze and we will see that
with every modification to the fuzzer, we increased the efficiency to the point
that our fuzzer is almost as good as a specialized maze solver.

```
$ ./fuzz.sh maze.small -c /2

[ ... ]
# fuzz for a while
[ ... ]

$ ls -ltr snapshot/maze.small/current_corpus/
$ cat snapshot/maze.small/current_corpus/c236706a3d5ebb4a
ayasssxsddddydxdwwwwswwwwaawwwwwwddddddddddsssssssssssddadwwwwwwssada

$ make -C harness
$ ./harness/maze.small ./snapshot/maze.small/current_corpus/c236706a3d5ebb4a

[ ... ]

pos = (9, 3)
+-+---+---+
| |     |#|
| | --+ |X|
| |   | | |
| +-- | | |
|     |   |
+-----+---+

pos = (9, 2)
You win
... or did you really?
bye(0)

```

Hooray, we win the maze!!!

However, in the input we can see that the fuzzed input first attempts to go to the
left with `a`, which is definitely pointless, since there is a wall there, so
this is effectively a no-op.


## Minimizing Testcases

Since we have found an input that reaches the end of the maze, we can now use
the fuzzer to minimize the input and find the minimal input that wins the maze.

We implement the `minimize` function in the `FuzzInput` trait to reduce the
input. Here we mostly perform two actions: `Truncate` and `Delete`. Our goal is
to remove excess "button presses" from the input that don't do anything useful.

* `Truncate` - remove the last `Wasd` in the input array.
* `Delete` - remove a `Wasd` at a random index.

We can now run snapchange's `minimize` command, which attempts to minimize an
input. We can configure what snapchange will take into account when deciding
whether the minimized and original inputs are equivalent. In this case we will
only use our custom feedback mechanism, so we pass

* `--rip-only` - only check whether execution ends at the same `RIP` and not
  whether the full register state is the same.
* `--ignore-stack` - do not check stack contents for equality.
* `--ignore-console-output` - do not check if the console output is the same.
* `--consider-coverage none` - do not check code coverage.
    * We could also leave this the default, which is `basic-block` for checking
      regular fuzzing coverage. However, without coverage breakpoints, fuzzing
      is a bit faster.

```
$ cat snapshot/maze.small/current_corpus/c236706a3d5ebb4a
ayasssxsddddydxdwwwwswwwwaawwwwwwddddddddddsssssssssssddadwwwwwwssada

$ ./run.sh maze.small minimize --rip-only --ignore-stack --ignore-console-output --consider-coverage none ./snapshot/maze.small/current_corpus/c236706a3d5ebb4a
[...]

$ cat snapshot/maze.small/current_corpus/c236706a3d5ebb4a_min_by_size
ssssddddwwaawwddddssssddwwwwwwssada
```


## Bypassing the obfuscated string comparison.

We can see that there is another hidden functionality that is guarded by the
`check_contra_code` function. This function takes the input and uses a bit of
obfuscation to determine whether the remaining input after the maze exit
satisfies some condition. For the sake of the example, we will assume that
we do not know what this function does. With manual reverse engineering (or using symbolic execution) we can try to reverse the obfuscation algorithm and determine the correct input.
However, we can also let snapchange do that for us. Luckily we can see with
some debugging, that there is a comparison with some constant byte string at
the end of the obfuscation. In this case we look to the `eq16` function. We can
also see that a single change in the input leads to a single change in the
obfuscated bytes that are compared. This means that we can make incremental
progress towards a solution, which means we can use a fuzzer to solve this.

Snapchange features a "max feedback" mechanism, that turns the fuzzer into a
generic optimizer for certain conditions. In our case, we want to minimize the
distance between both strings. Luckily, snapchange already has a builtin
convenience method to deal with this.

The only thing that we need to do is to create another breakpoint hook. In this
case we will hook the `eq16` function, which conveniently gives us pointers to
the two compared arguments. We then use the `feedback.record_prefix_dist` to
compute the length of the longest common prefix of both arguments to the `eq16`
function and record that with the fuzzer. We use the max feedback to minimize
the distance between both strings. Again allowing the fuzzer to make
incremental progress towards solving the comparison.

```rust
Breakpoint {
    lookup: AddressLookup::SymbolOffset(constants::TARGET_EQ16, 0x0),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<Self>, _input, _fuzzer, feedback| {
        if let Some(feedback) = feedback {
            let ptr_a = fuzzvm.rdi();
            let ptr_b = fuzzvm.rsi();
            let mut a = [0u8; 16];
            fuzzvm.read_bytes(VirtAddr(ptr_a), fuzzvm.cr3(), &mut a)?;
            let mut b = [0u8; 16];
            fuzzvm.read_bytes(VirtAddr(ptr_b), fuzzvm.cr3(), &mut b)?;
            if let Some(new_len) = feedback.record_prefix_dist(0u64, &a, &b) {
                log::debug!(
                    "found new minimal code with distance {} - {:?} vs. {:?}",
                    new_len,
                    a,
                    b
                );
            }
        }
        Ok(Execution::Continue)
    },
}
```


## Finding the crash

Now finally, with all pieces implemented we can identify the crash:

```
$ ./fuzz.sh maze.small -c /2

[ ... ]
# fuzz for a while
[ ... ]

$ ls -tr snapshot/maze.small/crashes
'0x7ffff7f78c6c_ld-musl-x86_64.so.1!__assert_fail+0x0'
$ cat snapshot/maze.small/crashes/0x7ffff7f78c6c_ld-musl-x86_64.so.1\!__assert_fail+0x0/02ca55febb6e1a06
xxxasdasssssdsdddwwwaxwawaaaaaawdwddddddddssaxasssddddwdddysdddddwwwwwwssadadxy

$ make -C harness
$ ./harness/maze.small snapshot/maze.small/crashes/0x7ffff7f78c6c_ld-musl-x86_64.so.1\!__assert_fail+0x0/02ca55febb6e1a06

[ ... ]

pos = (9, 3)
+-+---+---+
| |     |#|
| | --+ |X|
| |   | | |
| +-- | | |
|     |   |
+-----+---+

pos = (9, 2)
You win
oh oh..
maze.small: maze.c:204: void walk_maze(const char *, const size_t): Assertion `0' failed.
[1]    1505091 IOT instruction  ./harness/maze.small

$ ./run.sh maze.small minimize --rip-only --ignore-stack --ignore-console-output --consider-coverage none './snapshot/maze.small/crashes/0x7ffff7f78c6c_ld-musl-x86_64.so.1!__assert_fail+0x0/02ca55febb6e1a06'
[...]
[2023-10-09T16:04:25Z INFO  snapchange::commands::minimize] Minimized from 79 -> 38 bytes
[2023-10-09T16:04:25Z INFO  snapchange::commands::minimize] Writing minimized file: "./snapshot/maze.small/crashes/0x7ffff7f78c6c_ld-musl-x86_64.so.1!__assert_fail+0x0/02ca55febb6e1a06_min_by_size"
[...]
$ cat snapshot/maze.small/crashes/0x7ffff7f78c6c_ld-musl-x86_64.so.1\!__assert_fail+0x0/02ca55febb6e1a06_min_by_size
ssssddddwwaawwddddssssddwwwwwwssadadxy
```
