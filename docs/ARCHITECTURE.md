# Architecture 

## Threads

The threads that are spawned and pinned to specific cores. The first core is responsible for
the statistics aggregation, the stats TUI, and the timer used to periodically kick all cores
out of execution to prevent infinite loops and checking for timeouts.

```
main (first core)
    Stats Thread      (aggregates fuzzer statistics)
    Kick Cores Thread (periodically kicks all fuzzer cores out of execution)
fuzzer_core1
fuzzer_core2
...
fuzzer_coreN
```

## Coverage gathering 

Each core has its own guest physical memory. All cores share the same original snapshot memory. 
The provided coverage breakpoints are applied to the shared snapshot memory.
This is the memory that all cores use to reset their local memory. Whenever a coverage breakpoint is
hit by any core, the breakpoint is restored in the shared snapshot memory so that no other core
needs to worry about hitting that coverage breakpoint. In this way, all coverage breakpoints
only have a one time cost of hitting them.

## Statistics gathering

Each fuzzer is executing on a single core with its own statistics. The gathering of
these statistics helps to understand how the system as a whole is performing. This is
accomplished by having a specific `Arc<Mutex<Stats>>` struct for each core currently
executing. 

The creation of the array of [`Stats`](crate::stats::Stats) structs for the system looks like the following:

```
let stats: Vec<Arc<Mutex<Stats>>> = (1..=cores)
    .map(|_| { Arc::new(Mutex::new(Stats::default())) })
    .collect();
```

When a fuzzer thread is initialized, it receives the element of this array for the
specific core. This is preferred over a giant lock over the entire stats `Vec` so that
there is less lock contention across all threads. If the structure was instead
`Arc<Mutex<Vec<Stats>>>>`, then all cores would be fighting over this one lock every
times statistics were updated, thus causing a massive performance dropoff.

There is a separate stats thread that periodically iterates over this stats `Vec` in
order to process the current stats of the system. These stats are displayed to the screen
as well as used to create various graphs to understand the data over time.

Here is the current stats table:

```
+------------------------------------------------------------------------------------------+
|     Time:   15:00:48 |  Exec/sec:    29620 |   Coverage:      16697 (last seen 01:09:09) |
|    Iters: 1039936900 |    Corpus:   174334 |    Crashes:    4230804                      |
| Timeouts:     790522 | Cov. Left:    91989 |      Alive:         92                      |
+------------------------------------------------------------------------------------------+
```

#### NOTE: All of the statistics are for the entire system and not for an individual core

* `Time`:      Current elapsed time 
* `Exec/sec`:  Executions per second 
* `Coverage`:  Number of coverage points hit 
* `Iters`:     Number of iterations executed
* `Corpus`:    Size of the corpus
* `Crashes`:   Number of times a VM has exited due to a crash
* `Timeouts`:  Number of times a VM has exited due to a timeout
* `Cov. Left`: Number of coverage points not hit (if using coverage breakpoints)
* `Alive`:     Number of cores currently fuzzing

Along with the stats in the terminal, a few graphs are generated. These are generated in
the `<project_dir>/web` directory. Serving a basic web server from this directory can
display the graphs.

```
cd <project_dir>/web
python3 -m http.server 31234 
## Browse to http://<YOUR_IP>:31234
```

## Preventing infinite loops

In order to prevent VMs from being stuck in an infinite loop, each fuzzing thread is
periodically kicked out of execution in order to determine if they have surpassed the
specified timeout. This is accomplished via interval timers.

An `ITIMER_REAL` timer is set to trigger roughly every second (`src/timer.rs`). When the
timer elapses, a `SIGALRM` signal is generated. When the signal is handled, a global
`KICK_CORES` `AtomicBool` is set to `true`. On the main core, there is another thread
executing that periodically checks the `KICK_CORES` for `true`. If it is true, this
thread attempts to kick all executing threads.

During fuzzer thread initialization, its `thread_id` (via `libc::pthread_self`) is stored
in a global `Vec<Option<AtomicU64>>` indexed by the id of the executing core:

```
// Store the thread ID of this thread used for passing the SIGALRM to this thread
let thread_id = unsafe { libc::pthread_self() };
*THREAD_IDS[core_id.id].lock().unwrap() = Some(thread_id);
```

With all of the thread IDs gathered, once the `kick_cores` thread sees that threads
should be kicked, it iterates over all `THREAD_IDS` and sends a `SIGALRM` to each
executing thread.

```rust
// Send SIGALRM to all executing threads
for core_id in 0..THREAD_IDS.len() {
    // Get stored address of this potential vcpu
    if let Some(thread_id) = *THREAD_IDS[core_id].lock().unwrap() {
        // Send SIGALRM to the current thread
        unsafe {
            libc::pthread_kill(thread_id, libc::SIGALRM);
        }
    }
}

// Reset the kick cores
KICK_CORES.store(false, Ordering::SeqCst);
```

`KVM_RUN` will return an error of `EINTR` if an unmasked signal if pending. At the
beginning of each fuzzer thread `SIGALRM` is unblocked in order for ensure the `SIGALRM`
actually does force exit `KVM_RUN`:

```rust
fn start_core(..) {
    ...
    // Create the empty sigset to obtain the currently blocked signals
    let mut curr_sigset = SigSet::empty();

    // Get the current unblocked signal set
    pthread_sigmask(SigmaskHow::SIG_UNBLOCK, None, Some(&mut curr_sigset))?;

    // Add SIGALRM to the unblocked signal set
    curr_sigset.add(Signal::SIGALRM);

    // Update the unblocked signal set
    pthread_sigmask(SigmaskHow::SIG_UNBLOCK, Some(&curr_sigset), None)?;
```

If the `fuzzvm::run()` function finds the `EINTR` on returning from `KVM_RUN`, then the
`FuzzVm` returns with a `FuzzVmExit::TimerElapsed`. This error is then handled by the
main fuzz loop to mark that a timeout occured and reset the VM.
