#!/bin/sh

# Set the timeout to test each configuration
TIME=300s

# Create the outdir
mkdir -p data_$TIME

# Build the bench harness
cargo build -r 

# v : 0 - Benchmark instructions, 1 - Benchmark breakpoints
# c : Number of cores
# p : Number of dirty pages
# i : Approximate number of instructions (Only counts instructions in a loop)
for v in 0 1; do
  for c in 1 2 4 8 16 32 64 92; do
    for p in 100 500 1000 5000 10000 25000; do
      for i in 1000 10000 100000 1000000 10000000 100000000; do
        # The bench harness relies on env variables for config options.
        # Setup the configuration for this bench run
        export INSTRS=$i
        export PAGES=$p
        export VMEXITS=$v

        # Create the correct file name based on instructions/breakpoints
        if [ $v == 0 ]; then
          export OUTFILE="data_intel_$TIME/pages_$p-instrs_$i-cores_$c"
        else
          export OUTFILE="data_intel_$TIME/pages_$p-vmexits_$i-cores_$c"
        fi

        # Ignore existing files
        if [ -f $OUTFILE ]; then
          echo "$OUTFILE Exists already.. continuing"
        fi

        # Run the benchmark for this configuration 
        timeout $TIME cargo run -r -- fuzz -c $c --timeout $TIME --ascii-stats 2>/dev/null >/dev/null

        # Save the stats file for this configuration
        cp ./snapshot/data/stats.toml $OUTFILE
      done
    done
  done
done

