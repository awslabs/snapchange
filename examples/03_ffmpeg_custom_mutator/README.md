# Tutorial 3 - FFmpeg with custom mutator

This tutorial is a walkthrough of:

    * Utilizing a custom generator
    * Minimizing a crashing test case

_There is an included `./make_example.sh` script to build and snapshot this example. This script
goes through each of the steps described below._

## Prepping for the snapshot

This tutorial will walk through using a basic `mov` generator in a fuzzer.

Let's begin by downloading and making `ffmpeg`

```
git clone https://github.com/FFmpeg/FFmpeg
cd FFmpeg
git checkout ab77b878f1205225c6de1370fb0e998dbcc8bc69
```

When building `ffmpeg`, let's also build with AddressSantizer and debug symbols:

```
./configure --toolchain=clang-asan --enable-debug=3 --disable-stripping
make -j`nproc`
```

A quick look at `strace` with a test file will show where the file is read to understand
where a useful snapshot location could be.

```
$ strace -e trace=openat,read ./ffmpeg -i ./tests/ref/lavf-fate/h264.mp4
```

```
openat(AT_FDCWD, "./tests/ref/lavf-fate/av1.mp4", O_RDONLY) = 3
 > /usr/lib/x86_64-linux-gnu/libpthread-2.31.so(__open64+0x5b) [0x13abb]
 > /home/ubuntu/snapchange/examples/03_ffmpeg_custom_mutator/FFmpeg/ffmpeg(avpriv_open+0x1c7) [0x36e8327]
 > /home/ubuntu/snapchange/examples/03_ffmpeg_custom_mutator/FFmpeg/ffmpeg(file_open+0x1ba) [0xd7c31a]
<snip>
read(3, "fe299ea5205b71a48281f917b1256a5d"..., 32768) = 161
 > /usr/lib/x86_64-linux-gnu/libpthread-2.31.so(read+0x12) [0x13392]
 > /home/ubuntu/snapchange/examples/03_ffmpeg_custom_mutator/FFmpeg/ffmpeg(read+0x60) [0x36ef0]
 > /home/ubuntu/snapchange/examples/03_ffmpeg_custom_mutator/FFmpeg/ffmpeg(file_read+0x79) [0xd7c639]
<snip>
read(3, "", 32768)                      = 0
 > /usr/lib/x86_64-linux-gnu/libpthread-2.31.so(read+0x12) [0x13392]
 > /home/ubuntu/snapchange/examples/03_ffmpeg_custom_mutator/FFmpeg/ffmpeg(read+0x60) [0x36ef0]
 > /home/ubuntu/snapchange/examples/03_ffmpeg_custom_mutator/FFmpeg/ffmpeg(file_read+0x79) [0xd7c639]
<ship>
read(3, "", 32768)                      = 0
 > /usr/lib/x86_64-linux-gnu/libpthread-2.31.so(read+0x12) [0x13392]
 > /home/ubuntu/snapchange/examples/03_ffmpeg_custom_mutator/FFmpeg/ffmpeg(read+0x60) [0x36ef0]
 > /home/ubuntu/snapchange/examples/03_ffmpeg_custom_mutator/FFmpeg/ffmpeg(file_read+0x79) [0xd7c639]
[mov,mp4,m4a,3gp,3g2,mj2 @ 0x617000000080] Format mov,mp4,m4a,3gp,3g2,mj2 detected only with low score of 1, misdetection possible!
[mov,mp4,m4a,3gp,3g2,mj2 @ 0x617000000080] moov atom not found
./tests/ref/lavf-fate/h264.mp4: Invalid data found when processing input
```

All of the `read`s are called from the `file_read` function. Let's look at this function
to see how easy it would be to snapshot.

```c
libavformat/mov.c

 109   │ static int file_read(URLContext *h, unsigned char *buf, int size)
 110   │ {
 111   │     FileContext *c = h->priv_data;
 112   │     int ret;
 113   │     size = FFMIN(size, c->blocksize);

             // File is read here into `buf`
 114   │     ret = read(c->fd, buf, size);

 115   │     if (ret == 0 && c->follow)
 116   │         return AVERROR(EAGAIN);
 117   │     if (ret == 0)
 118   │         return AVERROR_EOF;
 119   │     return (ret == -1) ? AVERROR(errno) : ret;
 120   │ }
```

The `file_read` function calls `read` which we can hook in the fuzzer. This function is
also called multiple times, so we need the ability to snapshot once and not trigger the
mechanism multiple times. One potential snapshot is below:

```c
libavformat/mov.c

 109 + │ // Flag to signal when to snapshot
 110 + │ int ready_to_snapshot = 1;
 111 + │
 112   │ static int file_read(URLContext *h, unsigned char *buf, int size)
 113   │ {
 114   │     FileContext *c = h->priv_data;
 115   │     int ret;
 116   │     size = FFMIN(size, c->blocksize);
 117 + │
 118 + │     if (ready_to_snapshot && getenv("SNAPSHOT") != NULL) {
 119 + │         // Reset the snapshot to never trigger again
 120 + │         ready_to_snapshot = 0;
 121 + │
 122 + │         // Take the snapshot
 123 + │         __asm("int3 ; vmcall");
 124 + │     }
 125 + │
 126   │     ret = read(c->fd, buf, size);
```

Rebuilding `ffmpeg` will prep the binary for the snapshot.

```
make
```

## Taking the snapsthot

The `qemu_snapshot` project is how we will take a snapshot for this project. Briefly, the
project will build a Linux kernel, a patched QEMU which enables snapshotting via
`vmcall` instruction, and a Debian disk with the target binary running during boot under
`gdb`.

The fuzzer template included in snapchange contains scripts that facilitates:
    * Building the harness for a target
    * Taking a snapshot of the harness using `qemu_snapshot`
    * Generating a fuzzer.rs template, filling in information for this specific snapshot
    * Generating coverage breakpoints using `bn_snapchange.py`

Copy the fuzzer template (containing `qemu_snapshot`) and target source code from Snapchange as this example's repository:

```sh
$ cp -r -L <snapchange_dir>/fuzzer_template snapchange-example-03
$ cd snapchange-example-03
```

Add snapchange path as a dependency:

```sh
$ cargo add snapchange --path <snapchange_dir>
```

Modify the `snapchange-example-03/create_snapshot.sh` to build and use the example1 binary.

```sh
# Take the snapshot
take_snapshot() {
  # Build the image to execute the harness on start
  pushd ./qemu_snapshot/IMAGE
  ./build.sh ../../FFmpeg/ffmpeg -i ../../FFmpeg/tests/ref/lavf-fate/h264.mp4
  popd

  # Take the snapshot
  pushd ./qemu_snapshot
  ./snapshot.sh
  popd
}
```

Execute the `./create_snapshot.sh` script to build and take the snapshot of the target.

```sh
./create_snapshot.sh
```

While coverage breakpoints are necessary to enable coverage feedback, they will be
skipped in this tutorial in lieu of focusing on the custom generator.

Update the `MAX_INPUT_LENGTH` in `src/fuzzer.rs` based on the harness and the `type Input` to be
the soon-to-be-created `MovGenerator` struct.

```rust
// src/fuzzer.rs

impl Fuzzer for Example3Fuzzer {
    type Input = MovGenerator;
    const MAX_INPUT_LENGTH: usize = 0x7fff;
```

## Adding a custom generator

_NOTE: This section will assume a custom generator has already been written. There is a
bonus section at the end of the tutorial on writing the provided generator using the
FFmpeg source. The `Chunk::generate` function is the top level generation function._

Note that the `type Input` above is of type `MovGenerator` instead of `Vec<u8>` from the
previous two examples. This `MovGenerator` type is where the custom generation will be written.

This `Input` type is of type `FuzzInput`. In the `FuzzInput` trait, there are several trait
function to enable mutation and generation of this custom data type.

The `mutate` function in this case will generate a random number of mp4 `Chunk`s.

```rust
// src/fuzzer.rs

impl snapchange::FuzzInput for MovGenerator {
    <snip>
    fn mutate(
        input: &mut Self,
        _corpus: &[Self],
        rng: &mut Rng,
        _dictionary: &Option<Vec<Vec<u8>>>,
        _max_length: usize,
        _max_mutations: u64,
    ) -> Vec<String> {
        let mut count = 0;
        input.bytes.clear();

        for _ in 0..(rng.next() % 8 + 1) {
            let chunk = Chunk::generate(rng, &mut count);
            chunk.to_bytes(&mut input.bytes);
            count += 1;
        }

        Vec::new()
    }
}
```

The `generate` function returns a randomly generated `MovGenerator`.

```rust
// src/fuzzer.rs

impl snapchange::FuzzInput for MovGenerator {
    <snip>
    fn generate(
        corpus: &[Self],
        rng: &mut Rng,
        dictionary: &Option<Vec<Vec<u8>>>,
        max_length: usize,
    ) -> Self {
        let mut res = MovGenerator::default();
        MovGenerator::mutate(&mut res, corpus, rng, &dictionary, max_length);
        res
    }
}
```

Lastly, there needs to be a way of serializing and deserializing inputs to disk. `FuzzInput`
requires an input type to provide `to_bytes` and `from_bytes` functions to facilitate this.

```rust
// src/fuzzer.rs

impl snapchange::FuzzInput for MovGenerator {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(MovGenerator {
            bytes: bytes.to_vec(),
        })
    }

    fn to_bytes(&self, output: &mut Vec<u8>) -> Result<()> {
        output.clear();
        output.extend(&self.bytes);
        Ok(())
    }
}
```

With the generator in place, let's write the `read` hook to get the generated input into
the guest.

## Hooking read

This snapshot relies on hooking `read` to set the input into the guest. We'll hook the
`read` function and manually track the file offset to know what slice of the input should
be written into the guest.

```rust
// src/fuzzer.rs

#[derive(Default)]
pub struct Example3Fuzzer {
    file_offset: usize
}

fn breakpoints(&self) -> Option<&[Breakpoint]> {
    Some(&[
        Breakpoint {
            lookup:  AddressLookup::SymbolOffset("ffmpeg!__interceptor_read", 0x0),
            bp_type: BreakpointType::Repeated,
            bp_hook: |fuzzvm: &mut FuzzVm, input, fuzzer| { 
                // Parse the read arguments
                let args = read_args(&fuzzvm);
                let ReadArgs { fd, buf, count } = args;

                // Get the current slice of the input based on the current file offset
                let input = &input[fuzzer.file_offset..];

                // Truncate the requested read size with the remaining of input left
                let size = std::cmp::min(input.len(), count as usize);

                // Only write bytes if there are bytes left in the input to write
                if size > 0 {
                    // Write the input bytes into the buffer
                    fuzzvm.write_bytes_dirty(
                        buf, 
                        fuzzvm.cr3(), 
                        &input[..size])?;
                }

                // Set the return value to the number of bytes read
                fuzzvm.set_rax(size as u64);
                 
                // Update the file offset based on the written size
                fuzzer.file_offset += size;

                // Immediately return from the read
                fuzzvm.fake_immediate_return()?;

                Ok(Execution::Continue)
            }
        },
    ])
}
```

With `read` hooked, we the ability can start fuzzing and see the ability how the generator does.

## Fuzzing

Fuzzing can now begin. Let's use all but 4 of the total cores on the machine.

```sh
cargo run -r -- fuzz -c -4
```

After a bit of time, a few crashes can be found in the `snapshot/crashes` directory:

Let's see if any of the out-of-bounds write crashes found by Address Sanitizer reproduce
in `ffmpeg`:

```
$ cp ASAN_WRITE4_pc\:0xf18c8f_crashing_addr\:0x7ffff46fec8c_ffmpeg\!mov_read_trak+0x7e8f/c2e621f5eabc6415 /tmp/test.mp4
$ <FFmpeg_dir>/ffmpeg -i /tmp/test.mp4
```

```
=================================================================
==2066379==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7fc1489fec8c at pc 0x000000f18c8f bp 0x7fff08547410 sp 0x7fff085
47408
WRITE of size 4 at 0x7fc1489fec8c thread T0
    #0 0xf18c8e in build_open_gop_key_points /home/ubuntu/snapchange/examples/03_ffmpeg_custom_mutator/FFmpeg/libavformat/mov.c:3915:3
8
    #1 0xf18c8e in mov_build_index /home/ubuntu/snapchange/examples/03_ffmpeg_custom_mutator/FFmpeg/libavformat/mov.c:3964:15
    #2 0xf18c8e in mov_read_trak /home/ubuntu/snapchange/examples/03_ffmpeg_custom_mutator/FFmpeg/libavformat/mov.c:4423:5
    #3 0xef7397 in mov_read_default /home/ubuntu/snapchange/examples/03_ffmpeg_custom_mutator/FFmpeg/libavformat/mov.c:7506:23
    #4 0xf091eb in mov_read_moov /home/ubuntu/snapchange/examples/03_ffmpeg_custom_mutator/FFmpeg/libavformat/mov.c:1168:16
    #5 0xef7397 in mov_read_default /home/ubuntu/snapchange/examples/03_ffmpeg_custom_mutator/FFmpeg/libavformat/mov.c:7506:23
    #6 0xef8179 in mov_read_header /home/ubuntu/snapchange/examples/03_ffmpeg_custom_mutator/FFmpeg/libavformat/mov.c:8056:20
    #7 0xdeb357 in avformat_open_input /home/ubuntu/snapchange/examples/03_ffmpeg_custom_mutator/FFmpeg/libavformat/demux.c:297:20
    #8 0x4c89c1 in open_input_file /home/ubuntu/snapchange/examples/03_ffmpeg_custom_mutator/FFmpeg/fftools/ffmpeg_opt.c:1173:11
    #9 0x4c7783 in open_files /home/ubuntu/snapchange/examples/03_ffmpeg_custom_mutator/FFmpeg/fftools/ffmpeg_opt.c:3416:15
    #10 0x4c71c5 in ffmpeg_parse_options /home/ubuntu/snapchange/examples/03_ffmpeg_custom_mutator/FFmpeg/fftools/ffmpeg_opt.c:3456:11
    #11 0x5065e8 in main /home/ubuntu/snapchange/examples/03_ffmpeg_custom_mutator/FFmpeg/fftools/ffmpeg.c:4861:11
    #12 0x7fc14c09b082 in __libc_start_main /build/glibc-SzIz7B/glibc-2.31/csu/../csu/libc-start.c:308:16
    #13 0x41eeed in _start (/home/ubuntu/snapchange/examples/03_ffmpeg_custom_mutator/FFmpeg/ffmpeg+0x41eeed)

0x7fc1489fec8c is located 0 bytes to the right of 198628492-byte region [0x7fc13cc91800,0x7fc1489fec8c)
allocated by thread T0 here:
    #0 0x4980c7 in posix_memalign (/home/ubuntu/snapchange/examples/03_ffmpeg_custom_mutator/FFmpeg/ffmpeg+0x4980c7)
    #1 0x3b0e156 in av_malloc /home/ubuntu/snapchange/examples/03_ffmpeg_custom_mutator/FFmpeg/libavutil/mem.c:105:9
    #2 0x3b0e156 in av_mallocz /home/ubuntu/snapchange/examples/03_ffmpeg_custom_mutator/FFmpeg/libavutil/mem.c:266:17
    #3 0x3b0e156 in av_calloc /home/ubuntu/snapchange/examples/03_ffmpeg_custom_mutator/FFmpeg/libavutil/mem.c:277:12
    #4 0xf117f3 in build_open_gop_key_points /home/ubuntu/snapchange/examples/03_ffmpeg_custom_mutator/FFmpeg/libavformat/mov.c:3909:2
6
    #5 0xf117f3 in mov_build_index /home/ubuntu/snapchange/examples/03_ffmpeg_custom_mutator/FFmpeg/libavformat/mov.c:3964:15
    #6 0xf117f3 in mov_read_trak /home/ubuntu/snapchange/examples/03_ffmpeg_custom_mutator/FFmpeg/libavformat/mov.c:4423:5
```

Looks like the crash does reproduce in `ffmpeg`! We can also minimize this test case to
attempt to reduce the size of the crashing input.

```sh
$ cargo run -r -- minimize src/crashes/ASAN_WRITE4_pc\:0xf18c8f_crashing_addr\:0x7ffff46fe8b8_ffmpeg\!mov_read_trak+0x7e8f/57ef60a5
```

The result of this minimization is below:
 
```
$ xxd snapshot/crashes/ASAN_WRITE4_pc\:0xf18c8f_crashing_addr\:0x7ffff46fec8c_ffmpeg\!mov_read_trak+0x7e8f/c2e621f5eabc6415_min_by_size

┌────────┬─────────────────────────┬─────────────────────────┬────────┬────────┐
│00000000│ cd cd cd cd 6d 6f 6f 76 ┊ cd cd cd cd 74 72 61 6b │××××moov┊××××trak│
│00000010│ 00 00 00 2d cd cd cd cd ┊ cd cd cd 00 cd cd cd cd │000-××××┊×××0××××│
│00000020│ cd cd cd cd cd 00 cd cd ┊ cd cd 00 cd cd 00 cd cd │×××××0××┊××0××0××│
│00000030│ cd 00 cd cd cd 00 cd 00 ┊ cd cd cd cd cd 00 00 00 │×0×××0×0┊×××××000│
│00000040│ 5c 73 62 67 70 cd cd cd ┊ cd 73 79 6e 63 00 00 00 │\sbgp×××┊×sync000│
│00000050│ 09 cd cd cd cd cd cd cd ┊ cd cd cd cd cd cd cd cd │_×××××××┊××××××××│
│00000060│ cd cd cd d2 cd cd cd cd ┊ cd cd cd cd cd cd cd cd │××××××××┊××××××××│
│00000070│ cd cd cd cd cd cd cd cd ┊ cd 28 cd cd cd cd cd cd │××××××××┊×(××××××│
│00000080│ cd cd cd cd 77 cd 9a cd ┊ cd cd cd cd cd cd cd cd │××××w×××┊××××××××│
│00000090│ cd b8 59 cd cd cd cd cd ┊ cd 00 00 00 40 63 74 74 │××Y×××××┊×000@ctt│
│000000a0│ 73 cd cd cd cd 00 00 00 ┊ 06 cd cd cd cd cd cd cd │s××××000┊•×××××××│
│000000b0│ cd 6c cd 07 44 f2 cd cd ┊ cd cd cd cd cd cd cd cd │×l×•D×××┊××××××××│
│000000c0│ cd cd cd cd cd cd cd cd ┊ cd 7b cd 53 8a cd cd cd │××××××××┊×{×S××××│
│000000d0│ 25 1a cd 5a 55 cd cd cd ┊ cd cd cd cd 5e 73 74 73 │%•×ZU×××┊××××^sts│
│000000e0│ 64 cd cd cd cd 00 00 00 ┊ 01 00 00 cd cd 68 65 76 │d××××000┊•00××hev│
│000000f0│ 31 cd cd cd cd cd cd cd ┊ cd cd cd cd cd cd cd cd │1×××××××┊××××××××│
│00000100│ cd cd cd cd cd cd cd cd ┊ cd cd cd cd cd 00 cd    │××××××××┊×××××0× │
└────────┴─────────────────────────┴─────────────────────────┴────────┴────────┘
```

And finally, checking if the minimized file reproduces:

```
$ cp snapshot/crashes/ASAN_WRITE4_pc\:0xf18c8f_crashing_addr\:0x7ffff46fec8c_ffmpeg\!mov_read_trak+0x7e8f/c2e621f5eabc6415_min_by_size
$ ./ffmpeg -i /tmp/test_min.mp4
```

And it looks like it does reproduce!

# Conclusion

This was a tutorial on how to use a custom generator in snapchange.

# Bonus: Writing the custom mutator

The mutator was written based on the ffmpeg source code. The input is parsed in the 
`mov_read_default`. This function loops over the input file, parsing various types of
chunks. 

There are a variety of functions used to read data from the input stream:

* `avio_rb[16|24|32|64]` - Read [16|24|32|64] bits big endian
* `avio_rl[16|24|32|64]` - Read [16|24|32|64] bits little endian
* `avio_skip(pb, bytes)` - Seek ahead `bytes` in the stream

Before parsing any particular type of chunk, the size and type of chunk is read:

```c
// libavformat/mov.c:7416

static int mov_read_default(MOVContext *c, AVIOContext *pb, MOVAtom atom)
{
    int64_t total_size = 0;
    MOVAtom a;
    int i;

   </snip>
    while (total_size <= atom.size - 8 && !avio_feof(pb)) {
        </snip>
        if (atom.size >= 8) {
            a.size = avio_rb32(pb); // Read the size of the next chunk
            a.type = avio_rl32(pb); // Read the type of the next chunk
```

Then based on the `a.type` of the chunk, a particular function is called to parse the
`a.size` bytes of data.

```c
// libavformat/mov.c:7481

for (i = 0; mov_default_parse_table[i].type; i++)
    if (mov_default_parse_table[i].type == a.type) {
        parse = mov_default_parse_table[i].parse; // Set parse function for this type
        break;
    }
```

```c
// libavformat/mov.c:7504

int64_t start_pos = avio_tell(pb);
int64_t left;
int err = parse(c, pb, a); // Call the parse function for the type
if (err < 0) {
    c->atom_depth --;
    return err;
}
```

The `mov_default_parse_table` contains all of the types with their parse functions.

```c
// libavformat/mov.c:7313

static const MOVParseTableEntry mov_default_parse_table[] = {
{ MKTAG('A','C','L','R'), mov_read_aclr },
{ MKTAG('A','P','R','G'), mov_read_avid },
{ MKTAG('A','A','L','P'), mov_read_avid },
{ MKTAG('A','R','E','S'), mov_read_ares },
{ MKTAG('a','v','s','s'), mov_read_avss },
{ MKTAG('a','v','1','C'), mov_read_glbl },
{ MKTAG('c','h','p','l'), mov_read_chpl },
...
```

The generator's job now is to write random chunks into an input stream (`Vec<u8>` in our
case). Let's use the `ctts` type as the example chunk.


```c
// libavformat/mov.c:3068

static int mov_read_ctts(MOVContext *c, AVIOContext *pb, MOVAtom atom)
{
    AVStream *st;
    MOVStreamContext *sc;
    unsigned int i, entries, ctts_count = 0;

    if (c->fc->nb_streams < 1)
        return 0;
    st = c->fc->streams[c->fc->nb_streams-1];
    sc = st->priv_data;

    avio_r8(pb);   // Read an 8 bit (unused version)
    avio_rb24(pb); // Read a 24 bit (unused flags)
    entries = avio_rb32(pb); // Read the number of entries to loop over
    <snip>
    for (i = 0; i < entries && !pb->eof_reached; i++) {
        int count    = avio_rb32(pb); // Read a 32bit count
        int duration = avio_rb32(pb); // Read a 32bit duration
```

From the `mov_read_ctts` function, the generator needs to write the following data:

* `u32` - Combine the r8/rb24 since they are unused
* `u32` - Number of entries
* [(`u32`, `u32`); entries] - `entries` number of (u32, u32)

The structure to populate for `ctts` could be the following:

```rust
struct Ctts {
    unused: u32,
    data: Vec<(u32, u32)>
}
```

Each structure will implement a `generate` function that takes in a random number
generator [`Rng`](crate::rng::Rng) (from Snapchange).

```rust
impl Ctts {
    pub fn generate(rng: &mut Rng) -> Self {
        let mut data = Vec::new();

        // Generate a maximum of 16 entries
        for _ in 0..rng.rand_u32() % 16 {
            let count    = rng.rand_u32();
            let duration = rng.rand_u32();
            data.push((count, duration));
        }

        let unused = (rng.rand_u32() % 16) as u32;

        Self {
            unused,
            data
        }

    }
}
```

This allows a random `ctts` chunk to be generated:

```rust
let mut rng = Rng::new();
let ctts = Ctts::generate(&mut rng);
```

The structure also can generate a `to_bytes` function which will write the randomly
generated data into a data stream:

```rust
// mov_read_ctts in libavformat/mov.c:3068

impl ToBytes for Ctts {
    fn to_bytes(&self, data: &mut Vec<u8>) {
        let mut ctts_chunk = Vec::new();

        // avio_r8 and avio_rb24 : libavformat/mov.c:3079
        ctts_chunk.extend(self.unused.to_be_bytes());

        // avio_rb32 : libavformat/mov.c:3081
        ctts_chunk.extend((self.data.len() as u32).to_be_bytes());

        for (count, duration) in &self.data {
            // avio_rb32 : libavformat/mov.c:3095
            ctts_chunk.extend(count.to_be_bytes());

            // avio_rb32 : libavformat/mov.c3096
            ctts_chunk.extend(duration.to_be_bytes());
        }

        LenTypeVal::new(b"ctts", ctts_chunk).to_bytes(data);
    }
}
```

Each chunk also needs to write its total size and type into the data stream. To reduce
duplication, we use a `LenTypeVal` struct to handle writing to the data stream.

```rust
struct LenTypeVal {
   type_: &'static [u8; 4],
   len:   u32,
   data:  Vec<u8>
}

impl ToBytes for LenTypeVal {
    fn to_bytes(&self, data: &mut Vec<u8>) {
        data.extend((self.len + 8).to_be_bytes());
        data.extend(self.type_);
        data.extend(&self.data);
    }
}
```

With this in place, the `ctts` chunk can be randomly generated and then written to a data
stream.

```rust
let mut rng  = Rng::new();
let mut data = Vec::new();
Ctts::generate(&mut rng).to_bytes(&mut data);
```

A subset of the chunk types have been implemented in the generator. The selection of
chunks are represented in a single enum in order to randomize which chunk to generate at
a time.

```rust
enum Chunk {
    Stsd(Stsd),
    Sgpd(Sgpd),
    Sbgp(Sbgp),
    Ctts(Ctts),
    Trak(Trak),
    Moov(Moov),
}

impl Chunk {
    fn generate(rng: &mut Rng, count: &mut usize) -> Self {
        match rng.rand_u32() % core::mem::variant_count::<Chunk>() as u32 {
            0 => Chunk::Stsd(Stsd::generate(rng, count)),
            1 => Chunk::Sgpd(Sgpd::generate(rng, count)),
            2 => Chunk::Sbgp(Sbgp::generate(rng, count)),
            3 => Chunk::Ctts(Ctts::generate(rng, count)),
            4 => Chunk::Moov(Moov::generate(rng, count)),
            5 => Chunk::Trak(Trak::generate(rng, count)),
            _ => unreachable!()
        }
    }
}

impl ToBytes for Chunk {
    fn to_bytes(&self, data: &mut Vec<u8>) {
        match self {
            Chunk::Stsd(val) => val.to_bytes(data),
            Chunk::Sgpd(val) => val.to_bytes(data),
            Chunk::Sbgp(val) => val.to_bytes(data),
            Chunk::Ctts(val) => val.to_bytes(data),
            Chunk::Moov(val) => val.to_bytes(data),
            Chunk::Trak(val) => val.to_bytes(data),
        }

    }
}
```

In order to prevent recursion problems, each of the `generate` functions will check the
current recursion depth and exit early if the depth has exceeded the `MAX_RECURSION`
value.

This all comes together in the final `generate` function used in the above mutation
strategy to randomly create a `mov` file.

```rust
fn generate(rng: &mut Rng, data: &mut Vec<u8>) {
    let mut count = 0;

    for _ in 0..(rng.rand_u32() % 8 + 1) {
        if count > MAX_RECURSION { break }

        let chunk = Chunk::generate(rng, &mut count);
        chunk.to_bytes(data);

        count += 1;
    }
}
```
