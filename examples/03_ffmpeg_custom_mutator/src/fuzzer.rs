//! Fuzzer template

#![allow(clippy::missing_docs_in_private_items)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]

use anyhow::Result;
use rand::Rng as _;
use std::sync::Arc;

use snapchange::prelude::*;
use snapchange::linux::{read_args, ReadArgs};

#[derive(Default)]
pub struct Example03Fuzzer {
    file_offset: usize,
}

impl Fuzzer for Example03Fuzzer {
    type Input = MovGenerator;
    const START_ADDRESS: u64 = crate::constants::RIP;
    const MAX_INPUT_LENGTH: usize = 0x7fff;

    fn reset_fuzzer_state(&mut self) {
        // Reset the file offset
        self.file_offset = 0;
    }

    fn set_input(
        &mut self,
        _input: &InputWithMetadata<Self::Input>,
        _fuzzvm: &mut FuzzVm<Self>,
    ) -> Result<()> {
        // There is no set input condition since the input is written via the read
        // breakpoint below
        Ok(())
    }

    fn reset_breakpoints(&self) -> Option<&[AddressLookup]> {
        Some(&[AddressLookup::SymbolOffset("ffmpeg!exit_program", 0x0)])
    }

    fn breakpoints(&self) -> Option<&[Breakpoint<Self>]> {
        Some(&[
            // INSTRUCTION 010 0x0000000000436e90 0x06c3e000 | ffmpeg!__interceptor_read+0x0
            // Breakpoint based on a symbol offset
            // Below: the first instruction of `_int_malloc`
            Breakpoint {
                lookup: AddressLookup::SymbolOffset("ffmpeg!__interceptor_read", 0x0),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm: &mut FuzzVm<Self>, input, fuzzer, _feedback| {
                    let args = read_args(&fuzzvm);
                    let ReadArgs { fd, buf, count } = args;

                    let input = &input.bytes[fuzzer.file_offset..];

                    let size = std::cmp::min(input.len(), count as usize);

                    // log::info!("read({fd:#x}, {buf:x?}, {count:#x}) = {size:#x}");

                    if fd != 3 {
                        return Ok(Execution::Reset);
                    }

                    // Only write bytes if there are bytes left in the input to write
                    if size > 0 {
                        // Write the input bytes into the buffer
                        fuzzvm.write_bytes_dirty(buf, fuzzvm.cr3(), &input[..size])?;
                    }

                    // Set the return value to the number of bytes read
                    fuzzvm.set_rax(size as u64);

                    fuzzer.file_offset += size;

                    fuzzvm.fake_immediate_return()?;
                    Ok(Execution::Continue)
                },
            },
        ])
    }
}

trait ToBytes {
    fn to_bytes(&self, data: &mut Vec<u8>);
}

#[derive(Debug, Clone)]
enum Chunk {
    Stsd(Stsd),
    Sgpd(Sgpd),
    Sbgp(Sbgp),
    Ctts(Ctts),
    Trak(Trak),
    Moov(Moov),
}

const MAX_RECURSION: usize = 32;

impl Chunk {
    fn generate(rng: &mut Rng, count: &mut usize) -> Self {
        match rng.gen::<u32>() % core::mem::variant_count::<Chunk>() as u32 {
            0 => Chunk::Stsd(Stsd::generate(rng, count)),
            1 => Chunk::Sgpd(Sgpd::generate(rng, count)),
            2 => Chunk::Sbgp(Sbgp::generate(rng, count)),
            3 => Chunk::Ctts(Ctts::generate(rng, count)),
            4 => Chunk::Moov(Moov::generate(rng, count)),
            5 => Chunk::Trak(Trak::generate(rng, count)),
            _ => unreachable!(),
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

#[derive(Debug, Clone)]
struct LenTypeVal {
    type_: &'static [u8; 4],
    len: u32,
    data: Vec<u8>,
}

impl ToBytes for LenTypeVal {
    fn to_bytes(&self, data: &mut Vec<u8>) {
        data.extend((self.len + 8).to_be_bytes());
        data.extend(self.type_);
        data.extend(&self.data);
    }
}

impl LenTypeVal {
    fn new(type_: &'static [u8; 4], data: Vec<u8>) -> Self {
        Self {
            type_,
            len: data.len() as u32,
            data,
        }
    }
}

#[derive(Debug, Clone)]
struct Hev1;
impl ToBytes for Hev1 {
    fn to_bytes(&self, data: &mut Vec<u8>) {
        LenTypeVal::new(b"hev1", vec![]).to_bytes(data);
    }
}

#[derive(Debug, Clone)]
struct Ctts {
    version: u8,

    // (Count, Duration)  data
    data: Vec<(u32, u32)>,
}

impl Ctts {
    pub fn generate(rng: &mut Rng, _count: &mut usize) -> Self {
        let mut data = Vec::new();

        // Generate a maximum of 16 entries
        for _ in 0..rng.gen::<u32>() % 16 {
            let count = rng.gen::<u32>();
            let duration = rng.gen::<u32>();
            data.push((count, duration));
        }

        let version = (rng.gen::<u32>() % 16) as u8;

        Self { version, data }
    }
}

// mov_read_ctts in libavformat/mov.c:3068
impl ToBytes for Ctts {
    fn to_bytes(&self, data: &mut Vec<u8>) {
        let mut ctts_chunk = Vec::new();

        // avio_r8 and avio_rb24 : libavformat/mov.c:3079
        ctts_chunk.extend((self.version as u32).to_be_bytes());

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

/// mov_read_sbgp in libavformat/mov.c:3190
#[derive(Debug, Clone)]
struct Sgpd {
    version: u8,
    grouping_type: &'static [u8; 4],
    default_length: Option<u32>,
    default_group_description_index: Option<u32>,
    init_description_length: Option<u32>,

    /// libavformat/mov.c:3170
    /// nal_unit_type
    table: Vec<u8>,
}

impl Sgpd {
    pub fn generate(rng: &mut Rng, _count: &mut usize) -> Self {
        let mut table = Vec::new();

        // libavformat/mov.c:3149
        let version = (rng.gen::<u32>() % 3) as u8;

        // libavformat/mov.c:3151
        let grouping_type = b"sync";

        // libavformat/mov.c:3160
        let default_length = if version >= 1 {
            Some(rng.gen::<u32>() % 16 | 1)
        } else {
            None
        };

        // libavformat/mov.c:3161
        let default_group_description_index = if version >= 2 {
            Some(rng.gen::<u32>())
        } else {
            None
        };

        // libavformat/mov.c:3162
        let entry_count = rng.gen::<u32>() % 16;

        let mut init_description_length = None;
        if version >= 1 && default_length.is_none() {
            init_description_length = Some(rng.gen::<u32>() % 16);
        }

        let mut description_length = default_length.unwrap_or(init_description_length.unwrap_or(1));
        for _ in 0..entry_count {
            table.push(rng.gen::<u32>() as u8);
            description_length = description_length.saturating_sub(1);
            table.extend(vec![0; description_length as usize]);
        }

        Self {
            version,
            grouping_type,
            default_length,
            default_group_description_index,
            init_description_length,
            table,
        }
    }
}

// mov_read_sbgp in libavformat/mov.c:3068
impl ToBytes for Sgpd {
    fn to_bytes(&self, data: &mut Vec<u8>) {
        let mut sgpd_chunk: Vec<u8> = Vec::new();

        sgpd_chunk.extend((self.version as u32).to_le_bytes());
        sgpd_chunk.extend(self.grouping_type);

        if let Some(default_length) = self.default_length {
            assert!(self.version >= 1, "SGPD invalid default length");
            sgpd_chunk.extend(default_length.to_be_bytes());
        }

        if let Some(index) = self.default_group_description_index {
            assert!(
                self.version >= 2,
                "SGPD invalid default_group_description_index"
            );
            sgpd_chunk.extend(index.to_be_bytes());
        }

        sgpd_chunk.extend((self.table.len() as u32).to_be_bytes());

        if let Some(init_description_length) = self.init_description_length {
            sgpd_chunk.extend(init_description_length.to_be_bytes());
        }

        sgpd_chunk.extend(&self.table);

        LenTypeVal::new(b"sgpd", sgpd_chunk).to_bytes(data);
    }
}

/// mov_read_sbgp in libavformat/mov.c:3190
#[derive(Debug, Clone)]
struct Sbgp {
    version: u8,

    grouping_type: &'static [u8; 4],
    grouping_type_parameter: Option<u32>,

    /// libavformat/mov.c:3233
    /// (sample_count, group_description_index)
    table: Vec<(u32, u32)>,
}

impl Sbgp {
    pub fn generate(rng: &mut Rng, _count: &mut usize) -> Self {
        let mut table = Vec::new();

        // Generate a maximum of 16 entries
        for _ in 0..rng.gen::<u32>() % 16 {
            let sample_count = rng.gen::<u32>();
            let group_description_index = rng.gen::<u32>();
            table.push((sample_count, group_description_index));
        }

        let version = rng.gen::<u32>() as u8;
        let grouping_type = match rng.gen::<u32>() % 2 {
            0 => b"rap ",
            1 => b"sync",
            _ => unsafe { std::hint::unreachable_unchecked() },
        };

        let mut grouping_type_parameter = None;
        if version == 1 {
            grouping_type_parameter = Some(rng.gen::<u32>());
        }

        Self {
            version,
            grouping_type,
            grouping_type_parameter,
            table,
        }
    }
}

// mov_read_sbgp in libavformat/mov.c:3068
impl ToBytes for Sbgp {
    fn to_bytes(&self, data: &mut Vec<u8>) {
        let mut sbgp_chunk = Vec::new();

        // avio_r8 and avio_rb24 : libavformat/mov.c3205
        sbgp_chunk.extend((self.version as u32).to_be_bytes());

        // avio_rl32 : libavformat/mov.c:3207
        sbgp_chunk.extend(self.grouping_type);

        if let Some(val) = self.grouping_type_parameter {
            // avio_rb32 : libavformat/mov.c:3219
            sbgp_chunk.extend(val.to_be_bytes());
        }

        // avio_rb32 : libavformat/mov.c:3222
        sbgp_chunk.extend((self.table.len() as u32).to_be_bytes());

        for (count, index) in &self.table {
            // avio_rb32 : libavformat/mov.c:3234
            sbgp_chunk.extend(count.to_be_bytes());

            // avio_rb32 : libavformat/mov.c:3235
            sbgp_chunk.extend(index.to_be_bytes());
        }

        LenTypeVal::new(b"sbgp", sbgp_chunk).to_bytes(data);
    }
}

#[derive(Debug, Clone)]
struct Stsd {
    version: u8,
    entries: u32,
    data: Vec<u8>,
}

impl Stsd {
    pub fn generate(rng: &mut Rng, _count: &mut usize) -> Self {
        let version = 0;
        let mut data = Vec::new();

        let entries = 1;

        for _ in 0..entries {
            match rng.gen::<u32>() % 4 {
                _ => {
                    let hev1 = Hev1;
                    hev1.to_bytes(&mut data);
                }
            }
        }

        data.extend(&vec![0; 70]);

        Self {
            version,
            entries,
            data,
        }
    }
}

// mov_read_sbgp in libavformat/mov.c:3068
impl ToBytes for Stsd {
    fn to_bytes(&self, data: &mut Vec<u8>) {
        let mut stsd_chunk = Vec::new();

        stsd_chunk.extend((self.version as u32).to_le_bytes());
        stsd_chunk.extend((self.entries as u32).to_be_bytes());
        stsd_chunk.extend(&self.data);

        LenTypeVal::new(b"stsd", stsd_chunk).to_bytes(data);
    }
}

#[derive(Debug, Clone)]
struct Trak {
    data: Vec<Chunk>,
}

impl Trak {
    pub fn generate(rng: &mut Rng, count: &mut usize) -> Self {
        let mut data = Vec::new();

        for _ in 0..rng.gen::<u32>() % 8 {
            if *count > MAX_RECURSION {
                break;
            }

            data.push(Chunk::generate(rng, count));

            *count += 1;
        }

        Self { data }
    }
}

impl ToBytes for Trak {
    fn to_bytes(&self, data: &mut Vec<u8>) {
        let mut trak_chunk = Vec::new();

        for val in &self.data {
            val.to_bytes(&mut trak_chunk);
        }

        LenTypeVal::new(b"trak", trak_chunk).to_bytes(data);
    }
}

#[derive(Debug, Clone)]
struct Moov {
    data: Vec<Chunk>,
}

impl Moov {
    pub fn generate(rng: &mut Rng, count: &mut usize) -> Self {
        let mut data = Vec::new();

        for _ in 0..rng.gen::<u32>() % 8 {
            if *count > MAX_RECURSION {
                break;
            }

            data.push(Chunk::generate(rng, count));

            *count += 1;
        }

        Self { data }
    }
}

impl ToBytes for Moov {
    fn to_bytes(&self, data: &mut Vec<u8>) {
        let mut moov_chunk = Vec::new();

        for val in &self.data {
            val.to_bytes(&mut moov_chunk);
        }

        LenTypeVal::new(b"moov", moov_chunk).to_bytes(data);
    }
}

#[derive(Debug, Clone)]
struct Ftyp {
    minor_version: u32,
}

impl Ftyp {
    pub fn _generate(rng: &mut Rng, _count: &mut usize) -> Self {
        Self {
            minor_version: rng.gen::<u32>() & 0xff,
        }
    }
}

impl ToBytes for Ftyp {
    fn to_bytes(&self, data: &mut Vec<u8>) {
        let mut ftyp_chunk = Vec::new();

        ftyp_chunk.extend(b"mp42");
        ftyp_chunk.extend(self.minor_version.to_le_bytes());

        LenTypeVal::new(b"ftyp", ftyp_chunk).to_bytes(data);
    }
}

#[derive(Default, Debug, Clone, Hash, PartialEq, Eq)]
pub struct MovGenerator {
    bytes: Vec<u8>,
}

impl snapchange::FuzzInput for MovGenerator {
    type MinState = snapchange::fuzz_input::BytesMinimizeState;

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

    fn init_minimize(&mut self) -> (Self::MinState, MinimizeControlFlow) {
        self.bytes.init_minimize()
    }

    /// Minimize the given `input` based on a minimization strategy
    fn minimize(
        &mut self,
        state: &mut Self::MinState,
        current_iteration: u32,
        last_successful_iteration: u32,
        rng: &mut Rng,
    ) -> MinimizeControlFlow {
        self.bytes.minimize(state, current_iteration, last_successful_iteration, rng)
    }

    fn generate(
        corpus: &[Arc<InputWithMetadata<Self>>],
        rng: &mut Rng,
        dictionary: &Option<Vec<Vec<u8>>>,
        min_length: usize,
        max_length: usize,
    ) -> InputWithMetadata<Self> {
        let mut res = MovGenerator::default();
        MovGenerator::mutate(
            &mut res,
            corpus,
            rng,
            &dictionary,
            min_length,
            max_length,
            8,
        );
        InputWithMetadata::from_input(res)
    }

    /// Mutate the current object using a `corpus`, `rng`, and `dictionary` that has a
    /// maximum length of `max_length`
    fn mutate(
        input: &mut Self,
        _corpus: &[Arc<InputWithMetadata<Self>>],
        rng: &mut Rng,
        _dictionary: &Option<Vec<Vec<u8>>>,
        _min_length: usize,
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
