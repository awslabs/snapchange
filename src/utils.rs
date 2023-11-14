//! Various utility functions

use anyhow::Result;
use thiserror::Error;

use std::collections::hash_map::DefaultHasher;
use std::collections::VecDeque;
use std::hash::Hash;
use std::hash::Hasher;
use std::path::Path;
use std::str::FromStr;

use crate::fuzz_input::{FuzzInput, InputWithMetadata};
use crate::{Symbol, VirtAddr};

/// Fast `Vec<T: Copy` utility functions.
#[allow(dead_code)]
pub mod vec {

    /// Inserts a slice at a specific location in a vec.
    ///
    /// ## Panics:
    ///
    /// * if `src` and `dst` overlap!
    /// * if `index` is not in-bounds into `dst`
    ///
    /// ## Example:
    ///
    /// ```
    /// # use snapchange::utils::vec::fast_insert_at;
    /// let mut v = vec![0u8, 3u8];
    /// fast_insert_at(&mut v, 1, &[1u8, 2u8]);
    /// assert_eq!(v, vec![0u8, 1, 2, 3]);
    ///
    /// let mut v = vec![0u8, 0, 0, 0];
    /// fast_insert_at(&mut v, 0, &[1u8, 1]);
    /// assert_eq!(v, vec![1u8, 1, 0, 0, 0, 0]);
    ///
    /// // we can also do this with other Copy types, not only u8.
    /// let mut v = vec![0u16, 0, 0, 0];
    /// fast_insert_at(&mut v, 0, &[1u16, 1]);
    /// assert_eq!(v, vec![1u16, 1, 0, 0, 0, 0]);
    ///
    /// // if index is set to the length of the destination Vec, we are essentially appending.
    /// let mut v = vec![0u8, 1, 0, 1];
    /// let l = v.len();
    /// fast_insert_at(&mut v, l, &[2u8, 2u8]);
    /// assert_eq!(v, vec![0u8, 1, 0, 1, 2, 2]);
    /// ```
    pub fn fast_insert_at<T: Copy>(dst: &mut Vec<T>, index: usize, src: &[T]) {
        // verify safety conditions for the unsafe code
        assert!(index <= dst.len());
        assert!(!dst.as_ptr_range().contains(&src.as_ptr()));

        dst.reserve(src.len());
        let old_len = dst.len();
        let new_len = dst.len() + src.len();
        // SAFETY:
        // 1. we are copying the `src` slice into the `dst` Vec and ensure using `dst.reserve` that
        //    there are enough bytes available.
        // 2. we asserted before that `index` is in-bounds of `dst`.
        // 3. we asserted that `src` and `dst` do not overlap.
        unsafe {
            let ptr = dst.as_mut_ptr().offset(index as isize);
            // check if we are only appending -> no need to move old contents
            if index != src.len() {
                std::ptr::copy(ptr, ptr.offset(src.len() as isize), old_len - index);
            }
            std::ptr::copy_nonoverlapping(src.as_ptr(), ptr, src.len());
            dst.set_len(new_len);
        }
    }

    /// Inserts two slices at a specific location in a vec.
    ///
    /// ## Panics:
    ///
    /// * if `src` and `dst` overlap!
    /// * if `index` must is not in-bounds into `dst`
    ///
    /// ## Example:
    ///
    /// ```
    /// # use snapchange::utils::vec::fast_insert_two_at;
    /// let mut v = vec![0u8, 3u8];
    /// fast_insert_two_at(&mut v, 1, &[1u8], &[2u8]);
    /// assert_eq!(v, vec![0u8, 1, 2, 3]);
    ///
    /// let mut v = vec![0u8, 0, 0, 0];
    /// fast_insert_two_at(&mut v, 0, &[1u8], &[1u8]);
    /// assert_eq!(v, vec![1u8, 1, 0, 0, 0, 0]);
    ///
    /// // we can also do this with other Copy types, not only u8.
    /// let mut v = vec![0u16, 0, 0, 0];
    /// fast_insert_two_at(&mut v, 0, &[1u16, 1], &[42u16]);
    /// assert_eq!(v, vec![1u16, 1, 42, 0, 0, 0, 0]);
    ///
    /// // if index is set to the length of the destination Vec, we are essentially appending.
    /// let mut v = vec![0u8, 1, 0, 1];
    /// let l = v.len();
    /// fast_insert_two_at(&mut v, l, &[2u8, 2u8], &[3u8, 3u8]);
    /// assert_eq!(v, vec![0u8, 1, 0, 1, 2, 2, 3, 3]);
    /// ```
    pub fn fast_insert_two_at<T: Copy>(dst: &mut Vec<T>, index: usize, a: &[T], b: &[T]) {
        // verify safety conditions for the unsafe code
        assert!(index <= dst.len());
        assert!(!dst.as_ptr_range().contains(&a.as_ptr()));
        assert!(!dst.as_ptr_range().contains(&b.as_ptr()));
        debug_assert!(a.len() <= isize::MAX as usize);
        debug_assert!(b.len() <= isize::MAX as usize);

        dst.reserve(a.len() + b.len());
        let old_len = dst.len();
        let src_len = a.len() + b.len();
        let new_len = dst.len() + src_len;
        // SAFETY:
        // 1. we are copying the `a` nad `b` slices into the `dst` Vec and ensure using `dst.reserve` that
        //    there are enough bytes available.
        // 2. we asserted before that `index` is in-bounds of `dst`.
        // 3. we asserted that `a|b` and `dst` do not overlap.
        unsafe {
            let ptr = dst.as_mut_ptr().offset(index as isize);
            // check if we are only appending -> no need to move old contents
            if index != src_len {
                std::ptr::copy(ptr, ptr.offset(src_len as isize), old_len - index);
            }
            std::ptr::copy_nonoverlapping(a.as_ptr(), ptr, a.len());
            std::ptr::copy_nonoverlapping(b.as_ptr(), ptr.offset(a.len() as isize), b.len());
            dst.set_len(new_len);
        }
    }

    /// Inserts three slices at a specific location in a vec.
    ///
    /// ## Panics:
    ///
    /// * if `src` and `dst` overlap!
    /// * if `index` must is not in-bounds into `dst`
    ///
    /// ## Example:
    ///
    /// ```
    /// # use snapchange::utils::vec::fast_insert_three_at;
    /// let mut v = vec![0u8];
    /// fast_insert_three_at(&mut v, 0, b"<a>", b"aaaaaa", b"</a>");
    /// assert_eq!(&v, &b"<a>aaaaaa</a>\x00");
    ///
    /// let mut v = b"<p>bla</p>".to_vec();
    /// fast_insert_three_at(&mut v, 3, b"<a>", b"aaaaaa", b"</a>");
    /// assert_eq!(&v, &b"<p><a>aaaaaa</a>bla</p>");
    /// ```
    pub fn fast_insert_three_at<T: Copy>(dst: &mut Vec<T>, index: usize, a: &[T], b: &[T], c: &[T]) {
        // verify safety conditions for the unsafe code
        assert!(index <= dst.len());
        assert!(!dst.as_ptr_range().contains(&a.as_ptr()));
        assert!(!dst.as_ptr_range().contains(&b.as_ptr()));
        assert!(!dst.as_ptr_range().contains(&c.as_ptr()));
        debug_assert!(a.len() <= isize::MAX as usize);
        debug_assert!(b.len() <= isize::MAX as usize);
        debug_assert!(c.len() <= isize::MAX as usize);

        dst.reserve(a.len() + b.len() + c.len());
        let old_len = dst.len();
        let src_len = a.len() + b.len() + c.len();
        let new_len = dst.len() + src_len;
        // SAFETY:
        // 1. we are copying the `a`, `b`, and `c` slices into the `dst` Vec and ensure using `dst.reserve` that
        //    there are enough bytes available.
        // 2. we asserted before that `index` is in-bounds of `dst`.
        // 3. we asserted that `a|b|c` and `dst` do not overlap.
        unsafe {
            let ptr = dst.as_mut_ptr().offset(index as isize);
            // check if we are only appending -> no need to move old contents
            if index != src_len {
                std::ptr::copy(ptr, ptr.offset(src_len as isize), old_len - index);
            }
            std::ptr::copy_nonoverlapping(a.as_ptr(), ptr, a.len());
            let ptr = ptr.offset(a.len() as isize);
            std::ptr::copy_nonoverlapping(b.as_ptr(), ptr, b.len());
            let ptr = ptr.offset(b.len() as isize);
            std::ptr::copy_nonoverlapping(c.as_ptr(), ptr, c.len());
            dst.set_len(new_len);
        }
    }

    /// Inserts a byte slices at a specific location in a vec, delimited by two delimiters.
    ///
    /// ## Panics:
    ///
    /// * if `src` and `dst` overlap!
    /// * if `index` must is not in-bounds into `dst`
    ///
    /// ## Example:
    ///
    /// ```
    /// # use snapchange::utils::vec::fast_insert_delimited_at;
    /// let mut v = vec![0u8];
    /// fast_insert_delimited_at(&mut v, 0, b"aaaa", b'"', b'"');
    /// assert_eq!(&v, &b"\"aaaa\"\x00");
    /// ```
    pub fn fast_insert_delimited_at<T: Copy>(
        dst: &mut Vec<T>,
        index: usize,
        src: &[T],
        before: T,
        after: T,
    ) {
        // verify safety conditions for the unsafe code
        assert!(index <= dst.len());
        assert!(!dst.as_ptr_range().contains(&src.as_ptr()));

        dst.reserve(src.len() + 2);
        let old_len = dst.len();
        let src_len = src.len() + 2;
        let new_len = dst.len() + src_len;
        // SAFETY:
        // 1. we are copying the `src` slice into the `dst` Vec and ensure using `dst.reserve` that
        //    there are enough bytes available for `src` and both delimiters.
        // 2. we asserted before that `index` is in-bounds of `dst`.
        // 3. we asserted that `src` and `dst` do not overlap.
        unsafe {
            let ptr = dst.as_mut_ptr().offset(index as isize);
            // check if we are only appending -> no need to move old contents
            if index != src_len {
                std::ptr::copy(ptr, ptr.offset(src_len as isize), old_len - index);
            }
            std::ptr::write_unaligned(ptr, before);
            std::ptr::copy_nonoverlapping(src.as_ptr(), ptr.offset(1isize), src.len());
            std::ptr::write_unaligned(ptr.offset(1isize + src.len() as isize), after);
            dst.set_len(new_len);
        }
    }

    /// Overwrite a sub-slice from `&dst[dst_range]` with a subslice `&src[src_range]`. The size of the subslices must not be
    /// identical. If `&src[src_range]` is larger than `&dst[dst_range]`, then `dst` is grown.
    /// If `&src[src_range]` is smaller than `&dst[dst_range]`. This helper function is useful, if both
    /// sub-slice ranges are generated randomly while fuzzing and you do not want to worry about what
    /// Vec operation to use.
    ///
    /// The supplied range `dst_range` will be forced to be in-bounds of `dst`.
    ///
    /// Semantically, this is equivalent to calling
    /// ```rust,ignore
    /// dst.splice(dst_range, src.iter().copied());
    /// ```
    /// but with the restriction tath `dst` and `src` do not overlap, yielding in better performance (no
    /// temporary allocation needed).
    ///
    /// ## Panics:
    ///
    /// * if `src` and `dst` overlap!
    ///
    /// ## Example
    ///
    /// ```rust
    /// # use snapchange::utils::vec::splice_into;
    ///
    /// let mut v = vec![0u8, 10, 11, 0];
    /// let d = vec![1u8, 2, 3, 4, 5];
    /// splice_into(&mut v, 1..3, &d[1..4]);
    /// assert_eq!(v, vec![0u8, 2, 3, 4, 0], "basic test");
    ///
    /// // insert only
    /// let mut v = vec![0u8, 3u8];
    /// splice_into(&mut v, 1..1, &[1u8, 2u8]);
    /// assert_eq!(v, vec![0u8, 1, 2, 3], "insert only");
    ///
    /// // overwrite only
    /// let mut v = vec![0u8, 3u8];
    /// splice_into(&mut v, 0..2, &[1u8, 2u8]);
    /// assert_eq!(v, vec![1u8, 2], "overwrite only");
    ///
    /// // append only
    /// let mut v = vec![0u8, 0, 0, 0];
    /// let d = vec![1u8, 2, 3, 4, 5, 6, 7];
    /// splice_into(&mut v, 4..4, &d[1..3]);
    /// assert_eq!(v, vec![0u8, 0, 0, 0, 2, 3], "append only");
    ///
    /// // copy vec
    /// let mut v = vec![0u8, 0, 0, 0];
    /// let d = vec![1u8, 2, 3, 4, 5, 6, 7];
    /// splice_into(&mut v, 0.., &d[..]);
    /// assert_eq!(v, d, "copy vec grow");
    ///
    /// let mut v = vec![0u8, 0, 0, 0];
    /// let d = vec![1u8, 2];
    /// splice_into(&mut v, .., &d[..]);
    /// assert_eq!(v, d, "copy vec shrink");
    ///
    /// // different ranges supported
    /// let mut v = vec![0u8, 0, 0, 0];
    /// let d = vec![1u8; 3];
    /// splice_into(&mut v, 0..=1, &d[..]);
    /// assert_eq!(v, vec![1u8, 1, 1, 0, 0], "inclusive range");
    /// ```
    pub fn splice_into<T: Copy, R: std::ops::RangeBounds<usize>>(
        dst: &mut Vec<T>,
        dst_range: R,
        src: &[T],
    ) {
        // we are using a bit of unsafe to boil this down to calls to
        // ```
        // dst.splice(dst_range, src.iter().copied());
        // ```
        //
        // * realloc
        // * memmove
        // * memcpy

        // Deal with generic RangeBounds.
        let dst_start = match dst_range.start_bound() {
            std::ops::Bound::Unbounded => 0,
            std::ops::Bound::Included(t) => *t,
            // I don't think there is a range with Excluded start bound?
            std::ops::Bound::Excluded(_t) => unreachable!(),
        }
        .min(dst.len()) as isize;
        let dst_end = match dst_range.end_bound() {
            std::ops::Bound::Unbounded => dst.len(),
            std::ops::Bound::Excluded(t) => *t,
            std::ops::Bound::Included(t) => *t + 1,
        }
        .min(dst.len()) as isize;
        assert!(dst_start <= dst_end);

        // sanity checks only in debug builds.
        debug_assert!(dst.len() <= isize::MAX as usize);
        debug_assert!(src.len() <= isize::MAX as usize);

        // verify safety conditions for the unsafe code
        assert!(!dst.as_ptr_range().contains(&src.as_ptr()));
        assert!((dst_end as usize) <= dst.len());

        let dst_full_len = dst.len() as isize;
        let src_len = src.len() as isize;
        // dst_len is the length of the destination slice &dst[dst_range]
        let dst_len = dst_end - dst_start;

        let new_len = dst_full_len - dst_len + src_len;
        if src_len > dst_len {
            // we are inserting more bytes that we remove. so we reserve the additional bytes
            dst.reserve((src_len - dst_len) as usize);
        } else {
            // we do not require additional bytes, since we are shrinking the `dst` Vec
            debug_assert!(new_len <= dst_full_len);
        }
        debug_assert!(dst.capacity() >= new_len as usize);

        // SAFETY:
        // 1. we are copying the `src` slice into the `dst` Vec and ensure using `dst.reserve` that
        //    there are enough bytes available.
        // 2. we asserted before that `index` is in-bounds of `dst`.
        // 3. we asserted that `src` and `dst` do not overlap.
        unsafe {
            let dst_ptr = dst.as_mut_ptr().offset(dst_start);
            let tail_ptr = dst.as_ptr().offset(dst_end);
            let tail_len = dst_full_len - dst_end;
            println!("{:?} {:?} {:?}", dst_ptr, tail_ptr, tail_len);
            debug_assert!(tail_len >= 0);
            // move the old contents within dst to the new location -> memmove
            if tail_len > 0 {
                std::ptr::copy(tail_ptr, dst_ptr.offset(src_len), tail_len as usize);
            }
            std::ptr::copy_nonoverlapping(src.as_ptr(), dst_ptr, src.len());
            dst.set_len(new_len as usize);
        }
    }
}

/// Prints a hexdump representation of the given `data` assuming the data starts at
/// `starting_address`
///
/// Example:
///
/// ```rust
/// #use snapchange::utils::hexdump;
/// hexdump([0x41, 0x42, 0x43, 0x44], 0xdead0000)
/// ````
/// Output:
/// ```non-rust
/// 0xdead0000: 41 42 43 44 | ABCD
/// ```
///
pub fn hexdump(data: &[u8], starting_address: u64) {
    use crate::colors::Colorized;

    println!(
        "{:-^18}   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F    0123456789ABCDEF",
        " address "
    );

    let mut prev_chunk: &[u8] = &[2_u8; 0x10];
    let mut prev_chunk_id = 0;

    for (i, chunk) in data.chunks(0x10).enumerate() {
        if chunk == prev_chunk {
            if i - prev_chunk_id == 1 {
                println!(
                    "{:#018x}: {}",
                    starting_address + i as u64 * 0x10,
                    "** repeated line(s) **".red()
                );
            }
            continue;
        }

        // Store the current chunk as the most recent unique line
        prev_chunk = chunk;
        prev_chunk_id = i;

        // Display the current address
        print!("{:#018x}: ", starting_address + i as u64 * 0x10);

        // Display the bytes
        for b in chunk {
            match b {
                0x00 => print!("{:02x} ", b.green()),
                0x0a | 0xff => print!("{:02x} ", b.red()),
                0x21..0x7e => print!("{:02x} ", b.yellow()),
                0x7f => print!("{:02x} ", b.blue()),
                _ => print!("{:02x} ", b.white()),
            }
        }

        // Pad chunks that are not 16 bytes wide
        if chunk.len() < 16 {
            print!("{}", " ".repeat((16 - chunk.len()) * 3));
        }

        // Add the separation
        print!(" | ");

        // Display the bytes as characters
        for b in chunk {
            match b {
                0x00 => print!("{}", '.'.green()),
                0x0a | 0xff => print!("{}", '.'.red()),
                0x21..0x7e => print!("{}", (*b as char).yellow()),
                0x7f => print!("{}", '.'.blue()),
                _ => print!("{}", '.'.white()),
            }
        }

        // Go to the next line
        println!();
    }
}

/// Wrapper around `rdtsc`
#[must_use]
pub fn rdtsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}


/// calculate shannon entropy over a byte array
pub fn byte_entropy<T: AsRef<[u8]>>(buf: T) -> f64 {
    let buf = buf.as_ref();
    let mut entropy = 0f64;
    let mut bytecounts = [0u16; 256];
    for b in buf.iter().copied() {
        let b_idx = b as usize;
        bytecounts[b_idx] = bytecounts[b_idx].saturating_add(1);
    }
    let buf_len: f64 = (buf.len() as u32).into();
    for c in bytecounts.into_iter() {
        if c == 0 {
            continue;
        }
        let c: f64 = c.into();
        let p = c / buf_len;
        entropy -= p * p.log2();
    }

    entropy
}


/// Returns the hash of the given input using [`DefaultHasher`]
pub fn calculate_hash<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

/// Returns the formatted hash of the given input as hexadecimal digits
pub fn hexdigest<T: Hash>(t: &T) -> String {
    let h = calculate_hash(t);
    format!("{h:016x}")
}

/// Save the [`InputWithMetadata`] into the project directory using the hash of input as the filename
///
/// # Errors
///
/// * Given `input.to_bytes()` failed
/// * Creating the corpus or metadata directory failed
/// * Failed to write the bytes to disk
pub fn save_input_in_project<T: FuzzInput>(
    input: &InputWithMetadata<T>,
    project_dir: &Path,
) -> Result<usize> {
    let input_bytes = input.input_as_bytes()?;
    let length = input_bytes.len();

    // Create the filename for this input
    let filename = hexdigest(&input);

    let corpus_dir = project_dir.join("current_corpus");
    let metadata_dir = project_dir.join("metadata");

    // Ensure the corpus and metadata directories exist
    for dir in [&corpus_dir, &metadata_dir] {
        if !dir.exists() {
            std::fs::create_dir(dir)?;
        }
    }

    // Write the input
    let filepath = corpus_dir.join(&filename);
    if !filepath.exists() {
        std::fs::write(filepath, input_bytes)?;
    }

    // Write the metadata to the metadata folder
    let filepath = metadata_dir.join(filename);
    std::fs::write(filepath, input.serialized_metadata()?)?;

    Ok(length)
}

/// Errors that can be triggered during `project` subcommand
#[derive(Error, Debug)]
pub enum Error {
    /// Invalid symbol format: `symbol`, `symbol!offset`, `symbol+offset`
    #[error("Invalid symbol format: `symbol`, `symbol!offset`, `symbol+offset`")]
    InvalidSymbolFormat(String),

    /// Symbol offset failed to parse to a `u64`
    #[error("Symbol offset failed to parse to a `u64`")]
    InvalidSymbolOffset(String),

    /// Did not find symbol
    #[error("Invalid symbol format: `symbol`, `symbol!offset`, `symbol+offset`")]
    SymbolNotFound,
}

/// Parse the given `argument` as a `VirtAddr`
///
/// Examples:
///
/// ```
/// deadbeef
/// 0xdeadbeef
/// main
/// main+123
/// main+0x123
/// ```
///
/// # Errors
///
/// * Attempted to parse an unknown symbol format
/// * Requested symbol is not found
pub fn parse_cli_symbol(
    possible_virt_addr: &str,
    symbols: &Option<VecDeque<Symbol>>,
) -> Result<VirtAddr> {
    // Parse the given translation address or default to the starting RIP of the snapshot
    let parsed = VirtAddr::from_str(possible_virt_addr);

    if let Ok(addr) = parsed {
        Ok(addr)
    } else {
        let Some(symbols) = symbols.as_ref() else {
            return Err(Error::SymbolNotFound.into());
        };

        // Failed to parse the argument as a `VirtAddr`. Try to parse it as a
        // symbol of the following forms
        // `symbol`
        // `symbol+offset`
        let mut offset = 0;
        let virt_addr = possible_virt_addr;
        let mut symbol = virt_addr.to_string();
        let mut addr = None;

        if virt_addr.contains('+') {
            let mut iter = virt_addr.split('+');
            symbol = iter
                .next()
                .ok_or_else(|| Error::InvalidSymbolFormat(virt_addr.to_string()))?
                .to_string();

            let curr_offset = iter
                .next()
                .ok_or(Error::InvalidSymbolFormat(virt_addr.to_string()))?;

            let no_prefix = curr_offset.trim_start_matches("0x");

            // Attempt to parse the hex digit
            offset = u64::from_str_radix(no_prefix, 16)
                .map_err(|_| Error::InvalidSymbolOffset(offset.to_string()))?;
        }

        log::info!("Checking for symbol: {symbol}+{offset:#x}");

        let mut subsymbols = Vec::new();

        // Add the fuzzer specific symbols
        for Symbol {
            address,
            symbol: curr_symbol,
        } in symbols
        {
            if *curr_symbol == symbol {
                addr = Some(VirtAddr(*address).offset(offset));
            } else if curr_symbol.contains(&symbol) {
                subsymbols.push((curr_symbol, VirtAddr(*address).offset(offset)));
            }
        }

        if let Some(found) = addr {
            Ok(found)
        } else {
            if subsymbols.len() == 1 {
                log::info!("Did not find symbol {symbol}, but found 1 subsymbol.. using this one");
                return Ok(subsymbols[0].1);
            }

            log::error!("Did not find symbol {symbol}");
            if !subsymbols.is_empty() {
                log::error!("Did find symbols containing {symbol}. One of these might be a more specific symbol:");

                let min = subsymbols.len().min(50);
                if subsymbols.len() > 50 {
                    log::info!(
                        "Here are the first {min}/{} symbols containing {symbol}",
                        subsymbols.len()
                    );
                }

                for (subsymbol, _) in subsymbols.iter().take(min) {
                    log::info!("- {subsymbol}");
                }
            }

            Err(Error::SymbolNotFound.into())
        }
    }
}

/// helper functions for directly using libfuzzer binaries as harness.
pub mod libfuzzer {
    use crate::addrs::VirtAddr;
    use crate::fuzzer::Fuzzer;
    use crate::fuzzvm::FuzzVm;

    /// sets a input for libfuzzers LLVMFuzzerTestOneInput
    pub fn set_input<F: Fuzzer>(input: &[u8], fuzzvm: &mut FuzzVm<F>) -> anyhow::Result<()> {
        // Restore RIP to before the `int3 ; vmcall` snapshot point
        fuzzvm.set_rip(fuzzvm.rip() - 4);

        // Set the data buffer to the current mutated input
        let buffer = fuzzvm.rdi();
        fuzzvm.write_bytes_dirty(VirtAddr(buffer), fuzzvm.cr3(), input)?;

        // Set the length of the input
        fuzzvm.set_rsi(input.len() as u64);

        Ok(())
    }

    /// apply reset breakpoints at return address of libfuzzer's LLVMFuzzerTestOneInput
    pub fn init_vm<F: Fuzzer>(fuzzvm: &mut FuzzVm<F>) -> anyhow::Result<()> {
        let rsp = fuzzvm.rsp();
        let cr3 = fuzzvm.cr3();
        let retaddr = fuzzvm.read::<u64>(VirtAddr(rsp), cr3)?;
        fuzzvm.set_breakpoint(
            VirtAddr(retaddr),
            cr3,
            crate::fuzzer::BreakpointType::Repeated,
            crate::fuzzvm::BreakpointMemory::NotDirty,
            crate::fuzzvm::BreakpointHook::None,
        )?;
        if let Some(ref mut reset_bps) = fuzzvm.reset_breakpoints {
            reset_bps.insert(
                (VirtAddr(retaddr), cr3),
                crate::fuzzer::ResetBreakpointType::Reset,
            );
        }
        Ok(())
    }
}
