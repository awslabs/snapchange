//! Generic helper functions for mutation. Mostly splicing.

/// helper to splice data within a vector.
#[inline]
pub fn splice_within<C: Copy, T: AsMut<[C]>>(
    input: &mut T,
    rng: &mut impl rand::Rng,
) -> Option<(isize, isize, usize)> {
    let input = input.as_mut();
    if input.is_empty() {
        return None;
    }

    let src = rng.gen_range(0..input.len()) as isize;
    let dst = rng.gen_range(0..input.len()) as isize;

    // Get the larger of the two positions
    let largest = std::cmp::max(src, dst);

    // Get the maximum slice that is not out of bounds
    let max_len: usize = input.len() - (largest as usize);

    // Randomly choose a length of slice to copy that is in bounds
    let len = rng.gen_range(0..max_len);

    // Copy the slice internally. These buffers could overlap
    // SAFETY: src and dst are within the bounds of input
    unsafe {
        std::ptr::copy(
            input.as_ptr().offset(src),
            input.as_mut_ptr().offset(dst),
            len,
        );
    }

    Some((src, dst, len))
}

/// Copy a random sub-slice from `src` into a random subslice of `dst`.
/// This will potentially grow or shrink the destination vector.
#[inline]
pub fn splice_extend<C: Copy>(
    dst: &mut Vec<C>,
    src: &[C],
    rng: &mut impl rand::Rng,
) -> Option<(std::ops::Range<usize>, std::ops::Range<usize>)> {
    if src.is_empty() {
        return None;
    }

    let src_start = rng.gen_range(0..src.len());
    let src_end = rng.gen_range(src_start..=src.len());
    if dst.is_empty() {
        dst.extend_from_slice(&src[src_start..src_end]);
        return Some((0..0, src_start..src_end));
    }

    let dst_start = rng.gen_range(0..dst.len());
    let dst_end = rng.gen_range(dst_start..=dst.len());

    crate::utils::vec::splice_into(dst, dst_start..dst_end, &src[src_start..src_end]);
    Some(((dst_start..dst_end), (src_start..src_end)))
}

/// Copy a random sub-slice from `src` into a random subslice of `dst`.
/// This will potentially grow or shrink the destination vector.
/// This will call clone on every element. Use [`splice_extend`] if your type is `Copy` for better
/// performance.
#[inline]
pub fn splice_clone_extend<C: Clone>(
    dst: &mut Vec<C>,
    src: &[C],
    rng: &mut impl rand::Rng,
) -> Option<(std::ops::Range<usize>, std::ops::Range<usize>)> {
    if src.is_empty() {
        return None;
    }

    let src_start = rng.gen_range(0..src.len());
    let src_end = rng.gen_range(src_start..=src.len());
    if dst.is_empty() {
        dst.extend(
            src.iter()
                .skip(src_start)
                .take(src_end - src_start)
                .cloned(),
        );
        return Some((0..0, src_start..src_end));
    }

    let dst_start = rng.gen_range(0..dst.len());
    let dst_end = rng.gen_range(dst_start..=dst.len());

    dst.splice(
        dst_start..dst_end,
        src.iter()
            .skip(src_start)
            .take(src_end - src_start)
            .cloned(),
    );
    Some(((dst_start..dst_end), (src_start..src_end)))
}

/// Copy sub-slice from another slice into the current one.
///
/// # returns
///
/// `Some((input_offset, other_offset, length))` or `None` if not applicable.
#[inline]
pub fn splice_other_inplace<C: Copy, T: AsMut<[C]>, S: AsRef<[C]>>(
    input: &mut T,
    other: &S,
    rng: &mut impl rand::Rng,
) -> Option<(usize, usize, usize)> {
    let input = input.as_mut();
    let other = other.as_ref();
    if other.is_empty() || input.is_empty() || input.len() < 8 {
        return None;
    }

    let other_start = rng.gen_range(0..other.len()); // at least 0..1 -> no panic
    let other_end = rng.gen_range(other_start..=other.len()); // at least 1..=1 -> no panic

    // skip splicing another small input
    if (other_end - other_start) < 4 {
        return None;
    }
    let splice_from = &other[other_start..other_end];
    if splice_from.len() >= input.len() {
        return None;
    }

    let splice_len = splice_from.len();
    let input_offset = rng.gen_range(0_usize..(input.len() - splice_len));

    // Splice the found
    input[input_offset..(input_offset + splice_len)].copy_from_slice(splice_from);

    // Output mutation
    Some((input_offset, other_start, splice_len))
}
