//! Contains implementation for fuzzing feedback mechanisms, most notably code coverage feedback.
//! The main data structure is the [`FeedbackTracker`], which encapsulates all feedback mechanisms.
//! Note that the [`FeedbackTracker`] is exposed to the user when it is passed to breakpoint hooks.
//! This allows the user to adapt the fuzzer's feedback mechanism. It allows the user to extend the
//! coverage mechanism beyond breakpoint code coverage.
//!
//! ```rust
//! # use snapchange::{feedback::FeedbackTracker, addrs::VirtAddr};
//! let mut feedback = FeedbackTracker::new();
//! // ...
//! feedback.record_codecov(VirtAddr(0xdeadbeef));
//! assert!(feedback.has_new());
//! // ...
//! ```

use rustc_hash::{FxHashSet, FxHashMap};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet};
use std::default::Default;
use std::hash::Hash;

use crate::VirtAddr;

// TODO: maybe we should use the https://crates.io/crates/nohash-hasher crate for the feedback
// hashmaps?

/// Used to record address-based code coverage + a hitcount.
pub type HitcountFeedback = FxHashMap<VirtAddr, u16>;
/// Used to record a maximum value for a given tag.
pub type MaxFeedback = FxHashMap<u64, u64>;
/// Used to record custom feedback specified by the fuzzer/harness implementation.
pub type CustomFeedback = FxHashSet<u64>;

/// Used to record redqueen feedback
#[cfg(feature = "redqueen")]
pub type RedqueenFeedback = BTreeSet<(VirtAddr, u64)>;

/// The [`FeedbackTracker`] keeps track of a log of never-before seen feedback. This is logged for
/// each execution and can be obtained with [`FeedbackTracker::take_log`]. This enum is used to
/// distinguish between different entries within the feedback log.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
pub enum FeedbackLog {
    /// Observed new code coverage
    VAddr((VirtAddr, u16)),

    /// Observed new custom feedback.
    #[cfg(feature = "custom_feedback")]
    Custom(u64),
    /// Observed new max value for given tag.
    #[cfg(feature = "custom_feedback")]
    CustomMax((u64, u64)),

    /// While performing redqueen, observed new RFlags for a given comparison address.
    #[cfg(feature = "redqueen")]
    #[serde(skip)]
    Redqueen((VirtAddr, u64)),
}

/// AFL introduced a [bucketing mechanism](https://lcamtuf.coredump.cx/afl/technical_details.txt) to avoid filling the corpus/queue with too many similar
/// entries, e.g., one input for every loop iteration.
/// This functions implements a somewhat similar bucketing mechanism.
pub fn classify_hitcount_into_bucket(hitcount: u16) -> u16 {
    match hitcount {
        0..4 => hitcount,
        4..6 => 4,
        6..7 => 6,
        8..12 => 8,
        12..16 => 12,
        16..24 => 16,
        24..32 => 24,
        32..48 => 32,
        48..64 => 48,
        64..128 => 64,
        128..256 => 128,
        256..512 => 256,
        512..1024 => 512,
        1024..2048 => 1024,
        2048..3072 => 2048,
        3072..4096 => 3072,
        4096.. => 4096,
        _ => unreachable!(),
    }
}

/// The FeedbackTracker encapsulates various types of feedback mechanisms in the fuzzer.
/// The flow is the following:
///
/// ```
/// # use snapchange::{feedback::FeedbackTracker, addrs::VirtAddr};
/// # fn execute_target(input: Vec<u8>, feedback: &mut FeedbackTracker) { feedback.record_codecov(VirtAddr(0xdeadbeefu64)); }
/// # fn schedule_input() -> Vec<u8> { vec![] }
/// let mut feedback = FeedbackTracker::new();
/// let input = schedule_input();
/// execute_target(input, &mut feedback);
/// if feedback.has_new() {
///     // `input` is interesting!
/// }
/// assert!(feedback.has_new());
/// // take_log consumes the feedback log
/// for new_cov in feedback.take_log().into_iter() {
///     println!("newly discovered coverage: {:?}", new_cov);
/// }
/// assert!(!feedback.has_new());
/// // altenatively, we can manually clean the feedback log.
/// feedback.ensure_clean();
/// assert!(!feedback.has_new());
/// ```
#[derive(Default, Clone, Serialize, PartialEq, Eq)]
pub struct FeedbackTracker {
    /// A log of newly observed feedback entries.
    pub(crate) log: Vec<FeedbackLog>,
    /// Code coverage feedback.
    pub(crate) code_cov: HitcountFeedback,

    /// feedback required for redqueen
    #[cfg(feature = "redqueen")]
    pub(crate) redqueen: RedqueenFeedback,

    /// keeps track of custom feedback values.
    #[cfg(feature = "custom_feedback")]
    pub(crate) custom: CustomFeedback,

    /// keeps track of the current maximum value for a given context tag.
    #[cfg(feature = "custom_feedback")]
    pub(crate) max: MaxFeedback,
}

impl FeedbackTracker {
    /// Create new feedback tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create new feedback tracker, initialized with code coverage from a given
    pub fn from_prev(code_cov: BTreeSet<VirtAddr>) -> Self {
        let code_cov: HitcountFeedback = code_cov.into_iter().map(|v| (v, 1)).collect();
        Self {
            code_cov,
            ..Default::default()
        }
    }

    /// Returns the number of all entries recorded in any feedback map.
    ///
    /// Note: Ususally you should use the [`Self::has_new()`] function to determine if new coverage was recorded.
    pub fn len(&self) -> usize {
        let mut r = self.code_cov.len();

        #[cfg(feature = "redqueen")]
        {
            r += self.redqueen.len();
        }

        #[cfg(feature = "custom_feedback")]
        {
            r += self.custom.len();
            r += self.max.len();
        }

        r
    }

    /// Add all feedback entries from another [`FeedbackTracker`]. Returns true if a new entry was
    /// added while merging.
    pub fn merge(&mut self, other: &Self) -> bool {
        let mut r = false;

        for (vaddr, hitcount) in other.code_cov.iter() {
            let vaddr = *vaddr;
            let hitcount = *hitcount;
            if let Some(prev) = self.code_cov.get_mut(&vaddr) {
                if hitcount > *prev {
                    *prev = hitcount;
                    r = true;
                }
            } else {
                self.code_cov.insert(vaddr, hitcount);
                r = true;
            }
        }

        // TODO: do we sync this between cores?
        #[cfg(feature = "redqueen")]
        {
            let old_len = self.redqueen.len();
            self.redqueen.extend(other.redqueen.iter().copied());
            r |= self.redqueen.len() != old_len;
        }

        #[cfg(feature = "custom_feedback")]
        {
            if !other.custom.is_empty() {
                let old_len = self.custom.len();
                self.custom.extend(other.custom.iter().copied());
                r |= self.custom.len() != old_len;
            }

            if !other.max.is_empty() {
                for (t, v) in other.max.iter() {
                    let t = *t;
                    let v = *v;
                    if let Some(prev) = self.max.get_mut(&t) {
                        if v > *prev {
                            *prev = v;
                            r = true;
                        }
                    } else {
                        self.max.insert(t, v);
                        r = true;
                    }
                }
            }
        }

        r
    }

    /// Check whether there is some new feedback since the last time the log was cleared.
    pub fn has_new(&self) -> bool {
        !self.log.is_empty()
    }

    /// Obtain a log of newly observed feedback and resets the saved log.
    ///
    /// The idea is to
    /// 1. Execute target with hooks recording feedback in the [`FeedbackTracker`]
    /// 2. Call [`Self::take_log`] to check for new coverage.
    /// 3. Optionally: handle new coverage entries in the log
    /// 4. go to step 1.
    pub fn take_log(&mut self) -> Vec<FeedbackLog> {
        std::mem::take(&mut self.log)
    }

    /// Clear the coverage log.
    pub fn ensure_clean(&mut self) {
        self.log.clear();
    }

    /// Record a code coverage hitpoint -> a virtual address executed. Can be used both two record
    /// hitcount coverage and also single-shot scratch-away code coverage.
    ///
    /// Returns true if a new value `v` was observed.
    pub fn record_codecov(&mut self, v: VirtAddr) -> bool {
        match self.code_cov.entry(v) {
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(1);
                self.log.push(FeedbackLog::VAddr((v, 1)));
                true
            }
            std::collections::hash_map::Entry::Occupied(mut e) => {
                let hitcount = e.get_mut();
                let prev = *hitcount;
                let new = prev.saturating_add(1);
                // TODO: use classify_hitcount_into_bucket to check for meaningful new code coverage?
                if prev != new {
                    *hitcount = new;
                    self.log.push(FeedbackLog::VAddr((v, new)));
                    true
                } else {
                    false
                }
            }
        }
    }

    #[cfg(feature = "redqueen")]
    /// Record RFlags for redqueen coverage.
    pub fn record_redqueen(&mut self, v: VirtAddr, f: x86_64::registers::rflags::RFlags) -> bool {
        let flags_bits = f.bits();
        let r = self.redqueen.insert((v, flags_bits));
        if r {
            self.log.push(FeedbackLog::Redqueen((v, flags_bits)));
        }
        r
    }

    /// Record an arbitrary [`u64`] value as custom feedback.
    ///
    /// Returns true if the provided value `v` has not been observed before.
    #[cfg(feature = "custom_feedback")]
    pub fn record<T: Into<u64>>(&mut self, v: T) -> bool {
        let v: u64 = v.into();
        let r = self.custom.insert(v);
        if r {
            self.log.push(FeedbackLog::Custom(v));
        }
        r
    }

    /// Record a pair of [`u32`] value as a combined feedback.
    ///
    /// Returns true if a never-before discoverd pair was recorded.
    ///
    /// ```
    /// # use snapchange::{feedback::FeedbackTracker, addrs::VirtAddr};
    /// let mut feedback = FeedbackTracker::new();
    /// assert!(feedback.record_pair(1u32, 2u32));
    /// assert!(!feedback.record_pair(1u32, 2u32));
    /// ```
    #[cfg(feature = "custom_feedback")]
    pub fn record_pair<T: Into<u32>>(&mut self, a: T, b: T) -> bool {
        let a: u32 = a.into();
        let b: u32 = b.into();
        self.record((a as u64) << 32 | (b as u64))
    }

    /// Record four [`u16`] values as a combined feedback.
    ///
    /// Returns true if a never-before discoverd quadruple was recorded.
    ///
    /// ```
    /// # use snapchange::{feedback::FeedbackTracker, addrs::VirtAddr};
    /// let mut feedback = FeedbackTracker::new();
    /// assert!(feedback.record_quad(0u16, 1u16, 2u16, 3u16));
    /// assert!(!feedback.record_quad(0u16, 1u16, 2u16, 3u16));
    /// ```
    #[cfg(feature = "custom_feedback")]
    pub fn record_quad<T: Into<u16>>(&mut self, a: T, b: T, c: T, d: T) -> bool {
        let a: u16 = a.into();
        let b: u16 = b.into();
        let c: u16 = c.into();
        let d: u16 = d.into();
        self.record((a as u64) << 48 | (b as u64) << 32 | (c as u64) << 16 | (d as u64))
    }

    /// Records a hash of the given data as custom feedback. Distinct hashes are recorded as new
    /// coverage. Since only the hash of the data is recorded, there is a probability of hash
    /// collisions. If your values are in a smaller domain, consider [`Self::record_pair`] or
    /// [`Self::record_quad`] for collision free custom feedback.
    ///
    /// ```
    /// # use snapchange::{feedback::FeedbackTracker, addrs::VirtAddr};
    /// let mut feedback = FeedbackTracker::new();
    /// let new = feedback.record_hashed(&[13u64, 37u64]);
    /// assert!(new);
    /// let new = feedback.record_hashed(&[13u64, 37u64]);
    /// assert!(!new);
    ///
    /// #[derive(Hash)]
    /// struct State {
    ///     a: u64,
    ///     b: i32,
    /// };
    /// let state = State { a: 1234567890, b: -10 };
    /// // first time is recorded.
    /// assert!(feedback.record_hashed(&state));
    /// // second time is ignored, since the hash was already seen.
    /// assert!(!feedback.record_hashed(&state));
    /// ````
    ///
    /// Returns true if a previously unknown hash was recorded.
    #[cfg(feature = "custom_feedback")]
    pub fn record_hashed<T: Hash>(&mut self, val: T) -> bool {
        use ahash::RandomState;
        let hasher = RandomState::with_seeds(1, 2, 3, 4);
        let hash = hasher.hash_one(val);
        self.record(hash)
    }

    /// record a value [`v`] for a certain tag value that specifies a context. Records the value
    /// only if it is bigger than the previously seen value for tag [`t`t].
    ///
    /// Typically a tag can be the contents of a `fuzzvm.rip()` call. If there is only a single tag
    /// used by the fuzzer, simply specify `0u64`.
    #[cfg(feature = "custom_feedback")]
    pub fn record_max<T: Into<u64>, S: Into<u64>>(&mut self, t: T, v: S) -> bool {
        let t: u64 = t.into();
        let v: u64 = v.into();
        if let Some(prev) = self.max.get_mut(&t) {
            if v > *prev {
                self.log.push(FeedbackLog::CustomMax((t, v)));
                *prev = v;
                true
            } else {
                false
            }
        } else {
            self.log.push(FeedbackLog::CustomMax((t, v)));
            self.max.insert(t, v);
            true
        }
    }

    /// record a value [`v`] for a certain tag value that specifies a context. Records the value
    /// only if it is smaller than the previously seen value for tag [`t`t].
    ///
    /// Typically a tag can be the contents of a `fuzzvm.rip()` call. If there is only a single tag
    /// used by the fuzzer, simply specify `0u64`.
    #[cfg(feature = "custom_feedback")]
    pub fn record_min<T: Into<u64>, S: Into<u64>>(&mut self, t: T, v: S) -> bool {
        let t: u64 = t.into();
        let v: u64 = v.into();
        self.record_max(t, u64::MAX - v)
    }

    /// Record a value profile given two operands of a comparison, similar to what
    /// [libfuzzer](https://www.llvm.org/docs/LibFuzzer.html#value-profile) does. This will make the
    /// fuzzer attempt to minimize the hamming distance between the two operands.
    ///
    /// The tag value [`t`] provides context, e.g., the `fuzzvm.rip()` of the comparison.
    ///
    /// Returns true if a new minimum hamming distance is found.
    #[cfg(feature = "custom_feedback")]
    pub fn record_cmp_value_profile<T: Into<u64>, S: Into<u64>>(
        &mut self,
        t: T,
        a: S,
        b: S,
    ) -> bool {
        let a: u64 = a.into();
        let b: u64 = b.into();
        let profile = (!(a ^ b)).count_ones();
        self.record_max(t, profile)
    }

    /// Record the prefix distance between two byte-strings, i.e., attempt to maxmimize the length of a common
    /// prefix. This allows the fuzzer to make progress towards `a == b`. This can be useful to find
    /// inputs that bypas comparisons with `strcmp` or similar.
    ///
    /// [`t`] is a tag value that provides context, e.g., the `fuzzvm.rip()` or some other
    /// unique identifier. Provide `0u64` if there is no meaningful tag.
    ///
    /// Returns [`None`] if the common prefix length is smaller, or `Some(dist)`, where `dist` is
    /// the newly discovered distance between `a` and `b`.
    #[cfg(feature = "custom_feedback")]
    pub fn record_prefix_dist<T: Into<u64>>(&mut self, t: T, a: &[u8], b: &[u8]) -> Option<usize> {
        let len = std::cmp::min(a.len(), b.len());
        let dist = len - a.iter().zip(b).take_while(|(a, b)| *a == *b).count();

        if self.record_min(t, dist as u64) {
            Some(dist)
        } else {
            None
        }
    }
}
