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

use rustc_hash::{FxHashMap, FxHashSet};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use std::collections::hash_map::Entry;
use std::collections::BTreeSet;
use std::default::Default;
use std::hash::Hash;

use crate::VirtAddr;

#[cfg(feature = "redqueen")]
use crate::cmp_analysis::RedqueenCoverage;

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
pub type RedqueenFeedback = BTreeSet<RedqueenCoverage>;

/// The [`FeedbackTracker`] keeps track of a log of never-before seen feedback. This is logged for
/// each execution and can be obtained with [`FeedbackTracker::take_log`]. This enum is used to
/// distinguish between different entries within the feedback log.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Ord, PartialOrd)]
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
    Redqueen(RedqueenCoverage),
}
/// Custom serialize for FeedbackLog
impl Serialize for FeedbackLog {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Convert the u64 to hex strings

        // Begin the sequence of elements
        // let mut seq = serializer.serialize_seq(Some(values.len()))?;

        // for value in values {
        let element = match self {
            FeedbackLog::VAddr((addr, hits)) => {
                let addr = addr.0;
                format!("{addr:#x},{hits}")
            }
            #[cfg(feature = "custom_feedback")]
            FeedbackLog::Custom(val) => format!("Custom|{val:#x}"),
            #[cfg(feature = "custom_feedback")]
            FeedbackLog::CustomMax((tag, val)) => format!("CustomMax|{tag:#x},{val:#x}"),
            #[cfg(feature = "redqueen")]
            FeedbackLog::Redqueen(RedqueenCoverage {
                virt_addr,
                rflags,
                hit_count,
            }) => {
                let virt_addr = virt_addr.0;
                format!("RQ|{virt_addr:#x},{rflags:#x},{hit_count}")
            }
        };

        serializer.serialize_str(&element)
    }
}

impl<'de> Deserialize<'de> for FeedbackLog {
    /// Custom deserialize for Vec<u64>
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Get a Vec of hex strings from the deserializer
        let hex: String = Deserialize::deserialize(deserializer)?;

        #[cfg(feature = "redqueen")]
        if let Some(redqueen) = hex.strip_prefix("RQ|") {
            if let Some([addr, rflags, hit_count]) = redqueen.split(&",").array_chunks().next() {
                let virt_addr = u64::from_str_radix(&addr[2..], 16)
                    .expect(&format!("Failed to deserialize virt addr: {hex} {addr}"));
                let rflags = u64::from_str_radix(&rflags[2..], 16)
                    .expect(&format!("Failed to deserialize rflags: {hex} {rflags}"));
                let hit_count = hit_count.parse::<u32>().expect(&format!(
                    "Failed to deserialize hit_count {hex} {hit_count}"
                ));

                return Ok(FeedbackLog::Redqueen(RedqueenCoverage {
                    virt_addr: VirtAddr(virt_addr),
                    rflags,
                    hit_count,
                }));
            } else {
                panic!("Invalid format for redqueen found: {hex}");
            }
        }

        // Convert the hex strings back into CoverageType
        if let Some([addr, hit_count]) = hex.split(&",").array_chunks().next() {
            let addr = u64::from_str_radix(&addr[2..], 16)
                .expect(&format!("Failed to parse coverage address {hex} {addr}"));

            return Ok(FeedbackLog::VAddr((
                VirtAddr(addr),
                hit_count.parse::<u16>().unwrap(),
            )));
        }

        #[cfg(feature = "custom_feedback")]
        if let Some(custom_max) = hex.strip_prefix("CustomMax|") {
            if let Some([tag, val]) = hex.split(&",").array_chunks().next() {
                let tag =
                    u64::from_str_radix(&tag[2..], 16).expect("Failed to deserialize tag: {tag}");
                let val =
                    u64::from_str_radix(&val[2..], 16).expect("Failed to deserialize val: {val}");

                return Ok(FeedbackLog::CustomMax((tag, val)));
            } else {
                panic!("Invalid custom max format: {custom_max}")
            }
        }

        #[cfg(feature = "custom_feedback")]
        if let Some(custom) = hex.strip_prefix("Custom|") {
            let custom = u64::from_str_radix(&custom[2..], 16)
                .expect("Failed to deserialize custom: {custom}");

            return Ok(FeedbackLog::Custom(custom));
        }

        panic!("Failed to parse element: {hex}");
    }
}

/// AFL introduced a [bucketing mechanism](https://lcamtuf.coredump.cx/afl/technical_details.txt) to avoid filling the corpus/queue with too many similar
/// entries, e.g., one input for every loop iteration.
/// This functions implements a somewhat similar bucketing mechanism, with a bit more fine-granular
/// buckets.
///
/// See also [`classify_hitcount_into_bucket_afl_style`].
///
/// Takes hitcount and returns bucketed value.
pub(crate) fn classify_hitcount_into_bucket(hitcount: u16) -> u16 {
    // but we have 16-bit hitcounters and also we use
    match hitcount {
        0..4 => hitcount,
        4..6 => 4,
        6..8 => 6,
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
    }
}

/// original AFL-style bucketing + another bucket for hitcounts greater than 255.
/// See also [`classify_hitcount_into_bucket`].
///
/// Takes hitcount and returns bucketed value.
pub(crate) fn classify_hitcount_into_bucket_afl_style(hitcount: u16) -> u16 {
    match hitcount {
        0..4 => hitcount,
        4..8 => 4,
        8..16 => 8,
        16..32 => 16,
        32..128 => 32,
        128..256 => 128,
        256.. => 256,
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
#[derive(Default, Clone, Serialize, Deserialize)]
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
        #[allow(unused_mut)]
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

    /// Compute a log of entries in `self` that are not in `other`.
    ///
    /// ```
    /// # use snapchange::{feedback::{FeedbackLog, FeedbackTracker}, addrs::VirtAddr};
    /// let mut a = FeedbackTracker::new();
    /// a.record_codecov(0xdeadbeef.into());
    /// a.record_codecov(0xcafecafe.into());
    /// let mut b = FeedbackTracker::new();
    /// b.record_codecov(0xcafecafe.into());
    /// b.record_codecov(0x42424242.into());
    ///
    /// let d = a.diff(&b);
    /// assert_eq!(d, vec![FeedbackLog::VAddr((0xdeadbeef.into(), 1))]);
    /// let d = b.diff(&a);
    /// assert_eq!(d, vec![FeedbackLog::VAddr((0x42424242.into(), 1))]);
    ///
    /// b.record_codecov(0xdeadbeef.into());
    /// let d = a.diff(&b);
    /// assert!(d.is_empty())
    /// ```
    pub fn diff(&self, other: &FeedbackTracker) -> Vec<FeedbackLog> {
        let mut v = vec![];
        for (addr, count) in self.code_cov.iter() {
            if let Some(other_count) = other.code_cov.get(addr) {
                if *count != *other_count {
                    v.push(FeedbackLog::VAddr((*addr, *count)));
                }
            } else {
                v.push(FeedbackLog::VAddr((*addr, *count)));
            }
        }

        #[cfg(feature = "custom_feedback")]
        for value in self.custom.iter() {
            if !other.custom.contains(value) {
                v.push(FeedbackLog::Custom(*value));
            }
        }

        #[cfg(feature = "custom_feedback")]
        for (tag, value) in self.max.iter() {
            if let Some(other_value) = other.max.get(tag) {
                if *value != *other_value {
                    v.push(FeedbackLog::CustomMax((*tag, *value)));
                }
            } else {
                v.push(FeedbackLog::CustomMax((*tag, *value)));
            }
        }

        #[cfg(feature = "redqueen")]
        for rq in self.redqueen.iter() {
            if !other.redqueen.contains(rq) {
                v.push(FeedbackLog::Redqueen(*rq));
            }
        }

        v
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

    /// Add all feedback entries from another [`[FeedbackLog]`]. Returns true if a new entry was
    /// added while merging.
    pub fn merge_from_log(&mut self, log: &[FeedbackLog]) -> bool {
        // No need to keep the log around
        self.ensure_clean();

        for entry in log {
            match entry {
                FeedbackLog::VAddr((addr, hitcount)) => {
                    let curr_hitcount = self.code_cov.entry(*addr).or_insert(0);
                    if hitcount > curr_hitcount {
                        self.code_cov.insert(*addr, *hitcount);
                        self.log.push(FeedbackLog::VAddr((*addr, *hitcount)));
                    }
                }

                #[cfg(feature = "custom_feedback")]
                FeedbackLog::Custom(val) => {
                    let _new = self.record(*val);
                }

                // Observed new max value for given tag.
                #[cfg(feature = "custom_feedback")]
                FeedbackLog::CustomMax((tag, val)) => {
                    let _new = self.record_max(*tag, *val);
                }

                // while performing redqueen, observed new rflags for a given comparison address.
                #[cfg(feature = "redqueen")]
                FeedbackLog::Redqueen(rq_cov) => {
                    if self.redqueen.insert(*rq_cov) {
                        self.log.push(FeedbackLog::Redqueen(*rq_cov));
                        // log::info!("NEW RQ: {rq_cov:x?}");
                    }
                }
            }
        }

        self.has_new()
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

    /// Record the first time a coverage address has been executed. This differs from record_codecov_hitcount
    /// as this will not increase the hitcount. There is a possibility that multiple cores can reach the same
    /// coverage address at the same time.
    ///
    /// Returns true if a new value `v` was observed.
    pub fn record_codecov(&mut self, v: VirtAddr) -> bool {
        match self.code_cov.entry(v) {
            // fast path -> first time code cov is recorded
            Entry::Vacant(e) => {
                e.insert(1);
                self.log.push(FeedbackLog::VAddr((v, 1)));
                true
            }
            _ => false,
        }
    }

    /// Record a code coverage hitpoint -> a virtual address executed. Can be used both two record
    /// hitcount coverage and also single-shot scratch-away code coverage.
    ///
    /// Returns true if a new value `v` was observed.
    pub fn record_codecov_hitcount(&mut self, v: VirtAddr) -> bool {
        match self.code_cov.entry(v) {
            // fast path -> first time code cov is recorded
            Entry::Vacant(e) => {
                e.insert(1);
                self.log.push(FeedbackLog::VAddr((v, 1)));
                true
            }
            Entry::Occupied(mut e) => {
                let hitcount = e.get_mut();
                let prev = *hitcount;
                *hitcount = prev.saturating_add(1);
                if classify_hitcount_into_bucket(prev) < classify_hitcount_into_bucket(*hitcount) {
                    self.log.push(FeedbackLog::VAddr((v, *hitcount)));
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Check for equality of custom feedback only.
    #[cfg(feature = "redqueen")]
    pub fn eq_redqueen(&self, other: &Self) -> bool {
        self.redqueen == other.redqueen
    }

    /// Check for equal code coverage with an exact hitcount comparison
    pub fn eq_codecov_exact(&self, other: &Self) -> bool {
        self.eq_codecov_with(other, |x| x)
    }

    /// Check for equal code coverage with our standard classified hitcount comparison.
    pub fn eq_codecov(&self, other: &Self) -> bool {
        self.eq_codecov_with(other, classify_hitcount_into_bucket)
    }

    /// Check for equal custom feedback
    #[cfg(feature = "custom_feedback")]
    pub fn eq_custom_feedback(&self, other: &Self) -> bool {
        self.custom == other.custom
    }

    /// Check for equal code coverage using the given function to classify coverage hitcounts into
    /// buckets.
    ///
    /// ```
    /// # use snapchange::{feedback::FeedbackTracker, addrs::VirtAddr};
    /// let mut feedback = FeedbackTracker::new();
    /// feedback.record_codecov(0xdeadbeef.into());
    /// let mut other = FeedbackTracker::new();
    /// other.record_codecov(0xdeadbeef.into());
    /// other.record_codecov(0xdeadbeef.into());
    ///
    /// // exact comparison fails, because of different hitcounts
    /// assert!(!feedback.eq_codecov_with(&other, |x| x));
    /// // turn hitcounts into yes/no and the comparison fails
    /// assert!(feedback.eq_codecov_with(&other, |x| if x > 0 { 1 } else { 0 }));
    /// ```
    pub fn eq_codecov_with<F>(&self, other: &Self, classify: F) -> bool
    where
        F: Fn(u16) -> u16,
    {
        if self.code_cov.len() != other.code_cov.len() {
            return false;
        }
        // We have the same number of entries, so let's check the hitcounts.

        // I don't think this code would be correct, as iteration order of the coverage maps is not
        // guaranteed?
        // ```
        // self.code_cov.iter().eq(other.code_cov.iter())
        // ```
        // TODO: maybe there is a way to ensure same iteration order? Or maybe different
        // iteration orders already signal different coverage maps? We are using hashmaps so
        // iteration order is not guaranteed in general, but maybe integer keys are different? (maybe with the
        // no-hash hasher)?
        //
        // so conservatively we need to do this:

        // Since the length is equal, it is not possible for self.code_cov to be a strict subset of
        // other.code_cov. Therefore, it is sufficient to iterate over `self.code_cov`.
        for (vaddr, hitcount) in self.code_cov.iter() {
            if let Some(other_hitcount) = other.code_cov.get(vaddr) {
                let hitcount = classify(*hitcount);
                let other_hitcount = classify(*other_hitcount);
                if hitcount != other_hitcount {
                    return false;
                }
            } else {
                return false;
            }
        }
        true
    }

    /// Check equality of custom/max feedback and code coverage, using the given function to
    /// classify code coverage hitcounts.
    pub fn eq_with<F>(&self, other: &Self, classify: F) -> bool
    where
        F: Fn(u16) -> u16,
    {
        let r = self.eq_codecov_with(other, classify);
        #[cfg(feature = "custom_feedback")]
        let r = r & self.eq_custom_feedback(other);
        #[cfg(feature = "redqueen")]
        let r = r & (self.redqueen == other.redqueen);
        r
    }

    #[cfg(feature = "redqueen")]
    /// Record RFlags for redqueen coverage.
    pub fn record_redqueen(
        &mut self,
        virt_addr: VirtAddr,
        rflags: x86_64::registers::rflags::RFlags,
        hit_count: u32,
    ) -> bool {
        // Add this redqueen coverage
        let cov = RedqueenCoverage {
            virt_addr,
            rflags: rflags.bits(),
            hit_count,
        };

        let is_new_entry = self.redqueen.insert(cov);
        if is_new_entry {
            self.log.push(FeedbackLog::Redqueen(cov));
        }

        is_new_entry
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
            // log::info!("NEW MAX: tag {t:#x}  value {v:#x}");
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

impl std::cmp::PartialEq for FeedbackTracker {
    /// comparison based on recorded code coverage, and if enabled also custom feedback and redqueen.
    fn eq(&self, other: &FeedbackTracker) -> bool {
        self.eq_with(other, |x| x)
    }
}
