#![allow(missing_docs)]

use fxhash::FxHashSet;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::default::Default;
use std::hash::Hash;

use crate::VirtAddr;

pub type TaggedFeedback = BTreeMap<u64, FxHashSet<u64>>;
pub type ScratchFeedback = BTreeSet<VirtAddr>;
pub type MaxFeedback = BTreeMap<u64, u64>;
pub type CustomFeedback = FxHashSet<u64>;

#[cfg(feature = "redqueen")]
use x86_64::registers::rflags::RFlags;
#[cfg(feature = "redqueen")]
pub type RedqueenFeedback = BTreeSet<(VirtAddr, u64)>;

#[derive(Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FeedbackLog {
    VAddr(VirtAddr),

    #[cfg(feature = "custom_feedback")]
    Custom(u64),
    #[cfg(feature = "custom_feedback")]
    CustomTagged((u64, u64)),
    #[cfg(feature = "custom_feedback")]
    CustomMax((u64, u64)),

    #[cfg(feature = "redqueen")]
    #[serde(skip)]
    Redqueen((VirtAddr, u64)),
}

#[derive(Default, Clone, Serialize, PartialEq, Eq)]
pub struct FeedbackTracker {
    pub(crate) log: Vec<FeedbackLog>,
    pub(crate) code_cov: ScratchFeedback,

    #[cfg(feature = "redqueen")]
    pub(crate) redqueen: RedqueenFeedback,

    #[cfg(feature = "custom_feedback")]
    pub(crate) custom: CustomFeedback,
    #[cfg(feature = "custom_feedback")]
    pub(crate) tagged: TaggedFeedback,
    #[cfg(feature = "custom_feedback")]
    pub(crate) max: MaxFeedback,
}

impl FeedbackTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_prev(code_cov: BTreeSet<VirtAddr>) -> Self {
        Self {
            code_cov,
            ..Default::default()
        }
    }

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
            if !self.tagged.is_empty() {
                r += self.tagged.iter().map(|(_k, v)| v.len()).sum::<usize>();
            }
        }

        r
    }

    pub fn merge(&mut self, other: &Self) -> bool {
        let mut r = false;

        let old_len = self.code_cov.len();
        self.code_cov.extend(other.code_cov.iter().copied());
        r |= self.code_cov.len() != old_len;

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
                r |= other.max != self.max;
                let old_len = self.max.len();
                self.max.extend(other.max.iter().map(|(k, v)| (*k, *v)));
                r |= self.max.len() != old_len;
            }

            if !other.tagged.is_empty() {
                let old_len = self.tagged.len();
                self.tagged
                    .extend(other.tagged.iter().map(|(k, v)| (k.clone(), v.clone())));
                r |= self.tagged.len() != old_len;
            }
        }

        r
    }

    pub fn record_codecov(&mut self, v: VirtAddr) -> bool {
        let r = self.code_cov.insert(v);
        if r {
            self.log.push(FeedbackLog::VAddr(v))
        }
        r
    }

    pub fn has_new(&self) -> bool {
        !self.log.is_empty()
    }

    pub fn take_log(&mut self) -> Vec<FeedbackLog> {
        std::mem::take(&mut self.log)
    }

    pub fn ensure_clean(&mut self) {
        self.log.clear();
    }

    #[cfg(feature = "redqueen")]
    pub fn record_redqueen(&mut self, v: VirtAddr, f: RFlags) -> bool {
        let flags_bits = f.bits();
        let r = self.redqueen.insert((v, flags_bits));
        if r {
            self.log.push(FeedbackLog::Redqueen((v, flags_bits)));
        }
        r
    }

    #[cfg(feature = "custom_feedback")]
    pub fn record<T: Into<u64>>(&mut self, v: T) -> bool {
        let v: u64 = v.into();
        let r = self.custom.insert(v);
        if r {
            self.log.push(FeedbackLog::Custom(v));
        }
        r
    }

    #[cfg(feature = "custom_feedback")]
    pub fn record_pair<T: Into<u32>>(&mut self, a: T, b: T) -> bool {
        let a: u32 = a.into();
        let b: u32 = b.into();
        self.record((a as u64) << 32 | (b as u64))
    }

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

    #[cfg(feature = "custom_feedback")]
    pub fn record_tagged<T: Into<u64>, S: Into<u64>>(&mut self, t: T, v: S) -> bool {
        let t: u64 = t.into();
        let v: u64 = v.into();
        let r = if let Some(set) = self.tagged.get_mut(&t) {
            set.insert(v)
        } else {
            let mut m = FxHashSet::default();
            m.insert(v);
            self.tagged.insert(t, m);
            true
        };
        if r {
            self.log.push(FeedbackLog::CustomTagged((t, v)));
        }
        r
    }

    #[cfg(feature = "custom_feedback")]
    pub fn record_min<T: Into<u64>, S: Into<u64>>(&mut self, t: T, v: S) -> bool {
        let t: u64 = t.into();
        let v: u64 = v.into();
        self.record_max(t, u64::MAX - v)
    }

    #[cfg(feature = "custom_feedback")]
    pub fn record_data_hash<T: Hash>(&mut self, val: T) -> bool {
        use ahash::RandomState;
        let hasher = RandomState::with_seeds(1, 2, 3, 4);
        let hash = hasher.hash_one(val);
        self.record(hash)
    }

    #[cfg(feature = "custom_feedback")]
    pub fn record_min_prefix_dist<T: Into<u64>>(
        &mut self,
        t: T,
        a: &[u8],
        b: &[u8],
    ) -> Option<usize> {
        let dist = a.len() - a.iter().zip(b).take_while(|(a, b)| *a == *b).count();

        if self.record_min(t, dist as u64) {
            Some(dist)
        } else {
            None
        }
    }
}
