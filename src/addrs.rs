//! Various auxillary types

use serde::{Deserialize, Serialize};

use std::convert::TryInto;

/// A physical address
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PhysAddr(pub u64);

impl PhysAddr {
    /// Return a [`PhysAddr`] `offset` byte away from `self`
    ///
    /// Example:
    ///
    /// ```
    /// let page = PhysAddr(0xdead_0000)
    /// let entry = page.offset(0x1234)
    /// assert!(entry.0 == 0xdead_1234)
    /// ```
    #[must_use]
    pub const fn offset(self, offset: u64) -> PhysAddr {
        PhysAddr(self.0 + offset)
    }

    /// Return the page that contains this [`PhysAddr`]
    ///
    /// Example:
    ///
    /// ```
    /// let addr = PhysAddr(0xdead_1234)
    /// let page = addr.page()
    /// assert!(page.0 == 0xdead_1000)
    /// ```
    #[must_use]
    pub const fn page(self) -> PhysAddr {
        PhysAddr(self.0 & !0xfff)
    }
}

impl std::ops::Deref for PhysAddr {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A virtual address
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, Hash)]
pub struct VirtAddr(pub u64);

// From<u64> for VirtAddr implies Into<VirtAddr> for u64
impl From<u64> for VirtAddr {
    fn from(val: u64) -> VirtAddr {
        VirtAddr(val)
    }
}

impl Into<u64> for VirtAddr {
    fn into(self) -> u64 {
        self.0
    }
}

impl VirtAddr {
    /// Return a [`VirtAddr`] `offset` byte away from `self`
    ///
    /// Example:
    ///
    /// ```
    /// let page = VirtAddr(0xdead_0000)
    /// let entry = page.offset(0x1234)
    /// assert!(entry.0 == 0xdead_1234)
    /// ```
    #[allow(dead_code)]
    #[must_use]
    pub const fn offset(self, offset: u64) -> VirtAddr {
        // encountered overflow panics here in debug builds. should be fine letting it overflow, no?
        // VirtAddr(self.0 + offset)
        VirtAddr(self.0.overflowing_add(offset).0)
    }

    /// Get the 4 page table indexes that this [`VirtAddr`] corresponds maps with when
    /// translating via a 4-level page table
    ///
    /// # Panics
    ///
    /// * If attempting to get `table_indexes` on an 8 bit system
    #[must_use]
    pub fn table_indexes(self) -> [usize; 4] {
        [
            ((self.0 >> 39) & 0x1ff).try_into().unwrap(),
            ((self.0 >> 30) & 0x1ff).try_into().unwrap(),
            ((self.0 >> 21) & 0x1ff).try_into().unwrap(),
            ((self.0 >> 12) & 0x1ff).try_into().unwrap(),
        ]
    }

    /// Return the page that contains this [`VirtAddr`]
    ///
    /// Example:
    ///
    /// ```
    /// let addr = VirtAddr(0xdead_1234)
    /// let page = addr.page()
    /// assert!(page.0 == 0xdead_1000)
    /// ```
    #[must_use]
    pub const fn page(self) -> VirtAddr {
        VirtAddr(self.0 & !0xfff)
    }
}

impl std::ops::Deref for VirtAddr {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::str::FromStr for VirtAddr {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let no_prefix = s.trim_start_matches("0x");

        // Attempt to parse the hex digit
        Ok(VirtAddr(u64::from_str_radix(no_prefix, 16)?))
    }
}

/// A wrapper around the cr3
#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct Cr3(pub u64);

impl std::ops::Deref for Cr3 {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Debug for VirtAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VirtAddr({:#x})", self.0)
    }
}

impl std::fmt::Debug for PhysAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PhysAddr({:#x})", self.0)
    }
}
