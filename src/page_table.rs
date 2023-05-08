//! Utilities to help walk an Intel 4-level page table

use crate::addrs::{PhysAddr, VirtAddr};
use core::ops::{Index, IndexMut};
use core::slice::{Iter, IterMut};

/// Various flags corresponding to a page table entry.
#[derive(Debug, Copy, Clone)]
#[allow(dead_code, clippy::struct_excessive_bools)]
pub struct EntryFlags {
    /// Set if this entry is present
    present: bool,

    /// Set if this entry is writable
    writable: bool,

    /// Set if this entry can be accessed from Ring 3
    user_permitted: bool,

    /// Set if this entry has `write-through` caching policy or unset if this entry has
    /// `write-back` caching policy
    write_through: bool,

    /// Set if this entry is `uncacheable`
    cache_disable: bool,

    /// Set if this entry has been accessed
    accessed: bool,

    /// Set if this entry has been modified
    dirty: bool,

    /// Set if this entry is for an extended page size (For example, 1GB or 2MB)
    page_size: bool,

    /// Set if this entry is global (only applies when CR4.global is set)
    global: bool,

    /// Unused bit but can be used as a custom flag for implmentations
    bit_9: bool,

    /// Unused bit but can be used as a custom flag for implmentations
    bit_10: bool,

    /// Unused bit but can be used as a custom flag for implmentations
    bit_11: bool,

    /// Protection key for `Page Attribute Table`
    protection_key: u8,

    /// Set if execution is disabled for this entry
    execute_disable: bool,
}

impl EntryFlags {
    /// Returns `true` if the `present` bit is set in the [`EntryFlags`]
    pub fn present(&self) -> bool {
        self.present
    }

    /// Set the `present` bit in the [`EntryFlags`] to the given `present` flag
    pub fn set_present(&mut self, present: bool) {
        self.present = present;
    }

    /// Returns `true` if the `page_size` bit is set in the [`EntryFlags`]
    pub fn page_size(&self) -> bool {
        self.page_size
    }

    /// Returns `true` if the `writable` bit is set in the [`EntryFlags`]
    pub fn writable(&self) -> bool {
        self.writable
    }

    /// Returns `true` if the `execute_disable` bit is not set in the [`EntryFlags`]
    pub fn executable(&self) -> bool {
        !self.execute_disable
    }
}

impl From<Entry> for EntryFlags {
    #[inline]
    fn from(entry: Entry) -> Self {
        #[allow(clippy::cast_possible_truncation)]
        let protection_key = ((entry.0 >> 59) & 0xf) as u8;

        Self {
            present: entry.0 & (1 << 0) > 0,
            writable: entry.0 & (1 << 1) > 0,
            user_permitted: entry.0 & (1 << 2) > 0,
            write_through: entry.0 & (1 << 3) > 0,
            cache_disable: entry.0 & (1 << 4) > 0,
            accessed: entry.0 & (1 << 5) > 0,
            dirty: entry.0 & (1 << 6) > 0,
            page_size: entry.0 & (1 << 7) > 0,
            global: entry.0 & (1 << 8) > 0,
            bit_9: entry.0 & (1 << 9) > 0,
            bit_10: entry.0 & (1 << 10) > 0,
            bit_11: entry.0 & (1 << 11) > 0,
            execute_disable: entry.0 & (1 << 63) > 0,
            protection_key,
        }
    }
}

impl From<u64> for Entry {
    fn from(val: u64) -> Self {
        Self(val)
    }
}

/// A page table entry
#[derive(Debug, Copy, Clone)]
#[repr(transparent)]
pub struct Entry(pub u64);

impl Entry {
    /// Get the [`EntryFlags`] for this [`Entry`]
    #[inline]
    pub fn flags(self) -> EntryFlags {
        EntryFlags::from(self)
    }

    /// Get the [`PhysAddr`] address for this [`Entry`]
    #[inline]
    pub fn address(self) -> PhysAddr {
        PhysAddr(self.0 & 0x000f_ffff_ffff_f000)
    }

    /// Set the [`PhysAddr`] address for this [`Entry`]
    #[inline]
    pub fn set_address(&mut self, addr: PhysAddr) {
        // Clear the old address
        self.0 &= !0x000f_ffff_ffff_f000;

        // Set the new address
        self.0 |= addr.0 & !0xfff;
    }

    /// Set the present bit in the given entry
    pub fn set_present(&mut self) {
        self.0 |= 1 << 0;
    }

    /// Set the writable bit in the given entry
    pub fn set_writable(&mut self) {
        self.0 |= 1 << 1;
    }
}

/// A collection of 512 page table entries
#[derive(Debug)]
pub struct PageTable {
    /// The entries in the page table
    pub entries: [Entry; 512],
}

impl PageTable {
    /// Get a [`PageTable`] from the given `address`
    pub unsafe fn from_phys_addr(address: PhysAddr) -> &'static mut PageTable {
        // Cast the given `PhysAddr` into a pointer to the `PageTable`
        let table = address.0 as *mut PageTable;

        // Return a reference back to this table
        &mut *table
    }

    /// Get the starting address of this [`PageTable`]
    #[allow(dead_code)]
    pub fn start_address(&self) -> PhysAddr {
        PhysAddr(std::ptr::addr_of!(self[0]) as u64)
    }

    /// Get the [`PhysAddr`] of the entry at the given `index`.
    #[allow(dead_code)]
    pub fn entry_address(&self, index: usize) -> PhysAddr {
        assert!(index < 512, "Attempted to index page table out of bounds");

        // Get the address of the beginning of this table
        let table_start = self.start_address();

        // Add the offset to reach the given index
        table_start.offset((core::mem::size_of::<Entry>() * index) as u64)
    }

    /// Return an [`Iter`] of the internal array of [`Entry`]
    #[allow(dead_code)]
    pub fn iter(&self) -> Iter<Entry> {
        self.entries.iter()
    }

    /// Return an [`IterMut`] of the internal array of [`Entry`]
    #[allow(dead_code)]
    pub fn iter_mut(&mut self) -> IterMut<Entry> {
        self.entries.iter_mut()
    }
}

impl Index<usize> for PageTable {
    type Output = Entry;

    #[inline]
    fn index(&self, val: usize) -> &Self::Output {
        &self.entries[val]
    }
}

impl IndexMut<usize> for PageTable {
    #[inline]
    fn index_mut(&mut self, val: usize) -> &mut Self::Output {
        &mut self.entries[val]
    }
}

/// The result of a virtual address translation containing the page size and physical
/// address
#[derive(Debug)]
#[allow(dead_code)]
pub struct Translation {
    /// The virtual address for this translation
    virt_addr: VirtAddr,

    /// The physical address of the translation, if found
    phys_addr: Option<PhysAddr>,

    /// The size of the translation page
    pub page_size: Option<PageSize>,

    /// [`Permissions`] for this entry
    perms: Permissions,

    /// Intermediate physical addresses and their entries for the page table walk
    pub entries: [Option<(u64, Entry)>; 4],
}

impl Translation {
    /// Create a new [`Translation`] for the [`VirtAddr`]
    pub fn new(
        virt_addr: VirtAddr,
        phys_addr: PhysAddr,
        page_size: PageSize,
        perms: Permissions,
        entries: [Option<(u64, Entry)>; 4],
    ) -> Self {
        Self {
            virt_addr,
            phys_addr: Some(phys_addr),
            page_size: Some(page_size),
            perms,
            entries,
        }
    }

    /// Create a new [`Translation`] for the [`VirtAddr`] if that address is not present
    /// in the page table
    pub fn new_not_present(virt_addr: VirtAddr) -> Self {
        Self {
            virt_addr,
            phys_addr: None,
            page_size: None,
            perms: Permissions {
                readable: false,
                writable: false,
                executable: false,
            },
            entries: [None; 4],
        }
    }

    /// Get the [`PhysAddr`] for this translation
    pub fn phys_addr(&self) -> Option<PhysAddr> {
        self.phys_addr
    }
}

/// The size of the memory containing the translated address
#[derive(Debug, Copy, Clone)]
pub enum PageSize {
    /// A page with 512 gigabytes (512Gib)
    Size512G,

    /// A page with 2 megabytes (2MiB)
    Size2M,

    /// A page with 4 kilobytes (4KiB)
    Size4K,
}

/// The permissions for a translated address
#[derive(Debug, Copy, Clone)]
#[allow(dead_code)]
pub struct Permissions {
    /// The page is readable
    readable: bool,

    /// The page is writable
    writable: bool,

    /// The page is executable
    executable: bool,
}

impl Permissions {
    /// Get a read-only [`Permissions`]
    pub fn read_only() -> Self {
        Self {
            readable: true,
            writable: false,
            executable: false,
        }
    }

    /// Get the writable flag
    #[inline]
    #[allow(dead_code)]
    pub fn writable(&mut self) -> bool {
        self.writable
    }

    /// Set the writable flag with the given `writable` flag
    #[inline]
    pub fn set_writable(&mut self, writable: bool) {
        self.writable = writable;
    }

    /// Set the executable flag with the given `executable` flag
    #[inline]
    pub fn set_executable(&mut self, executable: bool) {
        self.executable = executable;
    }
}
