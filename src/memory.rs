//! Utilities to read/write data from a project

use anyhow::{anyhow, ensure, Context, Result};
// use thiserror::Error;
use iced_x86::{Decoder, DecoderOptions, FastFormatter, Instruction};

use crate::addrs::{Cr3, PhysAddr, VirtAddr};
use crate::cmdline::ProjectState;
use crate::fuzzvm::{GuestPhysAddr, APIC_BASE};
use crate::page_table::{PageSize, PageTable, Permissions, Translation};

use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::mem::size_of;
use std::os::unix::io::AsRawFd;

/// Address to start the custom physical page allocations
const START_CUSTOM_MAPPING: PhysAddr = PhysAddr(0x1000_0000);

/// Small wrapper around basic functions to manipulate a project
pub struct Memory {
    /// Address to the memory backing
    memory_backing: u64,

    /// Size of this memory backing
    size: u64,

    /// Pages that have been dirtied by writes
    pub dirty_pages: BTreeSet<PhysAddr>,

    /// Re-usable allocation for determining page boundaries during read/write
    temp_page_boundaries: Option<Vec<(VirtAddr, u64)>>,

    /// Physical addresses used by the snapshot. Used if we need to map new addresses
    /// into the snapshot.
    ///
    /// Populated by walking a set of page tables. Could miss used physical pages that
    /// are used in page tables that we don't yet know about.
    pub used_phys_pages: BTreeSet<PhysAddr>,

    /// Original next available physical address to allocate. `.next_avail_phys_page` is
    /// restored to this address on each reset.
    pub orig_next_avail_phys_page: Option<PhysAddr>,

    /// Next available physical address to allocate
    pub next_avail_phys_page: Option<PhysAddr>,
}

impl Drop for Memory {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.memory_backing as *mut libc::c_void, self.size as usize);
        }
    }
}

/// Custom errors [`FuzzVm`](crate::fuzzvm::FuzzVm) can throw
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Attempted to write to an unmapped virtual address
    #[error("WriteToUnmappedVirtualAddress_{0:x?}_{1:x?}_{2:#x}")]
    WriteToUnmappedVirtualAddress(VirtAddr, Cr3, usize),

    /// Attempted to read from an unmapped virtual address
    #[error("ReadFromUnmappedVirtualAddress_{0:x?}_{1:x?}")]
    ReadFromUnmappedVirtualAddress(VirtAddr, Cr3),

    /// Attempted to read out of bounds of the physical memory
    #[error("ReadPhysicalAddressOutOfBounds")]
    ReadPhysicalAddressOutOfBounds,

    /// Attempted to write out of bounds of the physical memory
    #[error("WritePhysicalAddressOutOfBounds")]
    WritePhysicalAddressOutOfBounds,

    /// Reading a virtual address causes an overflow of the address space
    #[error("Reading a virtual address causes an overflow of the address space")]
    ReadOverflow,

    /// Attempted to read from APIC
    #[error("Atempted to read from APIC")]
    ReadFromApic,

    /// Attempted to write past the page boundary
    #[error("WritePastPageBoundary_{0:x?}_{1:x?}")]
    WritePastPageBoundary(VirtAddr, Cr3),

    /// Attempted to translate a large page at page index 0
    #[error("LargePageAtPage0")]
    LargePageAtPage0,

    /// Temporary page boundaries is not set. This can happen if we `.take()` from
    /// `.temp_page_boundaries` and do not restore the variable
    #[error("Temporary page boundaries is not set. This can happen if we `.take()` from `.temp_page_boundaries` and do not restore the variable")]
    TempPageBoundariesIsNone,

    /// A page boundary was found to not be page aligned
    #[error("A page boundary was found to not be page aligned")]
    PageBoundaryNotAligned,

    /// Byte not found for read_byte_until
    #[error("Byte not found for read_byte_until")]
    ByteNotFound,
}

/// Various values that can be discovered during a pointer chain walk
pub enum ChainVal {
    /// A valid address that was able to be dereferenced
    Address(u64),

    /// A UTF-8 string
    Utf8(String),

    /// Some number that was not identified as anything else
    Number(u64),
}

impl std::fmt::Display for ChainVal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainVal::Address(val) | ChainVal::Number(val) => {
                write!(f, "{val:#x}")
            }
            ChainVal::Utf8(s) => write!(f, "'{s}'"),
        }
    }
}

impl ProjectState {
    /// Open the physical memory as writable to make changes
    ///
    /// # Errors
    ///
    /// * Fail to open physical memory file
    pub fn memory(&self) -> Result<Memory> {
        // Open the physical memory backing for this snapshot
        let physmem_file = OpenOptions::new()
            .write(true)
            .read(true)
            .open(&self.physical_memory)?;

        // Ensure the expected guest memory size can fit on this system
        let guest_memory_size: usize = self.config.guest_memory_size.try_into()?;

        // Create the memory backing from the file descriptor as RW
        let mem_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                guest_memory_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                physmem_file.as_raw_fd(),
                0,
            )
        };

        unsafe {
            libc::madvise(mem_ptr, guest_memory_size, libc::MADV_MERGEABLE);
        }

        log::info!(
            "Open memory backing: {:#x}..{:#x}",
            mem_ptr as u64,
            mem_ptr as u64 + guest_memory_size as u64
        );

        Ok(Memory {
            memory_backing: mem_ptr as u64,
            size: guest_memory_size as u64,
            dirty_pages: BTreeSet::new(),
            temp_page_boundaries: Some(Vec::new()),
            used_phys_pages: BTreeSet::new(),
            orig_next_avail_phys_page: None,
            next_avail_phys_page: None,
        })
    }
}

/// Determines if a write should add the written physical pages to the dirty list
pub enum WriteMem {
    /// The write for this memory should add the physical page to the dirty list
    Dirty,

    /// The write for this memory should not add the physical page to the dirty list
    NotDirty,
}

impl Memory {
    /// Create a `Memory` from the given backing
    #[must_use]
    pub fn from_addr(memory_backing: u64, size: u64) -> Self {
        Self {
            memory_backing,
            size,
            dirty_pages: BTreeSet::new(),
            temp_page_boundaries: Some(Vec::new()),
            used_phys_pages: BTreeSet::new(),
            orig_next_avail_phys_page: None,
            next_avail_phys_page: None,
        }
    }

    /// Create a `Memory` from an existing file descriptor
    #[must_use]
    pub fn from_fd(snapshot_fd: i32, guest_memory_size: u64) -> Result<Self> {
        // Create the memory backing from the file descriptor
        let mem_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                guest_memory_size as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE,
                snapshot_fd,
                0,
            )
        };

        // If mmap fails, return an error
        if mem_ptr as usize == usize::MAX {
            return Err(anyhow::anyhow!("mmap failed"));
        }

        unsafe {
            libc::madvise(mem_ptr, guest_memory_size as usize, libc::MADV_MERGEABLE);
        }

        Ok(Memory::from_addr(mem_ptr as u64, guest_memory_size as u64))
    }

    /// Get the underlying backing address
    #[must_use]
    pub fn backing(&self) -> u64 {
        self.memory_backing
    }

    /// Get the underlying backing address
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Get a translation from the opened memory
    ///
    /// # Panics
    ///
    /// * Invalid page size found during translation
    #[must_use]
    pub fn translate(&self, virt_addr: VirtAddr, cr3: Cr3) -> Translation {
        let page_table = GuestPhysAddr((cr3.0 & !0xfff) + self.memory_backing);

        // Get the page table pointed to by cr3
        //
        // UNSAFE: The given `cr3` could not actually point to a valid page table
        let mut curr_table = unsafe { PageTable::from_phys_addr(PhysAddr(page_table.0)) };

        // Permissions for the current page table entry
        let mut perms = Permissions::read_only();

        // Get the offsets into the table for each page table level
        //
        // Each offset is 9 bits
        // VirtAddr: 0baaaa_aaaa_abbb_bbbb_bbcc_cccc_cccd_dddd_dddd_0000_0000_0000
        //             [Lvl1index][Lvl2index][Lvl3index][Lvl4index]
        let table_indexes = virt_addr.table_indexes();

        // log::info!("{:#x}: Indexes: {:x?}\n", virt_addr.0, table_indexes);

        // Init intermediate translation entries
        let mut entries = [None; 4];

        // Init the final physical address found during the table walk
        let mut final_phys_addr = None;

        let mut next_table_address;

        for (level, index) in table_indexes.iter().enumerate() {
            // Get the page table entry at the given index
            let entry = curr_table[*index];

            // Cache the entry found at the current level
            let entry_addr =
                std::ptr::addr_of!(curr_table.entries) as u64 + (index * size_of::<u64>()) as u64;

            entries[level] = Some((entry_addr, entry));

            // Get the flags for this entry
            let flags = entry.flags();

            // Update the permissions for the page table entry
            perms.set_writable(flags.writable());
            perms.set_executable(flags.executable());

            // Return the current translation if this entry is not present
            if !flags.present() {
                return Translation::new_not_present(virt_addr);
            }

            next_table_address = entry.address().offset(self.memory_backing);

            if flags.page_size() {
                let (page_size, offset) = match level {
                    1 => {
                        // 512 GiB page found
                        let offset = virt_addr.0 & (512 * 1024 * 1024 * 1024 - 1);
                        (PageSize::Size512G, offset)
                    }
                    2 => {
                        // 2 MiB page found
                        let offset = virt_addr.0 & (2 * 1024 * 1024 - 1);
                        (PageSize::Size2M, offset)
                    }
                    3 => panic!("Page size bit set at 4k page?"),
                    level => panic!("Page size bit set at level {level} page?"),
                };

                let res = Translation::new(
                    virt_addr,
                    entry.address().offset(offset),
                    page_size,
                    perms,
                    entries,
                );

                // Return large page found
                return res;
            }

            // Update the next page table using the address from the current entry
            curr_table = unsafe { PageTable::from_phys_addr(next_table_address) };

            // Set the address for the final page when found. This is the physical
            // address, not the address into the memory backing
            final_phys_addr = Some(entry.address());
        }

        // Get the offset into the 4k page for the requested virtual address
        let offset = virt_addr.0 & (4 * 1024 - 1);

        if let Some(final_phys_addr) = final_phys_addr {
            // Return successful translation
            Translation::new(
                virt_addr,
                final_phys_addr.offset(offset),
                PageSize::Size4K,
                perms,
                entries,
            )
        } else {
            unreachable!("Final phys address was None?!")
        }
    }

    /// Set the internal used physical pages using the list of [`Cr3`]s given
    pub fn identify_used_phys_pages(&mut self, cr3s: &[Cr3]) {
        for &cr3 in cr3s.iter() {
            let mut new_addrs = self.used_phys_pages(cr3);
            self.used_phys_pages.append(&mut new_addrs);
        }

        let mut found = START_CUSTOM_MAPPING;

        // Starting at `START_CUSTOM_MAPPING`, look for the next available page
        loop {
            if !self.used_phys_pages.contains(&found) {
                break;
            }

            found = found.offset(0x1000);
        }

        // Set the first available physical page
        self.orig_next_avail_phys_page = Some(found);

        // Set the first available physical page
        self.next_avail_phys_page = Some(found);
    }

    /// Allocate an unused physical page
    ///
    /// # Panics
    ///
    /// * Attempted to allocate a physical page without calling
    ///   `memory.identify_used_phys_pages`.
    pub fn allocate_phys_page(&mut self) -> PhysAddr {
        if let Some(phys_page) = self.next_avail_phys_page {
            let mut found = phys_page.offset(0x1000);

            // Starting at `START_CUSTOM_MAPPING`, look for the next available page
            loop {
                if !self.used_phys_pages.contains(&found) {
                    break;
                }

                found = found.offset(0x1000);
            }

            // Set the next available physical page allocation
            self.next_avail_phys_page = Some(found);

            // Return the valid physical page
            phys_page
        } else {
            panic!(
                "Cannot allocate physical pages until physical pages are identified. \
                    Call memory.identify_used_phys_pages"
            );
        }
    }

    /// Map a physical page at the given [`VirtAddr`] in the given [`Cr3`]
    #[allow(dead_code)]
    pub fn map_virt_addr_4k(&mut self, virt_addr: VirtAddr, cr3: Cr3) {
        // Check the current translation of the given address
        let translation = self.translate(virt_addr, cr3);

        // Check if the mapping already exists.
        if translation.phys_addr().is_some() {
            return;
        }

        let page_table = GuestPhysAddr((cr3.0 & !0xfff) + self.memory_backing);

        // Get the page table pointed to by cr3
        //
        // UNSAFE: The given `cr3` could not actually point to a valid page table
        let mut curr_table = unsafe { PageTable::from_phys_addr(PhysAddr(page_table.0)) };

        // Permissions for the current page table entry
        let mut perms = Permissions::read_only();

        // Get the offsets into the table for each page table level
        //
        // Each offset is 9 bits
        // VirtAddr: 0baaaa_aaaa_abbb_bbbb_bbcc_cccc_cccd_dddd_dddd_0000_0000_0000
        //             [Lvl1index][Lvl2index][Lvl3index][Lvl4index]
        let mut table_indexes = virt_addr.table_indexes();

        for (_level, index) in table_indexes.iter_mut().enumerate() {
            // Get the page table entry at the given index
            let entry = &mut curr_table[*index];

            // Get the flags for this entry
            let flags = entry.flags();

            // Update the permissions for the page table entry
            perms.set_writable(flags.writable());
            perms.set_executable(flags.executable());

            // Get the physical address of the next table or allocate a new page if
            // needed
            if !flags.present() {
                // Allocate a physical page from the found "unused" pages
                let new_page = self.allocate_phys_page();

                // Set the entry to the allocated phys page
                entry.set_address(new_page);

                // Set this entry as now present and writable
                entry.set_present();
                entry.set_writable();

                let new_page = entry.address().offset(self.memory_backing).0;

                // Clear the allocated page
                unsafe {
                    *(new_page as *mut [u8; 0x1000]) = [0; 0x1000];
                }
            }

            let next_table_address = entry.address().offset(self.memory_backing);

            // Update the next page table using the address from the current entry
            curr_table = unsafe { PageTable::from_phys_addr(next_table_address) };
        }
    }

    /// Get all of the physical pages used by the given [`Cr3`]
    fn used_phys_pages(&mut self, cr3: Cr3) -> BTreeSet<PhysAddr> {
        // Init the used physical pages with only the `cr3`
        let mut addrs = BTreeSet::new();

        // List of addresses that still need to be checkd
        let mut addrs_to_check = vec![(0, PhysAddr(cr3.0))];

        // Loop through all found page tables looking for present pages
        while let Some((table_index, table_addr)) = addrs_to_check.pop() {
            // Read the current page table address as a `PageTable`
            let page_table = PhysAddr((table_addr.0 & !0xfff) + self.memory_backing);
            let curr_table = unsafe { PageTable::from_phys_addr(page_table) };

            // Iterate over the current page table looking for present pages
            for entry in curr_table.iter() {
                // Get the flags for this entry
                let flags = entry.flags();

                // Ignore entries that aren't present
                if !flags.present() {
                    continue;
                }

                // Add the found table address to the list of physical addresses
                let found_table = entry.address();

                // Attempt to add the next physical address into the list of found
                // addresses. If it was already found, continue
                if !addrs.insert(found_table) {
                    continue;
                }

                // If we aren't at the end of the 4 page walk, add the found physical
                // page to walk during another iteration
                if table_index < 3 {
                    addrs_to_check.push((table_index + 1, found_table));
                }
            }
        }

        // Return the found list of addresses
        addrs
    }

    /// Read bytes from the [`PhysAddr`] into the given `buf`
    ///
    /// # Errors
    ///
    /// * The given physical address is out of bounds of the allocated physical memory
    pub fn read_phys_bytes<T: Copy>(&mut self, phys_addr: PhysAddr, buf: &mut [T]) -> Result<()> {
        if let Some(last_addr) = phys_addr.0.checked_add(buf.len() as u64) {
            ensure!(
                last_addr <= self.memory_backing + self.size as u64,
                Error::ReadPhysicalAddressOutOfBounds
            );

            let end_addr = phys_addr.offset(buf.len() as u64);

            if (end_addr.0 & 0xfff) != 0 && end_addr.page() != phys_addr.page() {
                log::warn!(
                    "Attempted to read across the physical page boundary: {:#x} {:#x}",
                    phys_addr.0,
                    buf.len()
                );
            }

            // Calculate the address into the memory backing for this read
            let memory_addr = self.memory_backing + phys_addr.0;

            // Read the requested bytes from the physical memory backing
            let bytes = unsafe { std::slice::from_raw_parts(memory_addr as *const T, buf.len()) };

            // Write the result into the given `buf`
            buf.copy_from_slice(bytes);

            // Return successs
            Ok(())
        } else {
            // Would attempt to read out of bounds
            Err(Error::ReadPhysicalAddressOutOfBounds.into())
        }
    }

    /// Read a `T` from the given guest [`PhysAddr`]
    ///
    /// # Errors
    ///
    /// * If the given physical address is out of bounds of the allocated physical memory
    #[allow(dead_code)]
    pub fn read_phys<T: Sized>(&self, phys_addr: PhysAddr) -> Result<T> {
        if (APIC_BASE..APIC_BASE + 0x1000).contains(&phys_addr.0) {
            log::info!("Reading from APIC. Setting to 0 for now...");
            return Err(Error::ReadFromApic.into());
        }

        if let Some(last_addr) = phys_addr.0.checked_add(std::mem::size_of::<T>() as u64) {
            ensure!(
                last_addr <= self.memory_backing + self.size as u64,
                Error::ReadPhysicalAddressOutOfBounds
            );

            // Calculate the address into the memory backing for this read
            let memory_addr = self.memory_backing + phys_addr.0;

            // Read the requested value
            let res = unsafe { std::ptr::read_unaligned(memory_addr as *const T) };

            Ok(res)
        } else {
            // Would attempt to read out of bounds
            Err(Error::ReadPhysicalAddressOutOfBounds.into())
        }
    }

    /// Read a single byte from the given [`VirtAddr`] using the [`Cr3`] page table
    ///
    /// # Errors
    ///
    /// * Read from an unmapped virtual address
    pub fn read_byte(&self, virt_addr: VirtAddr, cr3: Cr3) -> Result<u8> {
        let cr3 = Cr3(cr3.0 & !0xfff);

        // Get the size of the T for this read
        let ret_size = 1;

        // Ensure the read won't overflow the address space
        ensure!(
            virt_addr.0.checked_add(ret_size as u64).is_some(),
            Error::ReadOverflow
        );

        // Translate the virtual address to physical address
        let translation = self.translate(virt_addr, cr3);

        // Get the physical address from this translation
        let phys_addr = translation
            .phys_addr()
            .context(Error::ReadFromUnmappedVirtualAddress(virt_addr, cr3))?;

        // Read the requested type from the translated physical address
        Ok(self.read_phys(phys_addr)?)
    }

    /// Read the requested type from the given [`VirtAddr`] using the [`Cr3`] page table
    ///
    /// # Errors
    ///
    /// * Read from an unmapped virtual address
    ///
    /// # Panics
    ///
    /// * If the `size_of::<T>` cannot fit in a `u64`
    pub fn read<T: Sized>(&mut self, virt_addr: VirtAddr, cr3: Cr3) -> Result<T> {
        let cr3 = Cr3(cr3.0 & !0xfff);

        // Get the size of the T for this read
        let ret_size = std::mem::size_of::<T>();

        // Ensure the read won't overflow the address space
        ensure!(
            virt_addr.0.checked_add(ret_size as u64).is_some(),
            Error::ReadOverflow
        );

        // Check if this read will straddle a page boundary
        self.set_page_boundaries(virt_addr, u64::try_from(ret_size).unwrap())?;

        let page_boundaries = self.temp_page_boundaries.take().unwrap();

        // Base case here. Not page straddling, no need to allocate and concat bytes from
        // different physical pages
        let ret: T = if page_boundaries.len() == 1 {
            let (virt_addr, _) = page_boundaries[0];

            // Translate the virtual address to physical address
            let translation = self.translate(virt_addr, cr3);

            // Get the physical address from this translation
            let phys_addr = translation
                .phys_addr()
                .context(Error::ReadFromUnmappedVirtualAddress(virt_addr, cr3))?;

            // Read the requested type from the translated physical address
            self.read_phys(phys_addr)?
        } else {
            let mut res = vec![0_u8; ret_size];

            let mut offset = 0_usize;

            for (virt_addr, size) in &page_boundaries {
                let virt_addr = *virt_addr;

                // Translate the virtual address to physical address
                let translation = self.translate(virt_addr, cr3);

                // Get the physical address from this translation
                let phys_addr = translation
                    .phys_addr()
                    .context(Error::ReadFromUnmappedVirtualAddress(virt_addr, cr3))?;

                let size = usize::try_from(*size).unwrap();

                // Read the requested type from the translated physical address
                self.read_phys_bytes(phys_addr, &mut res[offset..offset + size])?;

                // Increase the offset into the output buffer
                offset += size;
            }

            unsafe { std::ptr::read_unaligned(res.as_ptr().cast::<T>()) }
        };

        self.temp_page_boundaries = Some(page_boundaries);

        Ok(ret)
    }

    /// Read bytes from the [`VirtAddr`] translating using [`Cr3`] into the given `buf`
    ///
    /// # Errors
    ///
    /// * Read from an unmapped virtual address
    ///
    /// # Panics
    ///
    /// * If the `size_of::<T>` cannot fit in a `u64`
    pub fn read_bytes<T: Copy>(
        &mut self,
        virt_addr: VirtAddr,
        cr3: Cr3,
        buf: &mut [T],
    ) -> Result<()> {
        // Get the amount of bytes to read
        // let read_size = buf.len() * std::mem::size_of::<T>();
        let read_size = std::mem::size_of_val(buf);

        // Check if this read will straddle a page boundary
        self.set_page_boundaries(virt_addr, u64::try_from(read_size).unwrap())?;

        // Get the page boundaries out
        let page_boundaries = self.temp_page_boundaries.take().unwrap();

        if page_boundaries.len() == 1 {
            let (virt_addr, _) = page_boundaries[0];

            // Translate the virtual address to physical address
            let translation = self.translate(virt_addr, cr3);

            // Get the physical address from this translation
            let phys_addr = translation
                .phys_addr()
                .ok_or(Error::ReadFromUnmappedVirtualAddress(virt_addr, cr3))?;

            // Read the translated physical address into the given buf
            self.read_phys_bytes(phys_addr, buf)?;

            // Put the page boundaries back
            self.temp_page_boundaries = Some(page_boundaries);
            // Return from the base case
            return Ok(());
        }

        let mut offset = 0_usize;

        for (virt_addr, size) in &page_boundaries {
            // Translate the virtual address to physical address
            let translation = self.translate(*virt_addr, cr3);

            let size = usize::try_from(*size).unwrap();

            assert!(size % std::mem::size_of::<T>() == 0);

            let num_elems = size / std::mem::size_of::<T>();

            // Get the physical address from this translation
            let phys_addr = translation
                .phys_addr()
                .ok_or(Error::ReadFromUnmappedVirtualAddress(*virt_addr, cr3))?;

            // Read the translated physical address into the given buf
            self.read_phys_bytes(phys_addr, &mut buf[offset..offset + num_elems])?;

            offset += num_elems;
        }

        // Put the page boundaries back
        self.temp_page_boundaries = Some(page_boundaries);

        Ok(())
    }

    /// Write the requested type from the given [`VirtAddr`] using the [`Cr3`] page table
    ///
    /// # Errors
    ///
    /// * Attempted to write past page boundary
    ///
    /// # Panics
    ///
    /// * If the `size_if::<T>` cannot fit in a `u64`
    #[allow(clippy::needless_pass_by_value)]
    pub fn write<T: Sized>(
        &mut self,
        virt_addr: VirtAddr,
        cr3: Cr3,
        val: T,
        dirty: WriteMem,
    ) -> Result<()> {
        let cr3 = Cr3(cr3.0 & !0xfff);

        // Get the size of the T for this read
        let ret_size = std::mem::size_of::<T>();

        // Check if this read will straddle a page boundary
        self.set_page_boundaries(virt_addr, u64::try_from(ret_size).unwrap())?;

        let page_boundaries = self.temp_page_boundaries.take().unwrap();

        // Base case here. Not page straddling, no need to allocate and concat bytes from
        // different physical pages
        if page_boundaries.len() == 1 {
            let (virt_addr, _) = page_boundaries[0];

            // Translate the virtual address to physical address
            let translation = self.translate(virt_addr, cr3);

            // Get the physical address from this translation
            let phys_addr =
                translation
                    .phys_addr()
                    .context(Error::WriteToUnmappedVirtualAddress(
                        virt_addr,
                        cr3,
                        0xdead_beef,
                    ))?;

            if matches!(dirty, WriteMem::Dirty) {
                // Dirty the physical page
                self.dirty_pages.insert(phys_addr.page());
            }

            // Write the requested type from the translated physical address
            self.write_phys::<T>(phys_addr, val)
        } else {
            Err(anyhow!(Error::WritePastPageBoundary(virt_addr, cr3)))

            /*
            let mut offset = 0_usize;

            for (virt_addr, size) in &page_boundaries {
                let virt_addr = *virt_addr;

                // Translate the virtual address to physical address
                let translation = self.translate(virt_addr, cr3);

                // Get the physical address from this translation
                let phys_addr = translation.phys_addr()
                    .context(Error::WriteToUnmappedVirtualAddress(virt_addr, cr3))?;

                let size = usize::try_from(*size).unwrap();

                // Read the requested type from the translated physical address
                self.write_phys_bytes(phys_addr, &mut val[offset..offset + size])?;

                // Increase the offset into the output buffer
                offset += size;

            }

            Ok(())
            */
        }
    }

    /// Write a given value to the given guest [`PhysAddr`]
    ///
    /// # Errors
    ///
    /// * If the given physical address is out of bounds of the allocated physical memory
    #[allow(dead_code)]
    pub fn write_phys<T: Sized>(&mut self, phys_addr: PhysAddr, val: T) -> Result<()> {
        if let Some(last_addr) = phys_addr.0.checked_add(std::mem::size_of::<T>() as u64) {
            ensure!(
                last_addr <= self.size,
                Error::WritePhysicalAddressOutOfBounds
            );

            // Calculate the address into the memory backing for this read
            let memory_addr = self.memory_backing + phys_addr.0;

            // Write the requested value
            unsafe {
                std::ptr::write_unaligned(memory_addr as *mut T, val);
            }

            Ok(())
        } else {
            Err(Error::WritePhysicalAddressOutOfBounds.into())
        }
    }

    /// Write the bytes in `buf` to the [`PhysAddr`]
    ///
    /// # Errors
    ///
    /// * Write to an unmapped virtual address
    /// * Translated physical address is outside the bounds of guest memory
    pub fn write_phys_bytes(&mut self, phys_addr: PhysAddr, buf: &[u8]) -> Result<()> {
        if let Some(last_addr) = phys_addr.0.checked_add(buf.len() as u64) {
            ensure!(
                last_addr <= self.size,
                Error::WritePhysicalAddressOutOfBounds
            );

            // Calculate the address into the memory backing for this read
            let memory_addr = self.memory_backing + phys_addr.0;

            // Read the requested bytes from the physical memory backing
            let bytes =
                unsafe { std::slice::from_raw_parts_mut(memory_addr as *mut u8, buf.len()) };

            // Write given buf into the slice at the physical address
            bytes.copy_from_slice(buf);

            // Return successs
            Ok(())
        } else {
            Err(Error::WritePhysicalAddressOutOfBounds.into())
        }
    }

    /// Write bytes in `buf` to the [`VirtAddr`] translating using [`Cr3`]
    ///
    /// # Errors
    ///
    /// * Write to an unmapped virtual address
    /// * The tranlated physical address is outside the bounds of guest memory
    ///
    /// # Panics
    ///
    /// * If the `size_if::<T>` cannot fit in a `u64`
    pub fn write_bytes(&mut self, virt_addr: VirtAddr, cr3: Cr3, buf: &[u8]) -> Result<()> {
        // Check if this write will straddle a page boundary
        self.set_page_boundaries(virt_addr, u64::try_from(buf.len()).unwrap())?;

        // Get the page found page boundaries to enable &mut self
        let page_boundaries = self.temp_page_boundaries.take().unwrap();

        // Base case here. Not page straddling, no need to write bytes across multiple
        // pages
        if page_boundaries.len() == 1 {
            let (virt_addr, _) = page_boundaries[0];

            // Translate the virtual address to physical address
            let translation = self.translate(virt_addr, cr3);

            let phys_addr = translation
                .phys_addr()
                .ok_or(Error::WriteToUnmappedVirtualAddress(
                    virt_addr,
                    cr3,
                    buf.len(),
                ))?;

            // Read the translated physical address into the given buf
            self.write_phys_bytes(phys_addr, buf)?;
            // Put the page boundaries back and early return
            self.temp_page_boundaries = Some(page_boundaries);
            return Ok(());
        }

        // Offset into the input buffer
        let mut offset = 0_usize;

        for (virt_addr, size) in &page_boundaries {
            // Translate the virtual address to physical address
            let translation = self.translate(*virt_addr, cr3);

            let phys_addr = translation
                .phys_addr()
                .ok_or(Error::WriteToUnmappedVirtualAddress(
                    *virt_addr,
                    cr3,
                    buf.len(),
                ))?;

            let size = usize::try_from(*size).unwrap();

            // Read the translated physical address into the given buf
            self.write_phys_bytes(phys_addr, &buf[offset..offset + size])?;

            // Update the size
            offset += size;
        }

        // Put the page boundaries allocation back
        self.temp_page_boundaries = Some(page_boundaries);

        Ok(())
    }

    /// Write bytes in `buf` to the [`VirtAddr`] translating using [`Cr3`] and mark each
    /// physical page written as dirty
    ///
    /// # Errors
    ///
    /// * Write to an unmapped virtual address
    /// * The tranlated physical address is outside the bounds of guest memory
    ///
    /// # Panics
    ///
    /// * If the size of a page boundary cannot fit in a `usize`
    pub fn write_bytes_dirty(&mut self, virt_addr: VirtAddr, cr3: Cr3, buf: &[u8]) -> Result<()> {
        // Check if this read will straddle a page boundary
        self.set_page_boundaries(virt_addr, u64::try_from(buf.len())?)?;

        // Get the page found page boundaries to enable &mut self
        let page_boundaries = self
            .temp_page_boundaries
            .take()
            .ok_or(Error::TempPageBoundariesIsNone)?;

        // Base case here. Not page straddling, no need to allocate and concat bytes from
        // different physical pages
        if page_boundaries.len() == 1 {
            let (virt_addr, _) = page_boundaries[0];

            // Translate the virtual address to physical address
            let translation = self.translate(virt_addr, cr3);

            let phys_addr = translation
                .phys_addr()
                .ok_or(Error::WriteToUnmappedVirtualAddress(
                    virt_addr,
                    cr3,
                    0x3333_0000_0000_0000 + buf.len(),
                ))?;

            // Read the translated physical address into the given buf
            self.write_phys_bytes(phys_addr, buf)?;

            // Dirty the physical page
            self.dirty_pages.insert(phys_addr.page());
            // Put the page boundaries allocation back and early return.
            self.temp_page_boundaries = Some(page_boundaries);
            return Ok(());
        }

        // Offset into the input buffer
        let mut offset = 0_usize;

        for (virt_addr, size) in &page_boundaries {
            // Translate the virtual address to physical address
            let translation = self.translate(*virt_addr, cr3);

            let phys_addr = translation
                .phys_addr()
                .ok_or(Error::WriteToUnmappedVirtualAddress(
                    *virt_addr,
                    cr3,
                    0x4444_0000_0000_0000 + offset,
                ))?;

            let size = usize::try_from(*size).unwrap();

            // Read the translated physical address into the given buf
            self.write_phys_bytes(phys_addr, &buf[offset..offset + size])?;

            // Dirty the physical page
            self.dirty_pages.insert(phys_addr.page());

            // Update the size
            offset += size;
        }

        // Put the page boundaries allocation back
        self.temp_page_boundaries = Some(page_boundaries);

        Ok(())
    }

    /// Get the [`Instruction`] at the given instruction pointer using the given [`Cr3`]
    ///
    /// # Errors
    ///
    /// * Error during `read` of the given `virt_addr`
    pub fn get_instruction_at(&mut self, virt_addr: VirtAddr, cr3: Cr3) -> Result<Instruction> {
        // Create an empty instruction
        let mut instr = Instruction::default();

        // Init the array to read the instruction bytes into
        let bytes: [u8; 0x10] = self.read(virt_addr, cr3)?;

        // Decode the instruction assuming 64-bits
        let mut decoder = Decoder::new(64, &bytes, DecoderOptions::NONE);
        decoder.decode_out(&mut instr);

        // Return the result
        Ok(instr)
    }

    /// Print the [`Instruction`] at the given [`VirtAddr`] using the given [`Cr3`]
    ///
    /// # Errors
    ///
    /// * If getting the current instruction at `virt_addr` fails
    pub fn get_instruction_string_at(
        &mut self,
        virt_addr: VirtAddr,
        cr3: Cr3,
    ) -> Result<(String, Instruction)> {
        // Get the instruction at virt_addr
        let instr = self.get_instruction_at(virt_addr, cr3)?;

        // Create the string to write the decoded instruction into
        let mut output = String::new();

        // Create the formatter
        let mut formatter = FastFormatter::new();
        formatter.options_mut().set_uppercase_hex(false);
        formatter.options_mut().set_use_hex_prefix(true);
        formatter.options_mut().set_always_show_memory_size(true);
        formatter
            .options_mut()
            .set_space_after_operand_separator(true);
        formatter.options_mut().set_rip_relative_addresses(true);

        // Format the instruction into the output
        formatter.format(&instr, &mut output);

        // Return result
        Ok((output, instr))
    }

    /// Return the slice from [`VirtAddr`] of `size` bytes split between page boundaries.
    /// This is useful since virtual addresses that go across page boundaries are not
    /// necessarily guarenteed to be contiguous physically.
    ///
    /// # Errors
    ///
    /// * Found page boundary is not page aligned
    #[allow(dead_code)]
    #[allow(clippy::verbose_bit_mask)]
    pub fn set_page_boundaries(&mut self, virt_addr: VirtAddr, mut size: u64) -> Result<()> {
        // Get the page boundaries out of the Option
        let mut page_boundaries = self.temp_page_boundaries.take().unwrap_or_default();

        // Clear the buffer used to place the page boundaries
        page_boundaries.clear();

        // Allocation does split the page boundary, allocation needed to figure out the
        // correct sizes
        let mut curr_addr = virt_addr;

        let bytes_to_end_of_page = 0x1000 - (curr_addr.0 & 0xfff);

        let first_size = std::cmp::min(bytes_to_end_of_page, size);
        page_boundaries.push((virt_addr, first_size));

        // The read fits in the first page, no need to look for further pages
        if bytes_to_end_of_page >= size {
            // Restore the page boundaries
            self.temp_page_boundaries = Some(page_boundaries);

            // Fast return out
            return Ok(());
        }

        // Update the current address to the next page
        curr_addr = curr_addr.offset(first_size);

        // Update the remaining bytes left to chunk
        size -= first_size;

        ensure!(curr_addr.0 & 0xfff == 0, Error::PageBoundaryNotAligned);

        // At this point, every read address should be page aligned
        loop {
            let curr_size = if size > 0x1000 {
                // Get the number of bytes to the next page
                0x1000 - (curr_addr.0 & 0xfff)
            } else {
                size
            };

            page_boundaries.push((curr_addr, curr_size));

            // Update the current address to the next page
            curr_addr = curr_addr.offset(curr_size);

            // Update the remaining bytes left to chunk
            size -= curr_size;

            // If the remaining size fits in a page, then this is the last chunk
            if size <= 0x1000 {
                if size > 0 {
                    page_boundaries.push((curr_addr, size));
                }
                break;
            }
        }

        // Restore the page boundaries
        self.temp_page_boundaries = Some(page_boundaries);

        // Return success
        Ok(())
    }

    /// Print a hexdump of `count` bytes at the given [`VirtAddr`] [`Cr3`]
    ///
    /// # Errors
    ///
    /// * Failed to read `count` bytes from `virt_addr`
    pub fn hexdump(&mut self, virt_addr: VirtAddr, cr3: Cr3, count: usize) -> Result<()> {
        // Read the bytes at the given address
        let mut bytes = vec![0_u8; count];
        self.read_bytes(virt_addr, cr3, &mut bytes)?;

        // Print the bytes
        crate::utils::hexdump(&bytes, virt_addr.0);

        // Return success
        Ok(())
    }

    /// Attempt to perform a pointer walk from the given [`VirtAddr`] [`Cr3`]
    pub fn pointer_chain(&mut self, virt_addr: VirtAddr, cr3: Cr3) -> Vec<ChainVal> {
        // Init the res with no results
        let mut res = Vec::new();

        // Initialize the address to look for a pointer at the given address
        let mut curr_val = virt_addr;

        for index in 0..8 {
            // Attempt to read a `u64` from the current address. If one is found,
            // continue walking the pointers. If no address was found, the value of the
            // address wasn't a mapped location and break the loop
            if let Ok(new_addr) = self.read::<u64>(curr_val, cr3) {
                // Valid dereference, insert the address into the result
                res.push(ChainVal::Address(curr_val.0));

                // Continue walking the chain with the new value
                curr_val = VirtAddr(new_addr);
            } else {
                // Dereference failed. Attempt to check if the current value could be
                // something besides a raw number (like a String)

                // Only valid if there has been a previous address
                if index == 0 {
                    res.push(ChainVal::Number(curr_val.0));
                    break;
                }

                // Get the previous pointer and check if it contains a different type
                // we care about
                if let ChainVal::Address(prev_addr) = res[index - 1] {
                    // Check if the previous address points to a utf8 string
                    if let Ok(s) = self.read_c_string(VirtAddr(prev_addr), cr3) {
                        if !s.is_empty() {
                            res.push(ChainVal::Utf8(s));
                            break;
                        }
                    }
                }

                // Didn't identify any other type, default to the raw number
                res.push(ChainVal::Number(curr_val.0));
                break;
            }
        }

        res
    }

    /// Read a null-termianted string from the given [`VirtAddr`]
    ///
    /// # Errors
    ///
    /// * Failed to read the null-terminated string from the `virt_addr`
    #[allow(dead_code)]
    pub fn read_c_string(&mut self, virt_addr: VirtAddr, cr3: Cr3) -> Result<String> {
        // Max 1024 length C string
        let result = self.read_bytes_until(virt_addr, cr3, 0, 1024)?;

        // Return the resulting owned string
        Ok(std::ffi::CStr::from_bytes_with_nul(&result)?
            .to_string_lossy()
            .into_owned())
    }

    /// Read a null-termianted string from the given [`VirtAddr`]
    ///
    /// # Errors
    ///
    /// * Failed to read the null-terminated string from the `virt_addr`
    #[allow(dead_code)]
    pub fn read_bytes_until(
        &mut self,
        virt_addr: VirtAddr,
        cr3: Cr3,
        byte: u8,
        max_size: usize,
    ) -> Result<Vec<u8>> {
        /// Number of bytes in each read chunk looking for a null terminator
        const CHUNK_SIZE: usize = 64;

        let mut result: Vec<u8> = Vec::new();
        let mut offset = 0;

        // Read a section of bytes from the virtual address
        let mut bytes = [0_u8; CHUNK_SIZE];

        loop {
            // Check if we've read beyond the max size
            if offset >= max_size {
                break;
            }

            // Read a section of bytes from the virtual address
            self.read_bytes(virt_addr.offset(offset as u64), cr3, &mut bytes)?;

            // Check if this byte chunk has a null terminator
            if bytes.contains(&0) {
                if let Some(found_end) = bytes.split_inclusive(|x| *x == byte).next() {
                    // Make room in the reuslt for the current byte chunk (+1 to always have an ending null terminator)
                    result.extend_from_slice(found_end);
                    return Ok(result);
                };
            }

            // Copy this chunk and continue reading
            result.extend_from_slice(&bytes);

            // Increment the current offset into the resulting vec
            offset += CHUNK_SIZE;
        }

        Err(Error::ByteNotFound.into())
    }
}
