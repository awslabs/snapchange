//! Modified functions from kvm-ioctls for KVM accessibility

use anyhow::{anyhow, Result};

use kvm_bindings::{
    kvm_clear_dirty_log, kvm_clear_dirty_log__bindgen_ty_1, kvm_dirty_log,
    kvm_dirty_log__bindgen_ty_1, KVMIO,
};
use kvm_ioctls::{Cap, Kvm};

use vmm_sys_util::ioctl::{ioctl_with_ref, ioctl_with_val};

use crate::fuzzer::Fuzzer;
use crate::fuzzvm::FuzzVm;

/// Expression that calculates an ioctl number.
///
/// ```
/// # #[macro_use] extern crate vmm_sys_util;
/// # use std::os::raw::c_uint;
/// use vmm_sys_util::ioctl::_IOC_NONE;
///
/// const KVMIO: c_uint = 0xAE;
/// ioctl_expr!(_IOC_NONE, KVMIO, 0x01, 0);
/// ```
#[macro_export]
macro_rules! ioctl_expr {
    ($dir:expr, $ty:expr, $nr:expr, $size:expr) => {
        (($dir << vmm_sys_util::ioctl::_IOC_DIRSHIFT)
            | ($ty << vmm_sys_util::ioctl::_IOC_TYPESHIFT)
            | ($nr << vmm_sys_util::ioctl::_IOC_NRSHIFT)
            | ($size << vmm_sys_util::ioctl::_IOC_SIZESHIFT)) as ::std::os::raw::c_ulong
    };
}

/// Declare a function that returns an ioctl number.
///
/// ```
/// # #[macro_use] extern crate vmm_sys_util;
/// # use std::os::raw::c_uint;
/// use vmm_sys_util::ioctl::_IOC_NONE;
///
/// const KVMIO: c_uint = 0xAE;
/// ioctl_ioc_nr!(KVM_CREATE_VM, _IOC_NONE, KVMIO, 0x01, 0);
/// ```
macro_rules! ioctl_ioc_nr {
    ($name:ident, $dir:expr, $ty:expr, $nr:expr, $size:expr) => {
        #[allow(non_snake_case)]
        #[allow(clippy::cast_lossless)]
        pub fn $name() -> ::std::os::raw::c_ulong {
            ioctl_expr!($dir, $ty, $nr, $size)
        }
    };
    ($name:ident, $dir:expr, $ty:expr, $nr:expr, $size:expr, $($v:ident),+) => {
        #[allow(non_snake_case)]
        #[allow(clippy::cast_lossless)]
        pub fn $name($($v: ::std::os::raw::c_uint),+) -> ::std::os::raw::c_ulong {
            ioctl_expr!($dir, $ty, $nr, $size)
        }
    };
}

/// Declare an ioctl that reads and writes data.
///
/// ```
/// # #[macro_use] extern crate vmm_sys_util;
/// const VHOST: ::std::os::raw::c_uint = 0xAF;
/// ioctl_iowr_nr!(VHOST_GET_VRING_BASE, VHOST, 0x12, ::std::os::raw::c_int);
/// ```
#[macro_export]
macro_rules! ioctl_iowr_nr {
    ($name:ident, $ty:expr, $nr:expr, $size:ty) => {
        ioctl_ioc_nr!(
            $name,
            vmm_sys_util::ioctl::_IOC_READ | vmm_sys_util::ioctl::_IOC_WRITE,
            $ty,
            $nr,
            ::std::mem::size_of::<$size>() as u32
        );
    };
    ($name:ident, $ty:expr, $nr:expr, $size:ty, $($v:ident),+) => {
        ioctl_ioc_nr!(
            $name,
            vmm_sys_util::ioctl::_IOC_READ | vmm_sys_util::ioctl::_IOC_WRITE,
            $ty,
            $nr,
            ::std::mem::size_of::<$size>() as u32,
            $($v),+
        );
    };
}

/// Declare an ioctl that writes data.
///
/// ```
/// # #[macro_use] extern crate vmm_sys_util;
/// const TUNTAP: ::std::os::raw::c_uint = 0x54;
/// ioctl_iow_nr!(TUNSETQUEUE, TUNTAP, 0xd9, ::std::os::raw::c_int);
/// ```
macro_rules! ioctl_iow_nr {
    ($name:ident, $ty:expr, $nr:expr, $size:ty) => {
        ioctl_ioc_nr!(
            $name,
            vmm_sys_util::ioctl::_IOC_WRITE,
            $ty,
            $nr,
            ::std::mem::size_of::<$size>() as u32
        );
    };
    ($name:ident, $ty:expr, $nr:expr, $size:ty, $($v:ident),+) => {
        ioctl_ioc_nr!(
            $name,
            vmm_sys_util::ioctl::_IOC_WRITE,
            $ty,
            $nr,
            ::std::mem::size_of::<$size>() as u32,
            $($v),+
        );
    };
}

/// Declare an ioctl that transfers no data.
///
/// ```
/// # #[macro_use] extern crate vmm_sys_util;
/// # use std::os::raw::c_uint;
/// const KVMIO: c_uint = 0xAE;
/// ioctl_io_nr!(KVM_CREATE_VM, KVMIO, 0x01);
/// ```
#[macro_export]
macro_rules! ioctl_io_nr {
    ($name:ident, $ty:expr, $nr:expr) => {
        ioctl_ioc_nr!($name, vmm_sys_util::ioctl::_IOC_NONE, $ty, $nr, 0);
    };
    ($name:ident, $ty:expr, $nr:expr, $($v:ident),+) => {
        ioctl_ioc_nr!($name, vmm_sys_util::ioctl::_IOC_NONE, $ty, $nr, 0, $($v),+);
    };
}

ioctl_iow_nr!(KVM_GET_DIRTY_LOG, KVMIO, 0x42, kvm_dirty_log);
ioctl_iowr_nr!(KVM_CLEAR_DIRTY_LOG, KVMIO, 0xc0, kvm_clear_dirty_log);
ioctl_io_nr!(KVM_CHECK_EXTENSION, KVMIO, 0x03);

impl<'a, FUZZER: Fuzzer> FuzzVm<'a, FUZZER> {
    /// Gets the dirty logs for each slot in `self.dirty_bitmaps`
    ///
    /// # Errors
    ///
    /// * `KVM_GET_DIRTY_LOG` failed
    pub fn get_dirty_logs(&mut self) -> Result<()> {
        for (slot, bitmap) in self.dirty_bitmaps.iter_mut().enumerate() {
            // Create the structure for this clear
            let dirty_bitmap = bitmap.as_mut_ptr().cast::<libc::c_void>();

            let dirty_log = kvm_dirty_log {
                slot: u32::try_from(slot)?,
                padding1: 0,
                __bindgen_anon_1: kvm_dirty_log__bindgen_ty_1 { dirty_bitmap },
            };

            // Safe because we know that our file is a VM fd, and we know that the amount
            // of memory we allocated for the bitmap is at least one bit per page.
            let ret = unsafe { ioctl_with_ref(self.vm, KVM_GET_DIRTY_LOG(), &dirty_log) };

            // Check if ioctl failed
            if ret != 0 {
                return Err(anyhow!(nix::errno::Errno::last()));
            }
        }

        // Return success
        Ok(())
    }

    /// Clear the dirty logs
    ///
    /// # Errors
    ///
    /// * `KVM_CLEAR_DIRTY_LOG` failed
    ///
    /// # Panics
    ///
    /// * Somehow the `core_id` doesn't fit in a usize
    pub fn clear_dirty_logs(&mut self) -> Result<()> {
        for (slot, bitmap) in self.dirty_bitmaps.iter_mut().enumerate() {
            // for (slot, bitmap) in DIRTY_BITMAPS[usize::try_from(self.core_id).unwrap()].iter().enumerate() {

            let dirty_bitmap = bitmap.as_mut_ptr().cast::<libc::c_void>();

            let clear_log = kvm_clear_dirty_log {
                slot: u32::try_from(slot).unwrap(),
                num_pages: self.number_of_pages[slot],
                first_page: 0,
                __bindgen_anon_1: kvm_clear_dirty_log__bindgen_ty_1 { dirty_bitmap },
            };

            // Safe because we know that our file is a VM fd, and we know that the amount
            // of memory we allocated for the bitmap is at least one bit per page.
            let ret = unsafe { ioctl_with_ref(self.vm, KVM_CLEAR_DIRTY_LOG(), &clear_log) };

            // Check if ioctl failed
            if ret != 0 {
                return Err(anyhow!(nix::errno::Errno::last()));
            }
        }

        // Return success
        Ok(())
    }
}

/// Wrapper over `KVM_CHECK_EXTENSION`.
///
/// Returns 0 if the capability is not available and a positive integer otherwise.
pub(crate) fn check_extension_int(kvm: &Kvm, c: Cap) -> i32 {
    // Safe because we know that our file is a KVM fd and that the extension is one of the ones
    // defined by kernel.
    unsafe { ioctl_with_val(kvm, KVM_CHECK_EXTENSION(), c as libc::c_ulong) }
}
