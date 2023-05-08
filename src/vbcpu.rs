//! `VirtualBox` register state structures from a `VirtualBox` coredump
//!
//! [`VirtualBox` Reference](https://www.virtualbox.org/svn/vbox/trunk/include/VBox/vmm/dbgfcorefmt.h)

use serde::{Deserialize, Serialize};
use serde_hex::{CompactPfx, SerHex};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Default)]
#[repr(C)]
#[allow(clippy::missing_docs_in_private_items)]
pub struct VmSelector {
    #[serde(with = "SerHex::<CompactPfx>")]
    pub(crate) base: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub(crate) limit: u32,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub(crate) access_rights: u32,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub(crate) selector: u16,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub(crate) reserved0: u16,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub(crate) reserved1: u32,
}

/// Expanded access rights structure for easier KVM initialization
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Default)]
#[repr(C)]
#[allow(clippy::missing_docs_in_private_items)]
pub struct AccessRights {
    pub(crate) segment_type: u8,
    pub(crate) descriptor_type: u8,
    pub(crate) privilege_level: u8,
    pub(crate) present: u8,
    pub(crate) avl: u8,
    pub(crate) long_mode_for_cs: u8,
    pub(crate) operation_size: u8,
    pub(crate) granularity: u8,
    pub(crate) unusable: u8,
}

impl VmSelector {
    /// Expand access rights from compact form
    ///
    /// Reference: Intel Manual: Table 24-2. Format of Access Rights
    #[allow(clippy::cast_possible_truncation)]
    pub fn get_access_rights(&self) -> AccessRights {
        AccessRights {
            segment_type: (self.access_rights & 0b1111) as u8,
            descriptor_type: ((self.access_rights >> 4) & 1) as u8,
            privilege_level: ((self.access_rights >> 5) & 0b11) as u8,
            present: ((self.access_rights >> 7) & 1) as u8,
            /* 11:8 reserved */
            avl: ((self.access_rights >> 12) & 1) as u8,
            long_mode_for_cs: ((self.access_rights >> 13) & 1) as u8,
            operation_size: ((self.access_rights >> 14) & 1) as u8,
            granularity: ((self.access_rights >> 15) & 1) as u8,
            unusable: ((self.access_rights >> 16) & 1) as u8,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[repr(C)]
#[allow(clippy::missing_docs_in_private_items)]
pub struct XSaveHeader {
    #[serde(with = "SerHex::<CompactPfx>")]
    pub xtate_bv: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub xcomp_bc: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub reserved_1: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub reserved_2: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub reserved_3: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub reserved_4: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub reserved_5: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub reserved_6: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Default)]
#[repr(C)]
#[allow(clippy::missing_docs_in_private_items)]
pub struct X86FxState {
    /// Control word
    #[serde(with = "SerHex::<CompactPfx>")]
    pub fcw: u16,

    /// Ttatus word
    #[serde(with = "SerHex::<CompactPfx>")]
    pub fsw: u16,

    /// Tag word
    #[serde(with = "SerHex::<CompactPfx>")]
    pub ftw: u16,

    /// Opcode
    #[serde(with = "SerHex::<CompactPfx>")]
    pub opcode: u16,

    /// Instruction pointer
    #[serde(with = "SerHex::<CompactPfx>")]
    pub fpuip: u32,

    /// Code selector
    #[serde(with = "SerHex::<CompactPfx>")]
    pub cs: u16,

    /// Reserved 1
    #[serde(with = "SerHex::<CompactPfx>")]
    pub reserved_1: u16,

    /// Data pointer
    #[serde(with = "SerHex::<CompactPfx>")]
    pub fpudp: u32,

    /// Data segment
    #[serde(with = "SerHex::<CompactPfx>")]
    pub ds: u16,

    /// Reserved 2
    #[serde(with = "SerHex::<CompactPfx>")]
    pub reserved_2: u16,

    /// MXCSR
    #[serde(with = "SerHex::<CompactPfx>")]
    pub mxcsr: u32,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub mxcsr_mask: u32,

    /// FPU Registers
    pub fpu_regs: [u128; 8],

    /// XMM registers
    pub xmm_regs: [u128; 16],

    pub reserved_rest: [u32; (464 - 416) / std::mem::size_of::<u32>()],
    pub reserved_rest2: [u32; (512 - 464) / std::mem::size_of::<u32>()],
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Default)]
#[repr(C)]
#[allow(clippy::missing_docs_in_private_items)]
pub struct X86XSaveHeader {
    #[serde(with = "SerHex::<CompactPfx>")]
    pub(crate) xstate: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub(crate) xcomp: u64,
    pub(crate) reserved: [u64; 6],
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Default)]
#[repr(C)]
#[allow(clippy::missing_docs_in_private_items)]
pub struct X86XsaveYmmHi {
    pub(crate) regs: [u128; 16],
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Default)]
#[repr(C)]
#[allow(clippy::missing_docs_in_private_items)]
pub struct X86XSaveArea {
    pub x87: X86FxState,
    pub header: X86XSaveHeader,
    pub ymm_hi: X86XsaveYmmHi,
}

/// CPU state used to initialize a `FuzzVm`
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[repr(C)]
#[allow(clippy::missing_docs_in_private_items, missing_docs)]
pub struct VbCpu {
    #[serde(with = "SerHex::<CompactPfx>")]
    pub rax: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub rbx: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub rcx: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub rdx: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub rsi: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub rdi: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub r8: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub r9: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub r10: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub r11: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub r12: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub r13: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub r14: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub r15: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub rip: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub rsp: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub rbp: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub rflags: u64,
    pub cs: VmSelector,
    pub ds: VmSelector,
    pub es: VmSelector,
    pub fs: VmSelector,
    pub gs: VmSelector,
    pub ss: VmSelector,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub cr0: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub cr2: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub cr3: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub cr4: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub dr0: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub dr1: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub dr2: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub dr3: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub dr4: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub dr5: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub dr6: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub dr7: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub gdtr_base: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub gdtr_limit: u32,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub gdtr_reserved: u32,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub idtr_base: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub idtr_limit: u32,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub idtr_reserved: u32,
    pub ldtr: VmSelector,
    pub tr: VmSelector,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub sysenter_cs: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub sysenter_eip: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub sysenter_esp: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub msr_efer: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub msr_star: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub msr_pat: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub msr_lstar: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub msr_cstar: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub msr_sfmask: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub msr_kernel_gs_base: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub msr_apic_base: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub xcr0: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub xcr1: u64,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub cbext: u32,
    #[serde(with = "SerHex::<CompactPfx>")]
    pub padding0: u32,
    pub xsave_state: X86XSaveArea,
}
