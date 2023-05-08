//! Register implementations for x86

use crate::fuzzer::Fuzzer;
use crate::FuzzVm;
use iced_x86::Register;

/// Implement getter/setters for register accesses in the VM
///
/// # Example
///
/// ```text
/// let rax = fuzzvm.rax();
/// fuzzvm.set_rax(0x1234);
/// ```
macro_rules! impl_reg {
    ($reg:ident,
        $reg8_lo:ident, $set_reg8_lo:ident,
        $reg8_hi:ident, $set_reg8_hi:ident,
        $reg16:ident,   $set_reg16:ident,
        $reg32:ident,   $set_reg32:ident,
        $reg64:ident,   $set_reg64:ident
    ) => {
        #[doc = concat!("Read the ", stringify!($reg8_lo), " register from the guest")]
        #[must_use]
        pub fn $reg8_lo(&self) -> u8 {
            self.regs().$reg as u8
        }
        #[doc = concat!("Write the ", stringify!($reg8_lo), " register in the guest")]
        pub fn $set_reg8_lo(&mut self, val: u8) {
            self.regs_mut().$reg = val as u64;
            self.dirtied_registers = true;
        }
        #[doc = concat!("Read the ", stringify!($reg8_hi), " register from the guest")]
        #[must_use]
        pub fn $reg8_hi(&self) -> u8 {
            (self.regs().$reg >> 8) as u8
        }
        #[doc = concat!("Write the ", stringify!($reg8_hi), " register in the guest")]
        pub fn $set_reg8_hi(&mut self, val: u8) {
            self.regs_mut().$reg = (val as u64) << 8;
            self.dirtied_registers = true;
        }
        #[doc = concat!("Read the ", stringify!($reg16), " register from the guest")]
        #[must_use]
        pub fn $reg16(&self) -> u16 {
            self.regs().$reg as u16
        }
        #[doc = concat!("Write the ", stringify!($reg16), " register in the guest")]
        pub fn $set_reg16(&mut self, val: u16) {
            self.regs_mut().$reg = val as u64;
            self.dirtied_registers = true;
        }
        #[doc = concat!("Read the ", stringify!($reg32), " register from the guest")]
        #[must_use]
        pub fn $reg32(&self) -> u32 {
            self.regs().$reg as u32
        }
        #[doc = concat!("Write the ", stringify!($reg32), " register in the guest")]
        pub fn $set_reg32(&mut self, val: u32) {
            self.regs_mut().$reg = val as u64;
            self.dirtied_registers = true;
        }
        #[doc = concat!("Read the ", stringify!($reg64), " register from the guest")]
        #[must_use]
        pub fn $reg64(&self) -> u64 {
            self.regs().$reg as u64
        }
        #[doc = concat!("Write the ", stringify!($reg64), " register in the guest")]
        pub fn $set_reg64(&mut self, val: u64) {
            self.regs_mut().$reg = val;
            self.dirtied_registers = true;
        }
    };
    ($reg:ident,
        $reg8_lo:ident, $set_reg8_lo:ident,
        $reg16:ident,   $set_reg16:ident,
        $reg32:ident,   $set_reg32:ident,
        $reg64:ident,   $set_reg64:ident
    ) => {
        #[doc = concat!("Read the ", stringify!($reg8_lo), " register from the guest")]
        #[must_use]
        pub fn $reg8_lo(&self) -> u8 {
            self.regs().$reg as u8
        }
        #[doc = concat!("Write the ", stringify!($reg8_lo), " register in the guest")]
        pub fn $set_reg8_lo(&mut self, val: u8) {
            self.regs_mut().$reg = val as u64;
            self.dirtied_registers = true;
        }
        #[doc = concat!("Read the ", stringify!($reg16), " register from the guest")]
        #[must_use]
        pub fn $reg16(&self) -> u16 {
            self.regs().$reg as u16
        }
        #[doc = concat!("Write the ", stringify!($reg16), " register in the guest")]
        pub fn $set_reg16(&mut self, val: u16) {
            self.regs_mut().$reg = val as u64;
            self.dirtied_registers = true;
        }
        #[doc = concat!("Read the ", stringify!($reg32), " register from the guest")]
        #[must_use]
        pub fn $reg32(&self) -> u32 {
            self.regs().$reg as u32
        }
        #[doc = concat!("Write the ", stringify!($reg32), " register in the guest")]
        pub fn $set_reg32(&mut self, val: u32) {
            self.regs_mut().$reg = val as u64;
            self.dirtied_registers = true;
        }
        #[doc = concat!("Read the ", stringify!($reg64), " register from the guest")]
        #[must_use]
        pub fn $reg64(&self) -> u64 {
            self.regs().$reg as u64
        }
        #[doc = concat!("Write the ", stringify!($reg64), " register in the guest")]
        pub fn $set_reg64(&mut self, val: u64) {
            self.regs_mut().$reg = val;
            self.dirtied_registers = true;
        }
    };
    ($reg:ident,
        $reg16:ident,   $set_reg16:ident,
        $reg32:ident,   $set_reg32:ident,
        $reg64:ident,   $set_reg64:ident
    ) => {
        #[doc = concat!("Read the ", stringify!($reg16), " register from the guest")]
        #[must_use]
        pub fn $reg16(&self) -> u16 {
            self.regs().$reg as u16
        }
        #[doc = concat!("Write the ", stringify!($reg16), " register in the guest")]
        pub fn $set_reg16(&mut self, val: u16) {
            self.regs_mut().$reg = val as u64;
            self.dirtied_registers = true;
        }
        #[doc = concat!("Read the ", stringify!($reg32), " register from the guest")]
        #[must_use]
        pub fn $reg32(&self) -> u32 {
            self.regs().$reg as u32
        }
        #[doc = concat!("Write the ", stringify!($reg32), " register in the guest")]
        pub fn $set_reg32(&mut self, val: u32) {
            self.regs_mut().$reg = val as u64;
            self.dirtied_registers = true;
        }
        #[doc = concat!("Read the ", stringify!($reg64), " register from the guest")]
        #[must_use]
        pub fn $reg64(&self) -> u64 {
            self.regs().$reg as u64
        }
        #[doc = concat!("Write the ", stringify!($reg64), " register in the guest")]
        pub fn $set_reg64(&mut self, val: u64) {
            self.regs_mut().$reg = val;
            self.dirtied_registers = true;
        }
    };
    ($reg:ident,
        $reg32:ident,   $set_reg32:ident,
        $reg64:ident,   $set_reg64:ident
    ) => {
        #[doc = concat!("Read the ", stringify!($reg32), " register from the guest")]
        #[must_use]
        pub fn $reg32(&self) -> u32 {
            self.regs().$reg as u32
        }
        #[doc = concat!("Write the ", stringify!($reg32), " register in the guest")]
        pub fn $set_reg32(&mut self, val: u32) {
            self.regs_mut().$reg = val as u64;
            self.dirtied_registers = true;
        }
        #[doc = concat!("Read the ", stringify!($reg64), " register from the guest")]
        #[must_use]
        pub fn $reg64(&self) -> u64 {
            self.regs().$reg as u64
        }
        #[doc = concat!("Write the ", stringify!($reg64), " register in the guest")]
        pub fn $set_reg64(&mut self, val: u64) {
            self.regs_mut().$reg = val;
            self.dirtied_registers = true;
        }
    };
}

/// Implement the XMM register functions
macro_rules! impl_xmm {
    ($reg:ident, $f32:ident, $f64:ident, $i128:ident, $set_reg:ident, $num:expr) => {
        #[doc = concat!("Read the ", stringify!($reg), " register from the guest")]
        #[must_use]
        pub fn $reg(&self) -> Vec<u8> {
            if let Ok(fpu) = self.fpu() {
                fpu.xmm[$num].to_vec()
            } else {
                vec![0xcd; 0x10]
            }
        }

        #[doc = concat!("Read the ", stringify!($reg), " register from the guest as an i128")]
        #[must_use]
        pub fn $i128(&self) -> i128 {
            if let Ok(fpu) = self.fpu() {
                i128::from_le_bytes(fpu.xmm[$num].try_into().unwrap())
            } else {
                0xcdcd_cdcd_cdcd_cdcd
            }
        }

        #[doc = concat!("Read the ", stringify!($reg), " register from the guest as an f32")]
        #[must_use]
        pub fn $f32(&self) -> f32 {
            if let Ok(fpu) = self.fpu() {
                f32::from_le_bytes(fpu.xmm[$num][..4].try_into().unwrap())
            } else {
                f32::NEG_INFINITY
            }
        }

        #[doc = concat!("Read the ", stringify!($reg), " register from the guest as an f64")]
        #[must_use]
        pub fn $f64(&self) -> f64 {
            if let Ok(fpu) = self.fpu() {
                f64::from_le_bytes(fpu.xmm[$num][..8].try_into().unwrap())
            } else {
                f64::NEG_INFINITY
            }
        }

        /*
        #[doc = concat!("Write the ", stringify!($reg), " register in the guest")]
        pub fn $set_reg(&mut self, val: u128) {
            self.fpu_mut().xmm[$num] = val.to_le_bytes();
        }
        */
    };
}

impl<FUZZER: Fuzzer> FuzzVm<'_, FUZZER> {
    //        reg,    <   8lo       > <   8hi   > <   16bit     > <   32bit     >   <   64bit    >
    impl_reg!(rax, al, set_al, ah, set_ah, ax, set_ax, eax, set_eax, rax, set_rax);
    impl_reg!(rbx, bl, set_bl, bh, set_bh, bx, set_bx, ebx, set_ebx, rbx, set_rbx);
    impl_reg!(rcx, cl, set_cl, ch, set_ch, cx, set_cx, ecx, set_ecx, rcx, set_rcx);
    impl_reg!(rdx, dl, set_dl, dh, set_dh, dx, set_dx, edx, set_edx, rdx, set_rdx);
    impl_reg!(rsi, sil, set_sil, /*       */ si, set_si, esi, set_esi, rsi, set_rsi);
    impl_reg!(rdi, dil, set_dil, /*       */ di, set_di, edi, set_edi, rdi, set_rdi);
    impl_reg!(rsp, spl, set_spl, /*       */ sp, set_sp, esp, set_esp, rsp, set_rsp);
    impl_reg!(rbp, bpl, set_bpl, /*       */ bp, set_bp, ebp, set_ebp, rbp, set_rbp);
    impl_reg!(r8, r8b, set_r8b, /*       */ r8w, set_r8w, r8d, set_r8d, r8, set_r8);
    impl_reg!(r9, r9b, set_r9b, /*       */ r9w, set_r9w, r9d, set_r9d, r9, set_r9);
    impl_reg!(r10, r10b, set_r10b, /*       */ r10w, set_r10w, r10d, set_r10d, r10, set_r10);
    impl_reg!(r11, r11b, set_r11b, /*       */ r11w, set_r11w, r11d, set_r11d, r11, set_r11);
    impl_reg!(r12, r12b, set_r12b, /*       */ r12w, set_r12w, r12d, set_r12d, r12, set_r12);
    impl_reg!(r13, r13b, set_r13b, /*       */ r13w, set_r13w, r13d, set_r13d, r13, set_r13);
    impl_reg!(r14, r14b, set_r14b, /*       */ r14w, set_r14w, r14d, set_r14d, r14, set_r14);
    impl_reg!(r15, r15b, set_r15b, /*       */ r15w, set_r15w, r15d, set_r15d, r15, set_r15);
    impl_reg!(rip, /*        */    /*       */ /*           */ eip, set_eip, rip, set_rip);
    impl_reg!(
        rflags, /*        */    /*       */ /*           */ flags, set_flags, rflags,
        set_rflags
    );

    impl_xmm!(xmm0, xmm0_f32, xmm0_f64, xmm0_i128, set_xmm0, 0);
    impl_xmm!(xmm1, xmm1_f32, xmm1_f64, xmm1_i128, set_xmm1, 1);
    impl_xmm!(xmm2, xmm2_f32, xmm2_f64, xmm2_i128, set_xmm2, 2);
    impl_xmm!(xmm3, xmm3_f32, xmm3_f64, xmm3_i128, set_xmm3, 3);
    impl_xmm!(xmm4, xmm4_f32, xmm4_f64, xmm4_i128, set_xmm4, 4);
    impl_xmm!(xmm5, xmm5_f32, xmm5_f64, xmm5_i128, set_xmm5, 5);
    impl_xmm!(xmm6, xmm6_f32, xmm6_f64, xmm6_i128, set_xmm6, 6);
    impl_xmm!(xmm7, xmm7_f32, xmm7_f64, xmm7_i128, set_xmm7, 7);
    impl_xmm!(xmm8, xmm8_f32, xmm8_f64, xmm8_i128, set_xmm8, 8);
    impl_xmm!(xmm9, xmm9_f32, xmm9_f64, xmm9_i128, set_xmm9, 9);
    impl_xmm!(xmm10, xmm10_f32, xmm10_f64, xmm10_i128, set_xmm10, 10);
    impl_xmm!(xmm11, xmm11_f32, xmm11_f64, xmm11_i128, set_xmm11, 11);
    impl_xmm!(xmm12, xmm12_f32, xmm12_f64, xmm12_i128, set_xmm12, 12);
    impl_xmm!(xmm13, xmm13_f32, xmm13_f64, xmm13_i128, set_xmm13, 13);
    impl_xmm!(xmm14, xmm14_f32, xmm14_f64, xmm14_i128, set_xmm14, 14);
    impl_xmm!(xmm15, xmm15_f32, xmm15_f64, xmm15_i128, set_xmm15, 15);

    /// Get the guest register for the given [`iced_x86::Register`]
    ///
    /// # Panics
    ///
    /// * Given [`iced_x86::Register`] is not yet implemented
    #[must_use]
    #[allow(clippy::cast_lossless)]
    pub fn get_iced_reg(&self, reg: Register) -> i128 {
        match reg {
            Register::AL => self.al() as i128,
            Register::AH => self.ah() as i128,
            Register::AX => self.ax() as i128,
            Register::EAX => self.eax() as i128,
            Register::RAX => self.rax() as i128,

            Register::BL => self.bl() as i128,
            Register::BH => self.bh() as i128,
            Register::BX => self.bx() as i128,
            Register::EBX => self.ebx() as i128,
            Register::RBX => self.rbx() as i128,

            Register::CL => self.cl() as i128,
            Register::CH => self.ch() as i128,
            Register::CX => self.cx() as i128,
            Register::ECX => self.ecx() as i128,
            Register::RCX => self.rcx() as i128,

            Register::DL => self.dl() as i128,
            Register::DH => self.dh() as i128,
            Register::DX => self.dx() as i128,
            Register::EDX => self.edx() as i128,
            Register::RDX => self.rdx() as i128,

            Register::SIL => self.sil() as i128,
            Register::SI => self.si() as i128,
            Register::ESI => self.esi() as i128,
            Register::RSI => self.rsi() as i128,

            Register::DIL => self.dil() as i128,
            Register::DI => self.di() as i128,
            Register::EDI => self.edi() as i128,
            Register::RDI => self.rdi() as i128,

            Register::SPL => self.spl() as i128,
            Register::SP => self.sp() as i128,
            Register::ESP => self.esp() as i128,
            Register::RSP => self.rsp() as i128,

            Register::BPL => self.bpl() as i128,
            Register::BP => self.bp() as i128,
            Register::EBP => self.ebp() as i128,
            Register::RBP => self.rbp() as i128,

            Register::R8L => self.r8b() as i128,
            Register::R8W => self.r8w() as i128,
            Register::R8D => self.r8d() as i128,
            Register::R8 => self.r8() as i128,

            Register::R9L => self.r9b() as i128,
            Register::R9W => self.r9w() as i128,
            Register::R9D => self.r9d() as i128,
            Register::R9 => self.r9() as i128,

            Register::R10L => self.r10b() as i128,
            Register::R10W => self.r10w() as i128,
            Register::R10D => self.r10d() as i128,
            Register::R10 => self.r10() as i128,

            Register::R11L => self.r11b() as i128,
            Register::R11W => self.r11w() as i128,
            Register::R11D => self.r11d() as i128,
            Register::R11 => self.r11() as i128,

            Register::R12L => self.r12b() as i128,
            Register::R12W => self.r12w() as i128,
            Register::R12D => self.r12d() as i128,
            Register::R12 => self.r12() as i128,

            Register::R13L => self.r13b() as i128,
            Register::R13W => self.r13w() as i128,
            Register::R13D => self.r13d() as i128,
            Register::R13 => self.r13() as i128,

            Register::R14L => self.r14b() as i128,
            Register::R14W => self.r14w() as i128,
            Register::R14D => self.r14d() as i128,
            Register::R14 => self.r14() as i128,

            Register::R15L => self.r15b() as i128,
            Register::R15W => self.r15w() as i128,
            Register::R15D => self.r15d() as i128,
            Register::R15 => self.r15() as i128,

            Register::EIP => self.eip() as i128,
            Register::RIP => self.rip() as i128,

            Register::CR0 => self.sregs().cr0 as i128,
            Register::CR2 => self.sregs().cr2 as i128,
            Register::CR3 => self.sregs().cr3 as i128,
            Register::CR4 => self.sregs().cr4 as i128,
            Register::FS => self.sregs().fs.base as i128,
            Register::GS => self.sregs().gs.base as i128,
            Register::CS => self.sregs().cs.base as i128,
            Register::DS => self.sregs().ds.base as i128,
            Register::ES => self.sregs().es.base as i128,
            Register::SS => self.sregs().ss.base as i128,

            Register::XMM0 => self.xmm0_i128(),
            Register::XMM1 => self.xmm1_i128(),
            Register::XMM2 => self.xmm2_i128(),
            Register::XMM3 => self.xmm3_i128(),
            Register::XMM4 => self.xmm4_i128(),
            Register::XMM5 => self.xmm5_i128(),
            Register::XMM6 => self.xmm6_i128(),
            Register::XMM7 => self.xmm7_i128(),
            Register::XMM8 => self.xmm8_i128(),
            Register::XMM9 => self.xmm9_i128(),
            Register::XMM10 => self.xmm10_i128(),
            Register::XMM11 => self.xmm11_i128(),
            Register::XMM12 => self.xmm12_i128(),
            Register::XMM13 => self.xmm13_i128(),
            Register::XMM14 => self.xmm14_i128(),
            Register::XMM15 => self.xmm15_i128(),

            Register::DR0 => {
                if let Ok(regs) = self.debug_regs() {
                    regs.db[0] as i128
                } else {
                    0x1ead_beef_cafe_babe_aaaa_bbbb_cccc_dddd
                }
            }
            Register::DR1 => {
                if let Ok(regs) = self.debug_regs() {
                    regs.db[1] as i128
                } else {
                    0x1ead_beef_cafe_babe_aaaa_bbbb_cccc_dddd
                }
            }
            Register::DR2 => {
                if let Ok(regs) = self.debug_regs() {
                    regs.db[2] as i128
                } else {
                    0x1ead_beef_cafe_babe_aaaa_bbbb_cccc_dddd
                }
            }
            Register::DR3 => {
                if let Ok(regs) = self.debug_regs() {
                    regs.db[3] as i128
                } else {
                    0x1ead_beef_cafe_babe_aaaa_bbbb_cccc_dddd
                }
            }
            Register::DR6 => {
                if let Ok(regs) = self.debug_regs() {
                    regs.dr6 as i128
                } else {
                    0x1ead_beef_cafe_babe_aaaa_bbbb_cccc_dddd
                }
            }
            Register::DR7 => {
                if let Ok(regs) = self.debug_regs() {
                    regs.dr7 as i128
                } else {
                    0x1ead_beef_cafe_babe_aaaa_bbbb_cccc_dddd
                }
            }

            Register::YMM0 => 0xdead_0000,
            Register::YMM1 => 0xdead_0001,
            Register::YMM2 => 0xdead_0002,
            Register::YMM3 => 0xdead_0003,
            Register::YMM4 => 0xdead_0004,
            Register::YMM5 => 0xdead_0005,
            Register::YMM6 => 0xdead_0006,
            Register::YMM7 => 0xdead_0007,
            Register::YMM8 => 0xdead_0008,
            Register::YMM9 => 0xdead_0009,
            Register::YMM10 => 0xdead_000a,
            Register::YMM11 => 0xdead_000b,
            Register::YMM12 => 0xdead_000c,
            Register::YMM13 => 0xdead_000d,
            Register::YMM14 => 0xdead_000e,
            Register::YMM15 => 0xdead_000f,

            _ => unimplemented!("Unimpl reg: {:?}", reg),
        }
    }

    /// Get the current FS base
    #[must_use]
    pub fn fsbase(&self) -> u64 {
        self.sregs().fs.base
    }
}
