//! Interrupt entry implementation

/// An entry in the interrupt descriptor table
#[derive(Debug, Default)]
#[repr(C)]
pub(crate) struct IdtEntry {
    /// Low 16 bits of the interrupt service routine
    isr_low: u16,

    /// CS selector for the kernel
    kernel_cs: u16,

    /// IST
    ist: u8,

    /// Attributes
    attributes: u8,

    /// Middle 16 bits of the interrupt service routine
    isr_mid: u16,

    /// High 32 bits of the interrupt service routine
    isr_high: u32,

    /// Reserved
    reserved: u32,
}

impl IdtEntry {
    /// Get the interrupt service routine's address from the [`IdtEntry`]
    #[allow(dead_code)]
    pub(crate) fn isr(&self) -> u64 {
        u64::from(self.isr_high) << 32 | u64::from(self.isr_mid) << 16 | u64::from(self.isr_low)
    }

    /// Get the interrupt service routine's address from the [`IdtEntry`]
    #[allow(dead_code)]
    #[allow(clippy::cast_possible_truncation)]
    pub(crate) fn set_isr(&mut self, val: u64) {
        self.isr_high = (val >> 32) as u32;
        self.isr_mid = (val >> 16) as u16;
        self.isr_low = val as u16;
    }
}
