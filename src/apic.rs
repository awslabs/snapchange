//! APIC utilities for KVM
#![allow(dead_code)]

use anyhow::{Context, Result};
use kvm_bindings::kvm_lapic_state;
use kvm_ioctls::VcpuFd;

/// Delivery mode used to trigger an interrupt
#[repr(u8)]
pub(crate) enum DeliveryMode {
    /// Delivers the interrupt specified in the vector field to the target processor or
    /// processors
    Fixed = 0,

    /// Same as fixed mode, except that the interrupt is delivered to the processor
    /// executing at the lowest priority among the set of processors specified in the
    /// destination field
    LowestPriority = 1,

    /// Deliveres a System Management Interrupt (SMI) interrupt to the target processor
    /// or processors. The vector information is ignored.
    SystemManagementInterrupt = 2,

    /// Delivers a Non-Maskable Interrupt (NMI) interrupt to the target processor or
    /// processors. The vector information is ignored.
    NonMaskableInterrupt = 4,

    /// Delivers an INIT request to the target processor or processors, which causes them
    /// to perform an INIT. As a result of this IPI message, all the tar-get processors
    /// perform an INIT. The vector field must be programmed to 00H for future
    /// compatibility.
    Init = 5,

    /// Causes the processor to respond to the interrupt as if the interrupt originated
    /// in an externally connected (8259A-compatible) interrupt controller.
    ExternalInterrupt = 7,
}

/// Timer modes
#[allow(dead_code)]
pub(crate) enum TimerMode {
    /// One-Shot mode using a count-down value
    OneShot = 0,

    /// Periodic mode reloading a count-down value
    Periodic = 1,

    /// TSC-Deadline mode using absolute target value in IA32_TSC_DEADLINE MSR
    TscDeadline = 2,
}

/// An APIC Register
#[repr(u32)]
#[allow(dead_code)]
pub(crate) enum Register {
    /// Specifies the value to divide the core crystal clock frequency or processor's bus
    /// clock frequency to calculate the APIC timer frequency
    DivideConfiguration = 0x30,

    /// Determines the vector number to be delivered to the processor when the local APIC
    /// generates a spurious vector.
    SpuriousInterrupt = 0xf0,

    /// LVT Timer
    LvtTimer = 0x320,

    /// LVT Performance Monitoring register
    LvtPerformanceMonitoringCounters = 0x340,

    /// LVT LINT0 Register
    LvtLint0 = 0x350,

    /// LVT LINT1 Register
    LvtLint1 = 0x360,

    /// The initial count value of the timer register
    TimerInitialCount = 0x380,

    /// The initial count value of the timer register
    TimerCurrentCount = 0x390,
}

/// The value to divide the processor's bus frequency to determine how often the lapic
/// timer interrupt triggers
///
/// NOTE: As per the Intel manual, bit 2 is always 0
#[repr(u8)]
#[allow(dead_code)]
pub(crate) enum DivideConfig {
    /// APIC timer frequency is bus clock or core crystal clock frequency dividied by 2
    DivideBy2 = 0b0000,

    /// APIC timer frequency is bus clock or core crystal clock frequency dividied by 4
    DivideBy4 = 0b0001,

    /// APIC timer frequency is bus clock or core crystal clock frequency dividied by 8
    DivideBy8 = 0b0010,

    /// APIC timer frequency is bus clock or core crystal clock frequency dividied by 16
    DivideBy16 = 0b0011,

    /// APIC timer frequency is bus clock or core crystal clock frequency dividied by 32
    DivideBy32 = 0b1000,

    /// APIC timer frequency is bus clock or core crystal clock frequency dividied by 64
    DivideBy64 = 0b1001,

    /// APIC timer frequency is bus clock or core crystal clock frequency dividied by 128
    DivideBy128 = 0b1010,

    /// APIC timer frequency is bus clock or core crystal clock frequency dividied by 1
    DivideBy1 = 0b1011,
}

/// Spurious Interrupt register
struct SpuriousInterrupt {
    /// determines whether an eoi for a level-triggered interrupt causes eoi messages to
    /// be broad-cast to the i/o apics (0) or not (1). see section 10.8.5. the default
    /// value for this bit is 0, indicating that eoi broadcasts are performed. this bit
    /// is reserved to 0 if the processor does not support eoi-broadcast suppression.
    eoi_broadcast_suppression: bool,

    /// determines if focus processor checking is enabled (0) or disabled (1) when using
    /// the lowest-priority delivery mode. in pentium 4 and intel xeon processors, this
    /// bit is reserved and should be cleared to 0.
    focus_processor_checking: bool,

    /// allows software to temporarily enable (1) or disable (0) the local apic (see
    /// section 10.4.3, “enabling or disabling the local apic”).
    apic_software_enable: bool,

    /// determines the vector number to be delivered to the processor when the local apic
    /// generates a spurious vector.
    vector: u8,
}

impl SpuriousInterrupt {
    /// Create a clean spurious interrupt
    pub fn new() -> Self {
        Self {
            eoi_broadcast_suppression: false,
            focus_processor_checking: false,
            apic_software_enable: false,
            vector: 0,
        }
    }

    /// Create the `u32` from the current [`SpuriousInterrupt`]
    pub fn finish(self) -> u32 {
        u32::from(self.eoi_broadcast_suppression) << 12
            | u32::from(self.focus_processor_checking) << 9
            | u32::from(self.apic_software_enable) << 8
            | u32::from(self.vector)
    }

    /// Set the EOI Broadcast Supporession flag to the given `val`
    #[allow(dead_code)]
    pub fn eoi_broadcast_suppression(mut self, val: bool) -> Self {
        self.eoi_broadcast_suppression = val;
        self
    }

    /// Set the Focus Processor Checking flag to the given `val`
    #[allow(dead_code)]
    pub fn focus_processor_checking(mut self, val: bool) -> Self {
        self.focus_processor_checking = val;
        self
    }

    /// Set the APIC Software Enable flag to the given `val`
    pub fn apic_software_enable(mut self, val: bool) -> Self {
        self.apic_software_enable = val;
        self
    }

    /// Set the `vector` for the spurious interrupt
    pub fn vector(mut self, val: u8) -> Self {
        self.vector = val;
        self
    }
}

/// Enable the spurious interrupt on the given `vector` for the given `apic`
#[allow(clippy::cast_possible_wrap, clippy::identity_op)]
fn enable_spurious_interrupt(apic: &mut kvm_lapic_state, vector: u8) {
    // Get the value to write into the spurious interrupt
    let value: u32 = SpuriousInterrupt::new()
        .apic_software_enable(true)
        .vector(vector)
        .finish();

    // Get the register number to write the value
    let register = Register::SpuriousInterrupt as usize;
    let bytes = value.to_le_bytes();
    apic.regs[register + 0] = bytes[0] as i8;
    apic.regs[register + 1] = bytes[1] as i8;
    apic.regs[register + 2] = bytes[2] as i8;
    apic.regs[register + 3] = bytes[3] as i8;
}

/// Performance counter configuration
struct InterruptRegister {
    /// Specifies the type of interrupt to be sent to the processor.
    delivery_mode: DeliveryMode,

    /// The vector field to deliver the interrupt
    vector: u8,
}

impl InterruptRegister {
    /// Create a blank [`InterruptRegister`]
    pub fn new() -> Self {
        Self {
            delivery_mode: DeliveryMode::Fixed,
            vector: 0xff,
        }
    }

    /// Set the [`DeliveryMode`] for the current [`InterruptRegister`]
    pub fn delivery_mode(mut self, delivery_mode: DeliveryMode) -> Self {
        self.delivery_mode = delivery_mode;
        self
    }

    /// Set the `vector` for the spurious interrupt
    #[allow(dead_code)]
    pub fn vector(mut self, vector: u8) -> Self {
        self.vector = vector;
        self
    }

    /// Create the `u32` from this [`InterruptRegister`]
    pub fn finish(self) -> u32 {
        (self.delivery_mode as u32) << 8 | u32::from(self.vector)
    }
}

/*
/// Read the given [`Register`] from the given `apic`
pub(crate) fn _read_register(apic: &mut kvm_lapic_state, reg: Register) -> usize {
    // Get the register number to write the value
    let register = reg as usize;

    // Read the value and convert to a usize
    u32::from_le_bytes(apic.regs[register..register + 4].try_into().unwrap()) as usize
}
*/

/// Write the given [`Register`] with the given `usize` into the given `apic`
#[allow(clippy::cast_possible_wrap, clippy::identity_op)]
fn write_register(apic: &mut kvm_lapic_state, reg: Register, value: u32) {
    // Get the register number to write the value
    let register = reg as usize;

    let bytes = value.to_le_bytes();
    apic.regs[register + 0] = bytes[0] as i8;
    apic.regs[register + 1] = bytes[1] as i8;
    apic.regs[register + 2] = bytes[2] as i8;
    apic.regs[register + 3] = bytes[3] as i8;
}

/// Enable LVT Performance Monitoring to trigger an SMI. This is how we can poll a
/// VM for execution points without having to worry about specific breakpoints in
/// the target
fn _enable_retired_instruction_counter(apic: &mut kvm_lapic_state) {
    // Get the value for the an NMI
    let value = InterruptRegister::new()
        .delivery_mode(DeliveryMode::NonMaskableInterrupt)
        .finish();

    // Write the register
    write_register(apic, Register::LvtPerformanceMonitoringCounters, value);
}

/// Enable the LAPIC timer to trigger an interrupt into the guest
#[allow(dead_code)]
fn enable_timer(apic: &mut kvm_lapic_state) {
    // Get the value for the timer to trigger on an external interrupt
    let timer = TimerMode::Periodic as u32;
    let vector: u8 = 236;

    // Calculate the timer value
    let timer_value = (timer << 17) | u32::from(vector);

    // Set the timer divide configuration value
    write_register(
        apic,
        Register::DivideConfiguration,
        DivideConfig::DivideBy32 as u32,
    );

    let init_count = 0xff_0000;
    write_register(apic, Register::TimerInitialCount, init_count);

    // Write the timer register
    write_register(apic, Register::LvtTimer, timer_value);
}

/// Initialize the APIC to send an NMI on the overflow of retired instruction
pub fn init(vcpu: &VcpuFd) -> Result<()> {
    // Create the local APIC
    let mut apic = vcpu
        .get_lapic()
        .context("Failed to get APIC. Is IRQCHIP created?")?;

    // Enable spurious interrupt on vector 0xff
    enable_spurious_interrupt(&mut apic, 0xff);

    // Enable NMI for retired instruction counter overflow
    // enable_retired_instruction_counter(&mut apic);

    // Enable the APIC timer
    // enable_timer(&mut apic);

    // Set the APIC for the guest VM
    vcpu.set_lapic(&apic).context("Failed to set APIC")?;

    // Success
    Ok(())
}
