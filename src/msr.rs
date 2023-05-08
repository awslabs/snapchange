//! Provides the [`Msr`] enum
use num_enum::{IntoPrimitive, TryFromPrimitive};

/// Model specific registers found available from KVM
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, TryFromPrimitive, IntoPrimitive)]
#[repr(u32)]
pub enum Msr {
    /// An unknown MSR
    Unknown = 0xdead_beef,

    /// Time Stamp Counter
    Ia32TimeStampCounter = 0x10,

    /// Control and Event Select Register
    Cesr = 0x11,

    /// APIC Base
    ApicBase = 0x1b,

    /// Control Features in Intel 64 Processor (R/W)
    ///
    /// Reference: Table 2-2. IA-32 Architectural MSRs
    Ia32FeatureControl = 0x3a,

    /// Per Logical Processor TSC Adjust (R/Write to clear)
    ///
    /// Reference: Table 2-2. IA-32 Architectural MSRs
    Ia32TscAdjust = 0x3b,

    /// Speculation Control (R/W)
    ///
    /// The MSR bits are defined as logical processor scope. On some core
    /// implementations, the bits may impact sibling logical processors on the same
    /// core.This MSR has a value of 0 after reset and is unaffected by INIT# or SIPI#
    ///
    /// Reference: Table 2-2. IA-32 Architectural MSRs
    Ia32SpecCtrl = 0x48,

    /// Base address of the logical processor’s SMRAM image (RO, SMM only).
    Ia32Smbase = 0x9e,

    /// General Performance Counter 0 (R/W)
    Ia32Pmc0 = 0xc1,

    /// General Performance Counter 1 (R/W)
    Ia32Pmc1 = 0xc2,

    /// General Performance Counter 2 (R/W)
    Ia32Pmc2 = 0xc3,

    /// General Performance Counter 3 (R/W)
    Ia32Pmc3 = 0xc4,

    ///  Platform Information
    ///
    ///  Contains power management and other model specific features enumeration. See
    ///  <http://biosbits.org>.
    PlatformInfo = 0xce,

    /// Enumeration of Architectural Features (RO)
    Ia32ArchCapabilities = 0x10a,

    /// MISC_FEATURE_ENABLES
    ///
    /// Bit 1:
    ///
    /// User Mode MONITOR and MWAIT (R/W)
    ///
    /// If set to 1, the MONITOR and MWAIT instructions do not cause invalid-opcode
    /// exceptions when executed with CPL > 0 or in virtual-8086 mode. If MWAIT is
    /// executed when CPL > 0 or in virtual-8086 mode, and if EAX indicates a C-state
    /// other than C0 or C1, the instruction operates as if EAX indicated the C-state C1.
    MiscFeatureEnables = 0x140,

    /// CS Register Target for CPL 0 Code (R/W)
    Ia32SysenterCs = 0x174,

    /// Stack pointer for CPL 0 stack
    Ia32SysenterEsp = 0x175,

    /// CPL 0 code entry point
    Ia32SysenterEip = 0x176,

    /// Machine Check Error Reporting Register
    ///
    /// Contains information related to a machine-check error if its VAL (valid) flag is
    /// set. Software is responsible for clearing IA32_MCi_STATUS MSRs by explicitly
    /// writing 0s to them; writing 1s to them causes a general-protection exception.
    McgStatus = 0x17a,

    /// Machine Check Error Reporting Register
    ///
    /// Controls signaling of #MC for errors produced by a particular hardware unit (or
    /// group of hardware units).
    McgCtl = 0x17b,

    /// Performance Event Select Register 0 (R/W)
    PerfEvtSel0 = 0x186,

    /// Performance Event Select Register 1 (R/W)
    PerfEvtSel1 = 0x187,

    /// Performance Event Select for Counter 2 (R/W)
    Ia32PerfEvtSel2 = 0x188,

    /// Performance Event Select for Counter 3 (R/W)
    Ia32PerfEvtSel3 = 0x189,

    /// Enable Miscellaneous Processor Features (R/W)
    ///
    /// Allows a variety of processor functions to be enabled and disabled.
    ///
    /// Bits  Description
    /// 0     Fast-Strings Enable When set, the fast-strings feature (for REP MOVS and
    ///       REP STORS) is enabled (default). When clear, fast-strings are disabled.
    /// 2:1   Reserved
    /// 3     Automatic Thermal Control Circuit Enable (R/W)
    ///       1 = Setting this bit enables the thermal control circuit (TCC) portion of the
    ///         Intel Thermal Monitor feature. This allows the processor to automatically
    ///         reduce power consumption in response to TCC activation.
    ///       0 =Disabled.
    ///       Note: In some products clearing this bit might be ignored in critical thermal
    ///       conditions, and TM1, TM2 and adaptive thermal throttling will still be
    ///       activated.The default value of this field varies with product . See
    ///       respective tables where default value is listed.
    /// 6:4   Reserved
    /// 7     Performance Monitoring Available (R)
    ///       1 = Performance monitoring enabled.
    ///       0 = Performance monitoring disabled.
    /// 10:8  Reserved
    /// 11    Branch Trace Storage Unavailable (RO)
    ///       1 = Processor doesn’t support branch trace storage (BTS).
    ///       0 = BTS is supported.
    /// 12    Processor Event Based Sampling (PEBS) Unavailable (RO)
    ///       1 =  PEBS is not supported.
    ///       0 =  PEBS is supported.
    /// 15:13 Reserved
    /// 16    Enhanced Intel SpeedStep Technology Enable (R/W)
    ///       0 = Enhanced Intel SpeedStep Technology disabled.
    ///       1 = Enhanced Intel SpeedStep Technology enabled.
    ///
    /// 17    Reserved
    /// 18    ENABLE MONITOR FSM (R/W)
    ///       When this bit is set to 0, the MONITOR feature flag is not set
    ///       (CPUID.01H:ECX[bit 3] = 0). This indicates that MONITOR/MWAIT are not
    ///       supported.
    ///       Software attempts to execute MONITOR/MWAIT will cause #UD when this bit is
    ///       0.
    ///       When this bit is set to 1 (default), MONITOR/MWAIT are supported
    ///       (CPUID.01H:ECX[bit 3] = 1).
    ///       If the SSE3 feature flag `ECX[0]` is not set (CPUID.01H:ECX[bit 0] = 0), the
    ///       OS must not attempt to alter this bit. BIOS must leave it in the default
    ///       state. Writing this bit when the SSE3 feature flag is set to 0 may generate
    ///       a #GP exception.
    /// 21:19 Reserved
    /// 22    Limit CPUID Maxval (R/W)
    ///       When this bit is set to 1, CPUID.00H returns a maximum value in `EAX[7:0]`
    ///       of 2.
    ///       BIOS should contain a setup question that allows users to specify when the
    ///       installed OS does not support CPUID functions greater than 2.
    ///       Before setting this bit, BIOS must execute the CPUID.0H and examine the
    ///       maximum value returned in `EAX[7:0]`. If the maximum value is greater than 2,
    ///       this bit is supported.
    ///       Otherwise, this bit is not supported.
    ///       Setting this bit when the maximum value is not greater than 2 may generate
    ///       a #GP exception.
    ///       Setting this bit may cause unexpected behavior in software that depends on
    ///       the availability of CPUID leaves greater than 2.
    /// 23    xTPR Message Disable (R/W)
    ///       When set to 1, xTPR messages are disabled. xTPR messages are optional
    ///       messages that allow the processor to inform the chipset of its priority.
    /// 33:24 Reserved
    /// 34    XD Bit Disable (R/W)
    ///       When set to 1, the Execute Disable Bit feature (XD Bit) is disabled and the
    ///       XD Bit extended feature flag will be clear (CPUID.80000001H: `EDX[20]`=0).
    ///       When set to a 0 (default), the Execute Disable Bit feature (if available)
    ///       allows the OS to enable PAE paging and take advantage of data only pages.
    ///       BIOS must not alter the contents of this bit location, if XD bit is not
    ///       supported. Writing this bit to 1 when the XD Bit extended feature flag is
    ///       set to 0 may generate a #GP exception.
    Ia32MiscEnable = 0x1a0,

    /// Power Control Register. See <https://biosbits.org>
    PowerCtl = 0x1fc,

    /// Page Attribute Table
    Ia32Pat = 0x277,

    /// Fixed-Function Performance Counter 0 (R/W): Counts Instr_Retired.Any.
    Ia32FixedCtr0 = 0x309,

    /// Fixed-Function Performance Counter 1 (R/W): Counts CPU_CLK_Unhalted.Core.
    Ia32FixedCtr1 = 0x30a,

    /// Fixed-Function Performance Counter 2 (R/W): Counts CPU_CLK_Unhalted.Ref.
    Ia32FixedCt2 = 0x30b,

    /// Fixed-Function Performance Counter Control (R/W)
    ///
    /// Counter increments while the results of ANDing respective enable bit in
    /// IA32_PERF_GLOBAL_CTRL with the corresponding OS or USR bits in this MSR is true.
    Ia32FixedCtrCtrl = 0x38d,

    /// Global Performance Counter Status (RO)
    Ia32PerfGlobalStatus = 0x38e,

    /// Global Performance Counter Control (R/W)
    ///
    /// Counter increments while the result of ANDing the respective enable bit in this
    /// MSR with the corresponding OS or USR bits in the general-purpose or fixed counter
    /// control MSR is true.
    Ia32PerfGlobalCtrl = 0x38f,

    /// Global Performance Counter Overflow Control (R/W)
    Ia32PerfGlobalOvfCtrl = 0x390,

    /// Reporting Register of Basic VMX Capabilities (R/O)
    ///
    /// See Appendix A.1, “Basic VMX Information.”
    Ia32VmxBasic = 0x480,

    /// Reporting Register of Miscellaneous VMX Capabilities (R/O)
    ///
    /// See Appendix A.6, “Miscellaneous Data.”
    Ia32VmxMisc = 0x485,

    /// Capability Reporting Register of CR0 Bits Fixed to 0 (R/O)
    ///
    /// See Appendix A.7, “VMX-Fixed Bits in CR0.”
    Ia32VmxCr0Fixed0 = 0x486,

    /// Capability Reporting Register of CR4 Bits Fixed to 0 (R/O)
    ///
    /// See Appendix A.7, “VMX-Fixed Bits in CR4.”
    Ia32VmxCr4Fixed0 = 0x488,

    /// Capability Reporting Register of VMCS Field Enumeration (R/O)
    ///
    /// See Appendix A.9, “VMCS Enumeration.”
    Ia32VmxVmcsEnum = 0x48a,

    /// Capability Reporting Register of Secondary Processor-Based VM-Execution Controls
    /// (R/O)
    ///
    /// See Appendix A.3.3, “Secondary Processor-Based VM-Execution Controls.”
    Ia32VmxProcbasedCtls2 = 0x48b,

    /// Capability Reporting Register of EPT and VPID (R/O)
    ///
    /// See Appendix A.10, “VPID and EPT Capabilities.”
    Ia32VmxEptVpidCap = 0x48c,

    /// Capability Reporting Register of Pin-Based VM-Execution Flex Controls (R/O)
    ///
    /// See Appendix A.3.1, “Pin-Based VM-Execution Controls.”
    Ia32VmxTruePinBasedCtls = 0x48d,

    /// Capability Reporting Register of Primary Processor-Based VM-Execution Flex
    /// Controls (R/O)
    ///
    /// See Appendix A.3.2, “Primary Processor-Based VM-Execution Controls.”
    Ia32VmxTrueProcbasedCtls = 0x48e,

    /// Capability Reporting Register of VM-Exit Flex Controls (R/O)
    ///
    /// See Appendix A.4, “VM-Exit Controls.”
    Ia32VmxTrueExitCtls = 0x48f,

    /// Capability Reporting Register of VM-Entry Flex Controls (R/O)
    ///
    /// See Appendix A.5, “VM-Entry Controls.”
    Ia32VmxTrueEntryCtls = 0x490,

    /// Capability Reporting Register of VM-Function Controls (R/O)
    Ia32VmxVmfunc = 0x491,

    /// Allows software to signal some MCEs to only a single logical processor in the
    /// system. (R/W)
    ///
    /// See Section 15.3.1.4, “IA32_MCG_EXT_CTL MSR”.
    Ia32McgExtCtl = 0x4d0,

    /// TSC Target of Local APIC’s TSC Deadline Mode (R/W)
    Ia32TscDeadlint = 0x6e0,

    /// Supervisor State of MPX Configuration (R/W)
    Ia32Bndcfgs = 0xd90,

    /// Msr used to identify the guest OS
    HvX86GuestOsId = 0x4000_0000,

    /// MSR used to setup pages used to communicate with the hypervisor
    HvX86MsrHypercall = 0x4000_0001,

    /// MSR used to provide vcpu index
    HvRegisterVpIndex = 0x4000_0002,

    /// MSR used to reset the guest OS
    HvX64MsrReset = 0x4000_0003,

    /// MSR used to provide vcpu runtime in 100ns units
    HvX64MsrVpRuntime = 0x4000_0010,

    /// MSR used to read the per-partition time reference counter
    HvRegisterTimeRefCount = 0x4000_0020,

    /// A partition's reference time stamp counter (TSC) page
    HvRegisterReferenceTsc = 0x4000_0021,

    /// MSR used to retrieve the TSC frequency
    HvX64MsrTscFrequency = 0x4000_0022,

    /// MSR used to retrieve the local APIC timer frequency
    HvX64MsrApicFrequency = 0x4000_0023,

    /// VP Assist Page
    HvX64MsrVpAssistPage = 0x4000_0073,

    /// Synthetic interrupt controller model specific registers
    HvRegisterSControl = 0x4000_0080,

    /// Synthetic timer MSRs. Four timers per vcpu
    HvRegisterSTimer0Config = 0x4000_00b0,

    /// Hyper-V guest crash notification MSRs 0
    HvRegisterCrashP0 = 0x4000_0100,

    /// Hyper-V guest crash notification MSRs 1
    HvRegisterCrashP1 = 0x4000_0101,

    /// Hyper-V guest crash notification MSRs 2
    HvRegisterCrashP2 = 0x4000_0102,

    /// Hyper-V guest crash notification MSRs 3
    HvRegisterCrashP3 = 0x4000_0103,

    /// Hyper-V guest crash notification MSRs 4
    HvRegisterCrashP4 = 0x4000_0104,

    /// Hyper-V guest crash control
    HvRegisterCrashCtl = 0x4000_0105,

    /// Re-enlightment Control
    HvX64MsrReenlightenmentControl = 0x4000_0106,

    /// TSC Emulation Control
    HvX64TscEmulationControl = 0x4000_0107,

    /// TSC Emulation Status
    HvX64TscEmulationStatus = 0x4000_0108,

    /// KVM wall clock
    KvmWallClockNew = 0x4b56_4d00,

    /// KVM system clock
    KvmSystemTimeNew = 0x4b56_4d01,

    /// KVM Async PF enable
    KvmAsyncPfEn = 0x4b56_4d02,

    /// KVM Steal Time
    KvmStealTime = 0x4b56_4d03,

    /// KVM PV EOI EN
    KvmPvEoiEn = 0x4b56_4d04,

    /// KVM Poll Control
    KvmPollControl = 0x4b56_4d05,

    /// Extended feature Enables
    Ia32Efer = 0xc000_0080,

    /// System Call Target Address (R/W)
    Ia32Star = 0xc000_0081,

    /// IA-32e Mode System Call Target Address (R/W)
    ///
    /// Target RIP for the called procedure when SYSCALL is executed in 64-bit mode.
    Ia32Lstar = 0xc000_0082,

    /// IA-32e Mode System Call Target Address (R/W)
    ///
    /// Not used, as the SYSCALL instruction is not recognized in compatibility mode.
    Ia32Cstar = 0xc000_0083,

    /// System Call Flag Mask (R/W)
    Ia32Fmask = 0xc000_0084,

    /// Map of BASE address of FS (R/W)
    Ia32FsBase = 0xc000_0100,

    /// Map of BASE address of GS (R/W)
    Ia32GsBase = 0xc000_0101,

    /// Swap Target of BASE Address of GS (R/W)
    Ia32KernelGsBase = 0xc000_0102,

    /// Auxiliary TSC (RW)
    Ia32TsxAux = 0xc000_0103,

    /// K7Hwcr (unknown?)
    K7Hwcr = 0xc001_0015,
}
