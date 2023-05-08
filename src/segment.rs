//! Segment descriptor helpers

use kvm_bindings::kvm_segment;

/// Indicates the segment or gate type and specifies the kinds of access that can be made
/// to the segment and the direction of growth.
#[allow(dead_code)]
#[derive(Debug, Copy, Clone)]
pub enum DescriptorType {
    /// Code segment
    Code,

    /// Data segment
    Data,
}

/// Various accesses available for a given segment
#[allow(dead_code)]
#[derive(Debug, Copy, Clone)]
pub enum Access {
    /// Read only
    ReadOnly = 0,

    /// Read only, accessed
    ReadOnlyAccessed = 1,

    /// Read and Write
    ReadWrite = 2,

    /// Read and Write, accessed
    ReadWriteAccessed = 3,

    /// Execute only
    ExecuteOnly = 8,

    /// Execute only, accessed
    ExecuteOnlyAccessed = 9,

    /// Execute and Read
    ExecuteRead = 10,

    /// Execute and Read, accessed
    ExecuteReadAccessed = 11,
}

/// Privilege level
#[allow(dead_code)]
#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum Privilege {
    /// Ring 0 privilege for Operating System / Kernel access
    Level0,

    /// Ring 1 privilege for Operating System Services
    Level1,

    /// Ring 2 privilege for Operating System Services
    Level2,

    /// Ring 3 privilege for Applications
    Level3,
}

/// A segment descriptor
#[derive(Debug, Copy, Clone)]
pub struct Descriptor {
    /// Defines the byte 0 of the segment within the 4-GByte linear addrses space
    base: Option<u64>,

    /// Specifies the size of the segment
    limit: u32,

    /// Index into the GDT of the selector for this segment
    selector: u16,

    /// Code or Data segment
    type_: Option<DescriptorType>,

    /// Read/Write/Execute access for this segment
    access: Access,

    /// Specifies whether the segment descriptor is for a system segment (S)
    system: bool,

    /// Specifies the privilege level of the segment (DPL)
    descriptor_privilege: Privilege,

    /// Indicates whether the segment is present in memory or not (P)
    present: bool,

    /// Determines the scaling of the segment limit field
    granularity: bool,
}

impl Descriptor {
    /// Create a [`kvm_segment`] from the [`Descriptor`]
    #[allow(dead_code)]
    pub fn to_kvm_segment(self) -> kvm_segment {
        // Sanity check to ensure this segment has a base value
        assert!(
            self.base.is_some(),
            "Attempted to create kvm_segment with no base"
        );
        assert!(
            self.type_.is_some(),
            "Attempted to create kvm_segment with no type"
        );

        // Get the current code/data type of the segment
        let curr_type = self.type_.unwrap();

        // Construct the type from Table 3-1. Code- and Data-Segment Types from Intel
        // Manual at 3.4.5.1
        let type_ = match (curr_type, self.access) {
            (DescriptorType::Data, Access::ReadOnly) => 0,
            (DescriptorType::Data, Access::ReadOnlyAccessed) => 1,
            (DescriptorType::Data, Access::ReadWrite) => 2,
            (DescriptorType::Data, Access::ReadWriteAccessed) => 3,
            (DescriptorType::Data, _) => {
                panic!("Access {:?} unavailable with Data segment", self.access);
            }
            (DescriptorType::Code, Access::ExecuteOnly) => 8,
            (DescriptorType::Code, Access::ExecuteOnlyAccessed) => 9,
            (DescriptorType::Code, Access::ExecuteRead) => 10,
            (DescriptorType::Code, Access::ExecuteReadAccessed) => 11,
            (DescriptorType::Code, _) => {
                panic!("Access {:?} unavailable with Code segment", self.access);
            }
        };

        kvm_segment {
            base: self.base.unwrap(),
            limit: self.limit,
            selector: self.selector,
            type_: type_,
            present: self.present.into(),
            dpl: self.descriptor_privilege as u8,
            db: 0,
            s: self.system.into(),
            l: matches!(self.type_, Some(DescriptorType::Code)).into(),
            // l: 1,
            g: self.granularity.into(),
            avl: 1,
            unusable: 0,
            padding: 0,
        }
    }

    /// Create a [`Descriptor`] from a given [`kvm_segment`]
    #[allow(dead_code)]
    pub fn from_kvm_segment(seg: &kvm_segment) -> Self {
        // Re-create the code/data type and access from the segment type_ variable
        let (type_, access) = match seg.type_ {
            0 => (DescriptorType::Data, Access::ReadOnly),
            1 => (DescriptorType::Data, Access::ReadOnlyAccessed),
            2 => (DescriptorType::Data, Access::ReadWrite),
            3 => (DescriptorType::Data, Access::ReadWriteAccessed),
            8 => (DescriptorType::Code, Access::ExecuteOnly),
            9 => (DescriptorType::Code, Access::ExecuteOnlyAccessed),
            10 => (DescriptorType::Code, Access::ExecuteRead),
            11 => (DescriptorType::Code, Access::ExecuteReadAccessed),
            _ => panic!("Unknown type_ from segment: {:?}\n", seg.type_),
        };

        let desc_priv = match seg.dpl {
            0 => Privilege::Level0,
            1 => Privilege::Level1,
            2 => Privilege::Level2,
            3 => Privilege::Level3,
            _ => panic!("Unknown privilege level"),
        };

        Self {
            base: Some(seg.base),
            limit: seg.limit,
            selector: seg.selector,
            type_: Some(type_),
            access,
            system: seg.s == 1,
            descriptor_privilege: desc_priv,
            present: seg.present == 1,
            granularity: seg.g == 1,
        }
    }
}
