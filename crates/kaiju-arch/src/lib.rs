#![forbid(unsafe_code)]

use kaiju_core::{ArchitectureId, Endian};

pub trait Architecture {
    fn id(&self) -> ArchitectureId;

    fn name(&self) -> &'static str;

    fn pointer_width(&self) -> u8;

    fn endian(&self) -> Endian;

    fn registers(&self) -> &'static [RegisterInfo] {
        &[]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltinArchitecture {
    id: ArchitectureId,
    name: &'static str,
    pointer_width: u8,
    endian: Endian,
    registers: &'static [RegisterInfo],
}

impl BuiltinArchitecture {
    #[must_use]
    pub const fn new(
        id: ArchitectureId,
        name: &'static str,
        pointer_width: u8,
        endian: Endian,
        registers: &'static [RegisterInfo],
    ) -> Self {
        Self {
            id,
            name,
            pointer_width,
            endian,
            registers,
        }
    }
}

impl Architecture for BuiltinArchitecture {
    fn id(&self) -> ArchitectureId {
        self.id
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn pointer_width(&self) -> u8 {
        self.pointer_width
    }

    fn endian(&self) -> Endian {
        self.endian
    }

    fn registers(&self) -> &'static [RegisterInfo] {
        self.registers
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterInfo {
    pub name: &'static str,
    pub bit_width: u16,
    pub role: RegisterRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterRole {
    General,
    StackPointer,
    FramePointer,
    InstructionPointer,
    Flags,
    Unknown,
}

pub const X86_64_REGISTERS: &[RegisterInfo] = &[
    RegisterInfo {
        name: "rax",
        bit_width: 64,
        role: RegisterRole::General,
    },
    RegisterInfo {
        name: "rbx",
        bit_width: 64,
        role: RegisterRole::General,
    },
    RegisterInfo {
        name: "rcx",
        bit_width: 64,
        role: RegisterRole::General,
    },
    RegisterInfo {
        name: "rdx",
        bit_width: 64,
        role: RegisterRole::General,
    },
    RegisterInfo {
        name: "rsp",
        bit_width: 64,
        role: RegisterRole::StackPointer,
    },
    RegisterInfo {
        name: "rbp",
        bit_width: 64,
        role: RegisterRole::FramePointer,
    },
    RegisterInfo {
        name: "rip",
        bit_width: 64,
        role: RegisterRole::InstructionPointer,
    },
    RegisterInfo {
        name: "rflags",
        bit_width: 64,
        role: RegisterRole::Flags,
    },
];

pub const X86_REGISTERS: &[RegisterInfo] = &[
    RegisterInfo {
        name: "eax",
        bit_width: 32,
        role: RegisterRole::General,
    },
    RegisterInfo {
        name: "esp",
        bit_width: 32,
        role: RegisterRole::StackPointer,
    },
    RegisterInfo {
        name: "ebp",
        bit_width: 32,
        role: RegisterRole::FramePointer,
    },
    RegisterInfo {
        name: "eip",
        bit_width: 32,
        role: RegisterRole::InstructionPointer,
    },
    RegisterInfo {
        name: "eflags",
        bit_width: 32,
        role: RegisterRole::Flags,
    },
];

pub const BUILTIN_ARCHITECTURES: &[BuiltinArchitecture] = &[
    BuiltinArchitecture::new(
        ArchitectureId::X86,
        "x86",
        32,
        Endian::Little,
        X86_REGISTERS,
    ),
    BuiltinArchitecture::new(
        ArchitectureId::X86_64,
        "x86_64",
        64,
        Endian::Little,
        X86_64_REGISTERS,
    ),
    BuiltinArchitecture::new(ArchitectureId::Arm, "arm", 32, Endian::Little, &[]),
    BuiltinArchitecture::new(ArchitectureId::Aarch64, "aarch64", 64, Endian::Little, &[]),
    BuiltinArchitecture::new(ArchitectureId::Unknown, "unknown", 0, Endian::Unknown, &[]),
];

#[must_use]
pub fn builtin_architecture(id: ArchitectureId) -> &'static BuiltinArchitecture {
    BUILTIN_ARCHITECTURES
        .iter()
        .find(|architecture| architecture.id() == id)
        .unwrap_or(&BUILTIN_ARCHITECTURES[4])
}

#[must_use]
pub fn builtin_architectures() -> &'static [BuiltinArchitecture] {
    BUILTIN_ARCHITECTURES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_x86_64_architecture_descriptor() {
        let architecture = builtin_architecture(ArchitectureId::X86_64);

        assert_eq!(architecture.name(), "x86_64");
        assert_eq!(architecture.pointer_width(), 64);
        assert_eq!(architecture.endian(), Endian::Little);
        assert!(architecture
            .registers()
            .iter()
            .any(|register| register.role == RegisterRole::InstructionPointer));
    }

    #[test]
    fn unknown_architecture_is_safe_default() {
        let architecture = builtin_architecture(ArchitectureId::Unknown);

        assert_eq!(architecture.name(), "unknown");
        assert_eq!(architecture.pointer_width(), 0);
        assert!(architecture.registers().is_empty());
    }
}
