#![forbid(unsafe_code)]

use std::fmt;

use kaiju_core::{Address, ArchitectureId, KaijuError, KaijuErrorKind, Result};

pub trait Disassembler {
    fn architecture(&self) -> ArchitectureId;

    fn disassemble_one(&self, bytes: &[u8], address: Address) -> Result<Instruction>;

    fn disassemble_block(
        &self,
        bytes: &[u8],
        start: Address,
        max_instructions: usize,
    ) -> Result<Vec<Instruction>> {
        let mut instructions = Vec::new();
        let mut offset = 0_usize;
        let mut address = start;

        while offset < bytes.len() && instructions.len() < max_instructions {
            let instruction = self.disassemble_one(&bytes[offset..], address)?;
            let size = usize::from(instruction.size);
            if size == 0 {
                return Err(KaijuError::new(
                    KaijuErrorKind::DecodeError,
                    "decoder returned a zero-sized instruction",
                ));
            }

            offset = offset.checked_add(size).ok_or_else(|| {
                KaijuError::new(KaijuErrorKind::DecodeError, "instruction offset overflow")
            })?;
            address = address.checked_add(size as u64).ok_or_else(|| {
                KaijuError::new(
                    KaijuErrorKind::InvalidAddress,
                    "instruction address overflow",
                )
            })?;
            instructions.push(instruction);
        }

        Ok(instructions)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    pub address: Address,
    pub size: u8,
    pub mnemonic: String,
    pub operands: Vec<Operand>,
    pub bytes: Vec<u8>,
    pub flow: FlowKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operand {
    Register(String),
    Immediate(u64),
    Memory(String),
    Address(Address),
    Text(String),
}

impl fmt::Display for Operand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Register(register) | Self::Memory(register) | Self::Text(register) => {
                formatter.write_str(register)
            }
            Self::Immediate(value) => write!(formatter, "0x{value:x}"),
            Self::Address(address) => write!(formatter, "{address}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowKind {
    Normal,
    Call { target: Option<Address> },
    Jump { target: Option<Address> },
    ConditionalJump { target: Option<Address> },
    Return,
    Trap,
    Unknown,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct X86_64Disassembler;

impl X86_64Disassembler {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Disassembler for X86_64Disassembler {
    fn architecture(&self) -> ArchitectureId {
        ArchitectureId::X86_64
    }

    fn disassemble_one(&self, bytes: &[u8], address: Address) -> Result<Instruction> {
        decode_x86_64(bytes, address)
    }
}

pub fn disassembler_for_architecture(architecture: ArchitectureId) -> Result<X86_64Disassembler> {
    match architecture {
        ArchitectureId::X86_64 => Ok(X86_64Disassembler::new()),
        unsupported => Err(KaijuError::new(
            KaijuErrorKind::UnsupportedArchitecture,
            format!("disassembly is not supported for {unsupported}"),
        )),
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct RexPrefix {
    w: bool,
    r: bool,
    b: bool,
}

fn decode_x86_64(bytes: &[u8], address: Address) -> Result<Instruction> {
    if bytes.is_empty() {
        return Err(KaijuError::new(
            KaijuErrorKind::DecodeError,
            format!("no bytes available at {address}"),
        ));
    }

    let mut index = 0_usize;
    let mut rex = RexPrefix::default();
    if let Some(prefix) = bytes
        .first()
        .copied()
        .filter(|byte| (0x40..=0x4f).contains(byte))
    {
        rex = RexPrefix {
            w: prefix & 0x08 != 0,
            r: prefix & 0x04 != 0,
            b: prefix & 0x01 != 0,
        };
        index = 1;
    }

    let Some(opcode) = bytes.get(index).copied() else {
        return Ok(unknown_instruction(bytes, address));
    };

    match opcode {
        0x90 => Ok(no_operand(
            address,
            bytes,
            index + 1,
            "nop",
            FlowKind::Normal,
        )),
        0xc3 => Ok(no_operand(
            address,
            bytes,
            index + 1,
            "ret",
            FlowKind::Return,
        )),
        0xcc => Ok(no_operand(
            address,
            bytes,
            index + 1,
            "int3",
            FlowKind::Trap,
        )),
        0x50..=0x57 => Ok(single_operand(
            address,
            bytes,
            index + 1,
            "push",
            Operand::Register(register_name((opcode - 0x50) | rex_b(&rex), true).to_string()),
            FlowKind::Normal,
        )),
        0x58..=0x5f => Ok(single_operand(
            address,
            bytes,
            index + 1,
            "pop",
            Operand::Register(register_name((opcode - 0x58) | rex_b(&rex), true).to_string()),
            FlowKind::Normal,
        )),
        0xb8..=0xbf => decode_mov_imm(bytes, address, index, opcode, rex),
        0xe8 => decode_relative(bytes, address, index, 4, "call", RelativeFlow::Call),
        0xe9 => decode_relative(bytes, address, index, 4, "jmp", RelativeFlow::Jump),
        0xeb => decode_relative(bytes, address, index, 1, "jmp", RelativeFlow::Jump),
        0x70..=0x7f => {
            let mnemonic = jcc_mnemonic(opcode - 0x70);
            decode_relative(
                bytes,
                address,
                index,
                1,
                mnemonic,
                RelativeFlow::ConditionalJump,
            )
        }
        0x0f => decode_two_byte_opcode(bytes, address, index, rex),
        0x09 => decode_modrm_reg_reg(bytes, address, index, rex, "or", OperandOrder::RmReg),
        0x0b => decode_modrm_reg_reg(bytes, address, index, rex, "or", OperandOrder::RegRm),
        0x21 => decode_modrm_reg_reg(bytes, address, index, rex, "and", OperandOrder::RmReg),
        0x23 => decode_modrm_reg_reg(bytes, address, index, rex, "and", OperandOrder::RegRm),
        0x89 => decode_modrm_reg_reg(bytes, address, index, rex, "mov", OperandOrder::RmReg),
        0x8b => decode_modrm_reg_reg(bytes, address, index, rex, "mov", OperandOrder::RegRm),
        0x01 => decode_modrm_reg_reg(bytes, address, index, rex, "add", OperandOrder::RmReg),
        0x03 => decode_modrm_reg_reg(bytes, address, index, rex, "add", OperandOrder::RegRm),
        0x29 => decode_modrm_reg_reg(bytes, address, index, rex, "sub", OperandOrder::RmReg),
        0x2b => decode_modrm_reg_reg(bytes, address, index, rex, "sub", OperandOrder::RegRm),
        0x31 => decode_modrm_reg_reg(bytes, address, index, rex, "xor", OperandOrder::RmReg),
        0x33 => decode_modrm_reg_reg(bytes, address, index, rex, "xor", OperandOrder::RegRm),
        0x39 => decode_modrm_reg_reg(bytes, address, index, rex, "cmp", OperandOrder::RmReg),
        0x3b => decode_modrm_reg_reg(bytes, address, index, rex, "cmp", OperandOrder::RegRm),
        0x85 => decode_modrm_reg_reg(bytes, address, index, rex, "test", OperandOrder::RmReg),
        0x83 => decode_group83(bytes, address, index, rex),
        _ => Ok(unknown_instruction(bytes, address)),
    }
}

fn decode_two_byte_opcode(
    bytes: &[u8],
    address: Address,
    index: usize,
    rex: RexPrefix,
) -> Result<Instruction> {
    let Some(opcode) = bytes.get(index + 1).copied() else {
        return Ok(unknown_instruction(bytes, address));
    };

    match opcode {
        0x80..=0x8f => {
            let mnemonic = jcc_mnemonic(opcode - 0x80);
            decode_relative(
                bytes,
                address,
                index + 1,
                4,
                mnemonic,
                RelativeFlow::ConditionalJump,
            )
        }
        0xaf => decode_modrm_reg_reg(bytes, address, index + 1, rex, "imul", OperandOrder::RegRm),
        _ => Ok(unknown_instruction(bytes, address)),
    }
}

fn decode_mov_imm(
    bytes: &[u8],
    address: Address,
    index: usize,
    opcode: u8,
    rex: RexPrefix,
) -> Result<Instruction> {
    let imm_len = if rex.w { 8 } else { 4 };
    let size = index + 1 + imm_len;
    let Some(imm_bytes) = bytes.get(index + 1..size) else {
        return Ok(unknown_instruction(bytes, address));
    };
    let mut value = 0_u64;
    for (shift, byte) in imm_bytes.iter().enumerate() {
        value |= u64::from(*byte) << (shift * 8);
    }

    Ok(instruction(
        address,
        bytes,
        size,
        "mov",
        vec![
            Operand::Register(register_name((opcode - 0xb8) | rex_b(&rex), rex.w).to_string()),
            Operand::Immediate(value),
        ],
        FlowKind::Normal,
    ))
}

#[derive(Debug, Clone, Copy)]
enum OperandOrder {
    RmReg,
    RegRm,
}

fn decode_modrm_reg_reg(
    bytes: &[u8],
    address: Address,
    opcode_index: usize,
    rex: RexPrefix,
    mnemonic: &str,
    order: OperandOrder,
) -> Result<Instruction> {
    let Some(modrm) = bytes.get(opcode_index + 1).copied() else {
        return Ok(unknown_instruction(bytes, address));
    };
    let Some((reg, rm)) = direct_register_operands(modrm, rex) else {
        return Ok(unknown_instruction(bytes, address));
    };
    let width64 = rex.w;
    let reg = Operand::Register(register_name(reg, width64).to_string());
    let rm = Operand::Register(register_name(rm, width64).to_string());
    let operands = match order {
        OperandOrder::RmReg => vec![rm, reg],
        OperandOrder::RegRm => vec![reg, rm],
    };

    Ok(instruction(
        address,
        bytes,
        opcode_index + 2,
        mnemonic,
        operands,
        FlowKind::Normal,
    ))
}

fn decode_group83(
    bytes: &[u8],
    address: Address,
    opcode_index: usize,
    rex: RexPrefix,
) -> Result<Instruction> {
    let Some(modrm) = bytes.get(opcode_index + 1).copied() else {
        return Ok(unknown_instruction(bytes, address));
    };
    let Some(imm) = bytes.get(opcode_index + 2).copied() else {
        return Ok(unknown_instruction(bytes, address));
    };
    let Some((reg, rm)) = direct_register_operands(modrm, rex) else {
        return Ok(unknown_instruction(bytes, address));
    };
    let mnemonic = match reg & 0x7 {
        0 => "add",
        5 => "sub",
        7 => "cmp",
        _ => return Ok(unknown_instruction(bytes, address)),
    };

    Ok(instruction(
        address,
        bytes,
        opcode_index + 3,
        mnemonic,
        vec![
            Operand::Register(register_name(rm, rex.w).to_string()),
            signed_imm8_operand(imm),
        ],
        FlowKind::Normal,
    ))
}

fn direct_register_operands(modrm: u8, rex: RexPrefix) -> Option<(u8, u8)> {
    if modrm >> 6 != 0b11 {
        return None;
    }

    let reg = ((modrm >> 3) & 0x7) | rex_r(&rex);
    let rm = (modrm & 0x7) | rex_b(&rex);
    Some((reg, rm))
}

#[derive(Debug, Clone, Copy)]
enum RelativeFlow {
    Call,
    Jump,
    ConditionalJump,
}

fn decode_relative(
    bytes: &[u8],
    address: Address,
    opcode_index: usize,
    displacement_len: usize,
    mnemonic: &str,
    flow: RelativeFlow,
) -> Result<Instruction> {
    let size = opcode_index + 1 + displacement_len;
    let Some(displacement_bytes) = bytes.get(opcode_index + 1..size) else {
        return Ok(unknown_instruction(bytes, address));
    };
    let displacement = match displacement_len {
        1 => i64::from(i8::from_le_bytes([displacement_bytes[0]])),
        4 => i64::from(i32::from_le_bytes([
            displacement_bytes[0],
            displacement_bytes[1],
            displacement_bytes[2],
            displacement_bytes[3],
        ])),
        _ => {
            return Err(KaijuError::new(
                KaijuErrorKind::DecodeError,
                "unsupported relative displacement width",
            ))
        }
    };
    let target = relative_target(address, size as u64, displacement);
    let flow = match flow {
        RelativeFlow::Call => FlowKind::Call { target },
        RelativeFlow::Jump => FlowKind::Jump { target },
        RelativeFlow::ConditionalJump => FlowKind::ConditionalJump { target },
    };
    let operand = target.map_or_else(
        || Operand::Text("<invalid-target>".to_string()),
        Operand::Address,
    );

    Ok(instruction(
        address,
        bytes,
        size,
        mnemonic,
        vec![operand],
        flow,
    ))
}

fn relative_target(address: Address, instruction_size: u64, displacement: i64) -> Option<Address> {
    let base = address.checked_add(instruction_size)?;
    if displacement >= 0 {
        base.checked_add(displacement as u64)
    } else {
        base.checked_sub(displacement.unsigned_abs())
    }
}

fn no_operand(
    address: Address,
    bytes: &[u8],
    size: usize,
    mnemonic: &str,
    flow: FlowKind,
) -> Instruction {
    instruction(address, bytes, size, mnemonic, Vec::new(), flow)
}

fn single_operand(
    address: Address,
    bytes: &[u8],
    size: usize,
    mnemonic: &str,
    operand: Operand,
    flow: FlowKind,
) -> Instruction {
    instruction(address, bytes, size, mnemonic, vec![operand], flow)
}

fn instruction(
    address: Address,
    bytes: &[u8],
    size: usize,
    mnemonic: &str,
    operands: Vec<Operand>,
    flow: FlowKind,
) -> Instruction {
    let bytes = bytes.get(..size).unwrap_or(bytes).to_vec();
    Instruction {
        address,
        size: size.min(u8::MAX as usize) as u8,
        mnemonic: mnemonic.to_string(),
        operands,
        bytes,
        flow,
    }
}

fn unknown_instruction(bytes: &[u8], address: Address) -> Instruction {
    let byte = bytes.first().copied().unwrap_or(0);
    instruction(
        address,
        bytes,
        1,
        "db",
        vec![Operand::Text(format!("0x{byte:02x}"))],
        FlowKind::Unknown,
    )
}

fn rex_r(rex: &RexPrefix) -> u8 {
    if rex.r {
        8
    } else {
        0
    }
}

fn rex_b(rex: &RexPrefix) -> u8 {
    if rex.b {
        8
    } else {
        0
    }
}

fn register_name(index: u8, width64: bool) -> &'static str {
    let index = usize::from(index & 0xf);
    if width64 {
        [
            "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11",
            "r12", "r13", "r14", "r15",
        ][index]
    } else {
        [
            "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d",
            "r12d", "r13d", "r14d", "r15d",
        ][index]
    }
}

fn signed_imm8_operand(value: u8) -> Operand {
    let value = i8::from_le_bytes([value]);
    if value < 0 {
        Operand::Text(format!("-0x{:x}", value.unsigned_abs()))
    } else {
        Operand::Immediate(value as u64)
    }
}

fn jcc_mnemonic(condition: u8) -> &'static str {
    match condition & 0xf {
        0x0 => "jo",
        0x1 => "jno",
        0x2 => "jb",
        0x3 => "jae",
        0x4 => "je",
        0x5 => "jne",
        0x6 => "jbe",
        0x7 => "ja",
        0x8 => "js",
        0x9 => "jns",
        0xa => "jp",
        0xb => "jnp",
        0xc => "jl",
        0xd => "jge",
        0xe => "jle",
        _ => "jg",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_simple_function_prologue() {
        let disassembler = X86_64Disassembler::new();
        let instructions = disassembler
            .disassemble_block(
                &[0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3],
                Address::new(0x401000),
                4,
            )
            .expect("disassemble");

        assert_eq!(instructions.len(), 4);
        assert_eq!(instructions[0].mnemonic, "push");
        assert_eq!(
            instructions[0].operands[0],
            Operand::Register("rbp".to_string())
        );
        assert_eq!(instructions[1].mnemonic, "mov");
        assert_eq!(
            instructions[1].operands[0],
            Operand::Register("rbp".to_string())
        );
        assert_eq!(
            instructions[1].operands[1],
            Operand::Register("rsp".to_string())
        );
        assert_eq!(instructions[3].flow, FlowKind::Return);
    }

    #[test]
    fn decodes_relative_call_and_conditional_jump() {
        let disassembler = X86_64Disassembler::new();
        let call = disassembler
            .disassemble_one(&[0xe8, 0x05, 0x00, 0x00, 0x00], Address::new(0x1000))
            .expect("call");
        let jump = disassembler
            .disassemble_one(&[0x75, 0xf9], Address::new(0x100a))
            .expect("jump");

        assert_eq!(call.mnemonic, "call");
        assert_eq!(
            call.flow,
            FlowKind::Call {
                target: Some(Address::new(0x100a))
            }
        );
        assert_eq!(jump.mnemonic, "jne");
        assert_eq!(
            jump.flow,
            FlowKind::ConditionalJump {
                target: Some(Address::new(0x1005))
            }
        );
    }

    #[test]
    fn reports_unsupported_architecture() {
        let error = disassembler_for_architecture(ArchitectureId::Arm)
            .expect_err("arm should not be supported yet");

        assert_eq!(error.kind(), KaijuErrorKind::UnsupportedArchitecture);
    }

    #[test]
    fn decodes_logic_compare_and_test_register_ops() {
        let disassembler = X86_64Disassembler::new();

        let and = disassembler
            .disassemble_one(&[0x48, 0x21, 0xd8], Address::new(0x2000))
            .expect("and");
        let or = disassembler
            .disassemble_one(&[0x48, 0x09, 0xd8], Address::new(0x2003))
            .expect("or");
        let cmp = disassembler
            .disassemble_one(&[0x48, 0x39, 0xd8], Address::new(0x2006))
            .expect("cmp");
        let test = disassembler
            .disassemble_one(&[0x48, 0x85, 0xd8], Address::new(0x2009))
            .expect("test");

        assert_eq!(and.mnemonic, "and");
        assert_eq!(or.mnemonic, "or");
        assert_eq!(cmp.mnemonic, "cmp");
        assert_eq!(test.mnemonic, "test");
    }
}
