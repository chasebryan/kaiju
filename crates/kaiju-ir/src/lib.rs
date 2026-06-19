#![forbid(unsafe_code)]

use std::fmt;

use kaiju_core::Address;
use kaiju_disasm::{FlowKind, Instruction, Operand};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IrModule {
    pub functions: Vec<IrFunction>,
}

impl IrModule {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            functions: Vec::new(),
        }
    }

    pub fn add_function(&mut self, function: IrFunction) {
        self.functions.push(function);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrFunction {
    pub name: Option<String>,
    pub address: Address,
    pub blocks: Vec<IrBlock>,
}

impl IrFunction {
    #[must_use]
    pub fn new(address: Address) -> Self {
        Self {
            name: None,
            address,
            blocks: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrBlock {
    pub label: String,
    pub instructions: Vec<IrInstruction>,
}

impl IrBlock {
    #[must_use]
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            instructions: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrInstruction {
    Assign {
        dst: IrValue,
        src: IrExpr,
    },
    Load {
        dst: IrValue,
        address: IrExpr,
        size: u8,
    },
    Store {
        address: IrExpr,
        value: IrExpr,
        size: u8,
    },
    Branch {
        target: String,
    },
    CondBranch {
        condition: IrExpr,
        then_target: String,
        else_target: String,
    },
    Call {
        target: IrExpr,
        args: Vec<IrExpr>,
        result: Option<IrValue>,
    },
    Return {
        value: Option<IrExpr>,
    },
    Nop,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrExpr {
    Const(u64),
    Var(IrValue),
    Add(Box<IrExpr>, Box<IrExpr>),
    Sub(Box<IrExpr>, Box<IrExpr>),
    Mul(Box<IrExpr>, Box<IrExpr>),
    And(Box<IrExpr>, Box<IrExpr>),
    Or(Box<IrExpr>, Box<IrExpr>),
    Xor(Box<IrExpr>, Box<IrExpr>),
    Not(Box<IrExpr>),
    Eq(Box<IrExpr>, Box<IrExpr>),
    Ne(Box<IrExpr>, Box<IrExpr>),
    Lt(Box<IrExpr>, Box<IrExpr>),
    Le(Box<IrExpr>, Box<IrExpr>),
    Gt(Box<IrExpr>, Box<IrExpr>),
    Ge(Box<IrExpr>, Box<IrExpr>),
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrValue {
    Temp(u32),
    Register(String),
    Local(String),
    Global(Address),
}

#[must_use]
pub fn lift_instructions(function_address: Address, instructions: &[Instruction]) -> IrFunction {
    let mut function = IrFunction {
        name: Some(format!("sub_{:x}", function_address.value())),
        address: function_address,
        blocks: vec![IrBlock::new(block_label(function_address))],
    };

    if let Some(block) = function.blocks.first_mut() {
        for instruction in instructions {
            block.instructions.push(lift_instruction(instruction));
        }
    }

    function
}

#[must_use]
pub fn lift_instruction(instruction: &Instruction) -> IrInstruction {
    match instruction.mnemonic.as_str() {
        "nop" => IrInstruction::Nop,
        "mov" => lift_mov(instruction),
        "add" => lift_binary_assign(instruction, IrBinaryOp::Add),
        "sub" => lift_binary_assign(instruction, IrBinaryOp::Sub),
        "xor" => lift_binary_assign(instruction, IrBinaryOp::Xor),
        "and" => lift_binary_assign(instruction, IrBinaryOp::And),
        "or" => lift_binary_assign(instruction, IrBinaryOp::Or),
        "cmp" => lift_compare(instruction, IrBinaryOp::Sub),
        "test" => lift_compare(instruction, IrBinaryOp::And),
        "jmp" => lift_branch(instruction),
        "call" => lift_call(instruction),
        "ret" => IrInstruction::Return { value: None },
        "push" => lift_push(instruction),
        "pop" => lift_pop(instruction),
        mnemonic if is_conditional_jump(mnemonic) => lift_cond_branch(instruction),
        _ => match instruction.flow {
            FlowKind::Return => IrInstruction::Return { value: None },
            FlowKind::Jump { .. } => lift_branch(instruction),
            FlowKind::ConditionalJump { .. } => lift_cond_branch(instruction),
            FlowKind::Call { .. } => lift_call(instruction),
            _ => IrInstruction::Unknown,
        },
    }
}

fn lift_mov(instruction: &Instruction) -> IrInstruction {
    let Some(dst) = instruction.operands.first().and_then(operand_value) else {
        return IrInstruction::Unknown;
    };
    let Some(src) = instruction.operands.get(1).map(operand_expr) else {
        return IrInstruction::Unknown;
    };

    IrInstruction::Assign { dst, src }
}

#[derive(Debug, Clone, Copy)]
enum IrBinaryOp {
    Add,
    Sub,
    And,
    Or,
    Xor,
}

fn lift_binary_assign(instruction: &Instruction, op: IrBinaryOp) -> IrInstruction {
    let Some(dst) = instruction.operands.first().and_then(operand_value) else {
        return IrInstruction::Unknown;
    };
    let lhs = IrExpr::Var(dst.clone());
    let Some(rhs) = instruction.operands.get(1).map(operand_expr) else {
        return IrInstruction::Unknown;
    };

    IrInstruction::Assign {
        dst,
        src: binary_expr(op, lhs, rhs),
    }
}

fn lift_compare(instruction: &Instruction, op: IrBinaryOp) -> IrInstruction {
    let Some(lhs) = instruction.operands.first().map(operand_expr) else {
        return IrInstruction::Unknown;
    };
    let Some(rhs) = instruction.operands.get(1).map(operand_expr) else {
        return IrInstruction::Unknown;
    };

    IrInstruction::Assign {
        dst: IrValue::Register("flags".to_string()),
        src: binary_expr(op, lhs, rhs),
    }
}

fn lift_branch(instruction: &Instruction) -> IrInstruction {
    let target = match instruction.flow {
        FlowKind::Jump { target } => target,
        _ => instruction.operands.first().and_then(operand_address),
    };
    target.map_or(IrInstruction::Unknown, |address| IrInstruction::Branch {
        target: block_label(address),
    })
}

fn lift_cond_branch(instruction: &Instruction) -> IrInstruction {
    let target = match instruction.flow {
        FlowKind::ConditionalJump { target } => target,
        _ => instruction.operands.first().and_then(operand_address),
    };
    let Some(then_address) = target else {
        return IrInstruction::Unknown;
    };
    let Some(else_address) = instruction.address.checked_add(u64::from(instruction.size)) else {
        return IrInstruction::Unknown;
    };

    IrInstruction::CondBranch {
        condition: IrExpr::Var(IrValue::Register(format!("cond_{}", instruction.mnemonic))),
        then_target: block_label(then_address),
        else_target: block_label(else_address),
    }
}

fn lift_call(instruction: &Instruction) -> IrInstruction {
    let target = match instruction.flow {
        FlowKind::Call { target } => {
            target.map_or(IrExpr::Unknown, |address| IrExpr::Const(address.value()))
        }
        _ => instruction
            .operands
            .first()
            .map_or(IrExpr::Unknown, operand_expr),
    };

    IrInstruction::Call {
        target,
        args: Vec::new(),
        result: None,
    }
}

fn lift_push(instruction: &Instruction) -> IrInstruction {
    let Some(value) = instruction.operands.first().map(operand_expr) else {
        return IrInstruction::Unknown;
    };

    IrInstruction::Store {
        address: IrExpr::Unknown,
        value,
        size: 8,
    }
}

fn lift_pop(instruction: &Instruction) -> IrInstruction {
    let Some(dst) = instruction.operands.first().and_then(operand_value) else {
        return IrInstruction::Unknown;
    };

    IrInstruction::Load {
        dst,
        address: IrExpr::Unknown,
        size: 8,
    }
}

fn binary_expr(op: IrBinaryOp, lhs: IrExpr, rhs: IrExpr) -> IrExpr {
    let lhs = Box::new(lhs);
    let rhs = Box::new(rhs);
    match op {
        IrBinaryOp::Add => IrExpr::Add(lhs, rhs),
        IrBinaryOp::Sub => IrExpr::Sub(lhs, rhs),
        IrBinaryOp::And => IrExpr::And(lhs, rhs),
        IrBinaryOp::Or => IrExpr::Or(lhs, rhs),
        IrBinaryOp::Xor => IrExpr::Xor(lhs, rhs),
    }
}

fn operand_value(operand: &Operand) -> Option<IrValue> {
    match operand {
        Operand::Register(register) => Some(IrValue::Register(register.clone())),
        Operand::Address(address) => Some(IrValue::Global(*address)),
        _ => None,
    }
}

fn operand_expr(operand: &Operand) -> IrExpr {
    match operand {
        Operand::Register(register) => IrExpr::Var(IrValue::Register(register.clone())),
        Operand::Immediate(value) => IrExpr::Const(*value),
        Operand::Address(address) => IrExpr::Const(address.value()),
        Operand::Memory(_) | Operand::Text(_) => IrExpr::Unknown,
    }
}

fn operand_address(operand: &Operand) -> Option<Address> {
    match operand {
        Operand::Address(address) => Some(*address),
        _ => None,
    }
}

fn block_label(address: Address) -> String {
    format!("block_{:x}", address.value())
}

fn is_conditional_jump(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "jo" | "jno"
            | "jb"
            | "jae"
            | "je"
            | "jne"
            | "jbe"
            | "ja"
            | "js"
            | "jns"
            | "jp"
            | "jnp"
            | "jl"
            | "jge"
            | "jle"
            | "jg"
    )
}

impl fmt::Display for IrModule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for function in &self.functions {
            writeln!(formatter, "{function}")?;
        }
        Ok(())
    }
}

impl fmt::Display for IrFunction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.name.as_deref().unwrap_or("<unnamed>");
        writeln!(formatter, "fn {name} @ {} {{", self.address)?;
        for block in &self.blocks {
            write!(formatter, "{block}")?;
        }
        writeln!(formatter, "}}")
    }
}

impl fmt::Display for IrBlock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "{}:", self.label)?;
        for instruction in &self.instructions {
            writeln!(formatter, "  {instruction}")?;
        }
        Ok(())
    }
}

impl fmt::Display for IrInstruction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Assign { dst, src } => write!(formatter, "{dst} = {src}"),
            Self::Load { dst, address, size } => {
                write!(formatter, "{dst} = load{size}({address})")
            }
            Self::Store {
                address,
                value,
                size,
            } => write!(formatter, "store{size}({address}, {value})"),
            Self::Branch { target } => write!(formatter, "br {target}"),
            Self::CondBranch {
                condition,
                then_target,
                else_target,
            } => write!(formatter, "br_if {condition}, {then_target}, {else_target}"),
            Self::Call {
                target,
                args,
                result,
            } => {
                if let Some(result) = result {
                    write!(formatter, "{result} = ")?;
                }
                write!(formatter, "call {target}(")?;
                for (index, arg) in args.iter().enumerate() {
                    if index > 0 {
                        formatter.write_str(", ")?;
                    }
                    write!(formatter, "{arg}")?;
                }
                formatter.write_str(")")
            }
            Self::Return { value } => {
                if let Some(value) = value {
                    write!(formatter, "ret {value}")
                } else {
                    formatter.write_str("ret")
                }
            }
            Self::Nop => formatter.write_str("nop"),
            Self::Unknown => formatter.write_str("unknown"),
        }
    }
}

impl fmt::Display for IrExpr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Const(value) => write!(formatter, "0x{value:x}"),
            Self::Var(value) => write!(formatter, "{value}"),
            Self::Add(lhs, rhs) => write!(formatter, "({lhs} + {rhs})"),
            Self::Sub(lhs, rhs) => write!(formatter, "({lhs} - {rhs})"),
            Self::Mul(lhs, rhs) => write!(formatter, "({lhs} * {rhs})"),
            Self::And(lhs, rhs) => write!(formatter, "({lhs} & {rhs})"),
            Self::Or(lhs, rhs) => write!(formatter, "({lhs} | {rhs})"),
            Self::Xor(lhs, rhs) => write!(formatter, "({lhs} ^ {rhs})"),
            Self::Not(value) => write!(formatter, "(!{value})"),
            Self::Eq(lhs, rhs) => write!(formatter, "({lhs} == {rhs})"),
            Self::Ne(lhs, rhs) => write!(formatter, "({lhs} != {rhs})"),
            Self::Lt(lhs, rhs) => write!(formatter, "({lhs} < {rhs})"),
            Self::Le(lhs, rhs) => write!(formatter, "({lhs} <= {rhs})"),
            Self::Gt(lhs, rhs) => write!(formatter, "({lhs} > {rhs})"),
            Self::Ge(lhs, rhs) => write!(formatter, "({lhs} >= {rhs})"),
            Self::Unknown => formatter.write_str("unknown"),
        }
    }
}

impl fmt::Display for IrValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Temp(index) => write!(formatter, "t{index}"),
            Self::Register(register) | Self::Local(register) => formatter.write_str(register),
            Self::Global(address) => write!(formatter, "global_{:x}", address.value()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaiju_disasm::{FlowKind, Operand};

    #[test]
    fn pretty_prints_manual_ir() {
        let mut module = IrModule::new();
        module.add_function(IrFunction {
            name: Some("entry".to_string()),
            address: Address::new(0x401000),
            blocks: vec![IrBlock {
                label: "block_401000".to_string(),
                instructions: vec![
                    IrInstruction::Assign {
                        dst: IrValue::Register("rax".to_string()),
                        src: IrExpr::Const(1),
                    },
                    IrInstruction::Return {
                        value: Some(IrExpr::Var(IrValue::Register("rax".to_string()))),
                    },
                ],
            }],
        });

        let printed = module.to_string();

        assert!(printed.contains("fn entry @ 0x0000000000401000"));
        assert!(printed.contains("rax = 0x1"));
        assert!(printed.contains("ret rax"));
    }

    #[test]
    fn lifts_mov_add_and_return() {
        let instructions = vec![
            instruction(
                0x1000,
                "mov",
                vec![
                    Operand::Register("rax".to_string()),
                    Operand::Immediate(0x2a),
                ],
                FlowKind::Normal,
            ),
            instruction(
                0x1005,
                "add",
                vec![
                    Operand::Register("rax".to_string()),
                    Operand::Register("rbx".to_string()),
                ],
                FlowKind::Normal,
            ),
            instruction(0x1008, "ret", Vec::new(), FlowKind::Return),
        ];

        let function = lift_instructions(Address::new(0x1000), &instructions);
        let printed = function.to_string();

        assert!(printed.contains("rax = 0x2a"));
        assert!(printed.contains("rax = (rax + rbx)"));
        assert!(printed.contains("ret"));
    }

    #[test]
    fn lifts_branches_and_unknowns_without_failing() {
        let instructions = vec![
            instruction(
                0x2000,
                "jne",
                vec![Operand::Address(Address::new(0x2008))],
                FlowKind::ConditionalJump {
                    target: Some(Address::new(0x2008)),
                },
            ),
            instruction(
                0x2002,
                "db",
                vec![Operand::Text("0xff".to_string())],
                FlowKind::Unknown,
            ),
        ];

        let function = lift_instructions(Address::new(0x2000), &instructions);
        let printed = function.to_string();

        assert!(printed.contains("br_if cond_jne, block_2008, block_2001"));
        assert!(printed.contains("unknown"));
    }

    fn instruction(
        address: u64,
        mnemonic: &str,
        operands: Vec<Operand>,
        flow: FlowKind,
    ) -> Instruction {
        Instruction {
            address: Address::new(address),
            size: 1,
            mnemonic: mnemonic.to_string(),
            operands,
            bytes: Vec::new(),
            flow,
        }
    }
}
