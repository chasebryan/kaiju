#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use kaiju_core::{Address, KaijuError, KaijuErrorKind, Result as KaijuResult};
use kaiju_disasm::{disassembler_for_architecture, Disassembler, Instruction};
use kaiju_loader::{load_path, LoadedBinary};

const DEFAULT_COUNT: usize = 16;
const MAX_X86_INSTRUCTION_BYTES: usize = 15;

fn main() -> ExitCode {
    match run(env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run(mut args: impl Iterator<Item = String>) -> Result<(), String> {
    let path = args
        .next()
        .ok_or_else(|| "usage: kaiju-example-basic-disasm <file> [count]".to_string())?;
    let count = match args.next() {
        Some(value) => parse_count(&value)?,
        None => DEFAULT_COUNT,
    };
    if let Some(extra) = args.next() {
        return Err(format!("unexpected extra argument: {extra}"));
    }

    let binary = load_path(PathBuf::from(path)).map_err(|error| error.to_string())?;
    let instructions = disassemble_entrypoint(&binary, count).map_err(|error| error.to_string())?;
    for instruction in instructions {
        println!("{}", format_instruction(&instruction));
    }

    Ok(())
}

fn parse_count(value: &str) -> Result<usize, String> {
    let count = value
        .parse::<usize>()
        .map_err(|_| format!("invalid instruction count: {value}"))?;
    if count == 0 {
        return Err("instruction count must be greater than zero".to_string());
    }
    Ok(count)
}

fn disassemble_entrypoint(binary: &LoadedBinary, count: usize) -> KaijuResult<Vec<Instruction>> {
    let start = binary.entrypoint.ok_or_else(|| {
        KaijuError::new(
            KaijuErrorKind::InvalidAddress,
            "binary does not define an entrypoint",
        )
    })?;
    let bytes = read_disassembly_window(binary, start, count)?;
    let disassembler = disassembler_for_architecture(binary.arch)?;
    disassembler.disassemble_block(&bytes, start, count)
}

fn read_disassembly_window(
    binary: &LoadedBinary,
    start: Address,
    count: usize,
) -> KaijuResult<Vec<u8>> {
    let region = binary.memory_map.find_region(start).ok_or_else(|| {
        KaijuError::new(
            KaijuErrorKind::UnmappedAddress,
            format!("address {start} is not mapped"),
        )
    })?;
    let relative = start
        .value()
        .checked_sub(region.address.value())
        .ok_or_else(|| {
            KaijuError::new(
                KaijuErrorKind::InvalidAddress,
                "region-relative address underflow",
            )
        })?;
    let available = region.size.checked_sub(relative).ok_or_else(|| {
        KaijuError::new(
            KaijuErrorKind::InvalidAddress,
            "region-relative address exceeds region size",
        )
    })?;
    let max_bytes = count
        .checked_mul(MAX_X86_INSTRUCTION_BYTES)
        .ok_or_else(|| {
            KaijuError::new(
                KaijuErrorKind::AnalysisLimitExceeded,
                "requested disassembly byte window is too large",
            )
        })?;
    let len = usize::try_from(available.min(max_bytes as u64)).map_err(|_| {
        KaijuError::new(
            KaijuErrorKind::AnalysisLimitExceeded,
            "mapped disassembly window does not fit in memory",
        )
    })?;

    binary.memory_map.read_range(start, len)
}

fn format_instruction(instruction: &Instruction) -> String {
    let bytes = instruction
        .bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    let operands = instruction
        .operands
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    if operands.is_empty() {
        format!(
            "{:016x}  {:<24} {}",
            instruction.address.value(),
            bytes,
            instruction.mnemonic
        )
    } else {
        format!(
            "{:016x}  {:<24} {} {}",
            instruction.address.value(),
            bytes,
            instruction.mnemonic,
            operands
        )
    }
}
