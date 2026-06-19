#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use kaiju_analysis::{
    build_cfg, extract_strings, run_default_passes, AnalysisConfig, AnalysisReport, CfgEdge,
    CfgOptions, ControlFlowGraph, EdgeKind, ExtractedString,
};
use kaiju_arch::{builtin_architectures, Architecture};
use kaiju_core::{Address, DiagnosticSeverity, KaijuError, KaijuErrorKind, Result as KaijuResult};
use kaiju_disasm::{disassembler_for_architecture, Disassembler, Instruction};
use kaiju_ir::{lift_instructions, IrFunction};
use kaiju_loader::{load_path, LoadedBinary};
use kaiju_network::{load_network_evidence, NetworkEdge, NetworkMap, NetworkProtocol};
use kaiju_project::{CrossReferenceKind, Project};

const DEFAULT_MIN_STRING_LEN: usize = 4;
const DEFAULT_DISASM_COUNT: usize = 64;
const DEFAULT_CFG_MAX_INSTRUCTIONS: usize = 256;
const DEFAULT_CFG_MAX_BLOCKS: usize = 128;
const MAX_X86_INSTRUCTION_BYTES: usize = 15;

fn main() -> ExitCode {
    match run(env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(CliError::Usage(message)) => {
            eprintln!("{message}");
            eprintln!();
            print_usage();
            ExitCode::from(2)
        }
        Err(CliError::Kaiju(error)) => {
            eprintln!("kaiju: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(mut args: impl Iterator<Item = String>) -> Result<(), CliError> {
    let Some(command) = args.next() else {
        return Err(CliError::Usage("missing command".to_string()));
    };

    match command.as_str() {
        "-h" | "--help" => {
            print_usage();
            Ok(())
        }
        "info" => {
            let path = read_single_path_arg(&mut args, "info")?;
            let binary = load_path(path)?;
            print_info(&binary);
            Ok(())
        }
        "map" => {
            let path = read_single_path_arg(&mut args, "map")?;
            let binary = load_path(path)?;
            print_map(&binary);
            Ok(())
        }
        "diagnostics" => {
            let path = read_single_path_arg(&mut args, "diagnostics")?;
            let binary = load_path(path)?;
            print_diagnostics(&binary);
            Ok(())
        }
        "strings" => {
            let args = read_strings_args(&mut args)?;
            let binary = load_path(args.path)?;
            let strings = extract_strings(&binary, args.min_len);
            print_strings(&strings);
            Ok(())
        }
        "disasm" => {
            let args = read_disasm_args(&mut args)?;
            let binary = load_path(args.path)?;
            let instructions = disassemble_binary(&binary, args.target, args.count)?;
            print_disassembly(&instructions);
            Ok(())
        }
        "cfg" => {
            let args = read_cfg_args(&mut args)?;
            let binary = load_path(args.path)?;
            let start = resolve_target(&binary, args.target)?;
            let graph = build_cfg(
                &binary,
                start,
                CfgOptions {
                    max_instructions: args.max_instructions,
                    max_blocks: args.max_blocks,
                },
            )?;
            print_cfg(&graph, args.format);
            Ok(())
        }
        "lift" => {
            let args = read_lift_args(&mut args)?;
            let binary = load_path(args.path)?;
            let start = resolve_target(&binary, args.target)?;
            let instructions = disassemble_binary(&binary, args.target, args.count)?;
            let function = lift_instructions(start, &instructions);
            print_ir_function(&function);
            Ok(())
        }
        "analyze" => {
            let path = read_single_path_arg(&mut args, "analyze")?;
            let (project, reports) = analyze_project(path)?;
            print_analysis_summary(&project, &reports);
            Ok(())
        }
        "export" => {
            let path = read_single_path_arg(&mut args, "export")?;
            let (project, _reports) = analyze_project(path)?;
            println!("{}", project.to_json_pretty());
            Ok(())
        }
        "functions" => {
            let path = read_single_path_arg(&mut args, "functions")?;
            let (project, _reports) = analyze_project(path)?;
            print_functions(&project);
            Ok(())
        }
        "symbols" => {
            let path = read_single_path_arg(&mut args, "symbols")?;
            let binary = load_path(path)?;
            print_symbols(&binary);
            Ok(())
        }
        "imports" => {
            let path = read_single_path_arg(&mut args, "imports")?;
            let binary = load_path(path)?;
            print_imports(&binary);
            Ok(())
        }
        "exports" => {
            let path = read_single_path_arg(&mut args, "exports")?;
            let binary = load_path(path)?;
            print_exports(&binary);
            Ok(())
        }
        "relocations" => {
            let path = read_single_path_arg(&mut args, "relocations")?;
            let binary = load_path(path)?;
            print_relocations(&binary);
            Ok(())
        }
        "xrefs" => {
            let path = read_single_path_arg(&mut args, "xrefs")?;
            let (project, _reports) = analyze_project(path)?;
            print_xrefs(&project);
            Ok(())
        }
        "network" => {
            let args = read_network_args(&mut args)?;
            let network = load_network_evidence(&args.path)?;
            print_network(&network, args.format);
            Ok(())
        }
        "arch" => {
            ensure_no_args(&mut args, "arch")?;
            print_architectures();
            Ok(())
        }
        unknown => Err(CliError::Usage(format!("unknown command: {unknown}"))),
    }
}

fn read_single_path_arg(
    args: &mut impl Iterator<Item = String>,
    command: &str,
) -> Result<PathBuf, CliError> {
    let Some(path) = args.next() else {
        return Err(CliError::Usage(format!("missing file path for {command}")));
    };

    if let Some(extra) = args.next() {
        return Err(CliError::Usage(format!(
            "unexpected extra argument for {command}: {extra}"
        )));
    }

    Ok(PathBuf::from(path))
}

fn ensure_no_args(args: &mut impl Iterator<Item = String>, command: &str) -> Result<(), CliError> {
    if let Some(extra) = args.next() {
        return Err(CliError::Usage(format!(
            "unexpected extra argument for {command}: {extra}"
        )));
    }

    Ok(())
}

fn read_strings_args(args: &mut impl Iterator<Item = String>) -> Result<StringsArgs, CliError> {
    let mut path = None;
    let mut min_len = DEFAULT_MIN_STRING_LEN;

    while let Some(arg) = args.next() {
        if arg == "--min-len" {
            let Some(value) = args.next() else {
                return Err(CliError::Usage(
                    "missing value for strings --min-len".to_string(),
                ));
            };
            min_len = value.parse::<usize>().map_err(|_| {
                CliError::Usage(format!("invalid value for strings --min-len: {value}"))
            })?;
            if min_len == 0 {
                return Err(CliError::Usage(
                    "strings --min-len must be greater than zero".to_string(),
                ));
            }
        } else if path.is_none() {
            path = Some(PathBuf::from(arg));
        } else {
            return Err(CliError::Usage(format!(
                "unexpected extra argument for strings: {arg}"
            )));
        }
    }

    let Some(path) = path else {
        return Err(CliError::Usage("missing file path for strings".to_string()));
    };

    Ok(StringsArgs { path, min_len })
}

fn read_disasm_args(args: &mut impl Iterator<Item = String>) -> Result<DisasmArgs, CliError> {
    let mut path = None;
    let mut target = None;
    let mut count = DEFAULT_DISASM_COUNT;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--entry" => {
                if target.replace(DisasmTarget::Entry).is_some() {
                    return Err(CliError::Usage(
                        "disasm target specified more than once".to_string(),
                    ));
                }
            }
            "--addr" => {
                let Some(value) = args.next() else {
                    return Err(CliError::Usage(
                        "missing value for disasm --addr".to_string(),
                    ));
                };
                let address = parse_address(&value)?;
                if target.replace(DisasmTarget::Address(address)).is_some() {
                    return Err(CliError::Usage(
                        "disasm target specified more than once".to_string(),
                    ));
                }
            }
            "--count" => {
                let Some(value) = args.next() else {
                    return Err(CliError::Usage(
                        "missing value for disasm --count".to_string(),
                    ));
                };
                count = value.parse::<usize>().map_err(|_| {
                    CliError::Usage(format!("invalid value for disasm --count: {value}"))
                })?;
                if count == 0 {
                    return Err(CliError::Usage(
                        "disasm --count must be greater than zero".to_string(),
                    ));
                }
            }
            _ if path.is_none() => path = Some(PathBuf::from(arg)),
            _ => {
                return Err(CliError::Usage(format!(
                    "unexpected extra argument for disasm: {arg}"
                )))
            }
        }
    }

    let Some(path) = path else {
        return Err(CliError::Usage("missing file path for disasm".to_string()));
    };
    let Some(target) = target else {
        return Err(CliError::Usage(
            "disasm requires --entry or --addr <address>".to_string(),
        ));
    };

    Ok(DisasmArgs {
        path,
        target,
        count,
    })
}

fn read_cfg_args(args: &mut impl Iterator<Item = String>) -> Result<CfgArgs, CliError> {
    let mut path = None;
    let mut target = None;
    let mut max_instructions = DEFAULT_CFG_MAX_INSTRUCTIONS;
    let mut max_blocks = DEFAULT_CFG_MAX_BLOCKS;
    let mut format = CfgOutputFormat::Text;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--entry" => {
                if target.replace(DisasmTarget::Entry).is_some() {
                    return Err(CliError::Usage(
                        "cfg target specified more than once".to_string(),
                    ));
                }
            }
            "--addr" => {
                let Some(value) = args.next() else {
                    return Err(CliError::Usage("missing value for cfg --addr".to_string()));
                };
                let address = parse_address(&value)?;
                if target.replace(DisasmTarget::Address(address)).is_some() {
                    return Err(CliError::Usage(
                        "cfg target specified more than once".to_string(),
                    ));
                }
            }
            "--max-instructions" => {
                let Some(value) = args.next() else {
                    return Err(CliError::Usage(
                        "missing value for cfg --max-instructions".to_string(),
                    ));
                };
                max_instructions = parse_positive_usize(&value, "cfg --max-instructions")?;
            }
            "--max-blocks" => {
                let Some(value) = args.next() else {
                    return Err(CliError::Usage(
                        "missing value for cfg --max-blocks".to_string(),
                    ));
                };
                max_blocks = parse_positive_usize(&value, "cfg --max-blocks")?;
            }
            "--format" => {
                let Some(value) = args.next() else {
                    return Err(CliError::Usage(
                        "missing value for cfg --format".to_string(),
                    ));
                };
                format = parse_cfg_format(&value)?;
            }
            _ if path.is_none() => path = Some(PathBuf::from(arg)),
            _ => {
                return Err(CliError::Usage(format!(
                    "unexpected extra argument for cfg: {arg}"
                )))
            }
        }
    }

    let Some(path) = path else {
        return Err(CliError::Usage("missing file path for cfg".to_string()));
    };
    let Some(target) = target else {
        return Err(CliError::Usage(
            "cfg requires --entry or --addr <address>".to_string(),
        ));
    };

    Ok(CfgArgs {
        path,
        target,
        max_instructions,
        max_blocks,
        format,
    })
}

fn read_lift_args(args: &mut impl Iterator<Item = String>) -> Result<LiftArgs, CliError> {
    let mut path = None;
    let mut target = None;
    let mut count = DEFAULT_DISASM_COUNT;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--entry" => {
                if target.replace(DisasmTarget::Entry).is_some() {
                    return Err(CliError::Usage(
                        "lift target specified more than once".to_string(),
                    ));
                }
            }
            "--addr" => {
                let Some(value) = args.next() else {
                    return Err(CliError::Usage("missing value for lift --addr".to_string()));
                };
                let address = parse_address(&value)?;
                if target.replace(DisasmTarget::Address(address)).is_some() {
                    return Err(CliError::Usage(
                        "lift target specified more than once".to_string(),
                    ));
                }
            }
            "--count" => {
                let Some(value) = args.next() else {
                    return Err(CliError::Usage(
                        "missing value for lift --count".to_string(),
                    ));
                };
                count = parse_positive_usize(&value, "lift --count")?;
            }
            _ if path.is_none() => path = Some(PathBuf::from(arg)),
            _ => {
                return Err(CliError::Usage(format!(
                    "unexpected extra argument for lift: {arg}"
                )))
            }
        }
    }

    let Some(path) = path else {
        return Err(CliError::Usage("missing file path for lift".to_string()));
    };
    let Some(target) = target else {
        return Err(CliError::Usage(
            "lift requires --entry or --addr <address>".to_string(),
        ));
    };

    Ok(LiftArgs {
        path,
        target,
        count,
    })
}

fn read_network_args(args: &mut impl Iterator<Item = String>) -> Result<NetworkArgs, CliError> {
    let mut path = None;
    let mut format = NetworkOutputFormat::Text;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--format" => {
                let Some(value) = args.next() else {
                    return Err(CliError::Usage(
                        "missing value for network --format".to_string(),
                    ));
                };
                format = parse_network_format(&value)?;
            }
            _ if path.is_none() => path = Some(PathBuf::from(arg)),
            _ => {
                return Err(CliError::Usage(format!(
                    "unexpected extra argument for network: {arg}"
                )))
            }
        }
    }

    let Some(path) = path else {
        return Err(CliError::Usage(
            "missing evidence path for network".to_string(),
        ));
    };

    Ok(NetworkArgs { path, format })
}

fn parse_address(value: &str) -> Result<Address, CliError> {
    let parsed = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
    } else {
        value.parse::<u64>()
    }
    .map_err(|_| CliError::Usage(format!("invalid address: {value}")))?;

    Ok(Address::new(parsed))
}

fn parse_positive_usize(value: &str, option: &str) -> Result<usize, CliError> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| CliError::Usage(format!("invalid value for {option}: {value}")))?;
    if parsed == 0 {
        return Err(CliError::Usage(format!(
            "{option} must be greater than zero"
        )));
    }
    Ok(parsed)
}

fn parse_cfg_format(value: &str) -> Result<CfgOutputFormat, CliError> {
    match value {
        "text" => Ok(CfgOutputFormat::Text),
        "dot" => Ok(CfgOutputFormat::Dot),
        _ => Err(CliError::Usage(format!(
            "invalid cfg --format value: {value}"
        ))),
    }
}

fn parse_network_format(value: &str) -> Result<NetworkOutputFormat, CliError> {
    match value {
        "text" => Ok(NetworkOutputFormat::Text),
        "dot" => Ok(NetworkOutputFormat::Dot),
        "json" => Ok(NetworkOutputFormat::Json),
        _ => Err(CliError::Usage(format!(
            "invalid network --format value: {value}"
        ))),
    }
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  kaiju info <file>");
    eprintln!("  kaiju map <file>");
    eprintln!("  kaiju diagnostics <file>");
    eprintln!("  kaiju strings <file> [--min-len N]");
    eprintln!("  kaiju disasm <file> (--entry | --addr ADDRESS) [--count N]");
    eprintln!(
        "  kaiju cfg <file> (--entry | --addr ADDRESS) [--format text|dot] [--max-instructions N] [--max-blocks N]"
    );
    eprintln!("  kaiju lift <file> (--entry | --addr ADDRESS) [--count N]");
    eprintln!("  kaiju analyze <file>");
    eprintln!("  kaiju export <file>");
    eprintln!("  kaiju functions <file>");
    eprintln!("  kaiju symbols <file>");
    eprintln!("  kaiju imports <file>");
    eprintln!("  kaiju exports <file>");
    eprintln!("  kaiju relocations <file>");
    eprintln!("  kaiju xrefs <file>");
    eprintln!("  kaiju network <evidence-file> [--format text|dot|json]");
    eprintln!("  kaiju arch");
}

fn print_info(binary: &LoadedBinary) {
    let entrypoint = binary
        .entrypoint
        .map_or_else(|| "None".to_string(), |address| address.to_string());

    println!("Path: {}", binary.path.display());
    println!("Size: {} bytes", binary.file_size);
    println!("Format: {}", binary.format);
    println!("Architecture: {}", binary.arch);
    println!("Endian: {}", binary.endian);
    println!("Entrypoint: {entrypoint}");
    println!("Regions: {}", binary.memory_map.regions().len());
    println!("Sections: {}", binary.sections.len());
    println!("Symbols: {}", binary.symbols.len());
    println!("Imports: {}", binary.imports.len());
    println!("Exports: {}", binary.exports.len());
    println!("Relocations: {}", binary.relocations.len());
}

fn print_map(binary: &LoadedBinary) {
    println!("Name  Address  Size  Offset  Permissions");
    for region in binary.memory_map.regions() {
        let offset = region
            .file_offset
            .map_or_else(|| "-".to_string(), |value| format!("0x{value:x}"));
        let size = region.size;
        let address = region.address;
        let permissions = region.permissions;

        println!(
            "{:<16} {:<18} {:<10} {:<10} {}",
            region.name, address, size, offset, permissions
        );
    }
}

fn print_diagnostics(binary: &LoadedBinary) {
    println!("Severity  Message");
    for diagnostic in &binary.diagnostics {
        println!(
            "{:<8}  {}",
            diagnostic_severity_name(diagnostic.severity),
            diagnostic.message
        );
    }
}

fn print_symbols(binary: &LoadedBinary) {
    println!("Name  Address");
    for symbol in &binary.symbols {
        let address = symbol
            .address
            .map_or_else(|| "-".to_string(), |address| address.to_string());
        println!("{:<24} {}", symbol.name, address);
    }
}

fn print_imports(binary: &LoadedBinary) {
    println!("Library  Name  Ordinal  Thunk");
    for import in &binary.imports {
        let name = import.name.as_deref().unwrap_or("-");
        let ordinal = import
            .ordinal
            .map_or_else(|| "-".to_string(), |ordinal| ordinal.to_string());
        let thunk = import
            .thunk
            .map_or_else(|| "-".to_string(), |address| address.to_string());

        println!(
            "{:<20} {:<24} {:<8} {}",
            import.library, name, ordinal, thunk
        );
    }
}

fn print_exports(binary: &LoadedBinary) {
    println!("Module  Name  Ordinal  Address  Forwarder");
    for export in &binary.exports {
        let module = export.module.as_deref().unwrap_or("-");
        let name = export.name.as_deref().unwrap_or("-");
        let address = export
            .address
            .map_or_else(|| "-".to_string(), |address| address.to_string());
        let forwarder = export.forwarder.as_deref().unwrap_or("-");

        println!(
            "{:<16} {:<24} {:<8} {:<18} {}",
            module, name, export.ordinal, address, forwarder
        );
    }
}

fn print_relocations(binary: &LoadedBinary) {
    println!("Address  Kind");
    for relocation in &binary.relocations {
        println!("{:<18} {}", relocation.address, relocation.kind);
    }
}

fn diagnostic_severity_name(severity: DiagnosticSeverity) -> &'static str {
    match severity {
        DiagnosticSeverity::Note => "Note",
        DiagnosticSeverity::Warning => "Warning",
        DiagnosticSeverity::Error => "Error",
    }
}

fn disassemble_binary(
    binary: &LoadedBinary,
    target: DisasmTarget,
    count: usize,
) -> KaijuResult<Vec<Instruction>> {
    let start = match target {
        DisasmTarget::Entry => binary.entrypoint.ok_or_else(|| {
            KaijuError::new(
                KaijuErrorKind::InvalidAddress,
                "binary does not define an entrypoint",
            )
        })?,
        DisasmTarget::Address(address) => address,
    };
    let bytes = read_disassembly_window(binary, start, count)?;
    let disassembler = disassembler_for_architecture(binary.arch)?;
    disassembler.disassemble_block(&bytes, start, count)
}

fn resolve_target(binary: &LoadedBinary, target: DisasmTarget) -> KaijuResult<Address> {
    match target {
        DisasmTarget::Entry => binary.entrypoint.ok_or_else(|| {
            KaijuError::new(
                KaijuErrorKind::InvalidAddress,
                "binary does not define an entrypoint",
            )
        }),
        DisasmTarget::Address(address) => Ok(address),
    }
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

fn print_disassembly(instructions: &[Instruction]) {
    for instruction in instructions {
        println!("{}", format_instruction(instruction));
    }
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

fn print_cfg(graph: &ControlFlowGraph, format: CfgOutputFormat) {
    match format {
        CfgOutputFormat::Text => print_cfg_text(graph),
        CfgOutputFormat::Dot => print_cfg_dot(graph),
    }
}

fn print_cfg_text(graph: &ControlFlowGraph) {
    println!("Function: {}", graph.function_start);
    println!("Blocks:");
    for block in &graph.blocks {
        println!("block {}..{}", block.start, block.end);
        for instruction in &block.instructions {
            println!("  {}", format_instruction(instruction));
        }
    }
    println!("Edges:");
    for edge in &graph.edges {
        println!("{} -> {} {}", edge.from, edge.to, edge_kind_name(edge.kind));
    }
}

fn print_cfg_dot(graph: &ControlFlowGraph) {
    println!("digraph cfg {{");
    println!("  label=\"function {}\";", graph.function_start);
    for block in &graph.blocks {
        let mut label = block.start.to_string();
        for instruction in &block.instructions {
            label.push_str("\\n");
            label.push_str(&dot_escape(&format!(
                "{:x}: {}",
                instruction.address.value(),
                instruction.mnemonic
            )));
        }
        println!("  \"{}\" [label=\"{}\"];", block.start, label);
    }
    for edge in &graph.edges {
        print_dot_edge(edge);
    }
    println!("}}");
}

fn print_dot_edge(edge: &CfgEdge) {
    println!(
        "  \"{}\" -> \"{}\" [label=\"{}\"];",
        edge.from,
        edge.to,
        edge_kind_name(edge.kind)
    );
}

fn dot_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn edge_kind_name(kind: EdgeKind) -> &'static str {
    match kind {
        EdgeKind::Fallthrough => "fallthrough",
        EdgeKind::Jump => "jump",
        EdgeKind::ConditionalTaken => "conditional-taken",
        EdgeKind::ConditionalNotTaken => "conditional-not-taken",
        EdgeKind::Call => "call",
        EdgeKind::Return => "return",
        EdgeKind::Unknown => "unknown",
    }
}

fn print_strings(strings: &[ExtractedString]) {
    println!("Offset  Address  Encoding  Length  Value");
    for string in strings {
        let address = string
            .virtual_address
            .map_or_else(|| "-".to_string(), |address| address.to_string());

        println!(
            "{:<10} {:<18} {:<10} {:<8} {}",
            format!("0x{:x}", string.file_offset),
            address,
            string.encoding,
            string.char_len,
            escape_string_value(&string.value)
        );
    }
}

fn print_ir_function(function: &IrFunction) {
    print!("{function}");
}

fn print_analysis_summary(project: &Project, reports: &[AnalysisReport]) {
    println!("Path: {}", project.binary.path.display());
    println!("Passes: {}", reports.len());
    println!("Imports: {}", project.imports().len());
    println!("Exports: {}", project.exports().len());
    println!("Relocations: {}", project.relocations().len());
    println!("Strings: {}", project.strings().len());
    println!("Functions: {}", project.functions().len());
    println!("Blocks: {}", project.basic_blocks().len());
    println!("Xrefs: {}", project.xrefs().len());
    println!("AnalysisFacts: {}", project.analysis_facts().len());
    println!("Reports:");
    for report in reports {
        println!(
            "- {} facts={} warnings={}",
            report.pass_name,
            report.facts_added,
            report.warnings.len()
        );
        for warning in &report.warnings {
            println!("  warning: {warning}");
        }
    }
}

fn analyze_project(path: PathBuf) -> KaijuResult<(Project, Vec<AnalysisReport>)> {
    let binary = load_path(path)?;
    let mut project = Project::from_loaded_binary(binary);
    let reports = run_default_passes(&mut project, AnalysisConfig::default())?;
    Ok((project, reports))
}

fn print_functions(project: &Project) {
    println!("Start  Name  Blocks");
    for function in project.functions().values() {
        let name = function.name.as_deref().unwrap_or("-");
        println!(
            "{}  {}  {}",
            function.start,
            name,
            function.block_starts.len()
        );
    }
}

fn print_xrefs(project: &Project) {
    println!("From  To  Kind");
    for xref in project.xrefs() {
        println!("{}  {}  {}", xref.from, xref.to, xref_kind_name(xref.kind));
    }
}

fn print_architectures() {
    println!("Id  Name  PointerWidth  Endian  Registers");
    for architecture in builtin_architectures() {
        println!(
            "{}  {}  {}  {}  {}",
            architecture.id(),
            architecture.name(),
            architecture.pointer_width(),
            architecture.endian(),
            architecture.registers().len()
        );
    }
}

fn print_network(network: &NetworkMap, format: NetworkOutputFormat) {
    match format {
        NetworkOutputFormat::Text => print_network_text(network),
        NetworkOutputFormat::Dot => print_network_dot(network),
        NetworkOutputFormat::Json => println!("{}", network.to_json_pretty()),
    }
}

fn print_network_text(network: &NetworkMap) {
    let summary = network.summary();
    println!("Source: {}", network.source_name());
    println!("Hosts: {}", summary.hosts);
    println!("Services: {}", summary.services);
    println!("Edges: {}", summary.edges);
    println!("Observations: {}", summary.observations);
    println!("IgnoredLines: {}", summary.ignored_lines);

    println!("Hosts:");
    println!("Host  Kind  Observations  Lines");
    for host in network.hosts() {
        println!(
            "{:<28} {:<10} {:<12} {}",
            host.id,
            host.kind,
            host.observation_count(),
            format_line_numbers(&host.observation_lines)
        );
    }

    println!("Services:");
    println!("Host  Port  Protocol  Observations  Lines");
    for service in network.services() {
        println!(
            "{:<28} {:<6} {:<9} {:<12} {}",
            service.host,
            service.port,
            format_protocol(service.protocol.as_ref()),
            service.observation_count(),
            format_line_numbers(&service.observation_lines)
        );
    }

    println!("Edges:");
    println!("Source  Destination  Protocol  Port  Observations  Lines");
    for edge in network.edges() {
        println!(
            "{:<28} {:<28} {:<9} {:<6} {:<12} {}",
            edge.source,
            edge.destination,
            format_protocol(edge.protocol.as_ref()),
            format_optional_port(edge.port),
            edge.observation_count(),
            format_line_numbers(&edge.observation_lines)
        );
    }
}

fn print_network_dot(network: &NetworkMap) {
    println!("digraph network {{");
    println!(
        "  label=\"network evidence {}\";",
        dot_escape(network.source_name())
    );
    for host in network.hosts() {
        println!(
            "  \"{}\" [label=\"{}\\n{}\"];",
            dot_escape(&host.id),
            dot_escape(&host.id),
            host.kind
        );
    }
    for edge in network.edges() {
        print_network_dot_edge(edge);
    }
    println!("}}");
}

fn print_network_dot_edge(edge: &NetworkEdge) {
    println!(
        "  \"{}\" -> \"{}\" [label=\"{}\"];",
        dot_escape(&edge.source),
        dot_escape(&edge.destination),
        dot_escape(&network_edge_label(edge))
    );
}

fn network_edge_label(edge: &NetworkEdge) -> String {
    let mut parts = Vec::new();
    if let Some(protocol) = &edge.protocol {
        parts.push(protocol.to_string());
    }
    if let Some(port) = edge.port {
        parts.push(port.to_string());
    }
    parts.push(format!("{} obs", edge.observation_count()));
    parts.join("/")
}

fn format_protocol(protocol: Option<&NetworkProtocol>) -> String {
    protocol.map_or_else(|| "-".to_string(), ToString::to_string)
}

fn format_optional_port(port: Option<u16>) -> String {
    port.map_or_else(|| "-".to_string(), |port| port.to_string())
}

fn format_line_numbers(lines: &[usize]) -> String {
    lines
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn xref_kind_name(kind: CrossReferenceKind) -> &'static str {
    match kind {
        CrossReferenceKind::Flow => "flow",
        CrossReferenceKind::Call => "call",
        CrossReferenceKind::Data => "data",
        CrossReferenceKind::Read => "read",
        CrossReferenceKind::Write => "write",
        CrossReferenceKind::Unknown => "unknown",
    }
}

fn escape_string_value(value: &str) -> String {
    value
        .chars()
        .flat_map(char::escape_default)
        .collect::<String>()
}

#[derive(Debug)]
struct StringsArgs {
    path: PathBuf,
    min_len: usize,
}

#[derive(Debug)]
struct DisasmArgs {
    path: PathBuf,
    target: DisasmTarget,
    count: usize,
}

#[derive(Debug)]
struct CfgArgs {
    path: PathBuf,
    target: DisasmTarget,
    max_instructions: usize,
    max_blocks: usize,
    format: CfgOutputFormat,
}

#[derive(Debug)]
struct LiftArgs {
    path: PathBuf,
    target: DisasmTarget,
    count: usize,
}

#[derive(Debug)]
struct NetworkArgs {
    path: PathBuf,
    format: NetworkOutputFormat,
}

#[derive(Debug, Clone, Copy)]
enum CfgOutputFormat {
    Text,
    Dot,
}

#[derive(Debug, Clone, Copy)]
enum NetworkOutputFormat {
    Text,
    Dot,
    Json,
}

#[derive(Debug, Clone, Copy)]
enum DisasmTarget {
    Entry,
    Address(Address),
}

#[derive(Debug)]
enum CliError {
    Usage(String),
    Kaiju(KaijuError),
}

impl From<KaijuError> for CliError {
    fn from(error: KaijuError) -> Self {
        Self::Kaiju(error)
    }
}
