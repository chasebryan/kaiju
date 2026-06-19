#![forbid(unsafe_code)]

use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
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
use kaiju_network::{
    load_network_evidence, load_pcap_evidence, parse_hex_payload, parse_port_spec,
    parse_probe_target, probe_targets, scan_ports, NetworkEdge, NetworkMap, NetworkProtocol,
    ProbeOptions, ProbeReport,
};
use kaiju_project::{CrossReferenceKind, Project};

const DEFAULT_MIN_STRING_LEN: usize = 4;
const DEFAULT_DISASM_COUNT: usize = 64;
const DEFAULT_CFG_MAX_INSTRUCTIONS: usize = 256;
const DEFAULT_CFG_MAX_BLOCKS: usize = 128;
const MAX_X86_INSTRUCTION_BYTES: usize = 15;
const MAX_PACKAGE_JSON_BYTES: u64 = 16 * 1024 * 1024;

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
        "save" => {
            let args = read_save_args(&mut args)?;
            let (project, _reports) = analyze_project(args.path)?;
            save_project_package(&project, &args.output_dir)?;
            print_saved_project_package(&args.output_dir);
            Ok(())
        }
        "package" => {
            let path = read_single_path_arg(&mut args, "package")?;
            let inspection = inspect_project_package(&path)?;
            print_project_package_inspection(&inspection);
            Ok(())
        }
        "functions" => {
            let path = read_single_path_arg(&mut args, "functions")?;
            let (project, _reports) = analyze_project(path)?;
            print_functions(&project);
            Ok(())
        }
        "ir" => {
            let path = read_single_path_arg(&mut args, "ir")?;
            let (project, _reports) = analyze_project(path)?;
            print_ir_summaries(&project);
            Ok(())
        }
        "symbols" => {
            let path = read_single_path_arg(&mut args, "symbols")?;
            let binary = load_path(path)?;
            print_symbols(&binary);
            Ok(())
        }
        "dependencies" => {
            let path = read_single_path_arg(&mut args, "dependencies")?;
            let binary = load_path(path)?;
            print_dependencies(&binary);
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
            run_network(args)?;
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

fn read_save_args(args: &mut impl Iterator<Item = String>) -> Result<SaveArgs, CliError> {
    let mut path = None;
    let mut output_dir = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => {
                let Some(value) = args.next() else {
                    return Err(CliError::Usage("missing value for save --out".to_string()));
                };
                if output_dir.replace(PathBuf::from(value)).is_some() {
                    return Err(CliError::Usage(
                        "save output directory specified more than once".to_string(),
                    ));
                }
            }
            _ if path.is_none() => path = Some(PathBuf::from(arg)),
            _ => {
                return Err(CliError::Usage(format!(
                    "unexpected extra argument for save: {arg}"
                )))
            }
        }
    }

    let Some(path) = path else {
        return Err(CliError::Usage("missing file path for save".to_string()));
    };
    let Some(output_dir) = output_dir else {
        return Err(CliError::Usage(
            "save requires --out <project-dir>".to_string(),
        ));
    };

    Ok(SaveArgs { path, output_dir })
}

fn read_network_args(args: &mut impl Iterator<Item = String>) -> Result<NetworkCommand, CliError> {
    let Some(first) = args.next() else {
        return Err(CliError::Usage(
            "missing network evidence path or subcommand".to_string(),
        ));
    };

    match first.as_str() {
        "evidence" => read_network_map_args(args, "network evidence", None).map(|args| {
            NetworkCommand::Evidence {
                path: args.path,
                format: args.format,
            }
        }),
        "pcap" => {
            read_network_map_args(args, "network pcap", None).map(|args| NetworkCommand::Pcap {
                path: args.path,
                format: args.format,
            })
        }
        "probe" => read_network_probe_args(args),
        "scan" => read_network_scan_args(args),
        _ => read_network_map_args(args, "network", Some(PathBuf::from(first))).map(|args| {
            NetworkCommand::Evidence {
                path: args.path,
                format: args.format,
            }
        }),
    }
}

fn read_network_map_args(
    args: &mut impl Iterator<Item = String>,
    command: &str,
    initial_path: Option<PathBuf>,
) -> Result<NetworkMapArgs, CliError> {
    let mut path = None;
    let mut format = NetworkOutputFormat::Text;
    if let Some(initial_path) = initial_path {
        path = Some(initial_path);
    }

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
                    "unexpected extra argument for {command}: {arg}"
                )))
            }
        }
    }

    let Some(path) = path else {
        return Err(CliError::Usage(format!("missing path for {command}")));
    };

    Ok(NetworkMapArgs { path, format })
}

fn read_network_probe_args(
    args: &mut impl Iterator<Item = String>,
) -> Result<NetworkCommand, CliError> {
    let mut targets = Vec::new();
    let mut options = ProbeOptions::default();
    let mut format = NetworkProbeOutputFormat::Text;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--target" => {
                let Some(value) = args.next() else {
                    return Err(CliError::Usage(
                        "missing value for network probe --target".to_string(),
                    ));
                };
                let target = parse_probe_target(&value).ok_or_else(|| {
                    CliError::Usage(format!("invalid network probe target: {value}"))
                })?;
                targets.push(target);
            }
            "--timeout-ms" => {
                let Some(value) = args.next() else {
                    return Err(CliError::Usage(
                        "missing value for network probe --timeout-ms".to_string(),
                    ));
                };
                options.timeout_ms = parse_positive_u64(&value, "network probe --timeout-ms")?;
            }
            "--read-bytes" => {
                let Some(value) = args.next() else {
                    return Err(CliError::Usage(
                        "missing value for network probe --read-bytes".to_string(),
                    ));
                };
                options.read_bytes = parse_usize(&value, "network probe --read-bytes")?;
            }
            "--send-text" => {
                let Some(value) = args.next() else {
                    return Err(CliError::Usage(
                        "missing value for network probe --send-text".to_string(),
                    ));
                };
                options.payload = value.into_bytes();
            }
            "--send-hex" => {
                let Some(value) = args.next() else {
                    return Err(CliError::Usage(
                        "missing value for network probe --send-hex".to_string(),
                    ));
                };
                options.payload = parse_hex_payload(&value)?;
            }
            "--format" => {
                let Some(value) = args.next() else {
                    return Err(CliError::Usage(
                        "missing value for network probe --format".to_string(),
                    ));
                };
                format = parse_network_probe_format(&value)?;
            }
            _ => {
                let target = parse_probe_target(&arg).ok_or_else(|| {
                    CliError::Usage(format!("invalid network probe argument: {arg}"))
                })?;
                targets.push(target);
            }
        }
    }

    Ok(NetworkCommand::Probe {
        targets,
        options,
        format,
    })
}

fn read_network_scan_args(
    args: &mut impl Iterator<Item = String>,
) -> Result<NetworkCommand, CliError> {
    let mut host = None;
    let mut ports = None;
    let mut options = ProbeOptions {
        read_bytes: 0,
        ..ProbeOptions::default()
    };
    let mut format = NetworkProbeOutputFormat::Text;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--host" => {
                let Some(value) = args.next() else {
                    return Err(CliError::Usage(
                        "missing value for network scan --host".to_string(),
                    ));
                };
                host = Some(value);
            }
            "--ports" => {
                let Some(value) = args.next() else {
                    return Err(CliError::Usage(
                        "missing value for network scan --ports".to_string(),
                    ));
                };
                ports = Some(parse_port_spec(&value)?);
            }
            "--timeout-ms" => {
                let Some(value) = args.next() else {
                    return Err(CliError::Usage(
                        "missing value for network scan --timeout-ms".to_string(),
                    ));
                };
                options.timeout_ms = parse_positive_u64(&value, "network scan --timeout-ms")?;
            }
            "--read-bytes" => {
                let Some(value) = args.next() else {
                    return Err(CliError::Usage(
                        "missing value for network scan --read-bytes".to_string(),
                    ));
                };
                options.read_bytes = parse_usize(&value, "network scan --read-bytes")?;
            }
            "--send-text" => {
                let Some(value) = args.next() else {
                    return Err(CliError::Usage(
                        "missing value for network scan --send-text".to_string(),
                    ));
                };
                options.payload = value.into_bytes();
            }
            "--send-hex" => {
                let Some(value) = args.next() else {
                    return Err(CliError::Usage(
                        "missing value for network scan --send-hex".to_string(),
                    ));
                };
                options.payload = parse_hex_payload(&value)?;
            }
            "--format" => {
                let Some(value) = args.next() else {
                    return Err(CliError::Usage(
                        "missing value for network scan --format".to_string(),
                    ));
                };
                format = parse_network_probe_format(&value)?;
            }
            _ => {
                return Err(CliError::Usage(format!(
                    "unexpected argument for network scan: {arg}"
                )))
            }
        }
    }

    let Some(host) = host else {
        return Err(CliError::Usage(
            "network scan requires --host <host>".to_string(),
        ));
    };
    let Some(ports) = ports else {
        return Err(CliError::Usage(
            "network scan requires --ports <list>".to_string(),
        ));
    };

    Ok(NetworkCommand::Scan {
        host,
        ports,
        options,
        format,
    })
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

fn parse_usize(value: &str, option: &str) -> Result<usize, CliError> {
    value
        .parse::<usize>()
        .map_err(|_| CliError::Usage(format!("invalid value for {option}: {value}")))
}

fn parse_positive_u64(value: &str, option: &str) -> Result<u64, CliError> {
    let parsed = value
        .parse::<u64>()
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

fn parse_network_probe_format(value: &str) -> Result<NetworkProbeOutputFormat, CliError> {
    match value {
        "text" => Ok(NetworkProbeOutputFormat::Text),
        "json" => Ok(NetworkProbeOutputFormat::Json),
        _ => Err(CliError::Usage(format!(
            "invalid network probe --format value: {value}"
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
    eprintln!("  kaiju save <file> --out <project-dir>");
    eprintln!("  kaiju package <project-dir>");
    eprintln!("  kaiju functions <file>");
    eprintln!("  kaiju ir <file>");
    eprintln!("  kaiju symbols <file>");
    eprintln!("  kaiju dependencies <file>");
    eprintln!("  kaiju imports <file>");
    eprintln!("  kaiju exports <file>");
    eprintln!("  kaiju relocations <file>");
    eprintln!("  kaiju xrefs <file>");
    eprintln!("  kaiju network <evidence-file> [--format text|dot|json]");
    eprintln!("  kaiju network evidence <evidence-file> [--format text|dot|json]");
    eprintln!("  kaiju network pcap <pcap-file> [--format text|dot|json]");
    eprintln!(
        "  kaiju network probe (--target HOST:PORT | HOST:PORT)... [--timeout-ms N] [--read-bytes N] [--send-text TEXT | --send-hex HEX] [--format text|json]"
    );
    eprintln!(
        "  kaiju network scan --host HOST --ports LIST [--timeout-ms N] [--read-bytes N] [--send-text TEXT | --send-hex HEX] [--format text|json]"
    );
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
    println!("Dependencies: {}", binary.dependencies.len());
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

fn print_dependencies(binary: &LoadedBinary) {
    println!("Name");
    for dependency in &binary.dependencies {
        println!("{}", dependency.name);
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
    println!("Dependencies: {}", project.dependencies().len());
    println!("Imports: {}", project.imports().len());
    println!("Exports: {}", project.exports().len());
    println!("Relocations: {}", project.relocations().len());
    println!("Strings: {}", project.strings().len());
    println!("Functions: {}", project.functions().len());
    println!("Blocks: {}", project.basic_blocks().len());
    println!("IRFunctions: {}", project.ir_functions().len());
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

fn save_project_package(project: &Project, output_dir: &Path) -> KaijuResult<()> {
    prepare_project_package_dir(output_dir)?;
    write_package_file(
        &output_dir.join("manifest.json"),
        &project_package_manifest_json(project),
    )?;
    write_package_file(&output_dir.join("project.json"), &project.to_json_pretty())?;
    write_package_file(
        &output_dir.join("annotations.json"),
        &empty_annotations_json(),
    )?;
    Ok(())
}

fn prepare_project_package_dir(output_dir: &Path) -> KaijuResult<()> {
    if output_dir.exists() {
        if !output_dir.is_dir() {
            return Err(KaijuError::new(
                KaijuErrorKind::Io,
                format!(
                    "project package output is not a directory: {}",
                    output_dir.display()
                ),
            ));
        }

        if fs::read_dir(output_dir)?.next().is_some() {
            return Err(KaijuError::new(
                KaijuErrorKind::Io,
                format!(
                    "project package output directory is not empty: {}",
                    output_dir.display()
                ),
            ));
        }
        return Ok(());
    }

    fs::create_dir_all(output_dir)?;
    Ok(())
}

fn write_package_file(path: &Path, contents: &str) -> KaijuResult<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(contents.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

fn project_package_manifest_json(project: &Project) -> String {
    let summary = project.summary();
    let entrypoint = project.binary.entrypoint.map_or_else(
        || "null".to_string(),
        |address| json_string(&address.to_string()),
    );

    format!(
        concat!(
            "{{\n",
            "  \"schema\": \"kaiju.package.v1\",\n",
            "  \"project_schema\": \"kaiju.project.v1\",\n",
            "  \"source\": {{\n",
            "    \"path\": {},\n",
            "    \"file_size\": {},\n",
            "    \"format\": {},\n",
            "    \"architecture\": {},\n",
            "    \"endian\": {},\n",
            "    \"entrypoint\": {}\n",
            "  }},\n",
            "  \"files\": {{\n",
            "    \"project\": \"project.json\",\n",
            "    \"annotations\": \"annotations.json\"\n",
            "  }}\n",
            "}}"
        ),
        json_string(&summary.path),
        summary.file_size,
        json_string(&summary.format),
        json_string(&summary.architecture),
        json_string(&summary.endian),
        entrypoint
    )
}

fn empty_annotations_json() -> String {
    concat!(
        "{\n",
        "  \"schema\": \"kaiju.annotations.v1\",\n",
        "  \"labels\": [],\n",
        "  \"comments\": []\n",
        "}"
    )
    .to_string()
}

fn print_saved_project_package(output_dir: &Path) {
    println!("Saved: {}", output_dir.display());
    println!("Files:");
    println!("- manifest.json");
    println!("- project.json");
    println!("- annotations.json");
}

fn inspect_project_package(package_dir: &Path) -> KaijuResult<ProjectPackageInspection> {
    if !package_dir.is_dir() {
        return Err(KaijuError::new(
            KaijuErrorKind::Io,
            format!(
                "project package is not a directory: {}",
                package_dir.display()
            ),
        ));
    }

    let manifest = read_package_text_file(package_dir, "manifest.json")?;
    let project = read_package_text_file(package_dir, "project.json")?;
    let annotations = read_package_text_file(package_dir, "annotations.json")?;

    require_json_string_field(&manifest, "schema", "kaiju.package.v1", "manifest.json")?;
    require_json_string_field(
        &manifest,
        "project_schema",
        "kaiju.project.v1",
        "manifest.json",
    )?;
    require_json_string_field(&manifest, "project", "project.json", "manifest.json")?;
    require_json_string_field(
        &manifest,
        "annotations",
        "annotations.json",
        "manifest.json",
    )?;
    require_json_string_field(&project, "schema", "kaiju.project.v1", "project.json")?;
    require_json_string_field(
        &annotations,
        "schema",
        "kaiju.annotations.v1",
        "annotations.json",
    )?;

    Ok(ProjectPackageInspection {
        directory: package_dir.to_path_buf(),
        source_path: json_string_field(&manifest, "path").unwrap_or_else(|| "-".to_string()),
        file_size: json_u64_field(&manifest, "file_size").unwrap_or(0),
        format: json_string_field(&manifest, "format").unwrap_or_else(|| "-".to_string()),
        architecture: json_string_field(&manifest, "architecture")
            .unwrap_or_else(|| "-".to_string()),
        endian: json_string_field(&manifest, "endian").unwrap_or_else(|| "-".to_string()),
        functions: json_usize_field(&project, "functions").unwrap_or(0),
        blocks: json_usize_field(&project, "blocks").unwrap_or(0),
        ir_functions: json_usize_field(&project, "ir_functions").unwrap_or(0),
        xrefs: json_usize_field(&project, "xrefs").unwrap_or(0),
        analysis_facts: json_usize_field(&project, "analysis_facts").unwrap_or(0),
    })
}

fn read_package_text_file(package_dir: &Path, name: &str) -> KaijuResult<String> {
    let path = package_dir.join(name);
    let metadata = fs::metadata(&path)?;
    if !metadata.is_file() {
        return Err(KaijuError::new(
            KaijuErrorKind::Io,
            format!(
                "project package file is not a regular file: {}",
                path.display()
            ),
        ));
    }
    if metadata.len() > MAX_PACKAGE_JSON_BYTES {
        return Err(KaijuError::new(
            KaijuErrorKind::AnalysisLimitExceeded,
            format!(
                "project package file is too large: {} has {} bytes, limit is {MAX_PACKAGE_JSON_BYTES}",
                path.display(),
                metadata.len()
            ),
        ));
    }

    Ok(fs::read_to_string(path)?)
}

fn require_json_string_field(
    text: &str,
    field: &str,
    expected: &str,
    file_name: &str,
) -> KaijuResult<()> {
    match json_string_field(text, field) {
        Some(value) if value == expected => Ok(()),
        Some(value) => Err(KaijuError::new(
            KaijuErrorKind::MalformedBinary,
            format!("{file_name} has {field}={value}, expected {expected}"),
        )),
        None => Err(KaijuError::new(
            KaijuErrorKind::MalformedBinary,
            format!("{file_name} is missing string field {field}"),
        )),
    }
}

fn json_string_field(text: &str, field: &str) -> Option<String> {
    let key = format!("\"{}\"", json_string_inner(field));
    let mut rest = text;
    loop {
        let key_index = rest.find(&key)?;
        rest = &rest[key_index + key.len()..];
        let after_colon = rest.trim_start().strip_prefix(':')?.trim_start();
        if let Some(value) = parse_json_string_prefix(after_colon) {
            return Some(value);
        }
    }
}

fn parse_json_string_prefix(text: &str) -> Option<String> {
    let mut chars = text.chars();
    if chars.next()? != '"' {
        return None;
    }

    let mut value = String::new();
    let mut escape = false;
    while let Some(character) = chars.next() {
        if escape {
            match character {
                '"' => value.push('"'),
                '\\' => value.push('\\'),
                '/' => value.push('/'),
                'b' => value.push('\u{0008}'),
                'f' => value.push('\u{000c}'),
                'n' => value.push('\n'),
                'r' => value.push('\r'),
                't' => value.push('\t'),
                'u' => {
                    let mut digits = String::new();
                    for _ in 0..4 {
                        digits.push(chars.next()?);
                    }
                    let codepoint = u32::from_str_radix(&digits, 16).ok()?;
                    value.push(char::from_u32(codepoint)?);
                }
                _ => return None,
            }
            escape = false;
            continue;
        }

        match character {
            '"' => return Some(value),
            '\\' => escape = true,
            _ => value.push(character),
        }
    }

    None
}

fn json_usize_field(text: &str, field: &str) -> Option<usize> {
    let value = json_u64_field(text, field)?;
    usize::try_from(value).ok()
}

fn json_u64_field(text: &str, field: &str) -> Option<u64> {
    let key = format!("\"{}\"", json_string_inner(field));
    let mut rest = text;
    loop {
        let key_index = rest.find(&key)?;
        rest = &rest[key_index + key.len()..];
        let after_colon = rest.trim_start().strip_prefix(':')?.trim_start();
        let digits = after_colon
            .chars()
            .take_while(|character| character.is_ascii_digit())
            .collect::<String>();
        if !digits.is_empty() {
            return digits.parse::<u64>().ok();
        }
    }
}

fn print_project_package_inspection(inspection: &ProjectPackageInspection) {
    println!("Package: {}", inspection.directory.display());
    println!("Schema: kaiju.package.v1");
    println!("ProjectSchema: kaiju.project.v1");
    println!("Source: {}", inspection.source_path);
    println!("FileSize: {}", inspection.file_size);
    println!("Format: {}", inspection.format);
    println!("Architecture: {}", inspection.architecture);
    println!("Endian: {}", inspection.endian);
    println!("Functions: {}", inspection.functions);
    println!("Blocks: {}", inspection.blocks);
    println!("IRFunctions: {}", inspection.ir_functions);
    println!("Xrefs: {}", inspection.xrefs);
    println!("AnalysisFacts: {}", inspection.analysis_facts);
    println!("Files:");
    println!("- manifest.json ok");
    println!("- project.json ok");
    println!("- annotations.json ok");
}

fn run_network(command: NetworkCommand) -> KaijuResult<()> {
    match command {
        NetworkCommand::Evidence { path, format } => {
            let network = load_network_evidence(path)?;
            print_network(&network, format);
        }
        NetworkCommand::Pcap { path, format } => {
            let network = load_pcap_evidence(path)?;
            print_network(&network, format);
        }
        NetworkCommand::Probe {
            targets,
            options,
            format,
        } => {
            let report = probe_targets(targets, options)?;
            print_probe_report(&report, format);
        }
        NetworkCommand::Scan {
            host,
            ports,
            options,
            format,
        } => {
            let report = scan_ports(host, ports, options)?;
            print_probe_report(&report, format);
        }
    }
    Ok(())
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

fn print_ir_summaries(project: &Project) {
    println!("Function  Blocks  Instructions  Unknowns  Name");
    for function in project.ir_functions().values() {
        let name = function.name.as_deref().unwrap_or("-");
        println!(
            "{}  {}  {}  {}  {}",
            function.start,
            function.blocks.len(),
            function.instruction_count,
            function.unknown_count,
            name
        );
        for block in &function.blocks {
            println!("{}:", block.label);
            for instruction in &block.instructions {
                println!("  {}  {}", instruction.address, instruction.text);
            }
        }
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

fn print_probe_report(report: &ProbeReport, format: NetworkProbeOutputFormat) {
    match format {
        NetworkProbeOutputFormat::Text => print_probe_report_text(report),
        NetworkProbeOutputFormat::Json => println!("{}", report.to_json_pretty()),
    }
}

fn print_probe_report_text(report: &ProbeReport) {
    println!("Mode: {}", report.mode);
    println!("Targets: {}", report.results.len());
    println!("Open: {}", report.open_count());
    println!("Closed: {}", report.closed_count());
    println!("Errors: {}", report.error_count());
    println!("Results:");
    println!("Target  Status  Remote  ElapsedMs  Sent  Received  PayloadKind  Preview  Error");
    for result in &report.results {
        println!(
            "{:<28} {:<14} {:<24} {:<9} {:<5} {:<8} {:<11} {:<24} {}",
            result.target.label(),
            result.status,
            result.remote_addr.as_deref().unwrap_or("-"),
            result.elapsed_ms,
            result.sent_bytes,
            result.received.byte_len,
            result.received.kind,
            format_payload_preview(&result.received.ascii_preview),
            result.error.as_deref().unwrap_or("-")
        );
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

fn format_payload_preview(value: &str) -> &str {
    if value.is_empty() {
        "-"
    } else {
        value
    }
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

fn json_string(value: &str) -> String {
    let mut escaped = String::from("\"");
    escaped.push_str(&json_string_inner(value));
    escaped.push('"');
    escaped
}

fn json_string_inner(value: &str) -> String {
    let mut escaped = String::new();
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                escaped.push_str(&format!("\\u{:04x}", u32::from(character)));
            }
            character => escaped.push(character),
        }
    }
    escaped
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
struct SaveArgs {
    path: PathBuf,
    output_dir: PathBuf,
}

#[derive(Debug)]
struct ProjectPackageInspection {
    directory: PathBuf,
    source_path: String,
    file_size: u64,
    format: String,
    architecture: String,
    endian: String,
    functions: usize,
    blocks: usize,
    ir_functions: usize,
    xrefs: usize,
    analysis_facts: usize,
}

#[derive(Debug)]
struct NetworkMapArgs {
    path: PathBuf,
    format: NetworkOutputFormat,
}

#[derive(Debug)]
enum NetworkCommand {
    Evidence {
        path: PathBuf,
        format: NetworkOutputFormat,
    },
    Pcap {
        path: PathBuf,
        format: NetworkOutputFormat,
    },
    Probe {
        targets: Vec<kaiju_network::ProbeTarget>,
        options: ProbeOptions,
        format: NetworkProbeOutputFormat,
    },
    Scan {
        host: String,
        ports: Vec<u16>,
        options: ProbeOptions,
        format: NetworkProbeOutputFormat,
    },
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
enum NetworkProbeOutputFormat {
    Text,
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
