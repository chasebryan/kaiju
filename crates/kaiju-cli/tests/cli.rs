use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const RAW_FIXTURE_TOKEN: &str = "<RAW_FIXTURE>";

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn snapshot_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/snapshots")
        .join(name)
}

#[test]
fn cli_info_reports_raw_fixture() {
    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("info")
        .arg(fixture_path("raw.bin"))
        .output()
        .expect("run kaiju info");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Path:"));
    assert!(stdout.contains("Size:"));
    assert!(stdout.contains("Format: Raw"));
    assert!(stdout.contains("Architecture: Unknown"));
    assert!(stdout.contains("Endian: Unknown"));
    assert!(stdout.contains("Entrypoint: None"));
    assert!(stdout.contains("Regions: 1"));
    assert!(stdout.contains("Sections: 0"));
    assert!(stdout.contains("Symbols: 0"));
    assert!(stdout.contains("Imports: 0"));
    assert!(stdout.contains("Exports: 0"));
}

#[test]
fn cli_map_reports_raw_fixture() {
    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("map")
        .arg(fixture_path("raw.bin"))
        .output()
        .expect("run kaiju map");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Name  Address  Size  Offset  Permissions"));
    assert!(stdout.contains("raw"));
    assert!(stdout.contains("0x0000000000000000"));
    assert!(stdout.contains("r--"));
}

#[test]
fn cli_diagnostics_reports_raw_loader_note() {
    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("diagnostics")
        .arg(fixture_path("raw.bin"))
        .output()
        .expect("run kaiju diagnostics");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Severity  Message"));
    assert!(stdout.contains("Note"));
    assert!(stdout.contains("raw bytes"));
}

#[test]
fn cli_reports_elf_metadata_and_load_map() {
    let path = write_temp_elf_fixture();

    let info = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("info")
        .arg(&path)
        .output()
        .expect("run kaiju info on ELF");
    assert!(info.status.success());
    let stdout = String::from_utf8(info.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Format: ELF"));
    assert!(stdout.contains("Architecture: x86_64"));
    assert!(stdout.contains("Endian: Little"));
    assert!(stdout.contains("Entrypoint: 0x0000000000401000"));
    assert!(stdout.contains("Regions: 1"));
    assert!(stdout.contains("Symbols: 1"));

    let map = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("map")
        .arg(&path)
        .output()
        .expect("run kaiju map on ELF");
    assert!(map.status.success());
    let stdout = String::from_utf8(map.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("LOAD0"));
    assert!(stdout.contains("0x0000000000401000"));
    assert!(stdout.contains("r-x"));

    let _ = fs::remove_file(path);
}

#[test]
fn cli_reports_pe_metadata_and_section_map() {
    let path = write_temp_pe_fixture();

    let info = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("info")
        .arg(&path)
        .output()
        .expect("run kaiju info on PE");
    assert!(info.status.success());
    let stdout = String::from_utf8(info.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Format: PE"));
    assert!(stdout.contains("Architecture: x86_64"));
    assert!(stdout.contains("Endian: Little"));
    assert!(stdout.contains("Entrypoint: 0x0000000140001000"));
    assert!(stdout.contains("Regions: 1"));
    assert!(stdout.contains("Sections: 1"));
    assert!(stdout.contains("Imports: 0"));
    assert!(stdout.contains("Exports: 0"));

    let map = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("map")
        .arg(&path)
        .output()
        .expect("run kaiju map on PE");
    assert!(map.status.success());
    let stdout = String::from_utf8(map.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains(".text"));
    assert!(stdout.contains("0x0000000140001000"));
    assert!(stdout.contains("r-x"));

    let _ = fs::remove_file(path);
}

#[test]
fn cli_exports_reports_pe_exports() {
    let path = write_temp_pe_export_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("exports")
        .arg(&path)
        .output()
        .expect("run kaiju exports on PE");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Module  Name  Ordinal  Address  Forwarder"));
    assert!(stdout.contains("sample.dll"));
    assert!(stdout.contains("ExportedFunc"));
    assert!(stdout.contains("ForwardedFunc"));
    assert!(stdout.contains("OTHER.Forward"));
    assert!(stdout.contains("0x0000000140001000"));
    assert!(stdout.contains("0x0000000140001010"));

    let _ = fs::remove_file(path);
}

#[test]
fn cli_imports_reports_pe_imports() {
    let path = write_temp_pe_import_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("imports")
        .arg(&path)
        .output()
        .expect("run kaiju imports on PE");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Library  Name  Ordinal  Thunk"));
    assert!(stdout.contains("KERNEL32.dll"));
    assert!(stdout.contains("ExitProcess"));
    assert!(stdout.contains("7"));
    assert!(stdout.contains("0x00000001400020a0"));
    assert!(stdout.contains("0x00000001400020a8"));

    let _ = fs::remove_file(path);
}

#[test]
fn cli_reports_mach_o_metadata_and_diagnostic() {
    let path = write_temp_mach_o_fixture();

    let info = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("info")
        .arg(&path)
        .output()
        .expect("run kaiju info on Mach-O");
    assert!(info.status.success());
    let stdout = String::from_utf8(info.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Format: Mach-O"));
    assert!(stdout.contains("Architecture: x86_64"));
    assert!(stdout.contains("Endian: Little"));
    assert!(stdout.contains("Entrypoint: 0x0000000100000100"));
    assert!(stdout.contains("Regions: 1"));

    let map = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("map")
        .arg(&path)
        .output()
        .expect("run kaiju map on Mach-O");
    assert!(map.status.success());
    let stdout = String::from_utf8(map.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("__TEXT"));
    assert!(stdout.contains("0x0000000100000000"));
    assert!(stdout.contains("r-x"));

    let diagnostics = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("diagnostics")
        .arg(&path)
        .output()
        .expect("run kaiju diagnostics on Mach-O");
    assert!(diagnostics.status.success());
    let stdout = String::from_utf8(diagnostics.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Note"));
    assert!(stdout.contains("limited load-command parsing"));

    let _ = fs::remove_file(path);
}

#[test]
fn cli_disasm_entry_reports_x86_64_instructions() {
    let path = write_temp_elf_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("disasm")
        .arg(&path)
        .arg("--entry")
        .arg("--count")
        .arg("4")
        .output()
        .expect("run kaiju disasm on ELF");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("push rbp"));
    assert!(stdout.contains("mov rbp, rsp"));
    assert!(stdout.contains("pop rbp"));
    assert!(stdout.contains("ret"));

    let _ = fs::remove_file(path);
}

#[test]
fn cli_disasm_reports_unsupported_architecture_for_raw() {
    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("disasm")
        .arg(fixture_path("raw.bin"))
        .arg("--addr")
        .arg("0x0")
        .arg("--count")
        .arg("1")
        .output()
        .expect("run kaiju disasm on raw");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf-8");
    assert!(stderr.contains("UnsupportedArchitecture"));
}

#[test]
fn cli_cfg_entry_reports_blocks_and_edges() {
    let path = write_temp_cfg_elf_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("cfg")
        .arg(&path)
        .arg("--entry")
        .arg("--max-instructions")
        .arg("8")
        .output()
        .expect("run kaiju cfg on ELF");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Function: 0x0000000000401000"));
    assert!(stdout.contains("Blocks:"));
    assert!(stdout.contains("Edges:"));
    assert!(stdout.contains("conditional-taken"));
    assert!(stdout.contains("conditional-not-taken"));

    let _ = fs::remove_file(path);
}

#[test]
fn cli_cfg_dot_reports_graphviz() {
    let path = write_temp_cfg_elf_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("cfg")
        .arg(&path)
        .arg("--entry")
        .arg("--format")
        .arg("dot")
        .output()
        .expect("run kaiju cfg dot on ELF");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("digraph cfg"));
    assert!(stdout.contains("conditional-taken"));
    assert!(stdout.contains("conditional-not-taken"));

    let _ = fs::remove_file(path);
}

#[test]
fn cli_strings_reports_ascii_and_utf16le_strings() {
    let path = write_temp_strings_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("strings")
        .arg(&path)
        .output()
        .expect("run kaiju strings");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Offset  Address  Encoding  Length  Value"));
    assert!(stdout.contains("ASCII"));
    assert!(stdout.contains("kaiju"));
    assert!(stdout.contains("monster-class"));
    assert!(stdout.contains("UTF-16LE"));
    assert!(stdout.contains("Wide"));

    let _ = fs::remove_file(path);
}

#[test]
fn cli_strings_honors_min_len() {
    let path = write_temp_strings_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("strings")
        .arg(&path)
        .arg("--min-len")
        .arg("8")
        .output()
        .expect("run kaiju strings with min len");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("monster-class"));
    assert!(!stdout.contains("kaiju"));
    assert!(!stdout.contains("Wide"));

    let _ = fs::remove_file(path);
}

#[test]
fn cli_lift_entry_reports_ir() {
    let path = write_temp_elf_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("lift")
        .arg(&path)
        .arg("--entry")
        .arg("--count")
        .arg("4")
        .output()
        .expect("run kaiju lift on ELF");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("fn sub_401000 @ 0x0000000000401000"));
    assert!(stdout.contains("rbp = rsp"));
    assert!(stdout.contains("ret"));

    let _ = fs::remove_file(path);
}

#[test]
fn cli_analyze_reports_project_summary() {
    let path = write_temp_cfg_elf_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("analyze")
        .arg(&path)
        .output()
        .expect("run kaiju analyze on ELF");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Passes: 4"));
    assert!(stdout.contains("Imports: 0"));
    assert!(stdout.contains("Exports: 0"));
    assert!(stdout.contains("Functions: 1"));
    assert!(stdout.contains("Blocks:"));
    assert!(stdout.contains("Xrefs:"));
    assert!(stdout.contains("entrypoint-cfg"));

    let _ = fs::remove_file(path);
}

#[test]
fn cli_analyze_raw_fixture_succeeds_with_warnings() {
    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("analyze")
        .arg(fixture_path("raw.bin"))
        .output()
        .expect("run kaiju analyze on raw fixture");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Passes: 4"));
    assert!(stdout.contains("Imports: 0"));
    assert!(stdout.contains("Exports: 0"));
    assert!(stdout.contains("Strings: 1"));
    assert!(stdout.contains("warning: binary does not define an entrypoint"));
}

#[test]
fn cli_export_reports_project_json() {
    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("export")
        .arg(fixture_path("raw.bin"))
        .output()
        .expect("run kaiju export on raw fixture");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("\"schema\": \"kaiju.project.v1\""));
    assert!(stdout.contains("\"format\": \"Raw\""));
    assert!(stdout.contains("\"diagnostics\": 1"));
    assert!(stdout.contains("\"severity\": \"note\""));
    assert!(stdout.contains("\"strings\": 1"));
    assert!(stdout.contains("Kaiju raw fixture"));
}

#[test]
fn cli_functions_reports_discovered_entrypoint_function() {
    let path = write_temp_cfg_elf_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("functions")
        .arg(&path)
        .output()
        .expect("run kaiju functions");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Start  Name  Blocks"));
    assert!(stdout.contains("0x0000000000401000"));

    let _ = fs::remove_file(path);
}

#[test]
fn cli_symbols_reports_loader_symbols() {
    let path = write_temp_elf_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("symbols")
        .arg(&path)
        .output()
        .expect("run kaiju symbols");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Name  Address"));
    assert!(stdout.contains("entry"));
    assert!(stdout.contains("0x0000000000401000"));

    let _ = fs::remove_file(path);
}

#[test]
fn cli_imports_reports_header_for_files_without_imports() {
    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("imports")
        .arg(fixture_path("raw.bin"))
        .output()
        .expect("run kaiju imports");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert_eq!(stdout.trim_end(), "Library  Name  Ordinal  Thunk");
}

#[test]
fn cli_exports_reports_header_for_files_without_exports() {
    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("exports")
        .arg(fixture_path("raw.bin"))
        .output()
        .expect("run kaiju exports");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert_eq!(
        stdout.trim_end(),
        "Module  Name  Ordinal  Address  Forwarder"
    );
}

#[test]
fn cli_xrefs_reports_cfg_flow_edges() {
    let path = write_temp_cfg_elf_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("xrefs")
        .arg(&path)
        .output()
        .expect("run kaiju xrefs");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("From  To  Kind"));
    assert!(stdout.contains("flow"));

    let _ = fs::remove_file(path);
}

#[test]
fn cli_arch_lists_builtin_architectures() {
    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("arch")
        .output()
        .expect("run kaiju arch");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Id  Name  PointerWidth  Endian  Registers"));
    assert!(stdout.contains("x86_64"));
    assert!(stdout.contains("aarch64"));
}

#[test]
fn cli_raw_fixture_snapshots_match() {
    assert_raw_snapshot(&["info", RAW_FIXTURE_TOKEN], "raw-info.txt");
    assert_raw_snapshot(&["map", RAW_FIXTURE_TOKEN], "raw-map.txt");
    assert_raw_snapshot(&["diagnostics", RAW_FIXTURE_TOKEN], "raw-diagnostics.txt");
    assert_raw_snapshot(&["strings", RAW_FIXTURE_TOKEN], "raw-strings.txt");
    assert_raw_snapshot(&["analyze", RAW_FIXTURE_TOKEN], "raw-analyze.txt");
    assert_raw_snapshot(&["export", RAW_FIXTURE_TOKEN], "raw-export.json");
    assert_raw_snapshot(&["imports", RAW_FIXTURE_TOKEN], "raw-imports.txt");
    assert_raw_snapshot(&["exports", RAW_FIXTURE_TOKEN], "raw-exports.txt");
}

#[test]
fn cli_arch_snapshot_matches() {
    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("arch")
        .output()
        .expect("run kaiju arch");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert_eq!(stdout.trim_end(), snapshot("arch.txt"));
}

fn write_temp_elf_fixture() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("kaiju-cli-elf-{}-{unique}.bin", process::id()));
    fs::write(&path, synthetic_elf64_le()).expect("write ELF fixture");
    path
}

fn write_temp_cfg_elf_fixture() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after epoch")
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("kaiju-cli-cfg-elf-{}-{unique}.bin", process::id()));
    fs::write(&path, synthetic_cfg_elf64_le()).expect("write CFG ELF fixture");
    path
}

fn write_temp_pe_fixture() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("kaiju-cli-pe-{}-{unique}.exe", process::id()));
    fs::write(&path, synthetic_pe32_plus()).expect("write PE fixture");
    path
}

fn write_temp_pe_import_fixture() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "kaiju-cli-pe-imports-{}-{unique}.exe",
        process::id()
    ));
    fs::write(&path, synthetic_pe32_plus_with_imports()).expect("write PE import fixture");
    path
}

fn write_temp_pe_export_fixture() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "kaiju-cli-pe-exports-{}-{unique}.dll",
        process::id()
    ));
    fs::write(&path, synthetic_pe32_plus_with_exports()).expect("write PE export fixture");
    path
}

fn write_temp_mach_o_fixture() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("kaiju-cli-macho-{}-{unique}.bin", process::id()));
    fs::write(&path, synthetic_mach_o64_le()).expect("write Mach-O fixture");
    path
}

fn write_temp_strings_fixture() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after epoch")
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("kaiju-cli-strings-{}-{unique}.bin", process::id()));
    fs::write(&path, strings_fixture_bytes()).expect("write strings fixture");
    path
}

fn synthetic_elf64_le() -> Vec<u8> {
    synthetic_elf64_le_with_code(&[0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3])
}

fn synthetic_cfg_elf64_le() -> Vec<u8> {
    synthetic_elf64_le_with_code(&[0x75, 0x02, 0xc3, 0x90, 0xc3])
}

fn synthetic_elf64_le_with_code(code: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x400];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;

    write_u16_le(&mut bytes, 16, 2);
    write_u16_le(&mut bytes, 18, 62);
    write_u32_le(&mut bytes, 20, 1);
    write_u64_le(&mut bytes, 24, 0x401000);
    write_u64_le(&mut bytes, 32, 0x40);
    write_u64_le(&mut bytes, 40, 0x100);
    write_u16_le(&mut bytes, 52, 64);
    write_u16_le(&mut bytes, 54, 56);
    write_u16_le(&mut bytes, 56, 1);
    write_u16_le(&mut bytes, 58, 64);
    write_u16_le(&mut bytes, 60, 5);
    write_u16_le(&mut bytes, 62, 2);

    write_u32_le(&mut bytes, 0x40, 1);
    write_u32_le(&mut bytes, 0x40 + 4, 5);
    write_u64_le(&mut bytes, 0x40 + 8, 0x300);
    write_u64_le(&mut bytes, 0x40 + 16, 0x401000);
    write_u64_le(&mut bytes, 0x40 + 32, code.len() as u64);
    write_u64_le(&mut bytes, 0x40 + 40, code.len() as u64);
    write_u64_le(&mut bytes, 0x40 + 48, 0x1000);
    bytes[0x300..0x300 + code.len()].copy_from_slice(code);

    write_elf_section64(
        &mut bytes,
        0x100 + 64,
        ElfSection64Spec {
            name: 1,
            section_type: 1,
            flags: 0x6,
            address: 0x401000,
            file_offset: 0x300,
            size: code.len() as u64,
            link: 0,
            entry_size: 0,
        },
    );
    write_elf_section64(
        &mut bytes,
        0x100 + 128,
        ElfSection64Spec {
            name: 7,
            section_type: 3,
            flags: 0,
            address: 0,
            file_offset: 0x340,
            size: 33,
            link: 0,
            entry_size: 0,
        },
    );
    write_elf_section64(
        &mut bytes,
        0x100 + 192,
        ElfSection64Spec {
            name: 17,
            section_type: 3,
            flags: 0,
            address: 0,
            file_offset: 0x370,
            size: 7,
            link: 0,
            entry_size: 0,
        },
    );
    write_elf_section64(
        &mut bytes,
        0x100 + 256,
        ElfSection64Spec {
            name: 25,
            section_type: 2,
            flags: 0,
            address: 0,
            file_offset: 0x380,
            size: 48,
            link: 3,
            entry_size: 24,
        },
    );

    bytes[0x340..0x361].copy_from_slice(b"\0.text\0.shstrtab\0.strtab\0.symtab\0");
    bytes[0x370..0x377].copy_from_slice(b"\0entry\0");
    write_elf64_symbol(
        &mut bytes,
        0x380 + 24,
        1,
        0x12,
        1,
        0x401000,
        code.len() as u64,
    );

    bytes
}

struct ElfSection64Spec {
    name: u32,
    section_type: u32,
    flags: u64,
    address: u64,
    file_offset: u64,
    size: u64,
    link: u32,
    entry_size: u64,
}

fn write_elf_section64(bytes: &mut [u8], offset: usize, spec: ElfSection64Spec) {
    write_u32_le(bytes, offset, spec.name);
    write_u32_le(bytes, offset + 4, spec.section_type);
    write_u64_le(bytes, offset + 8, spec.flags);
    write_u64_le(bytes, offset + 16, spec.address);
    write_u64_le(bytes, offset + 24, spec.file_offset);
    write_u64_le(bytes, offset + 32, spec.size);
    write_u32_le(bytes, offset + 40, spec.link);
    write_u64_le(bytes, offset + 56, spec.entry_size);
}

fn write_elf64_symbol(
    bytes: &mut [u8],
    offset: usize,
    name: u32,
    info: u8,
    section_index: u16,
    value: u64,
    size: u64,
) {
    write_u32_le(bytes, offset, name);
    bytes[offset + 4] = info;
    write_u16_le(bytes, offset + 6, section_index);
    write_u64_le(bytes, offset + 8, value);
    write_u64_le(bytes, offset + 16, size);
}

fn synthetic_pe32_plus() -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x400];
    bytes[0] = b'M';
    bytes[1] = b'Z';
    write_u32_le(&mut bytes, 0x3c, 0x100);
    bytes[0x100..0x104].copy_from_slice(b"PE\0\0");

    let coff = 0x104;
    write_u16_le(&mut bytes, coff, 0x8664);
    write_u16_le(&mut bytes, coff + 2, 1);
    write_u16_le(&mut bytes, coff + 16, 0x70);

    let optional = coff + 20;
    write_u16_le(&mut bytes, optional, 0x20b);
    write_u32_le(&mut bytes, optional + 16, 0x1000);
    write_u64_le(&mut bytes, optional + 24, 0x140000000);

    let section = 0x188;
    bytes[section..section + 8].copy_from_slice(b".text\0\0\0");
    write_u32_le(&mut bytes, section + 8, 0x100);
    write_u32_le(&mut bytes, section + 12, 0x1000);
    write_u32_le(&mut bytes, section + 16, 0x200);
    write_u32_le(&mut bytes, section + 20, 0x200);
    write_u32_le(&mut bytes, section + 36, 0x6000_0000);
    bytes[0x200..0x204].copy_from_slice(&[0x90, 0x90, 0xc3, 0x00]);

    bytes
}

fn synthetic_pe32_plus_with_imports() -> Vec<u8> {
    const PE32_PLUS_ORDINAL_FLAG: u64 = 0x8000_0000_0000_0000;

    let mut bytes = vec![0_u8; 0x800];
    bytes[0] = b'M';
    bytes[1] = b'Z';
    write_u32_le(&mut bytes, 0x3c, 0x100);
    bytes[0x100..0x104].copy_from_slice(b"PE\0\0");

    let coff = 0x104;
    write_u16_le(&mut bytes, coff, 0x8664);
    write_u16_le(&mut bytes, coff + 2, 2);
    write_u16_le(&mut bytes, coff + 16, 0x90);

    let optional = coff + 20;
    write_u16_le(&mut bytes, optional, 0x20b);
    write_u32_le(&mut bytes, optional + 16, 0x1000);
    write_u64_le(&mut bytes, optional + 24, 0x140000000);
    write_u32_le(&mut bytes, optional + 108, 16);
    write_u32_le(&mut bytes, optional + 120, 0x2000);
    write_u32_le(&mut bytes, optional + 124, 0x40);

    let text = 0x1a8;
    bytes[text..text + 8].copy_from_slice(b".text\0\0\0");
    write_u32_le(&mut bytes, text + 8, 0x100);
    write_u32_le(&mut bytes, text + 12, 0x1000);
    write_u32_le(&mut bytes, text + 16, 0x200);
    write_u32_le(&mut bytes, text + 20, 0x200);
    write_u32_le(&mut bytes, text + 36, 0x6000_0000);

    let rdata = 0x1d0;
    bytes[rdata..rdata + 8].copy_from_slice(b".rdata\0\0");
    write_u32_le(&mut bytes, rdata + 8, 0x200);
    write_u32_le(&mut bytes, rdata + 12, 0x2000);
    write_u32_le(&mut bytes, rdata + 16, 0x200);
    write_u32_le(&mut bytes, rdata + 20, 0x400);
    write_u32_le(&mut bytes, rdata + 36, 0x4000_0000);

    bytes[0x200..0x204].copy_from_slice(&[0x90, 0x90, 0xc3, 0x00]);

    write_u32_le(&mut bytes, 0x400, 0x2080);
    write_u32_le(&mut bytes, 0x40c, 0x2060);
    write_u32_le(&mut bytes, 0x410, 0x20a0);

    bytes[0x460..0x46d].copy_from_slice(b"KERNEL32.dll\0");
    write_u64_le(&mut bytes, 0x480, 0x20c0);
    write_u64_le(&mut bytes, 0x488, PE32_PLUS_ORDINAL_FLAG | 7);
    write_u64_le(&mut bytes, 0x490, 0);
    write_u16_le(&mut bytes, 0x4c0, 0);
    bytes[0x4c2..0x4ce].copy_from_slice(b"ExitProcess\0");

    bytes
}

fn synthetic_pe32_plus_with_exports() -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x800];
    bytes[0] = b'M';
    bytes[1] = b'Z';
    write_u32_le(&mut bytes, 0x3c, 0x100);
    bytes[0x100..0x104].copy_from_slice(b"PE\0\0");

    let coff = 0x104;
    write_u16_le(&mut bytes, coff, 0x8664);
    write_u16_le(&mut bytes, coff + 2, 2);
    write_u16_le(&mut bytes, coff + 16, 0x90);

    let optional = coff + 20;
    write_u16_le(&mut bytes, optional, 0x20b);
    write_u32_le(&mut bytes, optional + 16, 0x1000);
    write_u64_le(&mut bytes, optional + 24, 0x140000000);
    write_u32_le(&mut bytes, optional + 108, 16);
    write_u32_le(&mut bytes, optional + 112, 0x2000);
    write_u32_le(&mut bytes, optional + 116, 0x100);

    let text = 0x1a8;
    bytes[text..text + 8].copy_from_slice(b".text\0\0\0");
    write_u32_le(&mut bytes, text + 8, 0x100);
    write_u32_le(&mut bytes, text + 12, 0x1000);
    write_u32_le(&mut bytes, text + 16, 0x200);
    write_u32_le(&mut bytes, text + 20, 0x200);
    write_u32_le(&mut bytes, text + 36, 0x6000_0000);

    let rdata = 0x1d0;
    bytes[rdata..rdata + 8].copy_from_slice(b".rdata\0\0");
    write_u32_le(&mut bytes, rdata + 8, 0x200);
    write_u32_le(&mut bytes, rdata + 12, 0x2000);
    write_u32_le(&mut bytes, rdata + 16, 0x200);
    write_u32_le(&mut bytes, rdata + 20, 0x400);
    write_u32_le(&mut bytes, rdata + 36, 0x4000_0000);

    bytes[0x200..0x204].copy_from_slice(&[0x90, 0x90, 0xc3, 0x00]);

    write_u32_le(&mut bytes, 0x40c, 0x2060);
    write_u32_le(&mut bytes, 0x410, 1);
    write_u32_le(&mut bytes, 0x414, 3);
    write_u32_le(&mut bytes, 0x418, 2);
    write_u32_le(&mut bytes, 0x41c, 0x2080);
    write_u32_le(&mut bytes, 0x420, 0x2090);
    write_u32_le(&mut bytes, 0x424, 0x20a0);

    bytes[0x460..0x46b].copy_from_slice(b"sample.dll\0");
    write_u32_le(&mut bytes, 0x480, 0x1000);
    write_u32_le(&mut bytes, 0x484, 0x20c0);
    write_u32_le(&mut bytes, 0x488, 0x1010);
    write_u32_le(&mut bytes, 0x490, 0x20d0);
    write_u32_le(&mut bytes, 0x494, 0x20e0);
    write_u16_le(&mut bytes, 0x4a0, 0);
    write_u16_le(&mut bytes, 0x4a2, 1);
    bytes[0x4c0..0x4ce].copy_from_slice(b"OTHER.Forward\0");
    bytes[0x4d0..0x4dd].copy_from_slice(b"ExportedFunc\0");
    bytes[0x4e0..0x4ee].copy_from_slice(b"ForwardedFunc\0");

    bytes
}

fn synthetic_mach_o64_le() -> Vec<u8> {
    const MACHO64_HEADER_SIZE: usize = 32;
    const MACHO64_SEGMENT_COMMAND_SIZE: usize = 72;
    const MACHO64_SECTION_SIZE: usize = 80;
    const LC_SEGMENT_64: u32 = 0x19;
    const LC_MAIN: u32 = 0x8000_0028;
    const VM_PROT_READ: u32 = 0x1;
    const VM_PROT_EXECUTE: u32 = 0x4;

    let segment_command_size = MACHO64_SEGMENT_COMMAND_SIZE + MACHO64_SECTION_SIZE;
    let command_size = segment_command_size + 24;
    let mut bytes = vec![0_u8; 0x240];
    bytes[0..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
    write_u32_le(&mut bytes, 4, 0x0100_0007);
    write_u32_le(&mut bytes, 8, 3);
    write_u32_le(&mut bytes, 12, 2);
    write_u32_le(&mut bytes, 16, 2);
    write_u32_le(&mut bytes, 20, command_size as u32);
    write_u32_le(&mut bytes, 24, 0);
    write_u32_le(&mut bytes, 28, 0);

    let segment = MACHO64_HEADER_SIZE;
    write_u32_le(&mut bytes, segment, LC_SEGMENT_64);
    write_u32_le(&mut bytes, segment + 4, segment_command_size as u32);
    bytes[segment + 8..segment + 24].copy_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
    write_u64_le(&mut bytes, segment + 24, 0x100000000);
    write_u64_le(&mut bytes, segment + 32, 0x1000);
    write_u64_le(&mut bytes, segment + 40, 0);
    write_u64_le(&mut bytes, segment + 48, 0x200);
    write_u32_le(&mut bytes, segment + 56, VM_PROT_READ | VM_PROT_EXECUTE);
    write_u32_le(&mut bytes, segment + 60, VM_PROT_READ | VM_PROT_EXECUTE);
    write_u32_le(&mut bytes, segment + 64, 1);
    write_u32_le(&mut bytes, segment + 68, 0);

    let section = segment + MACHO64_SEGMENT_COMMAND_SIZE;
    bytes[section..section + 16].copy_from_slice(b"__text\0\0\0\0\0\0\0\0\0\0");
    bytes[section + 16..section + 32].copy_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
    write_u64_le(&mut bytes, section + 32, 0x100000100);
    write_u64_le(&mut bytes, section + 40, 4);
    write_u32_le(&mut bytes, section + 48, 0x100);
    write_u32_le(&mut bytes, section + 52, 4);
    write_u32_le(&mut bytes, section + 56, 0);
    write_u32_le(&mut bytes, section + 60, 0);
    write_u32_le(&mut bytes, section + 64, 0);

    let entry = segment + segment_command_size;
    write_u32_le(&mut bytes, entry, LC_MAIN);
    write_u32_le(&mut bytes, entry + 4, 24);
    write_u64_le(&mut bytes, entry + 8, 0x100);
    write_u64_le(&mut bytes, entry + 16, 0);

    bytes[0x100..0x104].copy_from_slice(&[0x55, 0x48, 0x89, 0xe5]);
    bytes
}

fn strings_fixture_bytes() -> Vec<u8> {
    let mut bytes = b"\0abc\0kaiju\0monster-class\0".to_vec();
    bytes.extend_from_slice(&[b'W', 0, b'i', 0, b'd', 0, b'e', 0, 0, 0]);
    bytes
}

fn write_u16_le(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32_le(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64_le(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn assert_raw_snapshot(args: &[&str], snapshot_name: &str) {
    let raw_fixture = fixture_path("raw.bin");
    let mut command = Command::new(env!("CARGO_BIN_EXE_kaiju"));
    for arg in args {
        if *arg == RAW_FIXTURE_TOKEN {
            command.arg(&raw_fixture);
        } else {
            command.arg(arg);
        }
    }

    let output = command.output().expect("run kaiju snapshot command");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert_eq!(
        normalize_raw_fixture_path(stdout.trim_end(), &raw_fixture),
        snapshot(snapshot_name)
    );
}

fn snapshot(name: &str) -> String {
    fs::read_to_string(snapshot_path(name))
        .expect("read snapshot")
        .trim_end()
        .to_string()
}

fn normalize_raw_fixture_path(output: &str, raw_fixture: &Path) -> String {
    output.replace(&raw_fixture.display().to_string(), RAW_FIXTURE_TOKEN)
}
