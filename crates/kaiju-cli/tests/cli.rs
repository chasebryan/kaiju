use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process;
use std::process::Command;
use std::thread;
use std::time::Duration;
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
    assert!(stdout.contains("Dependencies: 0"));
    assert!(stdout.contains("Symbols: 0"));
    assert!(stdout.contains("Imports: 0"));
    assert!(stdout.contains("Exports: 0"));
    assert!(stdout.contains("Relocations: 0"));
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
    assert!(stdout.contains("Dependencies: 0"));
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
    assert!(stdout.contains("Dependencies: 0"));
    assert!(stdout.contains("Imports: 0"));
    assert!(stdout.contains("Exports: 0"));
    assert!(stdout.contains("Relocations: 0"));

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
fn cli_relocations_reports_pe_base_relocations() {
    let path = write_temp_pe_relocation_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("relocations")
        .arg(&path)
        .output()
        .expect("run kaiju relocations on PE");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Address  Kind"));
    assert!(stdout.contains("0x0000000140001008"));
    assert!(stdout.contains("pe-dir64"));
    assert!(stdout.contains("0x0000000140001020"));
    assert!(stdout.contains("pe-highlow"));
    assert!(stdout.contains("0x0000000140001040"));
    assert!(stdout.contains("pe-high"));

    let _ = fs::remove_file(path);
}

#[test]
fn cli_imports_reports_elf_imports() {
    let path = write_temp_elf_dynamic_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("imports")
        .arg(&path)
        .output()
        .expect("run kaiju imports on ELF");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Library  Name  Ordinal  Thunk"));
    assert!(stdout.contains("ELF"));
    assert!(stdout.contains("puts"));
    assert!(stdout.contains("0x0000000000402000"));

    let _ = fs::remove_file(path);
}

#[test]
fn cli_dependencies_reports_elf_needed_libraries() {
    let path = write_temp_elf_dynamic_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("dependencies")
        .arg(&path)
        .output()
        .expect("run kaiju dependencies on ELF");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Name"));
    assert!(stdout.contains("libc.so.6"));

    let _ = fs::remove_file(path);
}

#[test]
fn cli_relocations_reports_elf_relocations() {
    let path = write_temp_elf_dynamic_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("relocations")
        .arg(&path)
        .output()
        .expect("run kaiju relocations on ELF");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Address  Kind"));
    assert!(stdout.contains("0x0000000000402000"));
    assert!(stdout.contains("elf-x86_64-jump-slot"));
    assert!(stdout.contains("0x0000000000402008"));
    assert!(stdout.contains("elf-x86_64-relative"));

    let _ = fs::remove_file(path);
}

#[test]
fn cli_relocations_reports_mach_o_section_relocations() {
    let path = write_temp_mach_o_relocation_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("relocations")
        .arg(&path)
        .output()
        .expect("run kaiju relocations on Mach-O");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Address  Kind"));
    assert!(stdout.contains("0x0000000100000108"));
    assert!(stdout.contains("macho-x86_64-branch-pcrel-external-len4"));
    assert!(stdout.contains("0x0000000100000110"));
    assert!(stdout.contains("macho-x86_64-unsigned-absolute-local-len8"));

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
fn cli_dependencies_reports_pe_import_dlls() {
    let path = write_temp_pe_import_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("dependencies")
        .arg(&path)
        .output()
        .expect("run kaiju dependencies on PE");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Name"));
    assert!(stdout.contains("KERNEL32.dll"));

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
fn cli_reports_mach_o_universal_metadata_and_diagnostic() {
    let path = write_temp_mach_o_universal_fixture();

    let info = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("info")
        .arg(&path)
        .output()
        .expect("run kaiju info on universal Mach-O");
    assert!(info.status.success());
    let stdout = String::from_utf8(info.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Format: Mach-O"));
    assert!(stdout.contains("Architecture: x86_64"));
    assert!(stdout.contains("Entrypoint: 0x0000000100000100"));

    let diagnostics = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("diagnostics")
        .arg(&path)
        .output()
        .expect("run kaiju diagnostics on universal Mach-O");
    assert!(diagnostics.status.success());
    let stdout = String::from_utf8(diagnostics.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("universal binary selected x86_64 member"));

    let _ = fs::remove_file(path);
}

#[test]
fn cli_symbols_reports_mach_o_symbols() {
    let path = write_temp_mach_o_symbol_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("symbols")
        .arg(&path)
        .output()
        .expect("run kaiju symbols on Mach-O");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Name  Address"));
    assert!(stdout.contains("_main"));
    assert!(stdout.contains("0x0000000100000100"));
    assert!(stdout.contains("_puts"));

    let _ = fs::remove_file(path);
}

#[test]
fn cli_imports_reports_mach_o_imports() {
    let path = write_temp_mach_o_symbol_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("imports")
        .arg(&path)
        .output()
        .expect("run kaiju imports on Mach-O");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Library  Name  Ordinal  Thunk"));
    assert!(stdout.contains("Mach-O"));
    assert!(stdout.contains("_puts"));

    let _ = fs::remove_file(path);
}

#[test]
fn cli_dependencies_reports_mach_o_dylibs() {
    let path = write_temp_mach_o_dylib_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("dependencies")
        .arg(&path)
        .output()
        .expect("run kaiju dependencies on Mach-O");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Name"));
    assert!(stdout.contains("libSystem.B.dylib"));

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
fn cli_ir_reports_project_ir_summaries() {
    let path = write_temp_elf_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("ir")
        .arg(&path)
        .output()
        .expect("run kaiju ir on ELF");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Function  Blocks  Instructions  Unknowns  Name"));
    assert!(stdout.contains("0x0000000000401000"));
    assert!(stdout.contains("entry"));
    assert!(stdout.contains("block_401000:"));
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
    assert!(stdout.contains("Passes: 8"));
    assert!(stdout.contains("Dependencies: 0"));
    assert!(stdout.contains("Imports: 0"));
    assert!(stdout.contains("Exports: 0"));
    assert!(stdout.contains("Relocations: 0"));
    assert!(stdout.contains("Functions: 1"));
    assert!(stdout.contains("Blocks:"));
    assert!(stdout.contains("IRFunctions: 1"));
    assert!(stdout.contains("Xrefs:"));
    assert!(stdout.contains("entrypoint-cfg"));
    assert!(stdout.contains("function-discovery"));
    assert!(stdout.contains("function-cfg"));
    assert!(stdout.contains("data-references"));
    assert!(stdout.contains("ir-summary"));

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
    assert!(stdout.contains("Passes: 8"));
    assert!(stdout.contains("Dependencies: 0"));
    assert!(stdout.contains("Imports: 0"));
    assert!(stdout.contains("Exports: 0"));
    assert!(stdout.contains("Relocations: 0"));
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
    assert!(stdout.contains("\"dependencies\": 0"));
    assert!(stdout.contains("\"ir_functions\": 0"));
    assert!(stdout.contains("\"severity\": \"note\""));
    assert!(stdout.contains("\"strings\": 1"));
    assert!(stdout.contains("Kaiju raw fixture"));
}

#[test]
fn cli_save_writes_project_package() {
    let path = write_temp_elf_fixture();
    let output_dir = temp_package_dir("save");

    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("save")
        .arg(&path)
        .arg("--out")
        .arg(&output_dir)
        .output()
        .expect("run kaiju save");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Saved:"));
    assert!(stdout.contains("manifest.json"));
    assert!(stdout.contains("project.json"));
    assert!(stdout.contains("annotations.json"));

    let manifest = fs::read_to_string(output_dir.join("manifest.json")).expect("read manifest");
    let project = fs::read_to_string(output_dir.join("project.json")).expect("read project");
    let annotations =
        fs::read_to_string(output_dir.join("annotations.json")).expect("read annotations");

    assert!(manifest.contains("\"schema\": \"kaiju.package.v1\""));
    assert!(manifest.contains("\"project_schema\": \"kaiju.project.v1\""));
    assert!(manifest.contains("\"project\": \"project.json\""));
    assert!(manifest.contains("\"annotations\": \"annotations.json\""));
    assert!(project.contains("\"schema\": \"kaiju.project.v1\""));
    assert!(project.contains("\"ir_functions\":"));
    assert!(annotations.contains("\"schema\": \"kaiju.annotations.v1\""));
    assert!(annotations.contains("\"labels\": []"));
    assert!(annotations.contains("\"comments\": []"));

    let _ = fs::remove_file(path);
    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn cli_save_refuses_non_empty_project_package_dir() {
    let output_dir = temp_package_dir("save-non-empty");
    fs::create_dir_all(&output_dir).expect("create package dir");
    fs::write(output_dir.join("existing.txt"), "keep me").expect("write existing file");

    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("save")
        .arg(fixture_path("raw.bin"))
        .arg("--out")
        .arg(&output_dir)
        .output()
        .expect("run kaiju save");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf-8");
    assert!(stderr.contains("project package output directory is not empty"));
    assert!(output_dir.join("existing.txt").exists());

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn cli_package_inspects_saved_project_package() {
    let path = write_temp_elf_fixture();
    let output_dir = temp_package_dir("package");

    let save = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("save")
        .arg(&path)
        .arg("--out")
        .arg(&output_dir)
        .output()
        .expect("run kaiju save");
    assert!(save.status.success());

    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("package")
        .arg(&output_dir)
        .output()
        .expect("run kaiju package");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Schema: kaiju.package.v1"));
    assert!(stdout.contains("ProjectSchema: kaiju.project.v1"));
    assert!(stdout.contains("Format: ELF"));
    assert!(stdout.contains("Architecture: x86_64"));
    assert!(stdout.contains("Functions: 1"));
    assert!(stdout.contains("Blocks: 1"));
    assert!(stdout.contains("IRFunctions: 1"));
    assert!(stdout.contains("- manifest.json ok"));
    assert!(stdout.contains("- project.json ok"));
    assert!(stdout.contains("- annotations.json ok"));

    let _ = fs::remove_file(path);
    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn cli_package_rejects_malformed_project_package() {
    let output_dir = temp_package_dir("package-malformed");
    fs::create_dir_all(&output_dir).expect("create package dir");
    fs::write(output_dir.join("manifest.json"), "{\"schema\":\"wrong\"}").expect("write manifest");
    fs::write(
        output_dir.join("project.json"),
        "{\"schema\":\"kaiju.project.v1\"}",
    )
    .expect("write project");
    fs::write(
        output_dir.join("annotations.json"),
        "{\"schema\":\"kaiju.annotations.v1\"}",
    )
    .expect("write annotations");

    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("package")
        .arg(&output_dir)
        .output()
        .expect("run kaiju package");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf-8");
    assert!(stderr.contains("manifest.json has schema=wrong"));

    let _ = fs::remove_dir_all(output_dir);
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
fn cli_functions_reports_direct_call_target_functions() {
    let path = write_temp_call_elf_fixture();

    let functions = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("functions")
        .arg(&path)
        .output()
        .expect("run kaiju functions");

    assert!(functions.status.success());
    let stdout = String::from_utf8(functions.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Start  Name  Blocks"));
    assert!(stdout.contains("0x0000000000401000"));
    assert!(stdout.contains("0x0000000000401006"));
    assert!(stdout.contains("0x000000000040100c"));
    assert!(stdout.lines().any(|line| {
        let columns = line.split_whitespace().collect::<Vec<_>>();
        columns == ["0x0000000000401006", "-", "1"]
    }));
    assert!(stdout.lines().any(|line| {
        let columns = line.split_whitespace().collect::<Vec<_>>();
        columns == ["0x000000000040100c", "-", "1"]
    }));

    let xrefs = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("xrefs")
        .arg(&path)
        .output()
        .expect("run kaiju xrefs");

    assert!(xrefs.status.success());
    let stdout = String::from_utf8(xrefs.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("0x0000000000401000"));
    assert!(stdout.contains("0x0000000000401006"));
    assert!(stdout.contains("0x000000000040100c"));
    assert!(stdout.contains("call"));
    assert!(stdout.lines().any(|line| {
        let columns = line.split_whitespace().collect::<Vec<_>>();
        columns == ["0x0000000000401006", "0x000000000040100b", "flow"]
    }));
    assert!(stdout.lines().any(|line| {
        let columns = line.split_whitespace().collect::<Vec<_>>();
        columns == ["0x0000000000401006", "0x000000000040100c", "call"]
    }));
    assert!(stdout.lines().any(|line| {
        let columns = line.split_whitespace().collect::<Vec<_>>();
        columns == ["0x000000000040100c", "0x000000000040100c", "flow"]
    }));

    let _ = fs::remove_file(path);
}

#[test]
fn cli_xrefs_reports_rip_relative_string_data_refs() {
    let path = write_temp_data_xref_elf_fixture();

    let xrefs = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("xrefs")
        .arg(&path)
        .output()
        .expect("run kaiju xrefs");

    assert!(xrefs.status.success());
    let stdout = String::from_utf8(xrefs.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("From  To  Kind"));
    assert!(stdout.contains("0x0000000000401000"));
    assert!(stdout.contains("0x0000000000401008"));
    assert!(stdout.contains("data"));

    let analyze = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("analyze")
        .arg(&path)
        .output()
        .expect("run kaiju analyze");

    assert!(analyze.status.success());
    let stdout = String::from_utf8(analyze.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("data-references"));
    assert!(stdout.contains("- data-references facts=1 warnings=0"));

    let export = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("export")
        .arg(&path)
        .output()
        .expect("run kaiju export");

    assert!(export.status.success());
    let stdout = String::from_utf8(export.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("\"namespace\": \"data-references\""));
    assert!(stdout.contains("\"key\": \"string_targets\""));
    assert!(stdout.contains("\"kind\": \"data\""));
    assert!(stdout.contains("kaiju-target"));

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
fn cli_symbols_reports_pe_coff_symbols() {
    let path = write_temp_pe_symbol_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("symbols")
        .arg(&path)
        .output()
        .expect("run kaiju symbols on PE");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Name  Address"));
    assert!(stdout.contains("_start"));
    assert!(stdout.contains("0x0000000140001000"));
    assert!(stdout.contains("helper_long_name"));
    assert!(stdout.contains("0x0000000140001004"));

    let _ = fs::remove_file(path);
}

#[test]
fn cli_dependencies_reports_header_for_files_without_dependencies() {
    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("dependencies")
        .arg(fixture_path("raw.bin"))
        .output()
        .expect("run kaiju dependencies");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert_eq!(stdout.trim_end(), "Name");
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
fn cli_relocations_reports_header_for_files_without_relocations() {
    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("relocations")
        .arg(fixture_path("raw.bin"))
        .output()
        .expect("run kaiju relocations");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert_eq!(stdout.trim_end(), "Address  Kind");
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
fn cli_network_reports_offline_evidence_topology() {
    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("network")
        .arg(fixture_path("network-evidence.txt"))
        .output()
        .expect("run kaiju network");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Hosts: 7"));
    assert!(stdout.contains("Services: 4"));
    assert!(stdout.contains("Edges: 4"));
    assert!(stdout.contains("Observations: 4"));
    assert!(stdout.contains("IgnoredLines: 1"));
    assert!(stdout.contains("workstation.local"));
    assert!(stdout.contains("api.internal.example"));
    assert!(stdout.contains("db.internal"));
    assert!(stdout.contains("resolver.internal"));
    assert!(stdout.contains("10.0.0.8"));
    assert!(stdout.contains("https"));
    assert!(stdout.contains("5432"));
}

#[test]
fn cli_network_supports_json_and_dot_outputs() {
    let json = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("network")
        .arg(fixture_path("network-evidence.txt"))
        .arg("--format")
        .arg("json")
        .output()
        .expect("run kaiju network json");

    assert!(json.status.success());
    let stdout = String::from_utf8(json.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("\"schema\": \"kaiju.network.v1\""));
    assert!(stdout.contains("\"source\": \"workstation.local\""));
    assert!(stdout.contains("\"destination\": \"api.internal.example\""));

    let dot = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("network")
        .arg(fixture_path("network-evidence.txt"))
        .arg("--format")
        .arg("dot")
        .output()
        .expect("run kaiju network dot");

    assert!(dot.status.success());
    let stdout = String::from_utf8(dot.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("digraph network"));
    assert!(stdout.contains("\"workstation.local\" -> \"api.internal.example\""));
}

#[test]
fn cli_network_probe_opens_socket_and_inspects_payload() {
    let Some(listener) = bind_loopback_listener() else {
        return;
    };
    let port = listener
        .local_addr()
        .expect("listener local address")
        .port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept probe");
        stream
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("set read timeout");
        let mut buffer = [0_u8; 16];
        let _ = stream.read(&mut buffer);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nkaiju")
            .expect("write probe response");
    });

    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("network")
        .arg("probe")
        .arg("--target")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--send-text")
        .arg("ping")
        .arg("--read-bytes")
        .arg("128")
        .arg("--timeout-ms")
        .arg("1000")
        .output()
        .expect("run kaiju network probe");

    handle.join().expect("probe listener thread");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Mode: probe"));
    assert!(stdout.contains("Open: 1"));
    assert!(stdout.contains("open"));
    assert!(stdout.contains("http"));
    assert!(stdout.contains("HTTP/1.1 200 OK"));
}

#[test]
fn cli_network_scan_reports_local_open_port() {
    let Some(listener) = bind_loopback_listener() else {
        return;
    };
    let port = listener
        .local_addr()
        .expect("listener local address")
        .port();
    let handle = thread::spawn(move || {
        let _ = listener.accept().expect("accept scan");
    });

    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("network")
        .arg("scan")
        .arg("--host")
        .arg("127.0.0.1")
        .arg("--ports")
        .arg(port.to_string())
        .arg("--timeout-ms")
        .arg("1000")
        .output()
        .expect("run kaiju network scan");

    handle.join().expect("scan listener thread");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Mode: scan"));
    assert!(stdout.contains("Open: 1"));
    assert!(stdout.contains(&format!("127.0.0.1:{port}")));
}

#[test]
fn cli_network_pcap_imports_packet_payloads() {
    let path = write_temp_pcap_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_kaiju"))
        .arg("network")
        .arg("pcap")
        .arg(&path)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run kaiju network pcap");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("\"schema\": \"kaiju.network.v1\""));
    assert!(stdout.contains("\"source\": \"10.0.0.4\""));
    assert!(stdout.contains("\"destination\": \"10.0.0.8\""));
    assert!(stdout.contains("\"kind\": \"http\""));
    assert!(stdout.contains("GET / HTTP/1.1"));

    let _ = fs::remove_file(path);
}

#[test]
fn cli_raw_fixture_snapshots_match() {
    assert_raw_snapshot(&["info", RAW_FIXTURE_TOKEN], "raw-info.txt");
    assert_raw_snapshot(&["map", RAW_FIXTURE_TOKEN], "raw-map.txt");
    assert_raw_snapshot(&["diagnostics", RAW_FIXTURE_TOKEN], "raw-diagnostics.txt");
    assert_raw_snapshot(&["strings", RAW_FIXTURE_TOKEN], "raw-strings.txt");
    assert_raw_snapshot(&["analyze", RAW_FIXTURE_TOKEN], "raw-analyze.txt");
    assert_raw_snapshot(&["export", RAW_FIXTURE_TOKEN], "raw-export.json");
    assert_raw_snapshot(&["ir", RAW_FIXTURE_TOKEN], "raw-ir.txt");
    assert_raw_snapshot(&["dependencies", RAW_FIXTURE_TOKEN], "raw-dependencies.txt");
    assert_raw_snapshot(&["imports", RAW_FIXTURE_TOKEN], "raw-imports.txt");
    assert_raw_snapshot(&["exports", RAW_FIXTURE_TOKEN], "raw-exports.txt");
    assert_raw_snapshot(&["relocations", RAW_FIXTURE_TOKEN], "raw-relocations.txt");
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

fn bind_loopback_listener() -> Option<TcpListener> {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => Some(listener),
        Err(error) if error.kind() == ErrorKind::PermissionDenied => None,
        Err(error) => panic!("bind local listener: {error}"),
    }
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

fn write_temp_call_elf_fixture() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after epoch")
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("kaiju-cli-call-elf-{}-{unique}.bin", process::id()));
    fs::write(&path, synthetic_call_elf64_le()).expect("write call ELF fixture");
    path
}

fn write_temp_data_xref_elf_fixture() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "kaiju-cli-data-xref-{}-{unique}.bin",
        process::id()
    ));
    fs::write(&path, synthetic_data_xref_elf64_le()).expect("write data xref ELF fixture");
    path
}

fn write_temp_elf_dynamic_fixture() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "kaiju-cli-dynamic-elf-{}-{unique}.bin",
        process::id()
    ));
    fs::write(&path, synthetic_elf64_le_with_imports_and_relocations())
        .expect("write dynamic ELF fixture");
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

fn write_temp_pe_symbol_fixture() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "kaiju-cli-pe-symbols-{}-{unique}.exe",
        process::id()
    ));
    fs::write(&path, synthetic_pe32_plus_with_coff_symbols()).expect("write PE symbol fixture");
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

fn write_temp_pe_relocation_fixture() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "kaiju-cli-pe-relocations-{}-{unique}.exe",
        process::id()
    ));
    fs::write(&path, synthetic_pe32_plus_with_relocations()).expect("write PE relocation fixture");
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

fn write_temp_mach_o_symbol_fixture() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "kaiju-cli-macho-symbols-{}-{unique}.bin",
        process::id()
    ));
    fs::write(&path, synthetic_mach_o64_le_with_symbols()).expect("write Mach-O symbol fixture");
    path
}

fn write_temp_mach_o_dylib_fixture() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "kaiju-cli-macho-dylib-{}-{unique}.bin",
        process::id()
    ));
    fs::write(&path, synthetic_mach_o64_le_with_dylib()).expect("write Mach-O dylib fixture");
    path
}

fn write_temp_mach_o_relocation_fixture() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "kaiju-cli-macho-relocations-{}-{unique}.bin",
        process::id()
    ));
    fs::write(&path, synthetic_mach_o64_le_with_relocations())
        .expect("write Mach-O relocation fixture");
    path
}

fn write_temp_mach_o_universal_fixture() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "kaiju-cli-macho-universal-{}-{unique}.bin",
        process::id()
    ));
    fs::write(&path, synthetic_mach_o_universal_with_thin_member())
        .expect("write universal Mach-O fixture");
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

fn write_temp_pcap_fixture() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("kaiju-cli-pcap-{}-{unique}.pcap", process::id()));
    fs::write(&path, synthetic_pcap_tcp_http()).expect("write pcap fixture");
    path
}

fn temp_package_dir(label: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "kaiju-cli-{label}-{}-{unique}.kaiju",
        process::id()
    ))
}

fn synthetic_elf64_le() -> Vec<u8> {
    synthetic_elf64_le_with_code(&[0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3])
}

fn synthetic_cfg_elf64_le() -> Vec<u8> {
    synthetic_elf64_le_with_code(&[0x75, 0x02, 0xc3, 0x90, 0xc3])
}

fn synthetic_call_elf64_le() -> Vec<u8> {
    synthetic_elf64_le_with_code(&[
        0xe8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0xe8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0xc3,
    ])
}

fn synthetic_data_xref_elf64_le() -> Vec<u8> {
    let mut code = vec![0x48, 0x8d, 0x05, 0x01, 0x00, 0x00, 0x00, 0xc3];
    code.extend_from_slice(b"kaiju-target\0");
    synthetic_elf64_le_with_code(&code)
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

fn synthetic_elf64_le_with_imports_and_relocations() -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x600];
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
    write_u16_le(&mut bytes, 60, 7);
    write_u16_le(&mut bytes, 62, 2);

    write_u32_le(&mut bytes, 0x40, 1);
    write_u32_le(&mut bytes, 0x40 + 4, 5);
    write_u64_le(&mut bytes, 0x40 + 8, 0x300);
    write_u64_le(&mut bytes, 0x40 + 16, 0x401000);
    write_u64_le(&mut bytes, 0x40 + 32, 4);
    write_u64_le(&mut bytes, 0x40 + 40, 0x2000);
    write_u64_le(&mut bytes, 0x40 + 48, 0x1000);

    write_elf_section64(
        &mut bytes,
        0x100 + 64,
        ElfSection64Spec {
            name: 1,
            section_type: 1,
            flags: 0x6,
            address: 0x401000,
            file_offset: 0x300,
            size: 4,
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
            size: 52,
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
            file_offset: 0x390,
            size: 23,
            link: 0,
            entry_size: 0,
        },
    );
    write_elf_section64(
        &mut bytes,
        0x100 + 256,
        ElfSection64Spec {
            name: 25,
            section_type: 11,
            flags: 0,
            address: 0,
            file_offset: 0x3c0,
            size: 72,
            link: 3,
            entry_size: 24,
        },
    );
    write_elf_section64(
        &mut bytes,
        0x100 + 320,
        ElfSection64Spec {
            name: 33,
            section_type: 4,
            flags: 0,
            address: 0,
            file_offset: 0x420,
            size: 48,
            link: 4,
            entry_size: 24,
        },
    );
    write_elf_section64(
        &mut bytes,
        0x100 + 384,
        ElfSection64Spec {
            name: 43,
            section_type: 6,
            flags: 0,
            address: 0,
            file_offset: 0x480,
            size: 32,
            link: 3,
            entry_size: 16,
        },
    );

    bytes[0x300..0x304].copy_from_slice(&[0x90, 0x90, 0xc3, 0x00]);
    bytes[0x340..0x374]
        .copy_from_slice(b"\0.text\0.shstrtab\0.dynstr\0.dynsym\0.rela.plt\0.dynamic\0");
    bytes[0x390..0x3a7].copy_from_slice(b"\0puts\0printf\0libc.so.6\0");
    write_elf64_symbol(&mut bytes, 0x3c0 + 24, 1, 0x12, 0, 0, 0);
    write_elf64_symbol(&mut bytes, 0x3c0 + 48, 6, 0x12, 1, 0x401000, 0);
    write_elf64_rela(&mut bytes, 0x420, 0x402000, 1, 7, 0);
    write_elf64_rela(&mut bytes, 0x420 + 24, 0x402008, 0, 8, 0x401000);
    write_u64_le(&mut bytes, 0x480, 1);
    write_u64_le(&mut bytes, 0x488, 13);
    write_u64_le(&mut bytes, 0x490, 0);

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

fn write_elf64_rela(
    bytes: &mut [u8],
    offset: usize,
    relocation_offset: u64,
    symbol_index: u64,
    relocation_type: u64,
    addend: u64,
) {
    write_u64_le(bytes, offset, relocation_offset);
    write_u64_le(bytes, offset + 8, (symbol_index << 32) | relocation_type);
    write_u64_le(bytes, offset + 16, addend);
}

fn write_pe_coff_short_symbol(
    bytes: &mut [u8],
    offset: usize,
    name: &[u8; 8],
    value: u32,
    section_number: u16,
    auxiliary_count: u8,
) {
    bytes[offset..offset + 8].copy_from_slice(name);
    write_u32_le(bytes, offset + 8, value);
    write_u16_le(bytes, offset + 12, section_number);
    write_u16_le(bytes, offset + 14, 0x20);
    bytes[offset + 16] = 2;
    bytes[offset + 17] = auxiliary_count;
}

fn write_pe_coff_long_symbol(
    bytes: &mut [u8],
    offset: usize,
    string_offset: u32,
    value: u32,
    section_number: u16,
    auxiliary_count: u8,
) {
    write_u32_le(bytes, offset, 0);
    write_u32_le(bytes, offset + 4, string_offset);
    write_u32_le(bytes, offset + 8, value);
    write_u16_le(bytes, offset + 12, section_number);
    write_u16_le(bytes, offset + 14, 0x20);
    bytes[offset + 16] = 2;
    bytes[offset + 17] = auxiliary_count;
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

fn synthetic_pe32_plus_with_coff_symbols() -> Vec<u8> {
    let mut bytes = synthetic_pe32_plus();
    bytes.resize(0x800, 0);

    let coff = 0x104;
    write_u32_le(&mut bytes, coff + 8, 0x400);
    write_u32_le(&mut bytes, coff + 12, 3);
    write_pe_coff_short_symbol(&mut bytes, 0x400, b"_start\0\0", 0, 1, 0);
    write_pe_coff_long_symbol(&mut bytes, 0x412, 4, 4, 1, 1);
    write_u32_le(&mut bytes, 0x436, 21);
    bytes[0x43a..0x44b].copy_from_slice(b"helper_long_name\0");

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
    write_u16_le(&mut bytes, coff + 16, 0xf0);

    let optional = coff + 20;
    write_u16_le(&mut bytes, optional, 0x20b);
    write_u32_le(&mut bytes, optional + 16, 0x1000);
    write_u64_le(&mut bytes, optional + 24, 0x140000000);
    write_u32_le(&mut bytes, optional + 108, 16);
    write_u32_le(&mut bytes, optional + 120, 0x2000);
    write_u32_le(&mut bytes, optional + 124, 0x40);

    let text = 0x208;
    bytes[text..text + 8].copy_from_slice(b".text\0\0\0");
    write_u32_le(&mut bytes, text + 8, 0x100);
    write_u32_le(&mut bytes, text + 12, 0x1000);
    write_u32_le(&mut bytes, text + 16, 0x100);
    write_u32_le(&mut bytes, text + 20, 0x300);
    write_u32_le(&mut bytes, text + 36, 0x6000_0000);

    let rdata = 0x230;
    bytes[rdata..rdata + 8].copy_from_slice(b".rdata\0\0");
    write_u32_le(&mut bytes, rdata + 8, 0x200);
    write_u32_le(&mut bytes, rdata + 12, 0x2000);
    write_u32_le(&mut bytes, rdata + 16, 0x200);
    write_u32_le(&mut bytes, rdata + 20, 0x400);
    write_u32_le(&mut bytes, rdata + 36, 0x4000_0000);

    bytes[0x300..0x304].copy_from_slice(&[0x90, 0x90, 0xc3, 0x00]);

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
    write_u16_le(&mut bytes, coff + 16, 0xf0);

    let optional = coff + 20;
    write_u16_le(&mut bytes, optional, 0x20b);
    write_u32_le(&mut bytes, optional + 16, 0x1000);
    write_u64_le(&mut bytes, optional + 24, 0x140000000);
    write_u32_le(&mut bytes, optional + 108, 16);
    write_u32_le(&mut bytes, optional + 112, 0x2000);
    write_u32_le(&mut bytes, optional + 116, 0x100);

    let text = 0x208;
    bytes[text..text + 8].copy_from_slice(b".text\0\0\0");
    write_u32_le(&mut bytes, text + 8, 0x100);
    write_u32_le(&mut bytes, text + 12, 0x1000);
    write_u32_le(&mut bytes, text + 16, 0x100);
    write_u32_le(&mut bytes, text + 20, 0x300);
    write_u32_le(&mut bytes, text + 36, 0x6000_0000);

    let rdata = 0x230;
    bytes[rdata..rdata + 8].copy_from_slice(b".rdata\0\0");
    write_u32_le(&mut bytes, rdata + 8, 0x200);
    write_u32_le(&mut bytes, rdata + 12, 0x2000);
    write_u32_le(&mut bytes, rdata + 16, 0x200);
    write_u32_le(&mut bytes, rdata + 20, 0x400);
    write_u32_le(&mut bytes, rdata + 36, 0x4000_0000);

    bytes[0x300..0x304].copy_from_slice(&[0x90, 0x90, 0xc3, 0x00]);

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

fn synthetic_pe32_plus_with_relocations() -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x800];
    bytes[0] = b'M';
    bytes[1] = b'Z';
    write_u32_le(&mut bytes, 0x3c, 0x100);
    bytes[0x100..0x104].copy_from_slice(b"PE\0\0");

    let coff = 0x104;
    write_u16_le(&mut bytes, coff, 0x8664);
    write_u16_le(&mut bytes, coff + 2, 2);
    write_u16_le(&mut bytes, coff + 16, 0xf0);

    let optional = coff + 20;
    write_u16_le(&mut bytes, optional, 0x20b);
    write_u32_le(&mut bytes, optional + 16, 0x1000);
    write_u64_le(&mut bytes, optional + 24, 0x140000000);
    write_u32_le(&mut bytes, optional + 108, 16);
    write_u32_le(&mut bytes, optional + 152, 0x3000);
    write_u32_le(&mut bytes, optional + 156, 0x10);

    let text = 0x208;
    bytes[text..text + 8].copy_from_slice(b".text\0\0\0");
    write_u32_le(&mut bytes, text + 8, 0x100);
    write_u32_le(&mut bytes, text + 12, 0x1000);
    write_u32_le(&mut bytes, text + 16, 0x200);
    write_u32_le(&mut bytes, text + 20, 0x300);
    write_u32_le(&mut bytes, text + 36, 0x6000_0000);

    let reloc = 0x230;
    bytes[reloc..reloc + 8].copy_from_slice(b".reloc\0\0");
    write_u32_le(&mut bytes, reloc + 8, 0x100);
    write_u32_le(&mut bytes, reloc + 12, 0x3000);
    write_u32_le(&mut bytes, reloc + 16, 0x200);
    write_u32_le(&mut bytes, reloc + 20, 0x500);
    write_u32_le(&mut bytes, reloc + 36, 0x4000_0000);

    bytes[0x300..0x304].copy_from_slice(&[0x90, 0x90, 0xc3, 0x00]);
    write_u32_le(&mut bytes, 0x500, 0x1000);
    write_u32_le(&mut bytes, 0x504, 0x10);
    write_u16_le(&mut bytes, 0x508, (10 << 12) | 0x008);
    write_u16_le(&mut bytes, 0x50a, (3 << 12) | 0x020);
    write_u16_le(&mut bytes, 0x50c, (1 << 12) | 0x040);
    write_u16_le(&mut bytes, 0x50e, 0);

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

fn synthetic_mach_o64_le_with_symbols() -> Vec<u8> {
    const MACHO64_SEGMENT_COMMAND_SIZE: usize = 72;
    const MACHO64_SECTION_SIZE: usize = 80;
    const LC_SYMTAB: u32 = 0x2;
    const N_STAB: u8 = 0xe0;
    const N_TYPE_SECT: u8 = 0x0e;
    const N_TYPE_UNDF: u8 = 0x00;
    const N_EXT: u8 = 0x01;

    let mut bytes = synthetic_mach_o64_le();
    bytes.resize(0x300, 0);

    let segment_command_size = MACHO64_SEGMENT_COMMAND_SIZE + MACHO64_SECTION_SIZE;
    let command_size = segment_command_size + 24 + 24;
    let symtab = mach_o64_symtab_command_offset();

    write_u32_le(&mut bytes, 16, 3);
    write_u32_le(&mut bytes, 20, command_size as u32);
    write_u32_le(&mut bytes, symtab, LC_SYMTAB);
    write_u32_le(&mut bytes, symtab + 4, 24);
    write_u32_le(&mut bytes, symtab + 8, 0x240);
    write_u32_le(&mut bytes, symtab + 12, 3);
    write_u32_le(&mut bytes, symtab + 16, 0x280);
    write_u32_le(&mut bytes, symtab + 20, 20);

    write_mach_o64_symbol(&mut bytes, 0x240, 1, N_TYPE_SECT | N_EXT, 1, 0, 0x100000100);
    write_mach_o64_symbol(&mut bytes, 0x250, 7, N_TYPE_UNDF | N_EXT, 0, 0, 0);
    write_mach_o64_symbol(&mut bytes, 0x260, 13, N_STAB, 0, 0, 0);
    bytes[0x280..0x294].copy_from_slice(b"\0_main\0_puts\0_debug\0");

    bytes
}

fn synthetic_mach_o64_le_with_dylib() -> Vec<u8> {
    const MACHO64_SEGMENT_COMMAND_SIZE: usize = 72;
    const MACHO64_SECTION_SIZE: usize = 80;
    const LC_LOAD_DYLIB: u32 = 0xc;

    let mut bytes = synthetic_mach_o64_le();

    let segment_command_size = MACHO64_SEGMENT_COMMAND_SIZE + MACHO64_SECTION_SIZE;
    let command_size = segment_command_size + 24 + 48;
    let dylib = mach_o64_dylib_command_offset();

    write_u32_le(&mut bytes, 16, 3);
    write_u32_le(&mut bytes, 20, command_size as u32);
    write_u32_le(&mut bytes, dylib, LC_LOAD_DYLIB);
    write_u32_le(&mut bytes, dylib + 4, 48);
    write_u32_le(&mut bytes, dylib + 8, 24);
    bytes[dylib + 24..dylib + 42].copy_from_slice(b"libSystem.B.dylib\0");

    bytes
}

fn synthetic_mach_o64_le_with_relocations() -> Vec<u8> {
    const MACHO64_HEADER_SIZE: usize = 32;
    const MACHO64_SEGMENT_COMMAND_SIZE: usize = 72;

    let mut bytes = synthetic_mach_o64_le();
    bytes.resize(0x280, 0);

    let section = MACHO64_HEADER_SIZE + MACHO64_SEGMENT_COMMAND_SIZE;
    write_u64_le(&mut bytes, section + 40, 0x20);
    write_u32_le(&mut bytes, section + 56, 0x240);
    write_u32_le(&mut bytes, section + 60, 2);
    bytes[0x104..0x120].copy_from_slice(&[0xcc; 0x1c]);

    write_mach_o_relocation(
        &mut bytes,
        0x240,
        MachORelocationSpec {
            address: 0x8,
            symbol_index: 1,
            relocation_type: 2,
            length: 2,
            pcrel: true,
            is_external: true,
        },
    );
    write_mach_o_relocation(
        &mut bytes,
        0x248,
        MachORelocationSpec {
            address: 0x10,
            symbol_index: 0,
            relocation_type: 0,
            length: 3,
            pcrel: false,
            is_external: false,
        },
    );

    bytes
}

fn synthetic_mach_o_universal_with_thin_member() -> Vec<u8> {
    let thin = synthetic_mach_o64_le();
    let member_offset = 0x100;
    let mut bytes = vec![0_u8; member_offset + thin.len()];
    bytes[0..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
    write_u32_be(&mut bytes, 4, 1);
    write_u32_be(&mut bytes, 8, 0x0100_0007);
    write_u32_be(&mut bytes, 12, 3);
    write_u32_be(&mut bytes, 16, member_offset as u32);
    write_u32_be(&mut bytes, 20, thin.len() as u32);
    write_u32_be(&mut bytes, 24, 12);
    bytes[member_offset..member_offset + thin.len()].copy_from_slice(&thin);
    bytes
}

fn mach_o64_symtab_command_offset() -> usize {
    const MACHO64_HEADER_SIZE: usize = 32;
    const MACHO64_SEGMENT_COMMAND_SIZE: usize = 72;
    const MACHO64_SECTION_SIZE: usize = 80;

    MACHO64_HEADER_SIZE + MACHO64_SEGMENT_COMMAND_SIZE + MACHO64_SECTION_SIZE + 24
}

fn mach_o64_dylib_command_offset() -> usize {
    const MACHO64_HEADER_SIZE: usize = 32;
    const MACHO64_SEGMENT_COMMAND_SIZE: usize = 72;
    const MACHO64_SECTION_SIZE: usize = 80;

    MACHO64_HEADER_SIZE + MACHO64_SEGMENT_COMMAND_SIZE + MACHO64_SECTION_SIZE + 24
}

fn write_mach_o64_symbol(
    bytes: &mut [u8],
    offset: usize,
    name_offset: u32,
    symbol_type: u8,
    section_index: u8,
    desc: u16,
    value: u64,
) {
    write_u32_le(bytes, offset, name_offset);
    bytes[offset + 4] = symbol_type;
    bytes[offset + 5] = section_index;
    write_u16_le(bytes, offset + 6, desc);
    write_u64_le(bytes, offset + 8, value);
}

struct MachORelocationSpec {
    address: u32,
    symbol_index: u32,
    relocation_type: u32,
    length: u32,
    pcrel: bool,
    is_external: bool,
}

fn write_mach_o_relocation(bytes: &mut [u8], offset: usize, spec: MachORelocationSpec) {
    let info = spec.symbol_index
        | (u32::from(spec.pcrel) << 24)
        | (spec.length << 25)
        | (u32::from(spec.is_external) << 27)
        | (spec.relocation_type << 28);
    write_u32_le(bytes, offset, spec.address);
    write_u32_le(bytes, offset + 4, info);
}

fn strings_fixture_bytes() -> Vec<u8> {
    let mut bytes = b"\0abc\0kaiju\0monster-class\0".to_vec();
    bytes.extend_from_slice(&[b'W', 0, b'i', 0, b'd', 0, b'e', 0, 0, 0]);
    bytes
}

fn synthetic_pcap_tcp_http() -> Vec<u8> {
    let payload = b"GET / HTTP/1.1\r\n\r\n";
    let tcp_len = 20 + payload.len();
    let ip_total_len = 20 + tcp_len;
    let frame_len = 14 + ip_total_len;
    let mut bytes = Vec::new();

    bytes.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
    bytes.extend_from_slice(&2_u16.to_le_bytes());
    bytes.extend_from_slice(&4_u16.to_le_bytes());
    bytes.extend_from_slice(&0_i32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&65_535_u32.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&(frame_len as u32).to_le_bytes());
    bytes.extend_from_slice(&(frame_len as u32).to_le_bytes());

    bytes.extend_from_slice(&[0, 1, 2, 3, 4, 5]);
    bytes.extend_from_slice(&[6, 7, 8, 9, 10, 11]);
    bytes.extend_from_slice(&0x0800_u16.to_be_bytes());

    bytes.push(0x45);
    bytes.push(0);
    bytes.extend_from_slice(&(ip_total_len as u16).to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.push(64);
    bytes.push(6);
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(&[10, 0, 0, 4]);
    bytes.extend_from_slice(&[10, 0, 0, 8]);

    bytes.extend_from_slice(&51_110_u16.to_be_bytes());
    bytes.extend_from_slice(&80_u16.to_be_bytes());
    bytes.extend_from_slice(&0_u32.to_be_bytes());
    bytes.extend_from_slice(&0_u32.to_be_bytes());
    bytes.push(0x50);
    bytes.push(0x18);
    bytes.extend_from_slice(&1024_u16.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(payload);

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

fn write_u32_be(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
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
