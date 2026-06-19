#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use kaiju_core::{
    Address, ArchitectureId, Diagnostic, DiagnosticSeverity, Endian, KaijuError, KaijuErrorKind,
    MemoryMap, MemoryRegion, Permissions, Result,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryFormat {
    Elf,
    Pe,
    MachO,
    Raw,
    Unknown,
}

impl fmt::Display for BinaryFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Elf => formatter.write_str("ELF"),
            Self::Pe => formatter.write_str("PE"),
            Self::MachO => formatter.write_str("Mach-O"),
            Self::Raw => formatter.write_str("Raw"),
            Self::Unknown => formatter.write_str("Unknown"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LoadedBinary {
    pub path: PathBuf,
    pub file_size: u64,
    pub bytes: Vec<u8>,
    pub format: BinaryFormat,
    pub arch: ArchitectureId,
    pub endian: Endian,
    pub entrypoint: Option<Address>,
    pub memory_map: MemoryMap,
    pub sections: Vec<Section>,
    pub dependencies: Vec<Dependency>,
    pub symbols: Vec<Symbol>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub relocations: Vec<Relocation>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub address: Address,
    pub file_offset: Option<u64>,
    pub size: u64,
    pub permissions: Permissions,
}

#[derive(Debug, Clone)]
pub struct Dependency {
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub address: Option<Address>,
}

#[derive(Debug, Clone)]
pub struct Import {
    pub library: String,
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    pub thunk: Option<Address>,
}

#[derive(Debug, Clone)]
pub struct Export {
    pub module: Option<String>,
    pub name: Option<String>,
    pub ordinal: u32,
    pub address: Option<Address>,
    pub forwarder: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Relocation {
    pub address: Address,
    pub kind: String,
}

pub trait Loader {
    fn load(&self, path: PathBuf, bytes: &[u8]) -> Result<LoadedBinary>;
}

#[derive(Debug, Default)]
pub struct RawLoader;

impl RawLoader {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Loader for RawLoader {
    fn load(&self, path: PathBuf, bytes: &[u8]) -> Result<LoadedBinary> {
        Ok(load_as_single_region(
            path,
            bytes,
            BinaryFormat::Raw,
            Endian::Unknown,
            "raw",
            vec![loader_note(
                "unknown format loaded as raw bytes at virtual address 0x0",
            )],
        ))
    }
}

pub fn load_path(path: impl AsRef<Path>) -> Result<LoadedBinary> {
    let path = path.as_ref();
    let bytes = fs::read(path)?;
    load_bytes(path.to_path_buf(), &bytes)
}

pub fn load_bytes(path: PathBuf, bytes: &[u8]) -> Result<LoadedBinary> {
    match detect_format(bytes) {
        BinaryFormat::Unknown | BinaryFormat::Raw => RawLoader::new().load(path, bytes),
        BinaryFormat::Elf => ElfLoader::new().load(path, bytes),
        BinaryFormat::Pe => PeLoader::new().load(path, bytes),
        BinaryFormat::MachO => MachOLoader::new().load(path, bytes),
    }
}

#[derive(Debug, Default)]
pub struct MachOLoader;

impl MachOLoader {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Loader for MachOLoader {
    fn load(&self, path: PathBuf, bytes: &[u8]) -> Result<LoadedBinary> {
        let Some(magic) = mach_o_magic(bytes) else {
            return Err(malformed("input is not a Mach-O image"));
        };

        match magic {
            MachOMagic::Fat { endian, is_64 } => load_fat_mach_o(path, bytes, endian, is_64),
            MachOMagic::Thin { endian, is_64 } => {
                load_thin_mach_o(path, bytes, endian, is_64, Vec::new())
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct PeLoader;

impl PeLoader {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Loader for PeLoader {
    fn load(&self, path: PathBuf, bytes: &[u8]) -> Result<LoadedBinary> {
        let header = parse_pe_header(bytes)?;
        let sections = parse_pe_sections(bytes, &header)?;
        let symbols = parse_pe_symbols(bytes, &header, &sections)?;
        let imports = parse_pe_imports(bytes, &header, &sections)?;
        let dependencies = dependencies_from_imports(&imports);
        let exports = parse_pe_exports(bytes, &header, &sections)?;
        let relocations = parse_pe_relocations(bytes, &header, &sections)?;
        let mut memory_map = MemoryMap::new();
        let mut diagnostics = vec![loader_note(
            "PE loader uses limited metadata parsing; debug symbols and rich metadata are not yet populated",
        )];

        for section in &sections {
            if section.size == 0 {
                continue;
            }

            let initialized_bytes = match section.file_offset {
                Some(offset) => {
                    checked_range(bytes, offset, section.raw_size, "PE section data")?.to_vec()
                }
                None => Vec::new(),
            };
            let region = MemoryRegion::new_with_size(
                section.name.clone(),
                section.address,
                section.file_offset,
                section.size,
                section.permissions,
                initialized_bytes,
            )?;
            memory_map.add_region(region);
        }

        if memory_map.regions().is_empty() {
            diagnostics.push(loader_warning(
                "PE contained no mappable sections; loaded file as read-only bytes at virtual address 0x0",
            ));
            memory_map.add_region(MemoryRegion::new(
                "pe-file",
                Address::ZERO,
                Some(0),
                Permissions::read_only(),
                bytes.to_vec(),
            ));
        }

        Ok(LoadedBinary {
            path,
            file_size: bytes.len() as u64,
            bytes: bytes.to_vec(),
            format: BinaryFormat::Pe,
            arch: pe_machine_to_arch(header.machine),
            endian: Endian::Little,
            entrypoint: header.entrypoint,
            memory_map,
            sections: sections
                .into_iter()
                .map(|section| Section {
                    name: section.name,
                    address: section.address,
                    file_offset: section.file_offset,
                    size: section.size,
                    permissions: section.permissions,
                })
                .collect(),
            dependencies,
            symbols,
            imports,
            exports,
            relocations,
            diagnostics,
        })
    }
}

#[derive(Debug, Default)]
pub struct ElfLoader;

impl ElfLoader {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Loader for ElfLoader {
    fn load(&self, path: PathBuf, bytes: &[u8]) -> Result<LoadedBinary> {
        let header = parse_elf_header(bytes)?;
        let program_headers = parse_elf_program_headers(bytes, &header)?;
        let raw_sections = parse_elf_section_headers(bytes, &header)?;
        let sections = parse_elf_sections(bytes, &header, &raw_sections)?;
        let elf_symbols = parse_elf_symbol_entries(bytes, &header, &raw_sections)?;
        let elf_relocations = parse_elf_relocation_entries(bytes, &header, &raw_sections)?;
        let dependencies = parse_elf_dependencies(bytes, &header, &raw_sections)?;
        let symbols = elf_symbols
            .iter()
            .map(|symbol| Symbol {
                name: symbol.name.clone(),
                address: symbol.address,
            })
            .collect();
        let imports = elf_imports_from_symbols(&elf_symbols, &elf_relocations);
        let relocations = elf_relocations
            .iter()
            .map(|relocation| Relocation {
                address: relocation.address,
                kind: relocation.kind.clone(),
            })
            .collect();
        let mut memory_map = MemoryMap::new();
        let mut diagnostics = vec![loader_note(
            "ELF loader uses limited metadata parsing; dynamic symbols and relocation tables are parsed without versioning or full dependency resolution",
        )];

        for (index, program_header) in program_headers
            .iter()
            .filter(|program_header| program_header.segment_type == PT_LOAD)
            .enumerate()
        {
            if program_header.memory_size == 0 {
                continue;
            }
            if program_header.file_size > program_header.memory_size {
                return Err(malformed("ELF segment file size exceeds memory size"));
            }

            let segment_bytes = checked_range(
                bytes,
                program_header.offset,
                program_header.file_size,
                "ELF segment",
            )?
            .to_vec();
            let region = MemoryRegion::new_with_size(
                format!("LOAD{index}"),
                Address::new(program_header.virtual_address),
                Some(program_header.offset),
                program_header.memory_size,
                segment_permissions(program_header.flags),
                segment_bytes,
            )?;
            memory_map.add_region(region);
        }

        if memory_map.regions().is_empty() {
            diagnostics.push(loader_warning(
                "ELF contained no PT_LOAD regions; loaded file as read-only bytes at virtual address 0x0",
            ));
            memory_map.add_region(MemoryRegion::new(
                "elf-file",
                Address::ZERO,
                Some(0),
                Permissions::read_only(),
                bytes.to_vec(),
            ));
        }

        Ok(LoadedBinary {
            path,
            file_size: bytes.len() as u64,
            bytes: bytes.to_vec(),
            format: BinaryFormat::Elf,
            arch: elf_machine_to_arch(header.machine),
            endian: header.endian,
            entrypoint: Some(Address::new(header.entrypoint)),
            memory_map,
            sections,
            dependencies,
            symbols,
            imports,
            exports: Vec::new(),
            relocations,
            diagnostics,
        })
    }
}

#[must_use]
pub fn detect_format(bytes: &[u8]) -> BinaryFormat {
    if bytes.starts_with(b"\x7fELF") {
        return BinaryFormat::Elf;
    }

    if looks_like_pe(bytes) {
        return BinaryFormat::Pe;
    }

    if looks_like_mach_o(bytes) {
        return BinaryFormat::MachO;
    }

    BinaryFormat::Unknown
}

const ELF_IDENT_LEN: usize = 16;
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ELFDATA2MSB: u8 = 2;
const PT_LOAD: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHT_DYNAMIC: u32 = 6;
const SHT_NOBITS: u32 = 8;
const SHT_REL: u32 = 9;
const SHT_DYNSYM: u32 = 11;
const SHN_UNDEF: u16 = 0;
const SHF_WRITE: u64 = 0x1;
const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;
const PF_X: u32 = 0x1;
const PF_W: u32 = 0x2;
const PF_R: u32 = 0x4;
const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const EM_386: u16 = 3;
const EM_ARM: u16 = 40;
const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;
const PE_SIGNATURE: &[u8; 4] = b"PE\0\0";
const PE_COFF_HEADER_SIZE: u64 = 20;
const PE_SECTION_HEADER_SIZE: u16 = 40;
const PE32_MAGIC: u16 = 0x10b;
const PE32_PLUS_MAGIC: u16 = 0x20b;
const PE32_NUMBER_OF_RVA_AND_SIZES_OFFSET: u64 = 92;
const PE32_PLUS_NUMBER_OF_RVA_AND_SIZES_OFFSET: u64 = 108;
const PE32_DATA_DIRECTORY_OFFSET: u64 = 96;
const PE32_PLUS_DATA_DIRECTORY_OFFSET: u64 = 112;
const PE_DATA_DIRECTORY_SIZE: u64 = 8;
const PE_EXPORT_DIRECTORY_INDEX: u32 = 0;
const PE_IMPORT_DIRECTORY_INDEX: u32 = 1;
const PE_BASE_RELOCATION_DIRECTORY_INDEX: u32 = 5;
const PE_EXPORT_DIRECTORY_SIZE: u64 = 40;
const PE_IMPORT_DESCRIPTOR_SIZE: u64 = 20;
const PE_EXPORT_ADDRESS_TABLE_ENTRY_SIZE: u64 = 4;
const PE_EXPORT_NAME_POINTER_ENTRY_SIZE: u64 = 4;
const PE_EXPORT_ORDINAL_TABLE_ENTRY_SIZE: u64 = 2;
const PE_COFF_SYMBOL_SIZE: u64 = 18;
const PE_BASE_RELOCATION_BLOCK_HEADER_SIZE: u64 = 8;
const PE_BASE_RELOCATION_ENTRY_SIZE: u64 = 2;
const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
const IMAGE_REL_BASED_HIGH: u16 = 1;
const IMAGE_REL_BASED_LOW: u16 = 2;
const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
const IMAGE_REL_BASED_HIGHADJ: u16 = 4;
const IMAGE_REL_BASED_DIR64: u16 = 10;
const PE32_IMPORT_LOOKUP_ENTRY_SIZE: u64 = 4;
const PE32_PLUS_IMPORT_LOOKUP_ENTRY_SIZE: u64 = 8;
const PE32_ORDINAL_FLAG: u64 = 0x8000_0000;
const PE32_PLUS_ORDINAL_FLAG: u64 = 0x8000_0000_0000_0000;
const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
const IMAGE_FILE_MACHINE_ARMNT: u16 = 0x01c4;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const MACHO32_HEADER_SIZE: u64 = 28;
const MACHO64_HEADER_SIZE: u64 = 32;
const MACHO_FAT_HEADER_SIZE: u64 = 8;
const MACHO_FAT_ARCH_SIZE: u64 = 20;
const MACHO_FAT_ARCH64_SIZE: u64 = 32;
const MACHO32_SEGMENT_COMMAND_SIZE: u64 = 56;
const MACHO64_SEGMENT_COMMAND_SIZE: u64 = 72;
const MACHO32_SECTION_SIZE: u64 = 68;
const MACHO64_SECTION_SIZE: u64 = 80;
const MACHO32_SYMBOL_SIZE: u64 = 12;
const MACHO64_SYMBOL_SIZE: u64 = 16;
const MACHO_RELOCATION_SIZE: u64 = 8;
const MACHO_SCATTERED_RELOCATION_FLAG: u32 = 0x8000_0000;
const LC_SEGMENT: u32 = 0x1;
const LC_LOAD_DYLIB: u32 = 0xc;
const LC_SYMTAB: u32 = 0x2;
const LC_SEGMENT_64: u32 = 0x19;
const LC_MAIN: u32 = 0x8000_0028;
const CPU_TYPE_X86: u32 = 7;
const CPU_TYPE_ARM: u32 = 12;
const CPU_TYPE_X86_64: u32 = 0x0100_0007;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const VM_PROT_READ: u32 = 0x1;
const VM_PROT_WRITE: u32 = 0x2;
const VM_PROT_EXECUTE: u32 = 0x4;
const SECTION_TYPE_MASK: u32 = 0xff;
const S_ZEROFILL: u32 = 0x1;
const N_STAB: u8 = 0xe0;
const N_TYPE: u8 = 0x0e;
const N_EXT: u8 = 0x01;
const N_UNDF: u8 = 0x00;
const N_SECT: u8 = 0x0e;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ElfClass {
    Elf32,
    Elf64,
}

#[derive(Debug, Clone, Copy)]
struct ElfHeader {
    class: ElfClass,
    endian: Endian,
    machine: u16,
    entrypoint: u64,
    program_header_offset: u64,
    section_header_offset: u64,
    program_header_entry_size: u16,
    program_header_count: u16,
    section_header_entry_size: u16,
    section_header_count: u16,
    section_name_table_index: u16,
}

#[derive(Debug, Clone, Copy)]
struct ElfProgramHeader {
    segment_type: u32,
    flags: u32,
    offset: u64,
    virtual_address: u64,
    file_size: u64,
    memory_size: u64,
}

#[derive(Debug, Clone, Copy)]
struct ElfSectionHeader {
    name_offset: u32,
    section_type: u32,
    flags: u64,
    address: u64,
    offset: u64,
    size: u64,
    link: u32,
    entry_size: u64,
}

#[derive(Debug, Clone)]
struct ElfSymbolEntry {
    table_section_index: usize,
    symbol_index: u64,
    is_dynamic: bool,
    name: String,
    section_index: u16,
    address: Option<Address>,
}

#[derive(Debug, Clone)]
struct ElfRelocationEntry {
    address: Address,
    kind: String,
    symbol_table_section_index: Option<usize>,
    symbol_index: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeKind {
    Pe32,
    Pe32Plus,
}

#[derive(Debug, Clone, Copy)]
struct PeHeader {
    kind: PeKind,
    machine: u16,
    image_base: u64,
    entrypoint: Option<Address>,
    section_table_offset: u64,
    section_count: u16,
    symbol_table_offset: u32,
    symbol_count: u32,
    export_directory: Option<PeDataDirectory>,
    import_directory: Option<PeDataDirectory>,
    base_relocation_directory: Option<PeDataDirectory>,
}

#[derive(Debug, Clone, Copy)]
struct PeDataDirectory {
    rva: u32,
    size: u32,
}

#[derive(Debug, Clone)]
struct PeSection {
    name: String,
    virtual_address: u64,
    address: Address,
    file_offset: Option<u64>,
    size: u64,
    raw_size: u64,
    permissions: Permissions,
}

#[derive(Debug, Clone, Copy)]
enum MachOMagic {
    Thin { endian: Endian, is_64: bool },
    Fat { endian: Endian, is_64: bool },
}

#[derive(Debug, Clone, Copy)]
struct MachOHeader {
    arch: ArchitectureId,
    command_count: u32,
    command_offset: u64,
    command_size: u64,
    is_64: bool,
    endian: Endian,
}

#[derive(Debug, Clone, Copy)]
struct MachOFatMember {
    arch: ArchitectureId,
    offset: u64,
    size: u64,
}

#[derive(Debug, Default)]
struct MachOCommands {
    segments: Vec<MachOSegment>,
    dependencies: Vec<Dependency>,
    symbols: Vec<Symbol>,
    imports: Vec<Import>,
    entrypoint_file_offset: Option<u64>,
}

#[derive(Debug, Default)]
struct MachOSymbols {
    symbols: Vec<Symbol>,
    imports: Vec<Import>,
}

#[derive(Debug, Clone)]
struct MachOSegment {
    name: String,
    address: Address,
    file_offset: Option<u64>,
    size: u64,
    file_size: u64,
    permissions: Permissions,
    sections: Vec<MachOSection>,
}

#[derive(Debug, Clone)]
struct MachOSection {
    section: Section,
    relocations: Vec<Relocation>,
}

fn load_as_single_region(
    path: PathBuf,
    bytes: &[u8],
    format: BinaryFormat,
    endian: Endian,
    region_name: &str,
    diagnostics: Vec<Diagnostic>,
) -> LoadedBinary {
    let mut memory_map = MemoryMap::new();
    memory_map.add_region(MemoryRegion::new(
        region_name,
        Address::ZERO,
        Some(0),
        Permissions::read_only(),
        bytes.to_vec(),
    ));

    LoadedBinary {
        path,
        file_size: bytes.len() as u64,
        bytes: bytes.to_vec(),
        format,
        arch: ArchitectureId::Unknown,
        endian,
        entrypoint: None,
        memory_map,
        sections: Vec::new(),
        dependencies: Vec::new(),
        symbols: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        relocations: Vec::new(),
        diagnostics,
    }
}

fn loader_note(message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(DiagnosticSeverity::Note, message)
}

fn loader_warning(message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(DiagnosticSeverity::Warning, message)
}

fn load_fat_mach_o(
    path: PathBuf,
    bytes: &[u8],
    endian: Endian,
    is_64: bool,
) -> Result<LoadedBinary> {
    if bytes.len() < MACHO_FAT_HEADER_SIZE as usize {
        return Ok(load_as_single_region(
            path,
            bytes,
            BinaryFormat::MachO,
            endian,
            "macho-file",
            vec![loader_warning(
                "Mach-O universal header is truncated; loaded file as read-only bytes at virtual address 0x0",
            )],
        ));
    }

    let members = parse_mach_o_fat_members(bytes, endian, is_64)?;

    for member in members {
        let member_bytes = checked_range(bytes, member.offset, member.size, "Mach-O fat member")?;
        if let Some(MachOMagic::Thin {
            endian: member_endian,
            is_64: member_is_64,
        }) = mach_o_magic(member_bytes)
        {
            return load_thin_mach_o(
                path,
                member_bytes,
                member_endian,
                member_is_64,
                vec![loader_note(format!(
                    "Mach-O universal binary selected {} member at file offset 0x{:x} with size {} bytes",
                    member.arch, member.offset, member.size
                ))],
            );
        }
    }

    Ok(load_as_single_region(
        path,
        bytes,
        BinaryFormat::MachO,
        endian,
        "macho-file",
        vec![loader_warning(
            "Mach-O universal binary contained no supported thin member; loaded file as read-only bytes at virtual address 0x0",
        )],
    ))
}

fn load_thin_mach_o(
    path: PathBuf,
    bytes: &[u8],
    endian: Endian,
    is_64: bool,
    mut diagnostics: Vec<Diagnostic>,
) -> Result<LoadedBinary> {
    let header = parse_mach_o_header(bytes, endian, is_64)?;
    let commands = parse_mach_o_load_commands(bytes, &header)?;
    let mut memory_map = MemoryMap::new();
    let mut sections = Vec::new();
    diagnostics.push(loader_note(
        "Mach-O loader uses limited load-command parsing; section relocation entries are parsed without dynamic loader binding metadata",
    ));
    let mut relocations = Vec::new();

    for segment in commands.segments {
        if segment.size == 0 {
            append_mach_o_sections(segment.sections, &mut sections, &mut relocations);
            continue;
        }

        if segment.file_size > segment.size {
            return Err(malformed("Mach-O segment file size exceeds VM size"));
        }

        let initialized_bytes = match segment.file_offset {
            Some(offset) => {
                checked_range(bytes, offset, segment.file_size, "Mach-O segment data")?.to_vec()
            }
            None => Vec::new(),
        };
        let region = MemoryRegion::new_with_size(
            segment.name,
            segment.address,
            segment.file_offset,
            segment.size,
            segment.permissions,
            initialized_bytes,
        )?;
        memory_map.add_region(region);
        append_mach_o_sections(segment.sections, &mut sections, &mut relocations);
    }

    if memory_map.regions().is_empty() {
        diagnostics.push(loader_warning(
            "Mach-O contained no mappable segments; loaded file as read-only bytes at virtual address 0x0",
        ));
        memory_map.add_region(MemoryRegion::new(
            "macho-file",
            Address::ZERO,
            Some(0),
            Permissions::read_only(),
            bytes.to_vec(),
        ));
    }

    let entrypoint = commands
        .entrypoint_file_offset
        .and_then(|file_offset| memory_map.translate_file_offset_to_virtual(file_offset));
    if commands.entrypoint_file_offset.is_some() && entrypoint.is_none() {
        diagnostics.push(loader_warning(
            "Mach-O entrypoint file offset did not map to a virtual address",
        ));
    }

    Ok(LoadedBinary {
        path,
        file_size: bytes.len() as u64,
        bytes: bytes.to_vec(),
        format: BinaryFormat::MachO,
        endian,
        arch: header.arch,
        entrypoint,
        memory_map,
        sections,
        dependencies: commands.dependencies,
        symbols: commands.symbols,
        imports: commands.imports,
        exports: Vec::new(),
        relocations,
        diagnostics,
    })
}

fn parse_mach_o_fat_members(
    bytes: &[u8],
    endian: Endian,
    is_64: bool,
) -> Result<Vec<MachOFatMember>> {
    checked_range(bytes, 0, MACHO_FAT_HEADER_SIZE, "Mach-O universal header")?;
    let member_count = read_u32(bytes, 4, endian, "Mach-O universal architecture count")?;
    let entry_size = if is_64 {
        MACHO_FAT_ARCH64_SIZE
    } else {
        MACHO_FAT_ARCH_SIZE
    };
    let table_size = checked_table_size(
        MACHO_FAT_HEADER_SIZE,
        entry_size,
        member_count,
        "Mach-O universal architecture table",
    )?;
    checked_range(bytes, 0, table_size, "Mach-O universal architecture table")?;

    let mut members = Vec::with_capacity(
        usize::try_from(member_count)
            .map_err(|_| malformed("Mach-O universal architecture count does not fit in usize"))?,
    );
    for index in 0..member_count {
        let base = table_entry_offset_u32(
            MACHO_FAT_HEADER_SIZE,
            entry_size,
            index,
            "Mach-O universal architecture table",
        )?;
        let cpu_type = read_u32(bytes, base, endian, "Mach-O universal CPU type")?;
        let (offset, size) = if is_64 {
            (
                read_u64(bytes, base + 8, endian, "Mach-O universal member offset")?,
                read_u64(bytes, base + 16, endian, "Mach-O universal member size")?,
            )
        } else {
            (
                u64::from(read_u32(
                    bytes,
                    base + 8,
                    endian,
                    "Mach-O universal member offset",
                )?),
                u64::from(read_u32(
                    bytes,
                    base + 12,
                    endian,
                    "Mach-O universal member size",
                )?),
            )
        };

        if size == 0 {
            return Err(malformed("Mach-O universal member size is zero"));
        }
        checked_range(bytes, offset, size, "Mach-O universal member")?;
        members.push(MachOFatMember {
            arch: mach_o_cpu_type_to_arch(cpu_type),
            offset,
            size,
        });
    }

    Ok(members)
}

fn parse_mach_o_header(bytes: &[u8], endian: Endian, is_64: bool) -> Result<MachOHeader> {
    let header_size = if is_64 {
        MACHO64_HEADER_SIZE
    } else {
        MACHO32_HEADER_SIZE
    };
    checked_range(bytes, 0, header_size, "Mach-O header")?;
    let command_count = read_u32(bytes, 16, endian, "Mach-O ncmds")?;
    let load_commands_size = u64::from(read_u32(bytes, 20, endian, "Mach-O sizeofcmds")?);
    checked_range(
        bytes,
        header_size,
        load_commands_size,
        "Mach-O load commands",
    )?;
    let cpu_type = read_u32(bytes, 4, endian, "Mach-O CPU type")?;

    Ok(MachOHeader {
        arch: mach_o_cpu_type_to_arch(cpu_type),
        command_count,
        command_offset: header_size,
        command_size: load_commands_size,
        is_64,
        endian,
    })
}

fn parse_mach_o_load_commands(bytes: &[u8], header: &MachOHeader) -> Result<MachOCommands> {
    let mut commands = MachOCommands::default();
    let command_table_end = checked_add_offset(
        header.command_offset,
        header.command_size,
        "Mach-O load command table",
    )?;
    let mut command_offset = header.command_offset;

    for _ in 0..header.command_count {
        checked_range(bytes, command_offset, 8, "Mach-O load command header")?;
        let command = read_u32(bytes, command_offset, header.endian, "Mach-O load command")?;
        let command_size = u64::from(read_u32(
            bytes,
            command_offset + 4,
            header.endian,
            "Mach-O load command size",
        )?);
        if command_size < 8 {
            return Err(malformed("Mach-O load command size is too small"));
        }
        let command_end = checked_add_offset(command_offset, command_size, "Mach-O load command")?;
        if command_end > command_table_end {
            return Err(malformed(
                "Mach-O load command extends beyond declared command table",
            ));
        }
        checked_range(bytes, command_offset, command_size, "Mach-O load command")?;

        match command {
            LC_SEGMENT => {
                commands.segments.push(parse_mach_o_segment32(
                    bytes,
                    command_offset,
                    command_size,
                    header.endian,
                    header.arch,
                )?);
            }
            LC_SEGMENT_64 => {
                commands.segments.push(parse_mach_o_segment64(
                    bytes,
                    command_offset,
                    command_size,
                    header.endian,
                    header.arch,
                )?);
            }
            LC_MAIN if header.is_64 => {
                if command_size < 24 {
                    return Err(malformed("Mach-O LC_MAIN command is too small"));
                }
                commands.entrypoint_file_offset = Some(read_u64(
                    bytes,
                    command_offset + 8,
                    header.endian,
                    "Mach-O LC_MAIN entryoff",
                )?);
            }
            LC_LOAD_DYLIB => {
                commands.dependencies.push(parse_mach_o_dylib_command(
                    bytes,
                    command_offset,
                    command_size,
                    header.endian,
                )?);
            }
            LC_SYMTAB => {
                if command_size < 24 {
                    return Err(malformed("Mach-O LC_SYMTAB command is too small"));
                }
                let symbol_offset =
                    read_u32(bytes, command_offset + 8, header.endian, "Mach-O symoff")?;
                let symbol_count =
                    read_u32(bytes, command_offset + 12, header.endian, "Mach-O nsyms")?;
                let string_offset =
                    read_u32(bytes, command_offset + 16, header.endian, "Mach-O stroff")?;
                let string_size =
                    read_u32(bytes, command_offset + 20, header.endian, "Mach-O strsize")?;
                let symbols = parse_mach_o_symbols(
                    bytes,
                    header,
                    u64::from(symbol_offset),
                    symbol_count,
                    u64::from(string_offset),
                    u64::from(string_size),
                )?;
                commands.imports.extend(symbols.imports);
                commands.symbols.extend(symbols.symbols);
            }
            _ => {}
        }

        command_offset = command_end;
    }

    if command_offset != command_table_end {
        return Err(malformed(
            "Mach-O load commands did not consume declared command table",
        ));
    }

    Ok(commands)
}

fn parse_mach_o_dylib_command(
    bytes: &[u8],
    command_offset: u64,
    command_size: u64,
    endian: Endian,
) -> Result<Dependency> {
    if command_size < 24 {
        return Err(malformed("Mach-O dylib command is too small"));
    }
    let name_offset = u64::from(read_u32(
        bytes,
        command_offset + 8,
        endian,
        "Mach-O dylib name offset",
    )?);
    if name_offset < 24 || name_offset >= command_size {
        return Err(malformed("Mach-O dylib name offset is out of range"));
    }
    let name_start = checked_add_offset(command_offset, name_offset, "Mach-O dylib name")?;
    let command_end = checked_add_offset(command_offset, command_size, "Mach-O dylib command")?;
    let name = read_file_c_string(bytes, name_start, command_end, "Mach-O dylib name")?;

    Ok(Dependency { name })
}

fn parse_mach_o_symbols(
    bytes: &[u8],
    header: &MachOHeader,
    symbol_offset: u64,
    symbol_count: u32,
    string_offset: u64,
    string_size: u64,
) -> Result<MachOSymbols> {
    if symbol_count == 0 {
        return Ok(MachOSymbols::default());
    }

    let entry_size = if header.is_64 {
        MACHO64_SYMBOL_SIZE
    } else {
        MACHO32_SYMBOL_SIZE
    };
    let table_size = u64::from(symbol_count)
        .checked_mul(entry_size)
        .ok_or_else(|| malformed("Mach-O symbol table size overflow"))?;
    checked_range(bytes, symbol_offset, table_size, "Mach-O symbol table")?;
    let string_table = checked_range(bytes, string_offset, string_size, "Mach-O string table")?;

    let mut symbols = MachOSymbols::default();
    for index in 0..symbol_count {
        let base = symbol_offset
            .checked_add(
                u64::from(index)
                    .checked_mul(entry_size)
                    .ok_or_else(|| malformed("Mach-O symbol table offset overflow"))?,
            )
            .ok_or_else(|| malformed("Mach-O symbol table offset overflow"))?;
        let name_offset = read_u32(bytes, base, header.endian, "Mach-O n_strx")?;
        let symbol_type = read_u8(bytes, base + 4, "Mach-O n_type")?;
        let value = if header.is_64 {
            read_u64(bytes, base + 8, header.endian, "Mach-O n_value")?
        } else {
            u64::from(read_u32(bytes, base + 8, header.endian, "Mach-O n_value")?)
        };

        if symbol_type & N_STAB != 0 {
            continue;
        }
        let Some(name) = mach_o_string_table_name(string_table, name_offset)? else {
            continue;
        };
        let symbol_kind = symbol_type & N_TYPE;
        let address = if symbol_kind == N_SECT && value != 0 {
            Some(Address::new(value))
        } else {
            None
        };
        if symbol_kind == N_UNDF && (symbol_type & N_EXT) != 0 {
            symbols.imports.push(Import {
                library: "Mach-O".to_string(),
                name: Some(name.clone()),
                ordinal: None,
                thunk: None,
            });
        }
        symbols.symbols.push(Symbol { name, address });
    }

    Ok(symbols)
}

fn mach_o_string_table_name(table: &[u8], offset: u32) -> Result<Option<String>> {
    if offset == 0 {
        return Ok(None);
    }
    let start = usize::try_from(offset)
        .map_err(|_| malformed("Mach-O symbol name offset does not fit in usize"))?;
    let Some(rest) = table.get(start..) else {
        return Err(malformed("Mach-O symbol name offset is out of range"));
    };
    let end = rest
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(rest.len());
    let Some(bytes) = rest.get(..end) else {
        return Err(malformed("Mach-O symbol name has invalid range"));
    };
    if bytes.is_empty() {
        return Ok(None);
    }

    Ok(Some(String::from_utf8_lossy(bytes).into_owned()))
}

fn parse_mach_o_segment32(
    bytes: &[u8],
    command_offset: u64,
    command_size: u64,
    endian: Endian,
    arch: ArchitectureId,
) -> Result<MachOSegment> {
    if command_size < MACHO32_SEGMENT_COMMAND_SIZE {
        return Err(malformed("Mach-O LC_SEGMENT command is too small"));
    }

    let segment_name = read_fixed_string(bytes, command_offset + 8, 16, "Mach-O segment name")?;
    let address = u64::from(read_u32(
        bytes,
        command_offset + 24,
        endian,
        "Mach-O vmaddr",
    )?);
    let size = u64::from(read_u32(
        bytes,
        command_offset + 28,
        endian,
        "Mach-O vmsize",
    )?);
    let file_offset = u64::from(read_u32(
        bytes,
        command_offset + 32,
        endian,
        "Mach-O fileoff",
    )?);
    let file_size = u64::from(read_u32(
        bytes,
        command_offset + 36,
        endian,
        "Mach-O filesize",
    )?);
    let initprot = read_u32(bytes, command_offset + 44, endian, "Mach-O initprot")?;
    let section_count = read_u32(bytes, command_offset + 48, endian, "Mach-O nsects")?;
    let minimum_size = checked_table_size(
        MACHO32_SEGMENT_COMMAND_SIZE,
        MACHO32_SECTION_SIZE,
        section_count,
        "Mach-O LC_SEGMENT",
    )?;
    if command_size < minimum_size {
        return Err(malformed("Mach-O LC_SEGMENT command is missing sections"));
    }

    let permissions = mach_o_permissions(initprot);
    let sections = parse_mach_o_sections32(
        bytes,
        command_offset + MACHO32_SEGMENT_COMMAND_SIZE,
        section_count,
        endian,
        arch,
        permissions,
    )?;

    Ok(MachOSegment {
        name: fallback_name(segment_name, "SEGMENT"),
        address: Address::new(address),
        file_offset: nonzero_file_offset(file_size, file_offset),
        size,
        file_size,
        permissions,
        sections,
    })
}

fn parse_mach_o_segment64(
    bytes: &[u8],
    command_offset: u64,
    command_size: u64,
    endian: Endian,
    arch: ArchitectureId,
) -> Result<MachOSegment> {
    if command_size < MACHO64_SEGMENT_COMMAND_SIZE {
        return Err(malformed("Mach-O LC_SEGMENT_64 command is too small"));
    }

    let segment_name = read_fixed_string(bytes, command_offset + 8, 16, "Mach-O segment name")?;
    let address = read_u64(bytes, command_offset + 24, endian, "Mach-O vmaddr")?;
    let size = read_u64(bytes, command_offset + 32, endian, "Mach-O vmsize")?;
    let file_offset = read_u64(bytes, command_offset + 40, endian, "Mach-O fileoff")?;
    let file_size = read_u64(bytes, command_offset + 48, endian, "Mach-O filesize")?;
    let initprot = read_u32(bytes, command_offset + 60, endian, "Mach-O initprot")?;
    let section_count = read_u32(bytes, command_offset + 64, endian, "Mach-O nsects")?;
    let minimum_size = checked_table_size(
        MACHO64_SEGMENT_COMMAND_SIZE,
        MACHO64_SECTION_SIZE,
        section_count,
        "Mach-O LC_SEGMENT_64",
    )?;
    if command_size < minimum_size {
        return Err(malformed(
            "Mach-O LC_SEGMENT_64 command is missing sections",
        ));
    }

    let permissions = mach_o_permissions(initprot);
    let sections = parse_mach_o_sections64(
        bytes,
        command_offset + MACHO64_SEGMENT_COMMAND_SIZE,
        section_count,
        endian,
        arch,
        permissions,
    )?;

    Ok(MachOSegment {
        name: fallback_name(segment_name, "SEGMENT"),
        address: Address::new(address),
        file_offset: nonzero_file_offset(file_size, file_offset),
        size,
        file_size,
        permissions,
        sections,
    })
}

fn parse_mach_o_sections32(
    bytes: &[u8],
    table_offset: u64,
    section_count: u32,
    endian: Endian,
    arch: ArchitectureId,
    permissions: Permissions,
) -> Result<Vec<MachOSection>> {
    let mut sections = Vec::with_capacity(
        usize::try_from(section_count)
            .map_err(|_| malformed("Mach-O section count does not fit in usize"))?,
    );
    for index in 0..section_count {
        let base = table_entry_offset_u32(
            table_offset,
            MACHO32_SECTION_SIZE,
            index,
            "Mach-O section table",
        )?;
        checked_range(bytes, base, MACHO32_SECTION_SIZE, "Mach-O section")?;
        let name = read_fixed_string(bytes, base, 16, "Mach-O section name")?;
        let address = u64::from(read_u32(bytes, base + 32, endian, "Mach-O section addr")?);
        let size = u64::from(read_u32(bytes, base + 36, endian, "Mach-O section size")?);
        let offset = u64::from(read_u32(bytes, base + 40, endian, "Mach-O section offset")?);
        let relocation_offset =
            u64::from(read_u32(bytes, base + 48, endian, "Mach-O section reloff")?);
        let relocation_count = read_u32(bytes, base + 52, endian, "Mach-O section nreloc")?;
        let flags = read_u32(bytes, base + 56, endian, "Mach-O section flags")?;
        let file_offset = section_file_offset(bytes, offset, size, flags)?;
        let address = Address::new(address);
        let relocations = parse_mach_o_section_relocations(
            bytes,
            address,
            size,
            relocation_offset,
            relocation_count,
            endian,
            arch,
        )?;
        sections.push(MachOSection {
            section: Section {
                name: fallback_name(name, "section"),
                address,
                file_offset,
                size,
                permissions,
            },
            relocations,
        });
    }
    Ok(sections)
}

fn parse_mach_o_sections64(
    bytes: &[u8],
    table_offset: u64,
    section_count: u32,
    endian: Endian,
    arch: ArchitectureId,
    permissions: Permissions,
) -> Result<Vec<MachOSection>> {
    let mut sections = Vec::with_capacity(
        usize::try_from(section_count)
            .map_err(|_| malformed("Mach-O section count does not fit in usize"))?,
    );
    for index in 0..section_count {
        let base = table_entry_offset_u32(
            table_offset,
            MACHO64_SECTION_SIZE,
            index,
            "Mach-O section table",
        )?;
        checked_range(bytes, base, MACHO64_SECTION_SIZE, "Mach-O section")?;
        let name = read_fixed_string(bytes, base, 16, "Mach-O section name")?;
        let address = read_u64(bytes, base + 32, endian, "Mach-O section addr")?;
        let size = read_u64(bytes, base + 40, endian, "Mach-O section size")?;
        let offset = u64::from(read_u32(bytes, base + 48, endian, "Mach-O section offset")?);
        let relocation_offset =
            u64::from(read_u32(bytes, base + 56, endian, "Mach-O section reloff")?);
        let relocation_count = read_u32(bytes, base + 60, endian, "Mach-O section nreloc")?;
        let flags = read_u32(bytes, base + 64, endian, "Mach-O section flags")?;
        let file_offset = section_file_offset(bytes, offset, size, flags)?;
        let address = Address::new(address);
        let relocations = parse_mach_o_section_relocations(
            bytes,
            address,
            size,
            relocation_offset,
            relocation_count,
            endian,
            arch,
        )?;
        sections.push(MachOSection {
            section: Section {
                name: fallback_name(name, "section"),
                address,
                file_offset,
                size,
                permissions,
            },
            relocations,
        });
    }
    Ok(sections)
}

fn parse_mach_o_section_relocations(
    bytes: &[u8],
    section_address: Address,
    section_size: u64,
    relocation_offset: u64,
    relocation_count: u32,
    endian: Endian,
    arch: ArchitectureId,
) -> Result<Vec<Relocation>> {
    if relocation_count == 0 {
        return Ok(Vec::new());
    }

    let table_size = u64::from(relocation_count)
        .checked_mul(MACHO_RELOCATION_SIZE)
        .ok_or_else(|| malformed("Mach-O relocation table size overflow"))?;
    checked_range(
        bytes,
        relocation_offset,
        table_size,
        "Mach-O relocation table",
    )?;

    let mut relocations = Vec::with_capacity(
        usize::try_from(relocation_count)
            .map_err(|_| malformed("Mach-O relocation count does not fit in usize"))?,
    );
    for index in 0..relocation_count {
        let base = table_entry_offset_u32(
            relocation_offset,
            MACHO_RELOCATION_SIZE,
            index,
            "Mach-O relocation table",
        )?;
        let address_word = read_u32(bytes, base, endian, "Mach-O relocation address")?;
        let info = read_u32(bytes, base + 4, endian, "Mach-O relocation info")?;

        let relocation = if address_word & MACHO_SCATTERED_RELOCATION_FLAG != 0 {
            mach_o_scattered_relocation(section_address, section_size, address_word, info, arch)?
        } else {
            mach_o_relocation(section_address, section_size, address_word, info, arch)?
        };
        relocations.push(relocation);
    }

    Ok(relocations)
}

fn mach_o_relocation(
    section_address: Address,
    section_size: u64,
    address_word: u32,
    info: u32,
    arch: ArchitectureId,
) -> Result<Relocation> {
    let relative_address = u64::from(address_word);
    if relative_address >= section_size {
        return Err(malformed("Mach-O relocation address is outside section"));
    }
    let address = section_address
        .checked_add(relative_address)
        .ok_or_else(|| malformed("Mach-O relocation address overflow"))?;
    let relocation_type = (info >> 28) & 0xf;
    let is_external = info & (1 << 27) != 0;
    let length = (info >> 25) & 0x3;
    let pcrel = info & (1 << 24) != 0;

    Ok(Relocation {
        address,
        kind: mach_o_relocation_kind(arch, relocation_type, pcrel, is_external, length),
    })
}

fn mach_o_scattered_relocation(
    section_address: Address,
    section_size: u64,
    address_word: u32,
    _value: u32,
    arch: ArchitectureId,
) -> Result<Relocation> {
    let relative_address = u64::from(address_word & 0x00ff_ffff);
    if relative_address >= section_size {
        return Err(malformed(
            "Mach-O scattered relocation address is outside section",
        ));
    }
    let address = section_address
        .checked_add(relative_address)
        .ok_or_else(|| malformed("Mach-O scattered relocation address overflow"))?;
    let relocation_type = (address_word >> 24) & 0xf;
    let length = (address_word >> 28) & 0x3;
    let pcrel = address_word & (1 << 30) != 0;

    Ok(Relocation {
        address,
        kind: mach_o_scattered_relocation_kind(arch, relocation_type, pcrel, length),
    })
}

fn mach_o_relocation_kind(
    arch: ArchitectureId,
    relocation_type: u32,
    pcrel: bool,
    is_external: bool,
    length: u32,
) -> String {
    let binding = if is_external { "external" } else { "local" };
    format!(
        "{}-{}-{}-len{}",
        mach_o_relocation_base_kind(arch, relocation_type),
        mach_o_pcrel_name(pcrel),
        binding,
        mach_o_relocation_width(length)
    )
}

fn mach_o_scattered_relocation_kind(
    arch: ArchitectureId,
    relocation_type: u32,
    pcrel: bool,
    length: u32,
) -> String {
    format!(
        "{}-{}-scattered-len{}",
        mach_o_relocation_base_kind(arch, relocation_type),
        mach_o_pcrel_name(pcrel),
        mach_o_relocation_width(length)
    )
}

fn mach_o_pcrel_name(pcrel: bool) -> &'static str {
    if pcrel {
        "pcrel"
    } else {
        "absolute"
    }
}

fn mach_o_relocation_width(length: u32) -> u32 {
    1_u32 << length.min(3)
}

fn mach_o_relocation_base_kind(arch: ArchitectureId, relocation_type: u32) -> String {
    match arch {
        ArchitectureId::X86_64 => match relocation_type {
            0 => "macho-x86_64-unsigned".to_string(),
            1 => "macho-x86_64-signed".to_string(),
            2 => "macho-x86_64-branch".to_string(),
            3 => "macho-x86_64-got-load".to_string(),
            4 => "macho-x86_64-got".to_string(),
            5 => "macho-x86_64-subtractor".to_string(),
            6 => "macho-x86_64-signed-1".to_string(),
            7 => "macho-x86_64-signed-2".to_string(),
            8 => "macho-x86_64-signed-4".to_string(),
            9 => "macho-x86_64-tlv".to_string(),
            value => format!("macho-x86_64-unknown-{value}"),
        },
        ArchitectureId::X86 => match relocation_type {
            0 => "macho-x86-vanilla".to_string(),
            1 => "macho-x86-pair".to_string(),
            2 => "macho-x86-sectdiff".to_string(),
            3 => "macho-x86-pb-la-ptr".to_string(),
            4 => "macho-x86-local-sectdiff".to_string(),
            5 => "macho-x86-tlv".to_string(),
            value => format!("macho-x86-unknown-{value}"),
        },
        ArchitectureId::Arm => match relocation_type {
            0 => "macho-arm-vanilla".to_string(),
            1 => "macho-arm-pair".to_string(),
            2 => "macho-arm-sectdiff".to_string(),
            3 => "macho-arm-local-sectdiff".to_string(),
            4 => "macho-arm-pb-la-ptr".to_string(),
            5 => "macho-arm-br24".to_string(),
            6 => "macho-arm-thumb-br22".to_string(),
            7 => "macho-arm-thumb-32bit-branch".to_string(),
            value => format!("macho-arm-unknown-{value}"),
        },
        ArchitectureId::Aarch64 => match relocation_type {
            0 => "macho-arm64-unsigned".to_string(),
            1 => "macho-arm64-subtractor".to_string(),
            2 => "macho-arm64-branch26".to_string(),
            3 => "macho-arm64-page21".to_string(),
            4 => "macho-arm64-pageoff12".to_string(),
            5 => "macho-arm64-got-load-page21".to_string(),
            6 => "macho-arm64-got-load-pageoff12".to_string(),
            7 => "macho-arm64-pointer-to-got".to_string(),
            8 => "macho-arm64-tlvp-load-page21".to_string(),
            9 => "macho-arm64-tlvp-load-pageoff12".to_string(),
            10 => "macho-arm64-addend".to_string(),
            value => format!("macho-arm64-unknown-{value}"),
        },
        ArchitectureId::Unknown => format!("macho-relocation-{relocation_type}"),
    }
}

fn append_mach_o_sections(
    parsed_sections: Vec<MachOSection>,
    sections: &mut Vec<Section>,
    relocations: &mut Vec<Relocation>,
) {
    for parsed_section in parsed_sections {
        sections.push(parsed_section.section);
        relocations.extend(parsed_section.relocations);
    }
}

fn parse_pe_header(bytes: &[u8]) -> Result<PeHeader> {
    if !bytes.starts_with(b"MZ") {
        return Err(malformed("input is not a PE/DOS image"));
    }

    let pe_offset = u64::from(read_u32(bytes, 0x3c, Endian::Little, "PE header offset")?);
    let signature = checked_range(bytes, pe_offset, 4, "PE signature")?;
    if signature != PE_SIGNATURE.as_slice() {
        return Err(malformed("PE signature is missing"));
    }

    let coff_offset = checked_add_offset(pe_offset, 4, "PE COFF header offset")?;
    checked_range(bytes, coff_offset, PE_COFF_HEADER_SIZE, "PE COFF header")?;
    let machine = read_u16(bytes, coff_offset, Endian::Little, "PE machine")?;
    let section_count = read_u16(bytes, coff_offset + 2, Endian::Little, "PE section count")?;
    let symbol_table_offset = read_u32(
        bytes,
        coff_offset + 8,
        Endian::Little,
        "PE COFF symbol table offset",
    )?;
    let symbol_count = read_u32(
        bytes,
        coff_offset + 12,
        Endian::Little,
        "PE COFF symbol count",
    )?;
    let optional_header_size = read_u16(
        bytes,
        coff_offset + 16,
        Endian::Little,
        "PE optional header size",
    )?;
    let optional_header_offset = checked_add_offset(
        coff_offset,
        PE_COFF_HEADER_SIZE,
        "PE optional header offset",
    )?;
    checked_range(
        bytes,
        optional_header_offset,
        u64::from(optional_header_size),
        "PE optional header",
    )?;

    let magic = read_u16(
        bytes,
        optional_header_offset,
        Endian::Little,
        "PE optional header magic",
    )?;
    let kind = match magic {
        PE32_MAGIC => PeKind::Pe32,
        PE32_PLUS_MAGIC => PeKind::Pe32Plus,
        value => {
            return Err(malformed(format!(
                "unsupported PE optional header magic 0x{value:x}"
            )))
        }
    };
    if optional_header_size < 32 {
        return Err(malformed("PE optional header is too small"));
    }

    let entrypoint_rva = u64::from(read_u32(
        bytes,
        optional_header_offset + 16,
        Endian::Little,
        "PE entrypoint RVA",
    )?);
    let image_base = match kind {
        PeKind::Pe32 => u64::from(read_u32(
            bytes,
            optional_header_offset + 28,
            Endian::Little,
            "PE image base",
        )?),
        PeKind::Pe32Plus => read_u64(
            bytes,
            optional_header_offset + 24,
            Endian::Little,
            "PE image base",
        )?,
    };
    let entrypoint = if entrypoint_rva == 0 {
        None
    } else {
        Some(Address::new(
            image_base
                .checked_add(entrypoint_rva)
                .ok_or_else(|| malformed("PE entrypoint address overflow"))?,
        ))
    };
    let section_table_offset = checked_add_offset(
        optional_header_offset,
        u64::from(optional_header_size),
        "PE section table offset",
    )?;
    let export_directory = parse_pe_data_directory(
        bytes,
        kind,
        optional_header_offset,
        u64::from(optional_header_size),
        PE_EXPORT_DIRECTORY_INDEX,
        "PE export data directory",
    )?;
    let import_directory = parse_pe_data_directory(
        bytes,
        kind,
        optional_header_offset,
        u64::from(optional_header_size),
        PE_IMPORT_DIRECTORY_INDEX,
        "PE import data directory",
    )?;
    let base_relocation_directory = parse_pe_data_directory(
        bytes,
        kind,
        optional_header_offset,
        u64::from(optional_header_size),
        PE_BASE_RELOCATION_DIRECTORY_INDEX,
        "PE base relocation data directory",
    )?;

    Ok(PeHeader {
        kind,
        machine,
        image_base,
        entrypoint,
        section_table_offset,
        section_count,
        symbol_table_offset,
        symbol_count,
        export_directory,
        import_directory,
        base_relocation_directory,
    })
}

fn parse_pe_data_directory(
    bytes: &[u8],
    kind: PeKind,
    optional_header_offset: u64,
    optional_header_size: u64,
    directory_index: u32,
    context: &str,
) -> Result<Option<PeDataDirectory>> {
    let (number_offset, directory_offset) = match kind {
        PeKind::Pe32 => (
            PE32_NUMBER_OF_RVA_AND_SIZES_OFFSET,
            PE32_DATA_DIRECTORY_OFFSET,
        ),
        PeKind::Pe32Plus => (
            PE32_PLUS_NUMBER_OF_RVA_AND_SIZES_OFFSET,
            PE32_PLUS_DATA_DIRECTORY_OFFSET,
        ),
    };

    if optional_header_size < number_offset + 4 {
        return Ok(None);
    }

    let directory_count = read_u32(
        bytes,
        optional_header_offset + number_offset,
        Endian::Little,
        "PE number of data directories",
    )?;
    if directory_count <= directory_index {
        return Ok(None);
    }

    let data_directory_offset = directory_offset
        .checked_add(
            u64::from(directory_index)
                .checked_mul(PE_DATA_DIRECTORY_SIZE)
                .ok_or_else(|| malformed(format!("{context} offset overflow")))?,
        )
        .ok_or_else(|| malformed(format!("{context} offset overflow")))?;
    if optional_header_size < data_directory_offset + PE_DATA_DIRECTORY_SIZE {
        return Err(malformed(format!("{context} is truncated")));
    }

    let rva = read_u32(
        bytes,
        optional_header_offset + data_directory_offset,
        Endian::Little,
        &format!("{context} RVA"),
    )?;
    let size = read_u32(
        bytes,
        optional_header_offset + data_directory_offset + 4,
        Endian::Little,
        &format!("{context} size"),
    )?;

    if rva == 0 || size == 0 {
        Ok(None)
    } else {
        Ok(Some(PeDataDirectory { rva, size }))
    }
}

fn parse_pe_sections(bytes: &[u8], header: &PeHeader) -> Result<Vec<PeSection>> {
    let mut sections = Vec::with_capacity(usize::from(header.section_count));
    for index in 0..header.section_count {
        let base = table_entry_offset(
            header.section_table_offset,
            PE_SECTION_HEADER_SIZE,
            index,
            "PE section table",
        )?;
        checked_range(
            bytes,
            base,
            u64::from(PE_SECTION_HEADER_SIZE),
            "PE section header",
        )?;

        let name_bytes = checked_range(bytes, base, 8, "PE section name")?;
        let name = pe_section_name(name_bytes, usize::from(index));
        let virtual_size = u64::from(read_u32(
            bytes,
            base + 8,
            Endian::Little,
            "PE section virtual size",
        )?);
        let virtual_address = u64::from(read_u32(
            bytes,
            base + 12,
            Endian::Little,
            "PE section virtual address",
        )?);
        let raw_size = u64::from(read_u32(
            bytes,
            base + 16,
            Endian::Little,
            "PE section raw size",
        )?);
        let raw_offset = u64::from(read_u32(
            bytes,
            base + 20,
            Endian::Little,
            "PE section raw offset",
        )?);
        let characteristics = read_u32(
            bytes,
            base + 36,
            Endian::Little,
            "PE section characteristics",
        )?;
        let size = virtual_size.max(raw_size);
        let file_offset = if raw_size == 0 {
            None
        } else {
            checked_range(bytes, raw_offset, raw_size, "PE section data")?;
            Some(raw_offset)
        };
        let address = Address::new(
            header
                .image_base
                .checked_add(virtual_address)
                .ok_or_else(|| malformed("PE section virtual address overflow"))?,
        );

        sections.push(PeSection {
            name,
            virtual_address,
            address,
            file_offset,
            size,
            raw_size,
            permissions: pe_section_permissions(characteristics),
        });
    }

    Ok(sections)
}

fn pe_section_name(bytes: &[u8], index: usize) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    let name = String::from_utf8_lossy(&bytes[..end]).into_owned();
    if name.is_empty() {
        format!("section{index}")
    } else {
        name
    }
}

#[derive(Debug, Clone, Copy)]
struct PeFileLocation {
    offset: u64,
    limit: u64,
}

fn parse_pe_relocations(
    bytes: &[u8],
    header: &PeHeader,
    sections: &[PeSection],
) -> Result<Vec<Relocation>> {
    let Some(relocation_directory) = header.base_relocation_directory else {
        return Ok(Vec::new());
    };

    let relocation_size = u64::from(relocation_directory.size);
    if relocation_size == 0 {
        return Ok(Vec::new());
    }
    let directory_location = pe_rva_to_file_location(u64::from(relocation_directory.rva), sections)
        .ok_or_else(|| malformed("PE base relocation directory RVA does not map to file data"))?;
    let directory_end = checked_add_offset(
        directory_location.offset,
        relocation_size,
        "PE base relocation directory",
    )?;
    if directory_end > directory_location.limit {
        return Err(malformed(
            "PE base relocation directory extends beyond section file data",
        ));
    }
    checked_range(
        bytes,
        directory_location.offset,
        relocation_size,
        "PE base relocation directory",
    )?;

    let mut relocations = Vec::new();
    let mut block_offset = directory_location.offset;
    while block_offset < directory_end {
        checked_range(
            bytes,
            block_offset,
            PE_BASE_RELOCATION_BLOCK_HEADER_SIZE,
            "PE base relocation block header",
        )?;
        let page_rva = read_u32(
            bytes,
            block_offset,
            Endian::Little,
            "PE base relocation page RVA",
        )?;
        let block_size = u64::from(read_u32(
            bytes,
            block_offset + 4,
            Endian::Little,
            "PE base relocation block size",
        )?);
        if block_size < PE_BASE_RELOCATION_BLOCK_HEADER_SIZE {
            return Err(malformed("PE base relocation block size is too small"));
        }
        let block_end = checked_add_offset(block_offset, block_size, "PE base relocation block")?;
        if block_end > directory_end {
            return Err(malformed(
                "PE base relocation block extends beyond relocation directory",
            ));
        }

        let entries_size = block_size - PE_BASE_RELOCATION_BLOCK_HEADER_SIZE;
        if entries_size % PE_BASE_RELOCATION_ENTRY_SIZE != 0 {
            return Err(malformed(
                "PE base relocation entries are not 2-byte aligned",
            ));
        }
        let entry_count = entries_size / PE_BASE_RELOCATION_ENTRY_SIZE;
        for index in 0..entry_count {
            let entry_offset = block_offset
                .checked_add(PE_BASE_RELOCATION_BLOCK_HEADER_SIZE)
                .and_then(|offset| {
                    offset.checked_add(index.checked_mul(PE_BASE_RELOCATION_ENTRY_SIZE)?)
                })
                .ok_or_else(|| malformed("PE base relocation entry offset overflow"))?;
            let entry = read_u16(
                bytes,
                entry_offset,
                Endian::Little,
                "PE base relocation entry",
            )?;
            let relocation_type = entry >> 12;
            if relocation_type == IMAGE_REL_BASED_ABSOLUTE {
                continue;
            }
            let entry_rva = u64::from(page_rva)
                .checked_add(u64::from(entry & 0x0fff))
                .ok_or_else(|| malformed("PE base relocation RVA overflow"))?;
            let address = header
                .image_base
                .checked_add(entry_rva)
                .ok_or_else(|| malformed("PE base relocation address overflow"))?;
            relocations.push(Relocation {
                address: Address::new(address),
                kind: pe_base_relocation_kind(relocation_type),
            });
        }

        block_offset = block_end;
    }

    Ok(relocations)
}

fn pe_base_relocation_kind(relocation_type: u16) -> String {
    match relocation_type {
        IMAGE_REL_BASED_ABSOLUTE => "pe-absolute".to_string(),
        IMAGE_REL_BASED_HIGH => "pe-high".to_string(),
        IMAGE_REL_BASED_LOW => "pe-low".to_string(),
        IMAGE_REL_BASED_HIGHLOW => "pe-highlow".to_string(),
        IMAGE_REL_BASED_HIGHADJ => "pe-highadj".to_string(),
        IMAGE_REL_BASED_DIR64 => "pe-dir64".to_string(),
        _ => format!("pe-unknown-{relocation_type}"),
    }
}

fn parse_pe_symbols(
    bytes: &[u8],
    header: &PeHeader,
    sections: &[PeSection],
) -> Result<Vec<Symbol>> {
    if header.symbol_table_offset == 0 || header.symbol_count == 0 {
        return Ok(Vec::new());
    }

    let symbol_count = u64::from(header.symbol_count);
    let table_size = symbol_count
        .checked_mul(PE_COFF_SYMBOL_SIZE)
        .ok_or_else(|| malformed("PE COFF symbol table size overflow"))?;
    let symbol_table_offset = u64::from(header.symbol_table_offset);
    checked_range(
        bytes,
        symbol_table_offset,
        table_size,
        "PE COFF symbol table",
    )?;
    let string_table_offset = checked_add_offset(
        symbol_table_offset,
        table_size,
        "PE COFF string table offset",
    )?;
    let string_table = pe_coff_string_table(bytes, string_table_offset)?;

    let mut symbols = Vec::new();
    let mut index = 0_u64;
    while index < symbol_count {
        let base = symbol_table_offset
            .checked_add(
                index
                    .checked_mul(PE_COFF_SYMBOL_SIZE)
                    .ok_or_else(|| malformed("PE COFF symbol table offset overflow"))?,
            )
            .ok_or_else(|| malformed("PE COFF symbol table offset overflow"))?;
        let name = pe_coff_symbol_name(bytes, base, string_table)?;
        let value = u64::from(read_u32(
            bytes,
            base + 8,
            Endian::Little,
            "PE COFF symbol value",
        )?);
        let section_number = read_u16(
            bytes,
            base + 12,
            Endian::Little,
            "PE COFF symbol section number",
        )? as i16;
        let auxiliary_count = u64::from(byte_at(
            bytes,
            usize::try_from(base + 17)
                .map_err(|_| malformed("PE COFF auxiliary symbol count offset overflow"))?,
            "PE COFF auxiliary symbol count",
        )?);
        let next_index = index
            .checked_add(1)
            .and_then(|next| next.checked_add(auxiliary_count))
            .ok_or_else(|| malformed("PE COFF auxiliary symbol count overflow"))?;
        if next_index > symbol_count {
            return Err(malformed(
                "PE COFF auxiliary symbol entries exceed symbol table",
            ));
        }

        if !name.is_empty() {
            symbols.push(Symbol {
                name,
                address: pe_coff_symbol_address(sections, section_number, value)?,
            });
        }
        index = next_index;
    }

    Ok(symbols)
}

fn pe_coff_string_table(bytes: &[u8], offset: u64) -> Result<&[u8]> {
    checked_range(bytes, offset, 4, "PE COFF string table size")?;
    let size = u64::from(read_u32(
        bytes,
        offset,
        Endian::Little,
        "PE COFF string table size",
    )?);
    if size < 4 {
        return Err(malformed("PE COFF string table size is too small"));
    }
    checked_range(bytes, offset, size, "PE COFF string table")
}

fn pe_coff_symbol_name(bytes: &[u8], base: u64, string_table: &[u8]) -> Result<String> {
    let zeroes = read_u32(bytes, base, Endian::Little, "PE COFF symbol name zeroes")?;
    if zeroes == 0 {
        let string_offset = read_u32(
            bytes,
            base + 4,
            Endian::Little,
            "PE COFF symbol string offset",
        )?;
        pe_coff_string_table_name(string_table, string_offset)
    } else {
        read_fixed_string(bytes, base, 8, "PE COFF symbol short name")
    }
}

fn pe_coff_string_table_name(string_table: &[u8], offset: u32) -> Result<String> {
    if offset < 4 {
        return Err(malformed(
            "PE COFF symbol string offset is before string data",
        ));
    }
    let start = usize::try_from(offset)
        .map_err(|_| malformed("PE COFF symbol string offset does not fit in usize"))?;
    let Some(rest) = string_table.get(start..) else {
        return Err(malformed("PE COFF symbol string offset is out of range"));
    };
    let end = rest
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(rest.len());
    let Some(bytes) = rest.get(..end) else {
        return Err(malformed("PE COFF symbol string has invalid range"));
    };
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

fn pe_coff_symbol_address(
    sections: &[PeSection],
    section_number: i16,
    value: u64,
) -> Result<Option<Address>> {
    if section_number <= 0 {
        return Ok(None);
    }

    let section_index = usize::try_from(i32::from(section_number) - 1)
        .map_err(|_| malformed("PE COFF symbol section index does not fit in usize"))?;
    let Some(section) = sections.get(section_index) else {
        return Err(malformed("PE COFF symbol section index is out of range"));
    };
    section
        .address
        .checked_add(value)
        .map(Some)
        .ok_or_else(|| malformed("PE COFF symbol address overflow"))
}

fn parse_pe_exports(
    bytes: &[u8],
    header: &PeHeader,
    sections: &[PeSection],
) -> Result<Vec<Export>> {
    let Some(export_directory) = header.export_directory else {
        return Ok(Vec::new());
    };

    let export_size = u64::from(export_directory.size);
    if export_size < PE_EXPORT_DIRECTORY_SIZE {
        return Err(malformed("PE export directory is too small"));
    }
    let directory_location = pe_rva_to_file_location(u64::from(export_directory.rva), sections)
        .ok_or_else(|| malformed("PE export directory RVA does not map to file data"))?;
    let directory_end = checked_add_offset(
        directory_location.offset,
        export_size,
        "PE export directory",
    )?;
    if directory_end > directory_location.limit {
        return Err(malformed(
            "PE export directory extends beyond section file data",
        ));
    }
    checked_range(
        bytes,
        directory_location.offset,
        export_size,
        "PE export directory",
    )?;

    let module_name_rva = read_u32(
        bytes,
        directory_location.offset + 12,
        Endian::Little,
        "PE export module name RVA",
    )?;
    let ordinal_base = read_u32(
        bytes,
        directory_location.offset + 16,
        Endian::Little,
        "PE export ordinal base",
    )?;
    let function_count = read_u32(
        bytes,
        directory_location.offset + 20,
        Endian::Little,
        "PE export address count",
    )?;
    let name_count = read_u32(
        bytes,
        directory_location.offset + 24,
        Endian::Little,
        "PE export name count",
    )?;
    let address_table_rva = read_u32(
        bytes,
        directory_location.offset + 28,
        Endian::Little,
        "PE export address table RVA",
    )?;
    let name_pointer_table_rva = read_u32(
        bytes,
        directory_location.offset + 32,
        Endian::Little,
        "PE export name pointer table RVA",
    )?;
    let ordinal_table_rva = read_u32(
        bytes,
        directory_location.offset + 36,
        Endian::Little,
        "PE export ordinal table RVA",
    )?;

    if function_count == 0 {
        return Ok(Vec::new());
    }
    if address_table_rva == 0 {
        return Err(malformed("PE export address table RVA is zero"));
    }
    if name_count > 0 && (name_pointer_table_rva == 0 || ordinal_table_rva == 0) {
        return Err(malformed("PE export name or ordinal table RVA is zero"));
    }

    let module = if module_name_rva == 0 {
        None
    } else {
        Some(read_pe_c_string(
            bytes,
            sections,
            u64::from(module_name_rva),
            "PE export module name",
        )?)
    };

    let address_table = checked_pe_table(
        bytes,
        sections,
        u64::from(address_table_rva),
        function_count,
        PE_EXPORT_ADDRESS_TABLE_ENTRY_SIZE,
        "PE export address table",
    )?;
    let mut names_by_index = BTreeMap::<u32, Vec<String>>::new();
    if name_count > 0 {
        let name_pointer_table = checked_pe_table(
            bytes,
            sections,
            u64::from(name_pointer_table_rva),
            name_count,
            PE_EXPORT_NAME_POINTER_ENTRY_SIZE,
            "PE export name pointer table",
        )?;
        let ordinal_table = checked_pe_table(
            bytes,
            sections,
            u64::from(ordinal_table_rva),
            name_count,
            PE_EXPORT_ORDINAL_TABLE_ENTRY_SIZE,
            "PE export ordinal table",
        )?;
        for index in 0..name_count {
            let pointer_offset = table_entry_offset_u32(
                name_pointer_table.offset,
                PE_EXPORT_NAME_POINTER_ENTRY_SIZE,
                index,
                "PE export name pointer table",
            )?;
            let name_rva = read_u32(bytes, pointer_offset, Endian::Little, "PE export name RVA")?;
            let ordinal_offset = table_entry_offset_u32(
                ordinal_table.offset,
                PE_EXPORT_ORDINAL_TABLE_ENTRY_SIZE,
                index,
                "PE export ordinal table",
            )?;
            let function_index = u32::from(read_u16(
                bytes,
                ordinal_offset,
                Endian::Little,
                "PE export ordinal index",
            )?);
            if function_index >= function_count {
                return Err(malformed("PE export ordinal index is out of range"));
            }
            let name = read_pe_c_string(bytes, sections, u64::from(name_rva), "PE export name")?;
            names_by_index.entry(function_index).or_default().push(name);
        }
    }

    let mut exports = Vec::new();
    let export_start_rva = u64::from(export_directory.rva);
    let export_end_rva = checked_add_offset(export_start_rva, export_size, "PE export directory")?;
    for function_index in 0..function_count {
        let address_offset = table_entry_offset_u32(
            address_table.offset,
            PE_EXPORT_ADDRESS_TABLE_ENTRY_SIZE,
            function_index,
            "PE export address table",
        )?;
        let function_rva = read_u32(
            bytes,
            address_offset,
            Endian::Little,
            "PE export function RVA",
        )?;
        let names = names_by_index.remove(&function_index).unwrap_or_default();
        if function_rva == 0 && names.is_empty() {
            continue;
        }

        let ordinal = ordinal_base
            .checked_add(function_index)
            .ok_or_else(|| malformed("PE export ordinal overflow"))?;
        let (address, forwarder) = pe_export_target(
            bytes,
            header,
            sections,
            function_rva,
            export_start_rva,
            export_end_rva,
        )?;

        if names.is_empty() {
            exports.push(Export {
                module: module.clone(),
                name: None,
                ordinal,
                address,
                forwarder,
            });
        } else {
            for name in names {
                exports.push(Export {
                    module: module.clone(),
                    name: Some(name),
                    ordinal,
                    address,
                    forwarder: forwarder.clone(),
                });
            }
        }
    }

    Ok(exports)
}

fn pe_export_target(
    bytes: &[u8],
    header: &PeHeader,
    sections: &[PeSection],
    function_rva: u32,
    export_start_rva: u64,
    export_end_rva: u64,
) -> Result<(Option<Address>, Option<String>)> {
    if function_rva == 0 {
        return Ok((None, None));
    }

    let function_rva = u64::from(function_rva);
    if function_rva >= export_start_rva && function_rva < export_end_rva {
        let forwarder = read_pe_c_string(bytes, sections, function_rva, "PE export forwarder")?;
        return Ok((None, Some(forwarder)));
    }

    let address = header
        .image_base
        .checked_add(function_rva)
        .ok_or_else(|| malformed("PE export address overflow"))?;
    Ok((Some(Address::new(address)), None))
}

fn parse_pe_imports(
    bytes: &[u8],
    header: &PeHeader,
    sections: &[PeSection],
) -> Result<Vec<Import>> {
    let Some(import_directory) = header.import_directory else {
        return Ok(Vec::new());
    };

    let import_size = u64::from(import_directory.size);
    let directory_location = pe_rva_to_file_location(u64::from(import_directory.rva), sections)
        .ok_or_else(|| malformed("PE import directory RVA does not map to file data"))?;
    let directory_end = checked_add_offset(
        directory_location.offset,
        import_size,
        "PE import directory",
    )?;
    if directory_end > directory_location.limit {
        return Err(malformed(
            "PE import directory extends beyond section file data",
        ));
    }
    checked_range(
        bytes,
        directory_location.offset,
        import_size,
        "PE import directory",
    )?;

    let mut imports = Vec::new();
    let mut descriptor_offset = directory_location.offset;
    while checked_add_offset(
        descriptor_offset,
        PE_IMPORT_DESCRIPTOR_SIZE,
        "PE import descriptor",
    )? <= directory_end
    {
        let original_first_thunk = read_u32(
            bytes,
            descriptor_offset,
            Endian::Little,
            "PE import original first thunk",
        )?;
        let time_date_stamp = read_u32(
            bytes,
            descriptor_offset + 4,
            Endian::Little,
            "PE import time date stamp",
        )?;
        let forwarder_chain = read_u32(
            bytes,
            descriptor_offset + 8,
            Endian::Little,
            "PE import forwarder chain",
        )?;
        let name_rva = read_u32(
            bytes,
            descriptor_offset + 12,
            Endian::Little,
            "PE import DLL name RVA",
        )?;
        let first_thunk = read_u32(
            bytes,
            descriptor_offset + 16,
            Endian::Little,
            "PE import first thunk",
        )?;

        if original_first_thunk == 0
            && time_date_stamp == 0
            && forwarder_chain == 0
            && name_rva == 0
            && first_thunk == 0
        {
            return Ok(imports);
        }

        if name_rva == 0 {
            return Err(malformed("PE import descriptor DLL name RVA is zero"));
        }
        let lookup_table_rva = if original_first_thunk == 0 {
            first_thunk
        } else {
            original_first_thunk
        };
        if lookup_table_rva == 0 {
            return Err(malformed("PE import descriptor has no lookup table"));
        }

        let library = read_pe_c_string(bytes, sections, u64::from(name_rva), "PE import DLL name")?;
        imports.extend(parse_pe_import_lookup_table(
            bytes,
            header,
            sections,
            &library,
            u64::from(lookup_table_rva),
            u64::from(first_thunk),
        )?);

        descriptor_offset = checked_add_offset(
            descriptor_offset,
            PE_IMPORT_DESCRIPTOR_SIZE,
            "PE import descriptor table",
        )?;
    }

    Err(malformed(
        "PE import descriptor table is missing terminator",
    ))
}

fn parse_pe_import_lookup_table(
    bytes: &[u8],
    header: &PeHeader,
    sections: &[PeSection],
    library: &str,
    lookup_table_rva: u64,
    first_thunk: u64,
) -> Result<Vec<Import>> {
    let (entry_size, ordinal_flag) = match header.kind {
        PeKind::Pe32 => (PE32_IMPORT_LOOKUP_ENTRY_SIZE, PE32_ORDINAL_FLAG),
        PeKind::Pe32Plus => (PE32_PLUS_IMPORT_LOOKUP_ENTRY_SIZE, PE32_PLUS_ORDINAL_FLAG),
    };
    let table_location = pe_rva_to_file_location(lookup_table_rva, sections)
        .ok_or_else(|| malformed("PE import lookup table RVA does not map to file data"))?;

    let mut imports = Vec::new();
    let mut entry_offset = table_location.offset;
    let mut index = 0_u64;
    while checked_add_offset(entry_offset, entry_size, "PE import lookup entry")?
        <= table_location.limit
    {
        let value = match header.kind {
            PeKind::Pe32 => u64::from(read_u32(
                bytes,
                entry_offset,
                Endian::Little,
                "PE32 import lookup entry",
            )?),
            PeKind::Pe32Plus => read_u64(
                bytes,
                entry_offset,
                Endian::Little,
                "PE32+ import lookup entry",
            )?,
        };
        if value == 0 {
            return Ok(imports);
        }

        let (name, ordinal) = if value & ordinal_flag != 0 {
            (None, Some((value & 0xffff) as u16))
        } else {
            (Some(read_pe_import_name(bytes, sections, value)?), None)
        };
        imports.push(Import {
            library: library.to_string(),
            name,
            ordinal,
            thunk: pe_import_thunk_address(
                header,
                first_thunk,
                lookup_table_rva,
                index,
                entry_size,
            )?,
        });

        entry_offset = checked_add_offset(entry_offset, entry_size, "PE import lookup table")?;
        index = index
            .checked_add(1)
            .ok_or_else(|| malformed("PE import lookup table index overflow"))?;
    }

    Err(malformed("PE import lookup table is missing terminator"))
}

fn pe_import_thunk_address(
    header: &PeHeader,
    first_thunk: u64,
    lookup_table_rva: u64,
    index: u64,
    entry_size: u64,
) -> Result<Option<Address>> {
    let thunk_table_rva = if first_thunk == 0 {
        lookup_table_rva
    } else {
        first_thunk
    };
    let entry_delta = index
        .checked_mul(entry_size)
        .ok_or_else(|| malformed("PE import thunk address overflow"))?;
    let thunk_rva = thunk_table_rva
        .checked_add(entry_delta)
        .ok_or_else(|| malformed("PE import thunk address overflow"))?;
    let address = header
        .image_base
        .checked_add(thunk_rva)
        .ok_or_else(|| malformed("PE import thunk address overflow"))?;

    Ok(Some(Address::new(address)))
}

fn dependencies_from_imports(imports: &[Import]) -> Vec<Dependency> {
    let mut seen = BTreeSet::new();
    let mut dependencies = Vec::new();
    for import in imports {
        if import.library.is_empty() || !seen.insert(import.library.clone()) {
            continue;
        }
        dependencies.push(Dependency {
            name: import.library.clone(),
        });
    }
    dependencies
}

fn read_pe_import_name(bytes: &[u8], sections: &[PeSection], name_rva: u64) -> Result<String> {
    let location = pe_rva_to_file_location(name_rva, sections)
        .ok_or_else(|| malformed("PE import name RVA does not map to file data"))?;
    checked_range(bytes, location.offset, 2, "PE import hint")?;
    read_file_c_string(
        bytes,
        checked_add_offset(location.offset, 2, "PE import name")?,
        location.limit,
        "PE import name",
    )
}

fn read_pe_c_string(
    bytes: &[u8],
    sections: &[PeSection],
    rva: u64,
    context: &str,
) -> Result<String> {
    let location = pe_rva_to_file_location(rva, sections)
        .ok_or_else(|| malformed(format!("{context} RVA does not map to file data")))?;
    read_file_c_string(bytes, location.offset, location.limit, context)
}

fn read_file_c_string(bytes: &[u8], offset: u64, limit: u64, context: &str) -> Result<String> {
    let start = usize::try_from(offset)
        .map_err(|_| malformed(format!("{context} offset does not fit in usize")))?;
    let end = usize::try_from(limit)
        .map_err(|_| malformed(format!("{context} limit does not fit in usize")))?;
    if end > bytes.len() {
        return Err(malformed(format!("{context} limit extends beyond file")));
    }
    if start >= end {
        return Err(malformed(format!(
            "{context} offset is outside mapped file data"
        )));
    }

    let rest = &bytes[start..end];
    let Some(nul_offset) = rest.iter().position(|byte| *byte == 0) else {
        return Err(malformed(format!("{context} is not null terminated")));
    };
    let name_bytes = &rest[..nul_offset];
    if name_bytes.is_empty() {
        return Err(malformed(format!("{context} is empty")));
    }

    Ok(String::from_utf8_lossy(name_bytes).into_owned())
}

fn checked_pe_table(
    bytes: &[u8],
    sections: &[PeSection],
    rva: u64,
    count: u32,
    entry_size: u64,
    context: &str,
) -> Result<PeFileLocation> {
    let table_size = entry_size
        .checked_mul(u64::from(count))
        .ok_or_else(|| malformed(format!("{context} size overflow")))?;
    let location = pe_rva_to_file_location(rva, sections)
        .ok_or_else(|| malformed(format!("{context} RVA does not map to file data")))?;
    let table_end = checked_add_offset(location.offset, table_size, context)?;
    if table_end > location.limit {
        return Err(malformed(format!(
            "{context} extends beyond section file data"
        )));
    }
    checked_range(bytes, location.offset, table_size, context)?;

    Ok(location)
}

fn pe_rva_to_file_location(rva: u64, sections: &[PeSection]) -> Option<PeFileLocation> {
    for section in sections {
        let file_offset = section.file_offset?;
        if section.raw_size == 0 {
            continue;
        }
        let section_start = section.virtual_address;
        let section_end = section_start.checked_add(section.raw_size)?;
        if rva < section_start || rva >= section_end {
            continue;
        }

        let relative = rva.checked_sub(section_start)?;
        let offset = file_offset.checked_add(relative)?;
        let limit = file_offset.checked_add(section.raw_size)?;
        return Some(PeFileLocation { offset, limit });
    }

    None
}

fn parse_elf_header(bytes: &[u8]) -> Result<ElfHeader> {
    if bytes.len() < ELF_IDENT_LEN || !bytes.starts_with(b"\x7fELF") {
        return Err(malformed("input is not a complete ELF identifier"));
    }

    let class = match byte_at(bytes, 4, "ELF class")? {
        ELFCLASS32 => ElfClass::Elf32,
        ELFCLASS64 => ElfClass::Elf64,
        value => return Err(malformed(format!("unsupported ELF class {value}"))),
    };
    let endian = match byte_at(bytes, 5, "ELF data encoding")? {
        ELFDATA2LSB => Endian::Little,
        ELFDATA2MSB => Endian::Big,
        value => return Err(malformed(format!("unsupported ELF data encoding {value}"))),
    };

    let min_header_size = match class {
        ElfClass::Elf32 => 52,
        ElfClass::Elf64 => 64,
    };
    checked_range(bytes, 0, min_header_size, "ELF header")?;

    let machine = read_u16(bytes, 18, endian, "ELF machine")?;
    let entrypoint = match class {
        ElfClass::Elf32 => u64::from(read_u32(bytes, 24, endian, "ELF entrypoint")?),
        ElfClass::Elf64 => read_u64(bytes, 24, endian, "ELF entrypoint")?,
    };
    let program_header_offset = match class {
        ElfClass::Elf32 => u64::from(read_u32(bytes, 28, endian, "ELF program header offset")?),
        ElfClass::Elf64 => read_u64(bytes, 32, endian, "ELF program header offset")?,
    };
    let section_header_offset = match class {
        ElfClass::Elf32 => u64::from(read_u32(bytes, 32, endian, "ELF section header offset")?),
        ElfClass::Elf64 => read_u64(bytes, 40, endian, "ELF section header offset")?,
    };
    let program_header_entry_size = match class {
        ElfClass::Elf32 => read_u16(bytes, 42, endian, "ELF program header entry size")?,
        ElfClass::Elf64 => read_u16(bytes, 54, endian, "ELF program header entry size")?,
    };
    let program_header_count = match class {
        ElfClass::Elf32 => read_u16(bytes, 44, endian, "ELF program header count")?,
        ElfClass::Elf64 => read_u16(bytes, 56, endian, "ELF program header count")?,
    };
    let section_header_entry_size = match class {
        ElfClass::Elf32 => read_u16(bytes, 46, endian, "ELF section header entry size")?,
        ElfClass::Elf64 => read_u16(bytes, 58, endian, "ELF section header entry size")?,
    };
    let section_header_count = match class {
        ElfClass::Elf32 => read_u16(bytes, 48, endian, "ELF section header count")?,
        ElfClass::Elf64 => read_u16(bytes, 60, endian, "ELF section header count")?,
    };
    let section_name_table_index = match class {
        ElfClass::Elf32 => read_u16(bytes, 50, endian, "ELF section name table index")?,
        ElfClass::Elf64 => read_u16(bytes, 62, endian, "ELF section name table index")?,
    };

    Ok(ElfHeader {
        class,
        endian,
        machine,
        entrypoint,
        program_header_offset,
        section_header_offset,
        program_header_entry_size,
        program_header_count,
        section_header_entry_size,
        section_header_count,
        section_name_table_index,
    })
}

fn parse_elf_program_headers(bytes: &[u8], header: &ElfHeader) -> Result<Vec<ElfProgramHeader>> {
    if header.program_header_count == 0 {
        return Ok(Vec::new());
    }

    let minimum_entry_size = match header.class {
        ElfClass::Elf32 => 32,
        ElfClass::Elf64 => 56,
    };
    if header.program_header_entry_size < minimum_entry_size {
        return Err(malformed("ELF program header entry size is too small"));
    }

    let mut program_headers = Vec::with_capacity(usize::from(header.program_header_count));
    for index in 0..header.program_header_count {
        let base = table_entry_offset(
            header.program_header_offset,
            header.program_header_entry_size,
            index,
            "ELF program header table",
        )?;
        checked_range(
            bytes,
            base,
            u64::from(header.program_header_entry_size),
            "ELF program header",
        )?;

        let program_header = match header.class {
            ElfClass::Elf32 => ElfProgramHeader {
                segment_type: read_u32(bytes, base, header.endian, "ELF p_type")?,
                offset: u64::from(read_u32(bytes, base + 4, header.endian, "ELF p_offset")?),
                virtual_address: u64::from(read_u32(
                    bytes,
                    base + 8,
                    header.endian,
                    "ELF p_vaddr",
                )?),
                file_size: u64::from(read_u32(bytes, base + 16, header.endian, "ELF p_filesz")?),
                memory_size: u64::from(read_u32(bytes, base + 20, header.endian, "ELF p_memsz")?),
                flags: read_u32(bytes, base + 24, header.endian, "ELF p_flags")?,
            },
            ElfClass::Elf64 => ElfProgramHeader {
                segment_type: read_u32(bytes, base, header.endian, "ELF p_type")?,
                flags: read_u32(bytes, base + 4, header.endian, "ELF p_flags")?,
                offset: read_u64(bytes, base + 8, header.endian, "ELF p_offset")?,
                virtual_address: read_u64(bytes, base + 16, header.endian, "ELF p_vaddr")?,
                file_size: read_u64(bytes, base + 32, header.endian, "ELF p_filesz")?,
                memory_size: read_u64(bytes, base + 40, header.endian, "ELF p_memsz")?,
            },
        };
        program_headers.push(program_header);
    }

    Ok(program_headers)
}

fn parse_elf_section_headers(bytes: &[u8], header: &ElfHeader) -> Result<Vec<ElfSectionHeader>> {
    if header.section_header_count == 0 {
        return Ok(Vec::new());
    }

    let minimum_entry_size = match header.class {
        ElfClass::Elf32 => 40,
        ElfClass::Elf64 => 64,
    };
    if header.section_header_entry_size < minimum_entry_size {
        return Err(malformed("ELF section header entry size is too small"));
    }

    let mut raw_sections = Vec::with_capacity(usize::from(header.section_header_count));
    for index in 0..header.section_header_count {
        let base = table_entry_offset(
            header.section_header_offset,
            header.section_header_entry_size,
            index,
            "ELF section header table",
        )?;
        checked_range(
            bytes,
            base,
            u64::from(header.section_header_entry_size),
            "ELF section header",
        )?;

        let section = match header.class {
            ElfClass::Elf32 => ElfSectionHeader {
                name_offset: read_u32(bytes, base, header.endian, "ELF sh_name")?,
                section_type: read_u32(bytes, base + 4, header.endian, "ELF sh_type")?,
                flags: u64::from(read_u32(bytes, base + 8, header.endian, "ELF sh_flags")?),
                address: u64::from(read_u32(bytes, base + 12, header.endian, "ELF sh_addr")?),
                offset: u64::from(read_u32(bytes, base + 16, header.endian, "ELF sh_offset")?),
                size: u64::from(read_u32(bytes, base + 20, header.endian, "ELF sh_size")?),
                link: read_u32(bytes, base + 24, header.endian, "ELF sh_link")?,
                entry_size: u64::from(read_u32(bytes, base + 36, header.endian, "ELF sh_entsize")?),
            },
            ElfClass::Elf64 => ElfSectionHeader {
                name_offset: read_u32(bytes, base, header.endian, "ELF sh_name")?,
                section_type: read_u32(bytes, base + 4, header.endian, "ELF sh_type")?,
                flags: read_u64(bytes, base + 8, header.endian, "ELF sh_flags")?,
                address: read_u64(bytes, base + 16, header.endian, "ELF sh_addr")?,
                offset: read_u64(bytes, base + 24, header.endian, "ELF sh_offset")?,
                size: read_u64(bytes, base + 32, header.endian, "ELF sh_size")?,
                link: read_u32(bytes, base + 40, header.endian, "ELF sh_link")?,
                entry_size: read_u64(bytes, base + 56, header.endian, "ELF sh_entsize")?,
            },
        };
        raw_sections.push(section);
    }

    Ok(raw_sections)
}

fn parse_elf_sections(
    bytes: &[u8],
    header: &ElfHeader,
    raw_sections: &[ElfSectionHeader],
) -> Result<Vec<Section>> {
    let name_table = section_name_table(bytes, header, raw_sections)?;
    let mut sections = Vec::with_capacity(raw_sections.len());
    for (index, section) in raw_sections.iter().enumerate() {
        let name = section_name(name_table, section.name_offset)
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| format!("section{index}"));
        let file_offset = if section.section_type == SHT_NOBITS {
            None
        } else {
            Some(section.offset)
        };

        sections.push(Section {
            name,
            address: Address::new(section.address),
            file_offset,
            size: section.size,
            permissions: section_permissions(section.flags),
        });
    }

    Ok(sections)
}

fn parse_elf_symbol_entries(
    bytes: &[u8],
    header: &ElfHeader,
    raw_sections: &[ElfSectionHeader],
) -> Result<Vec<ElfSymbolEntry>> {
    let mut symbols = Vec::new();

    for (table_section_index, section) in raw_sections
        .iter()
        .enumerate()
        .filter(|(_, section)| matches!(section.section_type, SHT_SYMTAB | SHT_DYNSYM))
    {
        if section.size == 0 {
            continue;
        }

        let minimum_entry_size = elf_symbol_entry_size(header.class);
        if section.entry_size < minimum_entry_size {
            return Err(malformed("ELF symbol table entry size is too small"));
        }
        if section.size % section.entry_size != 0 {
            return Err(malformed(
                "ELF symbol table size is not a multiple of entry size",
            ));
        }

        let link_index = usize::try_from(section.link)
            .map_err(|_| malformed("ELF symbol string table index does not fit in usize"))?;
        let Some(string_section) = raw_sections.get(link_index) else {
            return Err(malformed("ELF symbol string table index is out of range"));
        };
        if string_section.section_type != SHT_STRTAB {
            return Err(malformed("ELF symbol table link does not point to STRTAB"));
        }
        if string_section.size == 0 {
            continue;
        }

        let string_table = checked_range(
            bytes,
            string_section.offset,
            string_section.size,
            "ELF symbol string table",
        )?;
        checked_range(bytes, section.offset, section.size, "ELF symbol table")?;
        let symbol_count = section.size / section.entry_size;
        for index in 0..symbol_count {
            let base = section
                .offset
                .checked_add(
                    index
                        .checked_mul(section.entry_size)
                        .ok_or_else(|| malformed("ELF symbol table offset overflow"))?,
                )
                .ok_or_else(|| malformed("ELF symbol table offset overflow"))?;
            if let Some(symbol) = parse_elf_symbol_entry(
                bytes,
                header,
                string_table,
                base,
                table_section_index,
                index,
                section.section_type == SHT_DYNSYM,
            )? {
                symbols.push(symbol);
            }
        }
    }

    Ok(symbols)
}

fn parse_elf_symbol_entry(
    bytes: &[u8],
    header: &ElfHeader,
    string_table: &[u8],
    base: u64,
    table_section_index: usize,
    symbol_index: u64,
    is_dynamic: bool,
) -> Result<Option<ElfSymbolEntry>> {
    let (name_offset, section_index, value) = match header.class {
        ElfClass::Elf32 => (
            read_u32(bytes, base, header.endian, "ELF st_name")?,
            read_u16(bytes, base + 14, header.endian, "ELF st_shndx")?,
            u64::from(read_u32(bytes, base + 4, header.endian, "ELF st_value")?),
        ),
        ElfClass::Elf64 => (
            read_u32(bytes, base, header.endian, "ELF st_name")?,
            read_u16(bytes, base + 6, header.endian, "ELF st_shndx")?,
            read_u64(bytes, base + 8, header.endian, "ELF st_value")?,
        ),
    };

    let Some(name) = string_table_name(string_table, name_offset, "ELF symbol name")? else {
        return Ok(None);
    };
    let address = if section_index == SHN_UNDEF || value == 0 {
        None
    } else {
        Some(Address::new(value))
    };

    Ok(Some(ElfSymbolEntry {
        table_section_index,
        symbol_index,
        is_dynamic,
        name,
        section_index,
        address,
    }))
}

fn parse_elf_relocation_entries(
    bytes: &[u8],
    header: &ElfHeader,
    raw_sections: &[ElfSectionHeader],
) -> Result<Vec<ElfRelocationEntry>> {
    let mut relocations = Vec::new();

    for section in raw_sections
        .iter()
        .filter(|section| matches!(section.section_type, SHT_REL | SHT_RELA))
    {
        if section.size == 0 {
            continue;
        }

        let is_rela = section.section_type == SHT_RELA;
        let minimum_entry_size = elf_relocation_entry_size(header.class, is_rela);
        if section.entry_size < minimum_entry_size {
            return Err(malformed("ELF relocation table entry size is too small"));
        }
        if section.size % section.entry_size != 0 {
            return Err(malformed(
                "ELF relocation table size is not a multiple of entry size",
            ));
        }

        let symbol_table_section_index = elf_relocation_symbol_table_index(raw_sections, section)?;
        checked_range(bytes, section.offset, section.size, "ELF relocation table")?;
        let relocation_count = section.size / section.entry_size;
        for index in 0..relocation_count {
            let base = section
                .offset
                .checked_add(
                    index
                        .checked_mul(section.entry_size)
                        .ok_or_else(|| malformed("ELF relocation table offset overflow"))?,
                )
                .ok_or_else(|| malformed("ELF relocation table offset overflow"))?;
            let (address, info) = match header.class {
                ElfClass::Elf32 => (
                    u64::from(read_u32(
                        bytes,
                        base,
                        header.endian,
                        "ELF relocation offset",
                    )?),
                    u64::from(read_u32(
                        bytes,
                        base + 4,
                        header.endian,
                        "ELF relocation info",
                    )?),
                ),
                ElfClass::Elf64 => (
                    read_u64(bytes, base, header.endian, "ELF relocation offset")?,
                    read_u64(bytes, base + 8, header.endian, "ELF relocation info")?,
                ),
            };
            let (symbol_index, relocation_type) = elf_relocation_info(header.class, info);
            let symbol_index = if symbol_index == 0 {
                None
            } else {
                let Some(table_index) = symbol_table_section_index else {
                    return Err(malformed(
                        "ELF relocation references a symbol without a linked symbol table",
                    ));
                };
                validate_elf_symbol_index(raw_sections, header, table_index, symbol_index)?;
                Some(symbol_index)
            };

            relocations.push(ElfRelocationEntry {
                address: Address::new(address),
                kind: elf_relocation_kind(header.machine, relocation_type),
                symbol_table_section_index,
                symbol_index,
            });
        }
    }

    Ok(relocations)
}

fn parse_elf_dependencies(
    bytes: &[u8],
    header: &ElfHeader,
    raw_sections: &[ElfSectionHeader],
) -> Result<Vec<Dependency>> {
    let mut dependencies = Vec::new();
    let mut seen = BTreeSet::new();

    for section in raw_sections
        .iter()
        .filter(|section| section.section_type == SHT_DYNAMIC)
    {
        if section.size == 0 {
            continue;
        }

        let minimum_entry_size = elf_dynamic_entry_size(header.class);
        if section.entry_size < minimum_entry_size {
            return Err(malformed("ELF dynamic table entry size is too small"));
        }
        if section.size % section.entry_size != 0 {
            return Err(malformed(
                "ELF dynamic table size is not a multiple of entry size",
            ));
        }

        let link_index = usize::try_from(section.link)
            .map_err(|_| malformed("ELF dynamic string table index does not fit in usize"))?;
        let Some(string_section) = raw_sections.get(link_index) else {
            return Err(malformed("ELF dynamic string table index is out of range"));
        };
        if string_section.section_type != SHT_STRTAB {
            return Err(malformed("ELF dynamic table link does not point to STRTAB"));
        }
        if string_section.size == 0 {
            continue;
        }

        let string_table = checked_range(
            bytes,
            string_section.offset,
            string_section.size,
            "ELF dynamic string table",
        )?;
        checked_range(bytes, section.offset, section.size, "ELF dynamic table")?;
        let entry_count = section.size / section.entry_size;
        for index in 0..entry_count {
            let base = section
                .offset
                .checked_add(
                    index
                        .checked_mul(section.entry_size)
                        .ok_or_else(|| malformed("ELF dynamic table offset overflow"))?,
                )
                .ok_or_else(|| malformed("ELF dynamic table offset overflow"))?;
            let (tag, value) = match header.class {
                ElfClass::Elf32 => (
                    u64::from(read_u32(bytes, base, header.endian, "ELF dynamic tag")?),
                    u64::from(read_u32(
                        bytes,
                        base + 4,
                        header.endian,
                        "ELF dynamic value",
                    )?),
                ),
                ElfClass::Elf64 => (
                    read_u64(bytes, base, header.endian, "ELF dynamic tag")?,
                    read_u64(bytes, base + 8, header.endian, "ELF dynamic value")?,
                ),
            };

            if tag == DT_NULL {
                break;
            }
            if tag != DT_NEEDED {
                continue;
            }
            let name_offset = u32::try_from(value)
                .map_err(|_| malformed("ELF needed library offset does not fit in u32"))?;
            let Some(name) = string_table_name(string_table, name_offset, "ELF needed library")?
            else {
                return Err(malformed("ELF needed library name is empty"));
            };
            if seen.insert(name.clone()) {
                dependencies.push(Dependency { name });
            }
        }
    }

    Ok(dependencies)
}

fn elf_imports_from_symbols(
    symbols: &[ElfSymbolEntry],
    relocations: &[ElfRelocationEntry],
) -> Vec<Import> {
    let mut imports = Vec::new();
    for symbol in symbols.iter().filter(|symbol| {
        symbol.is_dynamic && symbol.section_index == SHN_UNDEF && !symbol.name.is_empty()
    }) {
        let thunk = relocations
            .iter()
            .find(|relocation| {
                relocation.symbol_table_section_index == Some(symbol.table_section_index)
                    && relocation.symbol_index == Some(symbol.symbol_index)
            })
            .map(|relocation| relocation.address);
        imports.push(Import {
            library: "ELF".to_string(),
            name: Some(symbol.name.clone()),
            ordinal: None,
            thunk,
        });
    }
    imports
}

fn elf_symbol_entry_size(class: ElfClass) -> u64 {
    match class {
        ElfClass::Elf32 => 16,
        ElfClass::Elf64 => 24,
    }
}

fn elf_relocation_entry_size(class: ElfClass, is_rela: bool) -> u64 {
    match (class, is_rela) {
        (ElfClass::Elf32, false) => 8,
        (ElfClass::Elf32, true) => 12,
        (ElfClass::Elf64, false) => 16,
        (ElfClass::Elf64, true) => 24,
    }
}

fn elf_dynamic_entry_size(class: ElfClass) -> u64 {
    match class {
        ElfClass::Elf32 => 8,
        ElfClass::Elf64 => 16,
    }
}

fn elf_relocation_symbol_table_index(
    raw_sections: &[ElfSectionHeader],
    relocation_section: &ElfSectionHeader,
) -> Result<Option<usize>> {
    if relocation_section.link == 0 {
        return Ok(None);
    }

    let link_index = usize::try_from(relocation_section.link)
        .map_err(|_| malformed("ELF relocation symbol table index does not fit in usize"))?;
    let Some(symbol_section) = raw_sections.get(link_index) else {
        return Err(malformed(
            "ELF relocation symbol table index is out of range",
        ));
    };
    if !matches!(symbol_section.section_type, SHT_SYMTAB | SHT_DYNSYM) {
        return Err(malformed(
            "ELF relocation table link does not point to a symbol table",
        ));
    }

    Ok(Some(link_index))
}

fn validate_elf_symbol_index(
    raw_sections: &[ElfSectionHeader],
    header: &ElfHeader,
    table_index: usize,
    symbol_index: u64,
) -> Result<()> {
    let symbol_section = raw_sections
        .get(table_index)
        .ok_or_else(|| malformed("ELF relocation symbol table index is out of range"))?;
    let minimum_entry_size = elf_symbol_entry_size(header.class);
    if symbol_section.entry_size < minimum_entry_size {
        return Err(malformed("ELF symbol table entry size is too small"));
    }
    if symbol_section.size % symbol_section.entry_size != 0 {
        return Err(malformed(
            "ELF symbol table size is not a multiple of entry size",
        ));
    }

    let symbol_count = symbol_section.size / symbol_section.entry_size;
    if symbol_index >= symbol_count {
        return Err(malformed("ELF relocation symbol index is out of range"));
    }

    Ok(())
}

fn elf_relocation_info(class: ElfClass, info: u64) -> (u64, u64) {
    match class {
        ElfClass::Elf32 => (info >> 8, info & 0xff),
        ElfClass::Elf64 => (info >> 32, info & 0xffff_ffff),
    }
}

fn elf_relocation_kind(machine: u16, relocation_type: u64) -> String {
    match machine {
        EM_386 => match relocation_type {
            1 => "elf-i386-32".to_string(),
            2 => "elf-i386-pc32".to_string(),
            6 => "elf-i386-glob-dat".to_string(),
            7 => "elf-i386-jump-slot".to_string(),
            8 => "elf-i386-relative".to_string(),
            _ => format!("elf-i386-unknown-{relocation_type}"),
        },
        EM_X86_64 => match relocation_type {
            1 => "elf-x86_64-64".to_string(),
            2 => "elf-x86_64-pc32".to_string(),
            6 => "elf-x86_64-glob-dat".to_string(),
            7 => "elf-x86_64-jump-slot".to_string(),
            8 => "elf-x86_64-relative".to_string(),
            _ => format!("elf-x86_64-unknown-{relocation_type}"),
        },
        EM_AARCH64 => match relocation_type {
            257 => "elf-aarch64-abs64".to_string(),
            1025 => "elf-aarch64-glob-dat".to_string(),
            1026 => "elf-aarch64-jump-slot".to_string(),
            1027 => "elf-aarch64-relative".to_string(),
            _ => format!("elf-aarch64-unknown-{relocation_type}"),
        },
        _ => format!("elf-relocation-{relocation_type}"),
    }
}

fn section_name_table<'a>(
    bytes: &'a [u8],
    header: &ElfHeader,
    sections: &[ElfSectionHeader],
) -> Result<Option<&'a [u8]>> {
    let index = usize::from(header.section_name_table_index);
    if index == 0 {
        return Ok(None);
    }

    let Some(section) = sections.get(index) else {
        return Err(malformed("ELF section name table index is out of range"));
    };
    if section.section_type == SHT_NOBITS || section.size == 0 {
        return Ok(None);
    }

    checked_range(
        bytes,
        section.offset,
        section.size,
        "ELF section name table",
    )
    .map(Some)
}

fn section_name(name_table: Option<&[u8]>, offset: u32) -> Option<String> {
    let table = name_table?;
    let start = usize::try_from(offset).ok()?;
    let rest = table.get(start..)?;
    let end = rest
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(rest.len());
    let bytes = rest.get(..end)?;
    Some(String::from_utf8_lossy(bytes).into_owned())
}

fn string_table_name(table: &[u8], offset: u32, context: &str) -> Result<Option<String>> {
    if offset == 0 {
        return Ok(None);
    }

    let start = usize::try_from(offset)
        .map_err(|_| malformed(format!("{context} offset does not fit in usize")))?;
    let Some(rest) = table.get(start..) else {
        return Err(malformed(format!("{context} offset is out of range")));
    };
    let end = rest
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(rest.len());
    let Some(bytes) = rest.get(..end) else {
        return Err(malformed(format!("{context} has invalid range")));
    };
    if bytes.is_empty() {
        return Ok(None);
    }

    Ok(Some(String::from_utf8_lossy(bytes).into_owned()))
}

fn table_entry_offset(
    table_offset: u64,
    entry_size: u16,
    index: u16,
    context: &str,
) -> Result<u64> {
    let index_offset = u64::from(entry_size)
        .checked_mul(u64::from(index))
        .ok_or_else(|| malformed(format!("{context} offset overflow")))?;
    table_offset
        .checked_add(index_offset)
        .ok_or_else(|| malformed(format!("{context} offset overflow")))
}

fn table_entry_offset_u32(
    table_offset: u64,
    entry_size: u64,
    index: u32,
    context: &str,
) -> Result<u64> {
    let index_offset = entry_size
        .checked_mul(u64::from(index))
        .ok_or_else(|| malformed(format!("{context} offset overflow")))?;
    table_offset
        .checked_add(index_offset)
        .ok_or_else(|| malformed(format!("{context} offset overflow")))
}

fn checked_table_size(header_size: u64, entry_size: u64, count: u32, context: &str) -> Result<u64> {
    let entries_size = entry_size
        .checked_mul(u64::from(count))
        .ok_or_else(|| malformed(format!("{context} size overflow")))?;
    header_size
        .checked_add(entries_size)
        .ok_or_else(|| malformed(format!("{context} size overflow")))
}

fn checked_add_offset(base: u64, addend: u64, context: &str) -> Result<u64> {
    base.checked_add(addend)
        .ok_or_else(|| malformed(format!("{context} overflow")))
}

fn checked_range<'a>(bytes: &'a [u8], offset: u64, size: u64, context: &str) -> Result<&'a [u8]> {
    let start = usize::try_from(offset)
        .map_err(|_| malformed(format!("{context} offset does not fit in usize")))?;
    let len = usize::try_from(size)
        .map_err(|_| malformed(format!("{context} size does not fit in usize")))?;
    let end = start
        .checked_add(len)
        .ok_or_else(|| malformed(format!("{context} range overflow")))?;

    bytes
        .get(start..end)
        .ok_or_else(|| malformed(format!("{context} extends beyond file")))
}

fn byte_at(bytes: &[u8], offset: usize, context: &str) -> Result<u8> {
    bytes
        .get(offset)
        .copied()
        .ok_or_else(|| malformed(format!("{context} is missing")))
}

fn read_fixed_string(bytes: &[u8], offset: u64, size: u64, context: &str) -> Result<String> {
    let bytes = checked_range(bytes, offset, size, context)?;
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

fn read_u8(bytes: &[u8], offset: u64, context: &str) -> Result<u8> {
    Ok(checked_range(bytes, offset, 1, context)?[0])
}

fn read_u16(bytes: &[u8], offset: u64, endian: Endian, context: &str) -> Result<u16> {
    let bytes = checked_range(bytes, offset, 2, context)?;
    let array = <[u8; 2]>::try_from(bytes)
        .map_err(|_| malformed(format!("{context} has invalid width")))?;
    Ok(match endian {
        Endian::Little => u16::from_le_bytes(array),
        Endian::Big => u16::from_be_bytes(array),
        Endian::Unknown => return Err(malformed(format!("{context} has unknown endian"))),
    })
}

fn read_u32(bytes: &[u8], offset: u64, endian: Endian, context: &str) -> Result<u32> {
    let bytes = checked_range(bytes, offset, 4, context)?;
    let array = <[u8; 4]>::try_from(bytes)
        .map_err(|_| malformed(format!("{context} has invalid width")))?;
    Ok(match endian {
        Endian::Little => u32::from_le_bytes(array),
        Endian::Big => u32::from_be_bytes(array),
        Endian::Unknown => return Err(malformed(format!("{context} has unknown endian"))),
    })
}

fn read_u64(bytes: &[u8], offset: u64, endian: Endian, context: &str) -> Result<u64> {
    let bytes = checked_range(bytes, offset, 8, context)?;
    let array = <[u8; 8]>::try_from(bytes)
        .map_err(|_| malformed(format!("{context} has invalid width")))?;
    Ok(match endian {
        Endian::Little => u64::from_le_bytes(array),
        Endian::Big => u64::from_be_bytes(array),
        Endian::Unknown => return Err(malformed(format!("{context} has unknown endian"))),
    })
}

fn elf_machine_to_arch(machine: u16) -> ArchitectureId {
    match machine {
        EM_386 => ArchitectureId::X86,
        EM_ARM => ArchitectureId::Arm,
        EM_X86_64 => ArchitectureId::X86_64,
        EM_AARCH64 => ArchitectureId::Aarch64,
        _ => ArchitectureId::Unknown,
    }
}

fn pe_machine_to_arch(machine: u16) -> ArchitectureId {
    match machine {
        IMAGE_FILE_MACHINE_I386 => ArchitectureId::X86,
        IMAGE_FILE_MACHINE_ARMNT => ArchitectureId::Arm,
        IMAGE_FILE_MACHINE_AMD64 => ArchitectureId::X86_64,
        IMAGE_FILE_MACHINE_ARM64 => ArchitectureId::Aarch64,
        _ => ArchitectureId::Unknown,
    }
}

fn mach_o_cpu_type_to_arch(cpu_type: u32) -> ArchitectureId {
    match cpu_type {
        CPU_TYPE_X86 => ArchitectureId::X86,
        CPU_TYPE_ARM => ArchitectureId::Arm,
        CPU_TYPE_X86_64 => ArchitectureId::X86_64,
        CPU_TYPE_ARM64 => ArchitectureId::Aarch64,
        _ => ArchitectureId::Unknown,
    }
}

fn segment_permissions(flags: u32) -> Permissions {
    Permissions::new(flags & PF_R != 0, flags & PF_W != 0, flags & PF_X != 0)
}

fn section_permissions(flags: u64) -> Permissions {
    Permissions::new(
        flags & SHF_ALLOC != 0,
        flags & SHF_WRITE != 0,
        flags & SHF_EXECINSTR != 0,
    )
}

fn pe_section_permissions(characteristics: u32) -> Permissions {
    Permissions::new(
        characteristics & IMAGE_SCN_MEM_READ != 0,
        characteristics & IMAGE_SCN_MEM_WRITE != 0,
        characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
    )
}

fn mach_o_permissions(initprot: u32) -> Permissions {
    Permissions::new(
        initprot & VM_PROT_READ != 0,
        initprot & VM_PROT_WRITE != 0,
        initprot & VM_PROT_EXECUTE != 0,
    )
}

fn fallback_name(name: String, fallback: &str) -> String {
    if name.is_empty() {
        fallback.to_string()
    } else {
        name
    }
}

fn nonzero_file_offset(file_size: u64, file_offset: u64) -> Option<u64> {
    if file_size == 0 {
        None
    } else {
        Some(file_offset)
    }
}

fn section_file_offset(bytes: &[u8], offset: u64, size: u64, flags: u32) -> Result<Option<u64>> {
    if size == 0 || flags & SECTION_TYPE_MASK == S_ZEROFILL {
        return Ok(None);
    }

    checked_range(bytes, offset, size, "Mach-O section data")?;
    Ok(Some(offset))
}

fn malformed(message: impl Into<String>) -> KaijuError {
    KaijuError::new(KaijuErrorKind::MalformedBinary, message)
}

fn looks_like_pe(bytes: &[u8]) -> bool {
    if !bytes.starts_with(b"MZ") {
        return false;
    }

    let Some(pointer_bytes) = bytes.get(0x3c..0x40) else {
        return false;
    };
    let Ok(pointer_bytes) = <[u8; 4]>::try_from(pointer_bytes) else {
        return false;
    };
    let pe_offset = u32::from_le_bytes(pointer_bytes) as usize;
    let Some(pe_end) = pe_offset.checked_add(4) else {
        return false;
    };

    bytes.get(pe_offset..pe_end) == Some(b"PE\0\0")
}

fn looks_like_mach_o(bytes: &[u8]) -> bool {
    mach_o_magic(bytes).is_some()
}

fn mach_o_magic(bytes: &[u8]) -> Option<MachOMagic> {
    match bytes.get(0..4) {
        Some([0xfe, 0xed, 0xfa, 0xce]) => Some(MachOMagic::Thin {
            endian: Endian::Big,
            is_64: false,
        }),
        Some([0xce, 0xfa, 0xed, 0xfe]) => Some(MachOMagic::Thin {
            endian: Endian::Little,
            is_64: false,
        }),
        Some([0xfe, 0xed, 0xfa, 0xcf]) => Some(MachOMagic::Thin {
            endian: Endian::Big,
            is_64: true,
        }),
        Some([0xcf, 0xfa, 0xed, 0xfe]) => Some(MachOMagic::Thin {
            endian: Endian::Little,
            is_64: true,
        }),
        Some([0xca, 0xfe, 0xba, 0xbe]) => Some(MachOMagic::Fat {
            endian: Endian::Big,
            is_64: false,
        }),
        Some([0xbe, 0xba, 0xfe, 0xca]) => Some(MachOMagic::Fat {
            endian: Endian::Little,
            is_64: false,
        }),
        Some([0xca, 0xfe, 0xba, 0xbf]) => Some(MachOMagic::Fat {
            endian: Endian::Big,
            is_64: true,
        }),
        Some([0xbf, 0xba, 0xfe, 0xca]) => Some(MachOMagic::Fat {
            endian: Endian::Little,
            is_64: true,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_elf_magic() {
        assert_eq!(detect_format(b"\x7fELF\x02\x01\x01"), BinaryFormat::Elf);
    }

    #[test]
    fn detects_pe_magic() {
        let mut bytes = vec![0_u8; 0x80];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        bytes[0x3c..0x40].copy_from_slice(&0x40_u32.to_le_bytes());
        bytes[0x40..0x44].copy_from_slice(b"PE\0\0");

        assert_eq!(detect_format(&bytes), BinaryFormat::Pe);
    }

    #[test]
    fn loads_pe32_plus_metadata_sections_and_maps() {
        let bytes = synthetic_pe32_plus();
        let binary = load_bytes(PathBuf::from("sample.exe"), &bytes).expect("load PE");

        assert_eq!(binary.format, BinaryFormat::Pe);
        assert_eq!(binary.arch, ArchitectureId::X86_64);
        assert_eq!(binary.endian, Endian::Little);
        assert_eq!(binary.entrypoint, Some(Address::new(0x140001000)));
        assert_eq!(binary.sections.len(), 2);
        assert_eq!(binary.sections[0].name, ".text");
        assert_eq!(binary.sections[0].address, Address::new(0x140001000));
        assert!(binary.sections[0].permissions.execute);
        assert!(binary.imports.is_empty());
        assert!(binary.exports.is_empty());
        assert!(binary.relocations.is_empty());
        assert_eq!(binary.memory_map.regions().len(), 2);

        let text = &binary.memory_map.regions()[0];
        assert_eq!(text.name, ".text");
        assert_eq!(text.address, Address::new(0x140001000));
        assert_eq!(text.file_offset, Some(0x200));
        assert_eq!(text.size, 0x200);
        assert!(text.permissions.read);
        assert!(text.permissions.execute);
        assert!(!text.permissions.write);
        assert_eq!(
            binary
                .memory_map
                .read_range(Address::new(0x140001000), 4)
                .expect("read text"),
            vec![0x90, 0x90, 0xc3, 0x00]
        );
        assert_eq!(
            binary
                .memory_map
                .translate_virtual_to_file_offset(Address::new(0x140001003)),
            Some(0x203)
        );
    }

    #[test]
    fn loads_pe32_plus_coff_symbols() {
        let bytes = synthetic_pe32_plus_with_coff_symbols();
        let binary = load_bytes(PathBuf::from("sample.exe"), &bytes).expect("load PE");

        assert_eq!(binary.format, BinaryFormat::Pe);
        assert_eq!(binary.symbols.len(), 2);
        assert_eq!(binary.symbols[0].name, "_start");
        assert_eq!(binary.symbols[0].address, Some(Address::new(0x140001000)));
        assert_eq!(binary.symbols[1].name, "helper_long_name");
        assert_eq!(binary.symbols[1].address, Some(Address::new(0x140001004)));
        assert!(binary.diagnostics.iter().any(|diagnostic| {
            diagnostic.severity == DiagnosticSeverity::Note
                && diagnostic.message.contains("debug symbols")
        }));
    }

    #[test]
    fn loads_pe32_plus_imports_by_name_and_ordinal() {
        let bytes = synthetic_pe32_plus_with_imports();
        let binary = load_bytes(PathBuf::from("sample.exe"), &bytes).expect("load PE");

        assert_eq!(binary.format, BinaryFormat::Pe);
        assert_eq!(binary.dependencies.len(), 1);
        assert_eq!(binary.dependencies[0].name, "KERNEL32.dll");
        assert_eq!(binary.imports.len(), 2);
        assert_eq!(binary.imports[0].library, "KERNEL32.dll");
        assert_eq!(binary.imports[0].name.as_deref(), Some("ExitProcess"));
        assert_eq!(binary.imports[0].ordinal, None);
        assert_eq!(binary.imports[0].thunk, Some(Address::new(0x1400020a0)));
        assert_eq!(binary.imports[1].library, "KERNEL32.dll");
        assert_eq!(binary.imports[1].name, None);
        assert_eq!(binary.imports[1].ordinal, Some(7));
        assert_eq!(binary.imports[1].thunk, Some(Address::new(0x1400020a8)));
        assert!(binary.diagnostics.iter().any(|diagnostic| {
            diagnostic.severity == DiagnosticSeverity::Note
                && diagnostic.message.contains("debug symbols")
        }));
    }

    #[test]
    fn loads_pe32_plus_exports_by_name_ordinal_and_forwarder() {
        let bytes = synthetic_pe32_plus_with_exports();
        let binary = load_bytes(PathBuf::from("sample.dll"), &bytes).expect("load PE");

        assert_eq!(binary.format, BinaryFormat::Pe);
        assert_eq!(binary.exports.len(), 3);
        assert_eq!(binary.exports[0].module.as_deref(), Some("sample.dll"));
        assert_eq!(binary.exports[0].name.as_deref(), Some("ExportedFunc"));
        assert_eq!(binary.exports[0].ordinal, 1);
        assert_eq!(binary.exports[0].address, Some(Address::new(0x140001000)));
        assert_eq!(binary.exports[0].forwarder, None);
        assert_eq!(binary.exports[1].name.as_deref(), Some("ForwardedFunc"));
        assert_eq!(binary.exports[1].ordinal, 2);
        assert_eq!(binary.exports[1].address, None);
        assert_eq!(
            binary.exports[1].forwarder.as_deref(),
            Some("OTHER.Forward")
        );
        assert_eq!(binary.exports[2].name, None);
        assert_eq!(binary.exports[2].ordinal, 3);
        assert_eq!(binary.exports[2].address, Some(Address::new(0x140001010)));
        assert_eq!(binary.exports[2].forwarder, None);
    }

    #[test]
    fn loads_pe32_plus_base_relocations() {
        let bytes = synthetic_pe32_plus_with_relocations();
        let binary = load_bytes(PathBuf::from("sample.exe"), &bytes).expect("load PE");

        assert_eq!(binary.format, BinaryFormat::Pe);
        assert_eq!(binary.relocations.len(), 3);
        assert_eq!(binary.relocations[0].address, Address::new(0x140001008));
        assert_eq!(binary.relocations[0].kind, "pe-dir64");
        assert_eq!(binary.relocations[1].address, Address::new(0x140001020));
        assert_eq!(binary.relocations[1].kind, "pe-highlow");
        assert_eq!(binary.relocations[2].address, Address::new(0x140001040));
        assert_eq!(binary.relocations[2].kind, "pe-high");
        assert!(binary.diagnostics.iter().any(|diagnostic| {
            diagnostic.severity == DiagnosticSeverity::Note
                && diagnostic.message.contains("debug symbols")
        }));
    }

    #[test]
    fn detects_mach_o_magic() {
        assert_eq!(
            detect_format(&[0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0]),
            BinaryFormat::MachO
        );
        assert_eq!(
            detect_format(&[0xca, 0xfe, 0xba, 0xbf, 0, 0, 0, 0]),
            BinaryFormat::MachO
        );
    }

    #[test]
    fn loads_mach_o64_segment_sections_and_entrypoint() {
        let bytes = synthetic_mach_o64_le();
        let binary = load_bytes(PathBuf::from("sample.macho"), &bytes).expect("load Mach-O");

        assert_eq!(binary.format, BinaryFormat::MachO);
        assert_eq!(binary.arch, ArchitectureId::X86_64);
        assert_eq!(binary.endian, Endian::Little);
        assert_eq!(binary.entrypoint, Some(Address::new(0x100000100)));
        assert_eq!(binary.sections.len(), 1);
        assert_eq!(binary.sections[0].name, "__text");
        assert_eq!(binary.sections[0].address, Address::new(0x100000100));
        assert_eq!(binary.sections[0].file_offset, Some(0x100));
        assert_eq!(binary.sections[0].size, 4);
        assert!(binary.sections[0].permissions.execute);
        assert_eq!(binary.memory_map.regions().len(), 1);
        let text = &binary.memory_map.regions()[0];
        assert_eq!(text.name, "__TEXT");
        assert_eq!(text.address, Address::new(0x100000000));
        assert_eq!(text.file_offset, Some(0));
        assert_eq!(text.size, 0x1000);
        assert!(text.permissions.read);
        assert!(text.permissions.execute);
        assert!(!text.permissions.write);
        assert_eq!(
            binary
                .memory_map
                .read_range(Address::new(0x100000100), 4)
                .expect("read text"),
            vec![0x55, 0x48, 0x89, 0xe5]
        );
        assert_eq!(
            binary
                .memory_map
                .translate_virtual_to_file_offset(Address::new(0x100000103)),
            Some(0x103)
        );
        assert!(binary.symbols.is_empty());
        assert!(binary.dependencies.is_empty());
        assert!(binary.imports.is_empty());
        assert!(binary.diagnostics.iter().any(|diagnostic| {
            diagnostic.severity == DiagnosticSeverity::Note
                && diagnostic.message.contains("limited load-command parsing")
        }));
    }

    #[test]
    fn loads_mach_o64_symbols_and_imports() {
        let bytes = synthetic_mach_o64_le_with_symbols();
        let binary = load_bytes(PathBuf::from("sample.macho"), &bytes).expect("load Mach-O");

        assert_eq!(binary.format, BinaryFormat::MachO);
        assert_eq!(binary.symbols.len(), 2);
        assert_eq!(binary.symbols[0].name, "_main");
        assert_eq!(binary.symbols[0].address, Some(Address::new(0x100000100)));
        assert_eq!(binary.symbols[1].name, "_puts");
        assert_eq!(binary.symbols[1].address, None);
        assert_eq!(binary.imports.len(), 1);
        assert_eq!(binary.imports[0].library, "Mach-O");
        assert_eq!(binary.imports[0].name.as_deref(), Some("_puts"));
        assert_eq!(binary.imports[0].ordinal, None);
        assert_eq!(binary.imports[0].thunk, None);
    }

    #[test]
    fn loads_mach_o64_dylib_dependencies() {
        let bytes = synthetic_mach_o64_le_with_dylib();
        let binary = load_bytes(PathBuf::from("sample.macho"), &bytes).expect("load Mach-O");

        assert_eq!(binary.format, BinaryFormat::MachO);
        assert_eq!(binary.dependencies.len(), 1);
        assert_eq!(binary.dependencies[0].name, "libSystem.B.dylib");
    }

    #[test]
    fn loads_mach_o64_section_relocations() {
        let bytes = synthetic_mach_o64_le_with_relocations();
        let binary = load_bytes(PathBuf::from("sample.macho"), &bytes).expect("load Mach-O");

        assert_eq!(binary.format, BinaryFormat::MachO);
        assert_eq!(binary.relocations.len(), 2);
        assert_eq!(binary.relocations[0].address, Address::new(0x100000108));
        assert_eq!(
            binary.relocations[0].kind,
            "macho-x86_64-branch-pcrel-external-len4"
        );
        assert_eq!(binary.relocations[1].address, Address::new(0x100000110));
        assert_eq!(
            binary.relocations[1].kind,
            "macho-x86_64-unsigned-absolute-local-len8"
        );
    }

    #[test]
    fn loads_mach_o_universal_thin_member() {
        let bytes = synthetic_mach_o_universal_with_thin_member();
        let binary = load_bytes(PathBuf::from("universal.macho"), &bytes).expect("load Mach-O");

        assert_eq!(binary.format, BinaryFormat::MachO);
        assert_eq!(binary.arch, ArchitectureId::X86_64);
        assert_eq!(binary.endian, Endian::Little);
        assert_eq!(binary.entrypoint, Some(Address::new(0x100000100)));
        assert_eq!(binary.file_size, synthetic_mach_o64_le().len() as u64);
        assert_eq!(binary.memory_map.regions().len(), 1);
        assert!(binary.diagnostics.iter().any(|diagnostic| {
            diagnostic.severity == DiagnosticSeverity::Note
                && diagnostic
                    .message
                    .contains("universal binary selected x86_64 member")
        }));
    }

    #[test]
    fn loads_mach_o_universal64_thin_member() {
        let bytes = synthetic_mach_o_universal64_with_thin_member();
        let binary = load_bytes(PathBuf::from("universal.macho"), &bytes).expect("load Mach-O");

        assert_eq!(binary.format, BinaryFormat::MachO);
        assert_eq!(binary.arch, ArchitectureId::X86_64);
        assert_eq!(binary.entrypoint, Some(Address::new(0x100000100)));
        assert!(binary.diagnostics.iter().any(|diagnostic| {
            diagnostic.severity == DiagnosticSeverity::Note
                && diagnostic
                    .message
                    .contains("universal binary selected x86_64 member")
        }));
    }

    #[test]
    fn mach_o_fat_without_members_loads_as_raw_diagnostic() {
        let bytes = [0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0];
        let binary = load_bytes(PathBuf::from("fat.macho"), &bytes).expect("load Mach-O");

        assert_eq!(binary.format, BinaryFormat::MachO);
        assert_eq!(binary.arch, ArchitectureId::Unknown);
        assert_eq!(binary.endian, Endian::Big);
        assert_eq!(binary.memory_map.regions().len(), 1);
        assert!(binary.diagnostics.iter().any(|diagnostic| {
            diagnostic.severity == DiagnosticSeverity::Warning
                && diagnostic
                    .message
                    .contains("contained no supported thin member")
        }));
    }

    #[test]
    fn detects_unknown_file() {
        assert_eq!(detect_format(b"not an executable"), BinaryFormat::Unknown);
    }

    #[test]
    fn unknown_file_loads_as_raw() {
        let binary = load_bytes(PathBuf::from("sample.bin"), b"hello").expect("load");

        assert_eq!(binary.format, BinaryFormat::Raw);
        assert_eq!(binary.memory_map.regions().len(), 1);
        assert!(binary.diagnostics.iter().any(|diagnostic| {
            diagnostic.severity == DiagnosticSeverity::Note
                && diagnostic.message.contains("raw bytes")
        }));
        assert_eq!(
            binary
                .memory_map
                .read_range(Address::ZERO, 5)
                .expect("read"),
            b"hello"
        );
    }

    #[test]
    fn loads_elf64_metadata_sections_and_load_segment() {
        let bytes = synthetic_elf64_le();
        let binary = load_bytes(PathBuf::from("sample.elf"), &bytes).expect("load ELF");

        assert_eq!(binary.format, BinaryFormat::Elf);
        assert_eq!(binary.arch, ArchitectureId::X86_64);
        assert_eq!(binary.endian, Endian::Little);
        assert_eq!(binary.entrypoint, Some(Address::new(0x401000)));
        assert_eq!(binary.sections.len(), 5);
        assert_eq!(binary.sections[1].name, ".text");
        assert!(binary.sections[1].permissions.execute);
        assert_eq!(binary.symbols.len(), 2);
        assert_eq!(binary.symbols[0].name, "_start");
        assert_eq!(binary.symbols[0].address, Some(Address::new(0x401000)));
        assert_eq!(binary.symbols[1].name, "helper");
        assert_eq!(binary.symbols[1].address, Some(Address::new(0x401004)));
        assert_eq!(binary.memory_map.regions().len(), 1);

        let region = &binary.memory_map.regions()[0];
        assert_eq!(region.name, "LOAD0");
        assert_eq!(region.address, Address::new(0x401000));
        assert_eq!(region.size, 8);
        assert_eq!(region.file_offset, Some(0x300));
        assert!(region.permissions.read);
        assert!(region.permissions.execute);
        assert!(!region.permissions.write);
        assert_eq!(
            binary
                .memory_map
                .read_range(Address::new(0x401000), 8)
                .expect("read segment"),
            vec![0x90, 0x90, 0xc3, 0x00, 0, 0, 0, 0]
        );
        assert_eq!(
            binary
                .memory_map
                .translate_virtual_to_file_offset(Address::new(0x401003)),
            Some(0x303)
        );
        assert_eq!(
            binary
                .memory_map
                .translate_virtual_to_file_offset(Address::new(0x401004)),
            None
        );
    }

    #[test]
    fn loads_elf64_imports_and_relocations() {
        let bytes = synthetic_elf64_le_with_imports_and_relocations();
        let binary = load_bytes(PathBuf::from("sample.elf"), &bytes).expect("load ELF");

        assert_eq!(binary.format, BinaryFormat::Elf);
        assert!(binary
            .symbols
            .iter()
            .any(|symbol| symbol.name == "puts" && symbol.address.is_none()));
        assert!(binary.symbols.iter().any(|symbol| {
            symbol.name == "printf" && symbol.address == Some(Address::new(0x401000))
        }));
        assert_eq!(binary.dependencies.len(), 1);
        assert_eq!(binary.dependencies[0].name, "libc.so.6");
        assert_eq!(binary.imports.len(), 1);
        assert_eq!(binary.imports[0].library, "ELF");
        assert_eq!(binary.imports[0].name.as_deref(), Some("puts"));
        assert_eq!(binary.imports[0].ordinal, None);
        assert_eq!(binary.imports[0].thunk, Some(Address::new(0x402000)));
        assert_eq!(binary.relocations.len(), 2);
        assert_eq!(binary.relocations[0].address, Address::new(0x402000));
        assert_eq!(binary.relocations[0].kind, "elf-x86_64-jump-slot");
        assert_eq!(binary.relocations[1].address, Address::new(0x402008));
        assert_eq!(binary.relocations[1].kind, "elf-x86_64-relative");
    }

    #[test]
    fn truncated_elf_returns_clean_error() {
        let error = load_bytes(PathBuf::from("bad.elf"), b"\x7fELF")
            .expect_err("truncated ELF should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn truncated_mach_o_returns_clean_error() {
        let error = load_bytes(PathBuf::from("bad.macho"), &[0xcf, 0xfa, 0xed, 0xfe])
            .expect_err("truncated Mach-O should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn mach_o_fat_arch_table_truncated_returns_clean_error() {
        let mut bytes = vec![0_u8; 16];
        bytes[0..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
        write_u32_be(&mut bytes, 4, 1);

        let error =
            load_bytes(PathBuf::from("bad.macho"), &bytes).expect_err("bad Mach-O should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn mach_o_fat_member_outside_file_returns_clean_error() {
        let mut bytes = vec![0_u8; 0x40];
        bytes[0..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
        write_u32_be(&mut bytes, 4, 1);
        write_u32_be(&mut bytes, 8, CPU_TYPE_X86_64);
        write_u32_be(&mut bytes, 16, 0x1000);
        write_u32_be(&mut bytes, 20, 0x20);

        let error =
            load_bytes(PathBuf::from("bad.macho"), &bytes).expect_err("bad Mach-O should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn mach_o_fat_zero_sized_member_returns_clean_error() {
        let mut bytes = vec![0_u8; 0x40];
        bytes[0..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
        write_u32_be(&mut bytes, 4, 1);
        write_u32_be(&mut bytes, 8, CPU_TYPE_X86_64);
        write_u32_be(&mut bytes, 16, 0x20);
        write_u32_be(&mut bytes, 20, 0);

        let error =
            load_bytes(PathBuf::from("bad.macho"), &bytes).expect_err("bad Mach-O should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn mach_o_tiny_load_command_returns_clean_error() {
        let mut bytes = synthetic_mach_o64_le();
        write_u32_le(&mut bytes, MACHO64_HEADER_SIZE as usize + 4, 4);

        let error =
            load_bytes(PathBuf::from("bad.macho"), &bytes).expect_err("bad Mach-O should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn mach_o_tiny_symtab_command_returns_clean_error() {
        let mut bytes = synthetic_mach_o64_le_with_symbols();
        let symtab = mach_o64_symtab_command_offset();
        write_u32_le(&mut bytes, symtab + 4, 16);

        let error =
            load_bytes(PathBuf::from("bad.macho"), &bytes).expect_err("bad Mach-O should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn mach_o_tiny_dylib_command_returns_clean_error() {
        let mut bytes = synthetic_mach_o64_le_with_dylib();
        let dylib = mach_o64_dylib_command_offset();
        write_u32_le(&mut bytes, dylib + 4, 16);

        let error =
            load_bytes(PathBuf::from("bad.macho"), &bytes).expect_err("bad Mach-O should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn mach_o_dylib_name_outside_command_returns_clean_error() {
        let mut bytes = synthetic_mach_o64_le_with_dylib();
        let dylib = mach_o64_dylib_command_offset();
        write_u32_le(&mut bytes, dylib + 8, 0x80);

        let error =
            load_bytes(PathBuf::from("bad.macho"), &bytes).expect_err("bad Mach-O should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn mach_o_symbol_table_outside_file_returns_clean_error() {
        let mut bytes = synthetic_mach_o64_le_with_symbols();
        let symtab = mach_o64_symtab_command_offset();
        write_u32_le(&mut bytes, symtab + 8, 0x1000);

        let error =
            load_bytes(PathBuf::from("bad.macho"), &bytes).expect_err("bad Mach-O should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn mach_o_symbol_name_outside_string_table_returns_clean_error() {
        let mut bytes = synthetic_mach_o64_le_with_symbols();
        write_u32_le(&mut bytes, 0x250, 0x400);

        let error =
            load_bytes(PathBuf::from("bad.macho"), &bytes).expect_err("bad Mach-O should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn mach_o_segment_outside_file_returns_clean_error() {
        let mut bytes = synthetic_mach_o64_le();
        write_u64_le(&mut bytes, MACHO64_HEADER_SIZE as usize + 48, 0x400);

        let error =
            load_bytes(PathBuf::from("bad.macho"), &bytes).expect_err("bad Mach-O should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn mach_o_relocation_table_outside_file_returns_clean_error() {
        let mut bytes = synthetic_mach_o64_le_with_relocations();
        let section = mach_o64_text_section_offset();
        write_u32_le(&mut bytes, section + 56, 0x1000);

        let error =
            load_bytes(PathBuf::from("bad.macho"), &bytes).expect_err("bad Mach-O should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn mach_o_relocation_address_outside_section_returns_clean_error() {
        let mut bytes = synthetic_mach_o64_le_with_relocations();
        write_u32_le(&mut bytes, 0x240, 0x80);

        let error =
            load_bytes(PathBuf::from("bad.macho"), &bytes).expect_err("bad Mach-O should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn elf_segment_outside_file_returns_clean_error() {
        let mut bytes = synthetic_elf64_le();
        write_u64_le(&mut bytes, 0x40 + 32, 0x1000);

        let error =
            load_bytes(PathBuf::from("bad.elf"), &bytes).expect_err("bad segment should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn elf_symbol_table_bad_link_returns_clean_error() {
        let mut bytes = synthetic_elf64_le();
        write_u32_le(&mut bytes, 0x100 + 256 + 40, 99);

        let error =
            load_bytes(PathBuf::from("bad.elf"), &bytes).expect_err("bad symbols should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn elf_symbol_name_outside_string_table_returns_clean_error() {
        let mut bytes = synthetic_elf64_le();
        write_u32_le(&mut bytes, 0x380 + 24, 0xffff);

        let error =
            load_bytes(PathBuf::from("bad.elf"), &bytes).expect_err("bad symbols should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn elf_relocation_table_bad_link_returns_clean_error() {
        let mut bytes = synthetic_elf64_le_with_imports_and_relocations();
        write_u32_le(&mut bytes, 0x100 + (5 * 64) + 40, 99);

        let error =
            load_bytes(PathBuf::from("bad.elf"), &bytes).expect_err("bad relocation should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn elf_relocation_table_bad_entry_size_returns_clean_error() {
        let mut bytes = synthetic_elf64_le_with_imports_and_relocations();
        write_u64_le(&mut bytes, 0x100 + (5 * 64) + 56, 16);

        let error =
            load_bytes(PathBuf::from("bad.elf"), &bytes).expect_err("bad relocation should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn elf_relocation_symbol_index_out_of_range_returns_clean_error() {
        let mut bytes = synthetic_elf64_le_with_imports_and_relocations();
        write_u64_le(&mut bytes, 0x420 + 8, (9_u64 << 32) | 7);

        let error =
            load_bytes(PathBuf::from("bad.elf"), &bytes).expect_err("bad relocation should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn elf_dynamic_table_bad_link_returns_clean_error() {
        let mut bytes = synthetic_elf64_le_with_imports_and_relocations();
        write_u32_le(&mut bytes, 0x100 + (6 * 64) + 40, 99);

        let error =
            load_bytes(PathBuf::from("bad.elf"), &bytes).expect_err("bad dynamic should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn elf_dynamic_table_bad_entry_size_returns_clean_error() {
        let mut bytes = synthetic_elf64_le_with_imports_and_relocations();
        write_u64_le(&mut bytes, 0x100 + (6 * 64) + 56, 8);

        let error =
            load_bytes(PathBuf::from("bad.elf"), &bytes).expect_err("bad dynamic should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn elf_needed_name_outside_string_table_returns_clean_error() {
        let mut bytes = synthetic_elf64_le_with_imports_and_relocations();
        write_u64_le(&mut bytes, 0x480 + 8, 0x400);

        let error =
            load_bytes(PathBuf::from("bad.elf"), &bytes).expect_err("bad dynamic should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn pe_section_outside_file_returns_clean_error() {
        let mut bytes = synthetic_pe32_plus();
        write_u32_le(&mut bytes, 0x188 + 16, 0x4000);

        let error = load_bytes(PathBuf::from("bad.exe"), &bytes).expect_err("bad PE should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn pe_coff_symbol_table_outside_file_returns_clean_error() {
        let mut bytes = synthetic_pe32_plus_with_coff_symbols();
        write_u32_le(&mut bytes, 0x104 + 8, 0x900);

        let error = load_bytes(PathBuf::from("bad.exe"), &bytes).expect_err("bad PE should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn pe_coff_symbol_long_name_outside_string_table_returns_clean_error() {
        let mut bytes = synthetic_pe32_plus_with_coff_symbols();
        write_u32_le(&mut bytes, 0x612 + 4, 0x500);

        let error = load_bytes(PathBuf::from("bad.exe"), &bytes).expect_err("bad PE should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn pe_coff_symbol_section_index_out_of_range_returns_clean_error() {
        let mut bytes = synthetic_pe32_plus_with_coff_symbols();
        write_u16_le(&mut bytes, 0x600 + 12, 9);

        let error = load_bytes(PathBuf::from("bad.exe"), &bytes).expect_err("bad PE should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn pe_coff_symbol_aux_entries_overrun_returns_clean_error() {
        let mut bytes = synthetic_pe32_plus_with_coff_symbols();
        bytes[0x600 + 17] = 9;

        let error = load_bytes(PathBuf::from("bad.exe"), &bytes).expect_err("bad PE should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn pe_import_directory_outside_file_returns_clean_error() {
        let mut bytes = synthetic_pe32_plus_with_imports();
        let import_directory = pe32_plus_import_directory_offset();
        write_u32_le(&mut bytes, import_directory, 0x5000);

        let error = load_bytes(PathBuf::from("bad.exe"), &bytes).expect_err("bad PE should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn pe_import_descriptor_missing_terminator_returns_clean_error() {
        let mut bytes = synthetic_pe32_plus_with_imports();
        let import_directory_size = pe32_plus_import_directory_offset() + 4;
        write_u32_le(
            &mut bytes,
            import_directory_size,
            PE_IMPORT_DESCRIPTOR_SIZE as u32,
        );

        let error = load_bytes(PathBuf::from("bad.exe"), &bytes).expect_err("bad PE should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn pe_import_name_outside_file_returns_clean_error() {
        let mut bytes = synthetic_pe32_plus_with_imports();
        write_u64_le(&mut bytes, 0x480, 0x5000);

        let error = load_bytes(PathBuf::from("bad.exe"), &bytes).expect_err("bad PE should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn pe_export_directory_outside_file_returns_clean_error() {
        let mut bytes = synthetic_pe32_plus_with_exports();
        let export_directory = pe32_plus_export_directory_offset();
        write_u32_le(&mut bytes, export_directory, 0x5000);

        let error = load_bytes(PathBuf::from("bad.dll"), &bytes).expect_err("bad PE should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn pe_export_name_outside_file_returns_clean_error() {
        let mut bytes = synthetic_pe32_plus_with_exports();
        write_u32_le(&mut bytes, 0x490, 0x5000);

        let error = load_bytes(PathBuf::from("bad.dll"), &bytes).expect_err("bad PE should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn pe_export_ordinal_index_out_of_range_returns_clean_error() {
        let mut bytes = synthetic_pe32_plus_with_exports();
        write_u16_le(&mut bytes, 0x4a0, 9);

        let error = load_bytes(PathBuf::from("bad.dll"), &bytes).expect_err("bad PE should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn pe_base_relocation_directory_outside_file_returns_clean_error() {
        let mut bytes = synthetic_pe32_plus_with_relocations();
        let relocation_directory = pe32_plus_base_relocation_directory_offset();
        write_u32_le(&mut bytes, relocation_directory, 0x5000);

        let error = load_bytes(PathBuf::from("bad.exe"), &bytes).expect_err("bad PE should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn pe_base_relocation_block_too_small_returns_clean_error() {
        let mut bytes = synthetic_pe32_plus_with_relocations();
        write_u32_le(&mut bytes, 0x500 + 4, 6);

        let error = load_bytes(PathBuf::from("bad.exe"), &bytes).expect_err("bad PE should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn pe_base_relocation_entries_misaligned_returns_clean_error() {
        let mut bytes = synthetic_pe32_plus_with_relocations();
        write_u32_le(&mut bytes, 0x500 + 4, 15);

        let error = load_bytes(PathBuf::from("bad.exe"), &bytes).expect_err("bad PE should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    #[test]
    fn pe_base_relocation_block_overrun_returns_clean_error() {
        let mut bytes = synthetic_pe32_plus_with_relocations();
        write_u32_le(&mut bytes, 0x500 + 4, 0x20);

        let error = load_bytes(PathBuf::from("bad.exe"), &bytes).expect_err("bad PE should fail");

        assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary);
    }

    fn synthetic_pe32_plus() -> Vec<u8> {
        let mut bytes = vec![0_u8; 0x800];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        write_u32_le(&mut bytes, 0x3c, 0x100);
        bytes[0x100..0x104].copy_from_slice(PE_SIGNATURE);

        let coff = 0x104;
        write_u16_le(&mut bytes, coff, IMAGE_FILE_MACHINE_AMD64);
        write_u16_le(&mut bytes, coff + 2, 2);
        write_u16_le(&mut bytes, coff + 16, 0x70);

        let optional = coff + 20;
        write_u16_le(&mut bytes, optional, PE32_PLUS_MAGIC);
        write_u32_le(&mut bytes, optional + 16, 0x1000);
        write_u64_le(&mut bytes, optional + 24, 0x140000000);

        write_pe_section(
            &mut bytes,
            0x188,
            PeSectionSpec {
                name: b".text\0\0\0",
                virtual_size: 0x100,
                virtual_address: 0x1000,
                raw_size: 0x200,
                raw_offset: 0x200,
                characteristics: IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
            },
        );
        write_pe_section(
            &mut bytes,
            0x1b0,
            PeSectionSpec {
                name: b".data\0\0\0",
                virtual_size: 0x80,
                virtual_address: 0x2000,
                raw_size: 0x200,
                raw_offset: 0x400,
                characteristics: IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
            },
        );

        bytes[0x200..0x204].copy_from_slice(&[0x90, 0x90, 0xc3, 0x00]);
        bytes[0x400..0x404].copy_from_slice(&[1, 2, 3, 4]);

        bytes
    }

    fn synthetic_pe32_plus_with_coff_symbols() -> Vec<u8> {
        let mut bytes = synthetic_pe32_plus();
        let coff = 0x104;
        write_u32_le(&mut bytes, coff + 8, 0x600);
        write_u32_le(&mut bytes, coff + 12, 3);

        write_pe_coff_short_symbol(&mut bytes, 0x600, b"_start\0\0", 0, 1, 0);
        write_pe_coff_long_symbol(&mut bytes, 0x612, 4, 4, 1, 1);
        write_u32_le(&mut bytes, 0x636, 21);
        bytes[0x63a..0x64b].copy_from_slice(b"helper_long_name\0");

        bytes
    }

    fn synthetic_pe32_plus_with_imports() -> Vec<u8> {
        let mut bytes = vec![0_u8; 0x800];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        write_u32_le(&mut bytes, 0x3c, 0x100);
        bytes[0x100..0x104].copy_from_slice(PE_SIGNATURE);

        let coff = 0x104;
        write_u16_le(&mut bytes, coff, IMAGE_FILE_MACHINE_AMD64);
        write_u16_le(&mut bytes, coff + 2, 2);
        write_u16_le(&mut bytes, coff + 16, 0xf0);

        let optional = coff + 20;
        write_u16_le(&mut bytes, optional, PE32_PLUS_MAGIC);
        write_u32_le(&mut bytes, optional + 16, 0x1000);
        write_u64_le(&mut bytes, optional + 24, 0x140000000);
        write_u32_le(&mut bytes, optional + 108, 16);
        let import_directory = pe32_plus_import_directory_offset();
        write_u32_le(&mut bytes, import_directory, 0x2000);
        write_u32_le(&mut bytes, import_directory + 4, 0x40);

        write_pe_section(
            &mut bytes,
            0x208,
            PeSectionSpec {
                name: b".text\0\0\0",
                virtual_size: 0x100,
                virtual_address: 0x1000,
                raw_size: 0x100,
                raw_offset: 0x300,
                characteristics: IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
            },
        );
        write_pe_section(
            &mut bytes,
            0x230,
            PeSectionSpec {
                name: b".rdata\0\0",
                virtual_size: 0x200,
                virtual_address: 0x2000,
                raw_size: 0x200,
                raw_offset: 0x400,
                characteristics: IMAGE_SCN_MEM_READ,
            },
        );

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
        bytes[0x100..0x104].copy_from_slice(PE_SIGNATURE);

        let coff = 0x104;
        write_u16_le(&mut bytes, coff, IMAGE_FILE_MACHINE_AMD64);
        write_u16_le(&mut bytes, coff + 2, 2);
        write_u16_le(&mut bytes, coff + 16, 0xf0);

        let optional = coff + 20;
        write_u16_le(&mut bytes, optional, PE32_PLUS_MAGIC);
        write_u32_le(&mut bytes, optional + 16, 0x1000);
        write_u64_le(&mut bytes, optional + 24, 0x140000000);
        write_u32_le(&mut bytes, optional + 108, 16);
        let export_directory = pe32_plus_export_directory_offset();
        write_u32_le(&mut bytes, export_directory, 0x2000);
        write_u32_le(&mut bytes, export_directory + 4, 0x100);

        write_pe_section(
            &mut bytes,
            0x208,
            PeSectionSpec {
                name: b".text\0\0\0",
                virtual_size: 0x100,
                virtual_address: 0x1000,
                raw_size: 0x100,
                raw_offset: 0x300,
                characteristics: IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
            },
        );
        write_pe_section(
            &mut bytes,
            0x230,
            PeSectionSpec {
                name: b".rdata\0\0",
                virtual_size: 0x200,
                virtual_address: 0x2000,
                raw_size: 0x200,
                raw_offset: 0x400,
                characteristics: IMAGE_SCN_MEM_READ,
            },
        );

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
        bytes[0x100..0x104].copy_from_slice(PE_SIGNATURE);

        let coff = 0x104;
        write_u16_le(&mut bytes, coff, IMAGE_FILE_MACHINE_AMD64);
        write_u16_le(&mut bytes, coff + 2, 2);
        write_u16_le(&mut bytes, coff + 16, 0xf0);

        let optional = coff + 20;
        write_u16_le(&mut bytes, optional, PE32_PLUS_MAGIC);
        write_u32_le(&mut bytes, optional + 16, 0x1000);
        write_u64_le(&mut bytes, optional + 24, 0x140000000);
        write_u32_le(&mut bytes, optional + 108, 16);
        let relocation_directory = pe32_plus_base_relocation_directory_offset();
        write_u32_le(&mut bytes, relocation_directory, 0x3000);
        write_u32_le(&mut bytes, relocation_directory + 4, 0x10);

        write_pe_section(
            &mut bytes,
            0x208,
            PeSectionSpec {
                name: b".text\0\0\0",
                virtual_size: 0x100,
                virtual_address: 0x1000,
                raw_size: 0x200,
                raw_offset: 0x300,
                characteristics: IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
            },
        );
        write_pe_section(
            &mut bytes,
            0x230,
            PeSectionSpec {
                name: b".reloc\0\0",
                virtual_size: 0x100,
                virtual_address: 0x3000,
                raw_size: 0x200,
                raw_offset: 0x500,
                characteristics: IMAGE_SCN_MEM_READ,
            },
        );

        bytes[0x300..0x304].copy_from_slice(&[0x90, 0x90, 0xc3, 0x00]);
        write_u32_le(&mut bytes, 0x500, 0x1000);
        write_u32_le(&mut bytes, 0x504, 0x10);
        write_u16_le(&mut bytes, 0x508, (IMAGE_REL_BASED_DIR64 << 12) | 0x008);
        write_u16_le(&mut bytes, 0x50a, (IMAGE_REL_BASED_HIGHLOW << 12) | 0x020);
        write_u16_le(&mut bytes, 0x50c, (IMAGE_REL_BASED_HIGH << 12) | 0x040);
        write_u16_le(&mut bytes, 0x50e, IMAGE_REL_BASED_ABSOLUTE << 12);

        bytes
    }

    fn pe32_plus_export_directory_offset() -> usize {
        0x118
            + PE32_PLUS_DATA_DIRECTORY_OFFSET as usize
            + (PE_EXPORT_DIRECTORY_INDEX as usize * PE_DATA_DIRECTORY_SIZE as usize)
    }

    fn pe32_plus_base_relocation_directory_offset() -> usize {
        0x118
            + PE32_PLUS_DATA_DIRECTORY_OFFSET as usize
            + (PE_BASE_RELOCATION_DIRECTORY_INDEX as usize * PE_DATA_DIRECTORY_SIZE as usize)
    }

    fn pe32_plus_import_directory_offset() -> usize {
        0x118
            + PE32_PLUS_DATA_DIRECTORY_OFFSET as usize
            + (PE_IMPORT_DIRECTORY_INDEX as usize * PE_DATA_DIRECTORY_SIZE as usize)
    }

    fn synthetic_mach_o64_le() -> Vec<u8> {
        let segment_command_size = MACHO64_SEGMENT_COMMAND_SIZE + MACHO64_SECTION_SIZE;
        let command_size = segment_command_size + 24;
        let mut bytes = vec![0_u8; 0x240];
        bytes[0..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        write_u32_le(&mut bytes, 4, CPU_TYPE_X86_64);
        write_u32_le(&mut bytes, 8, 3);
        write_u32_le(&mut bytes, 12, 2);
        write_u32_le(&mut bytes, 16, 2);
        write_u32_le(&mut bytes, 20, command_size as u32);
        write_u32_le(&mut bytes, 24, 0);
        write_u32_le(&mut bytes, 28, 0);

        let segment = MACHO64_HEADER_SIZE as usize;
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

        let section = segment + MACHO64_SEGMENT_COMMAND_SIZE as usize;
        bytes[section..section + 16].copy_from_slice(b"__text\0\0\0\0\0\0\0\0\0\0");
        bytes[section + 16..section + 32].copy_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
        write_u64_le(&mut bytes, section + 32, 0x100000100);
        write_u64_le(&mut bytes, section + 40, 4);
        write_u32_le(&mut bytes, section + 48, 0x100);
        write_u32_le(&mut bytes, section + 52, 4);
        write_u32_le(&mut bytes, section + 56, 0);
        write_u32_le(&mut bytes, section + 60, 0);
        write_u32_le(&mut bytes, section + 64, 0);

        let entry = segment + segment_command_size as usize;
        write_u32_le(&mut bytes, entry, LC_MAIN);
        write_u32_le(&mut bytes, entry + 4, 24);
        write_u64_le(&mut bytes, entry + 8, 0x100);
        write_u64_le(&mut bytes, entry + 16, 0);

        bytes[0x100..0x104].copy_from_slice(&[0x55, 0x48, 0x89, 0xe5]);
        bytes
    }

    fn synthetic_mach_o64_le_with_symbols() -> Vec<u8> {
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

        write_mach_o64_symbol(&mut bytes, 0x240, 1, N_SECT | N_EXT, 1, 0, 0x100000100);
        write_mach_o64_symbol(&mut bytes, 0x250, 7, N_UNDF | N_EXT, 0, 0, 0);
        write_mach_o64_symbol(&mut bytes, 0x260, 13, N_STAB, 0, 0, 0);
        bytes[0x280..0x294].copy_from_slice(b"\0_main\0_puts\0_debug\0");

        bytes
    }

    fn synthetic_mach_o64_le_with_dylib() -> Vec<u8> {
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
        let mut bytes = synthetic_mach_o64_le();
        bytes.resize(0x280, 0);

        let section = mach_o64_text_section_offset();
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
        write_u32_be(&mut bytes, 8, CPU_TYPE_X86_64);
        write_u32_be(&mut bytes, 12, 3);
        write_u32_be(&mut bytes, 16, member_offset as u32);
        write_u32_be(&mut bytes, 20, thin.len() as u32);
        write_u32_be(&mut bytes, 24, 12);
        bytes[member_offset..member_offset + thin.len()].copy_from_slice(&thin);
        bytes
    }

    fn synthetic_mach_o_universal64_with_thin_member() -> Vec<u8> {
        let thin = synthetic_mach_o64_le();
        let member_offset = 0x100;
        let mut bytes = vec![0_u8; member_offset + thin.len()];
        bytes[0..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbf]);
        write_u32_be(&mut bytes, 4, 1);
        write_u32_be(&mut bytes, 8, CPU_TYPE_X86_64);
        write_u32_be(&mut bytes, 12, 3);
        write_u64_be(&mut bytes, 16, member_offset as u64);
        write_u64_be(&mut bytes, 24, thin.len() as u64);
        write_u32_be(&mut bytes, 32, 12);
        bytes[member_offset..member_offset + thin.len()].copy_from_slice(&thin);
        bytes
    }

    fn mach_o64_text_section_offset() -> usize {
        MACHO64_HEADER_SIZE as usize + MACHO64_SEGMENT_COMMAND_SIZE as usize
    }

    fn mach_o64_symtab_command_offset() -> usize {
        MACHO64_HEADER_SIZE as usize
            + (MACHO64_SEGMENT_COMMAND_SIZE + MACHO64_SECTION_SIZE) as usize
            + 24
    }

    fn mach_o64_dylib_command_offset() -> usize {
        MACHO64_HEADER_SIZE as usize
            + (MACHO64_SEGMENT_COMMAND_SIZE + MACHO64_SECTION_SIZE) as usize
            + 24
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

    fn synthetic_elf64_le() -> Vec<u8> {
        let mut bytes = vec![0_u8; 0x400];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = ELFCLASS64;
        bytes[5] = ELFDATA2LSB;
        bytes[6] = 1;

        write_u16_le(&mut bytes, 16, 2);
        write_u16_le(&mut bytes, 18, EM_X86_64);
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

        write_u32_le(&mut bytes, 0x40, PT_LOAD);
        write_u32_le(&mut bytes, 0x40 + 4, PF_R | PF_X);
        write_u64_le(&mut bytes, 0x40 + 8, 0x300);
        write_u64_le(&mut bytes, 0x40 + 16, 0x401000);
        write_u64_le(&mut bytes, 0x40 + 32, 4);
        write_u64_le(&mut bytes, 0x40 + 40, 8);
        write_u64_le(&mut bytes, 0x40 + 48, 0x1000);

        write_section64(
            &mut bytes,
            0x100 + 64,
            Section64Spec {
                name: 1,
                section_type: 1,
                flags: SHF_ALLOC | SHF_EXECINSTR,
                address: 0x401000,
                file_offset: 0x300,
                size: 4,
                link: 0,
                entry_size: 0,
            },
        );
        write_section64(
            &mut bytes,
            0x100 + 128,
            Section64Spec {
                name: 7,
                section_type: SHT_STRTAB,
                flags: 0,
                address: 0,
                file_offset: 0x340,
                size: 33,
                link: 0,
                entry_size: 0,
            },
        );
        write_section64(
            &mut bytes,
            0x100 + 192,
            Section64Spec {
                name: 17,
                section_type: SHT_STRTAB,
                flags: 0,
                address: 0,
                file_offset: 0x370,
                size: 15,
                link: 0,
                entry_size: 0,
            },
        );
        write_section64(
            &mut bytes,
            0x100 + 256,
            Section64Spec {
                name: 25,
                section_type: SHT_SYMTAB,
                flags: 0,
                address: 0,
                file_offset: 0x380,
                size: 72,
                link: 3,
                entry_size: 24,
            },
        );

        bytes[0x300..0x304].copy_from_slice(&[0x90, 0x90, 0xc3, 0x00]);
        bytes[0x340..0x361].copy_from_slice(b"\0.text\0.shstrtab\0.strtab\0.symtab\0");
        bytes[0x370..0x37f].copy_from_slice(b"\0_start\0helper\0");
        write_elf64_symbol(&mut bytes, 0x380 + 24, 1, 0x12, 1, 0x401000, 4);
        write_elf64_symbol(&mut bytes, 0x380 + 48, 8, 0x12, 1, 0x401004, 0);

        bytes
    }

    fn synthetic_elf64_le_with_imports_and_relocations() -> Vec<u8> {
        let mut bytes = vec![0_u8; 0x600];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = ELFCLASS64;
        bytes[5] = ELFDATA2LSB;
        bytes[6] = 1;

        write_u16_le(&mut bytes, 16, 2);
        write_u16_le(&mut bytes, 18, EM_X86_64);
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

        write_u32_le(&mut bytes, 0x40, PT_LOAD);
        write_u32_le(&mut bytes, 0x40 + 4, PF_R | PF_X);
        write_u64_le(&mut bytes, 0x40 + 8, 0x300);
        write_u64_le(&mut bytes, 0x40 + 16, 0x401000);
        write_u64_le(&mut bytes, 0x40 + 32, 4);
        write_u64_le(&mut bytes, 0x40 + 40, 0x2000);
        write_u64_le(&mut bytes, 0x40 + 48, 0x1000);

        write_section64(
            &mut bytes,
            0x100 + 64,
            Section64Spec {
                name: 1,
                section_type: 1,
                flags: SHF_ALLOC | SHF_EXECINSTR,
                address: 0x401000,
                file_offset: 0x300,
                size: 4,
                link: 0,
                entry_size: 0,
            },
        );
        write_section64(
            &mut bytes,
            0x100 + 128,
            Section64Spec {
                name: 7,
                section_type: SHT_STRTAB,
                flags: 0,
                address: 0,
                file_offset: 0x340,
                size: 52,
                link: 0,
                entry_size: 0,
            },
        );
        write_section64(
            &mut bytes,
            0x100 + 192,
            Section64Spec {
                name: 17,
                section_type: SHT_STRTAB,
                flags: 0,
                address: 0,
                file_offset: 0x390,
                size: 23,
                link: 0,
                entry_size: 0,
            },
        );
        write_section64(
            &mut bytes,
            0x100 + 256,
            Section64Spec {
                name: 25,
                section_type: SHT_DYNSYM,
                flags: 0,
                address: 0,
                file_offset: 0x3c0,
                size: 72,
                link: 3,
                entry_size: 24,
            },
        );
        write_section64(
            &mut bytes,
            0x100 + 320,
            Section64Spec {
                name: 33,
                section_type: SHT_RELA,
                flags: 0,
                address: 0,
                file_offset: 0x420,
                size: 48,
                link: 4,
                entry_size: 24,
            },
        );
        write_section64(
            &mut bytes,
            0x100 + 384,
            Section64Spec {
                name: 43,
                section_type: SHT_DYNAMIC,
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
        write_elf64_symbol(&mut bytes, 0x3c0 + 24, 1, 0x12, SHN_UNDEF, 0, 0);
        write_elf64_symbol(&mut bytes, 0x3c0 + 48, 6, 0x12, 1, 0x401000, 0);
        write_elf64_rela(&mut bytes, 0x420, 0x402000, 1, 7, 0);
        write_elf64_rela(&mut bytes, 0x420 + 24, 0x402008, 0, 8, 0x401000);
        write_u64_le(&mut bytes, 0x480, DT_NEEDED);
        write_u64_le(&mut bytes, 0x488, 13);
        write_u64_le(&mut bytes, 0x490, DT_NULL);

        bytes
    }

    struct Section64Spec {
        name: u32,
        section_type: u32,
        flags: u64,
        address: u64,
        file_offset: u64,
        size: u64,
        link: u32,
        entry_size: u64,
    }

    fn write_section64(bytes: &mut [u8], offset: usize, spec: Section64Spec) {
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

    struct PeSectionSpec {
        name: &'static [u8; 8],
        virtual_size: u32,
        virtual_address: u32,
        raw_size: u32,
        raw_offset: u32,
        characteristics: u32,
    }

    fn write_pe_section(bytes: &mut [u8], offset: usize, spec: PeSectionSpec) {
        bytes[offset..offset + 8].copy_from_slice(spec.name);
        write_u32_le(bytes, offset + 8, spec.virtual_size);
        write_u32_le(bytes, offset + 12, spec.virtual_address);
        write_u32_le(bytes, offset + 16, spec.raw_size);
        write_u32_le(bytes, offset + 20, spec.raw_offset);
        write_u32_le(bytes, offset + 36, spec.characteristics);
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

    fn write_u64_be(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
    }
}
