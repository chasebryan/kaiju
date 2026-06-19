# Loader Model

Kaiju loads bytes first, then normalizes recognized file formats into a common
`LoadedBinary` model. File offsets and virtual addresses are separate concepts.

## Current Flow

1. Read the input file as raw bytes.
2. Detect a container format from magic/header bytes.
3. Route to a defensive format loader when available.
4. Populate normalized metadata.
5. Build a virtual memory map.
6. Fall back to a conservative raw mapping when the format is unknown.

## Current Formats

- ELF: limited parser for class, endian, machine, entrypoint, section headers,
  and `PT_LOAD` memory regions.
- PE: limited parser for PE32/PE32+, machine, image base, entrypoint, section
  headers, and section-backed memory regions.
- Mach-O: magic detection only; currently exposed as conservative file-backed
  bytes until a dedicated parser lands.
- Raw: unknown inputs map at virtual address `0x0` with read-only permissions.

## Normalized Output

Loader output is a `LoadedBinary`:

```rust
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
    pub symbols: Vec<Symbol>,
    pub diagnostics: Vec<Diagnostic>,
}
```

## Loader Diagnostics

Loaders attach normalized diagnostics to `LoadedBinary` when behavior is
intentionally conservative or incomplete. The CLI exposes these facts without
changing `info` or `map` output:

```bash
kaiju diagnostics <file>
```

Current diagnostics include:

- a note when an unknown file is loaded through the raw fallback at virtual
  address `0x0`
- a warning when Mach-O magic is detected but no dedicated parser is available
- notes that ELF and PE loading currently populate only limited metadata
- warnings when ELF or PE inputs fall back to file-backed bytes because no
  mappable regions were found

## Safety Rules

Loader code must:

- bounds-check offsets before reading
- use checked arithmetic for offsets and virtual addresses
- return explicit `KaijuError` values on malformed input
- avoid panics on hostile or truncated binaries
- keep backend-specific parser details out of public APIs

## Future Work

The next loader expansions should add richer ELF and PE symbols/imports,
dedicated Mach-O parsing, and fuzz targets for malformed headers and
inconsistent section/segment tables.
