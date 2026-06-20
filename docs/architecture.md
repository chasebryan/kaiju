# Architecture

Kaiju is a Rust-first reverse-engineering framework built from small crates.
The first target is a reliable headless pipeline:

```text
bytes -> loader -> memory map -> project state -> analysis
```

Later phases extend that path with architecture adapters, disassembly, CFG
construction, IR lifting, scripting, plugins, and a GUI.

## Crate Layout

- `kaiju-core`: shared foundational types such as addresses, address ranges,
  endian markers, permissions, memory regions, memory maps, and typed errors.
- `kaiju-loader`: format detection, loader traits, normalized loaded-binary
  metadata, and raw fallback loading.
- `kaiju-analysis`: analysis helpers and passes. It currently owns strings
  extraction for ASCII and UTF-16LE data.
- `kaiju-disasm`: normalized disassembly traits and instruction data model. It
  currently includes a minimal x86-64 decoder subset.
- `kaiju-network`: network evidence parsing, PCAP import, topology inference,
  bounded payload inspection, and explicit TCP probe reports.
- `kaiju-project`: in-memory project state that can hold a loaded binary and
  analysis facts.
- `kaiju-workbench`: native Rust desktop workbench backed by loader, project,
  analysis, disassembly, CFG, and IR crates.
- `kaiju-cli`: headless command-line interface.

Future crates will split architecture modeling, disassembly, IR, analysis, and
plugin boundaries once the loader foundation is stable.

## Loader Model

A file is read as bytes first. Format detection then classifies the input as
ELF, PE, Mach-O, or unknown. Unknown files are loaded as raw bytes at virtual
address `0x0`.

ELF has a limited defensive parser for class, endian, machine architecture,
entrypoint, program headers, section headers, section names, `.symtab` /
`.dynsym` symbol names, undefined dynamic imports, `DT_NEEDED` dependencies,
REL/RELA relocation rows, and `PT_LOAD` regions. PE has a limited defensive
parser for PE32/PE32+, COFF machine, optional-header image base and entrypoint,
section headers, section names, section-backed memory regions, COFF symbol
tables, import-DLL dependencies, import tables, export tables, and base
relocation tables. Mach-O has a limited thin parser for CPU/endian metadata,
`LC_SEGMENT` / `LC_SEGMENT_64` memory maps, section metadata, `LC_MAIN`
entrypoint translation, `LC_SYMTAB` symbols, `LC_LOAD_DYLIB` dependencies, and
undefined external imports, plus section relocation entries. Universal/fat
Mach-O handling selects a bounded supported thin member for the same thin-loader
path. Full parsing of ELF dependency version metadata, PE debug/PDB metadata,
richer Mach-O dynamic-loader metadata, richer universal member-selection policy,
and format-specific edge cases is deferred.

Loader diagnostics are attached to the normalized `LoadedBinary` model. They
report conservative behavior such as raw fallback loading, limited Mach-O
load-command parsing, universal/fat Mach-O member selection or fallback
handling, limited ELF/PE metadata parsing, and file-backed fallback mapping when
a recognized container has no mappable regions. The `kaiju diagnostics <file>`
command prints these facts separately from the stable `info` and `map`
summaries.

## Memory Model

The memory model distinguishes virtual address, file offset, region size, and
permissions. A `MemoryMap` owns ordered `MemoryRegion` values and supports:

- region lookup by virtual address
- byte and range reads
- executable and readable region listing
- virtual-address to file-offset translation when a region is file-backed
- file-offset to virtual-address translation for initialized mapped bytes

Parser and memory APIs must return explicit errors for unmapped or invalid
reads.

## Strings Model

Strings extraction scans original file bytes, not only mapped memory. Results
include file offset, encoding, character length, value, and a virtual address
when the file offset belongs to an initialized mapped region. The current
extractor supports printable ASCII and UTF-16LE strings with a configurable
minimum character length.

## Network Model

The `kaiju-network` crate adds network reverse-engineering support. It can load
user-supplied evidence text, import classic PCAP captures, infer hosts,
destination services, and directed edges, and preserve source line or packet
record provenance. Payloads are summarized with bounded ASCII and hex previews.

The same crate also owns explicit TCP probe and port-scan helpers. These open
sockets only for user-supplied targets, use per-target timeouts, enforce target
and byte limits, and return deterministic `kaiju.network.probe.v1` reports.
There is no ambient discovery or privileged live interface capture backend.

## Disassembly Model

Disassembly is exposed through a backend-independent `Disassembler` trait and a
normalized instruction type. The current x86-64 implementation is intentionally
small: it handles common prologue/epilogue instructions, direct relative calls
and branches, simple register-to-register moves and arithmetic, and falls back
to an unknown byte directive for unrecognized opcodes.

Backend-specific decoder types must not leak through the public API. A later
phase can replace or augment the minimal decoder with a fuller backend while
keeping the normalized instruction model stable.

## Analysis Pass Model

The analysis framework is built around explicit passes over a project:

```rust
pub trait AnalysisPass {
    fn name(&self) -> &'static str;
    fn run(&self, project: &mut Project) -> Result<AnalysisReport>;
}
```

Current default passes cover string extraction, entrypoint function seeding,
entrypoint CFG construction, conservative function discovery, bounded
fixed-point CFG construction for direct-call-reachable functions, conservative
RIP-relative data/string reference discovery, bounded IR summaries for
discovered CFG blocks, and cross-reference summarization.

## CFG Model

The current CFG builder uses recursive descent from an entrypoint or requested
address. It decodes normalized instructions, ends blocks at unconditional
jumps, conditional jumps, returns, traps, and unknown instructions, and follows
direct branch targets when they land in mapped memory.

Conditional branches create taken and not-taken edges. Direct calls create call
edges, but the builder continues along the fallthrough path instead of entering
callee bodies. Indirect jumps, jump tables, exceptions, thunk recovery, and
advanced block splitting are deferred.

## Project State Model

The Phase 8 project model is an in-memory fact store around one loaded binary.
It owns user-facing and analysis-produced state without changing loader-owned
bytes or format metadata.

Current project facts include:

- labels and comments keyed by address
- discovered functions and their basic block starts
- basic block summaries
- CFG edges
- extracted strings
- normalized dependencies copied from loader metadata
- normalized symbols copied from loader metadata
- normalized imports copied from loader metadata
- normalized exports copied from loader metadata
- normalized relocations copied from loader metadata
- cross-references
- small namespaced analysis facts

Analysis crates record into this model through adapters. Strings analysis can
populate `ProjectString` facts, CFG analysis can populate function, block, edge,
and flow/call cross-reference facts, function discovery can promote
entrypoints, loader symbols, exports, and direct call targets into project
functions when they point into executable mapped memory, function CFG analysis
can iteratively promote direct call targets and build bounded direct-branch
graphs for functions that do not already have a starting block, and
data-reference analysis can record mapped RIP-relative `lea`/`mov` references
from decoded x86-64 basic blocks, and IR summary analysis can record derived
per-block lifted instruction text and unknown counts for discovered x86-64 CFG
blocks. Later phases can add persistence and richer xref provenance on top of
this model.

## IR And Lifting Model

The `kaiju-ir` crate owns the first IR data model and a compact pretty printer.
It currently contains modules, functions, blocks, instructions, expressions,
and values. A minimal x86-64 lifter maps normalized disassembly into this IR.

The lifter is intentionally conservative. It handles a small instruction subset
and emits `unknown` for shapes it cannot represent. This keeps headless lifting
usable without claiming complete x86 semantics.

The default analysis pipeline records bounded project IR summaries by
redisassembling discovered basic blocks and lowering each instruction through
the same lifter. These summaries are deterministic export rows, not SSA,
type recovery, or decompiler output.

## Default Analysis Runner

The analysis crate now defines an `AnalysisPass` trait and a small default
runner. The default runner records strings, discovers an entrypoint function
when one exists, attempts an entrypoint CFG, promotes conservative function
seeds from loader symbols, exports, and direct call targets, iterates bounded
direct-call target promotion with CFG construction for functions that do not
already have a starting block, records conservative RIP-relative data/string
cross-references from decoded x86-64 basic blocks, records bounded IR summaries
for discovered CFG blocks, and summarizes cross-references. CFG and IR failures
from unsupported architectures are reported as warnings so raw or unsupported
files can still produce a useful analysis summary.

## Workbench GUI

The first GUI surface is the native Rust `kaiju-workbench` app. It uses the same
headless loader and default analysis pipeline as `kaiju analyze`, then renders a
black, red, and white project browser, disassembly view, strings view, CFG view,
and IR view in a desktop window. It accepts an optional file path at startup and
also exposes desktop file actions for opening binaries, opening current
`.kaiju` package directories, and saving the loaded project as a new `.kaiju`
package.

The workbench keeps a selected function/address shared across the browser,
strings table, xref table, disassembly, CFG, and IR views. Loader diagnostics,
analysis warnings, status history, and recent binaries/packages are surfaced in
native panels so the GUI is no longer path-textbox-first.

This is intentionally not a full project database yet. Future GUI work should
add persistence, annotation editing, richer navigation contracts, and eventually
deeper disassembly/lifting views without weakening the headless APIs.

## Plugin And Scripting Boundaries

The `kaiju-plugin-api` crate defines plugin metadata, capability declarations,
analysis pass plugin traits, loader/architecture/command placeholders, and an
in-process registry. This is not a dynamic plugin host.

The scripting plan is documented separately. Scripts are not executed yet; the
planned direction is a restricted, project-API-first scripting surface after the
project, analysis, IR, plugin, and serialization APIs stabilize.

## Architecture Descriptor Model

The `kaiju-arch` crate provides a small architecture abstraction layer. It
defines an `Architecture` trait, built-in descriptors, pointer width metadata,
endian defaults, and a placeholder register model. The current loader and
disassembler still use `ArchitectureId` directly, but future backend selection
can move through these descriptors.

## Project Snapshot Export

The project crate can now produce a deterministic `kaiju.project.v1` JSON
snapshot. The snapshot is derived output for headless automation and tests. It
includes binary metadata, summary counts, discovered functions, block summaries,
derived IR summaries, loader diagnostics, dependencies, symbols, imports,
exports, relocations, strings, xrefs, and analysis facts.

The CLI can also write an initial `kaiju.package.v1` directory with a manifest,
the deterministic project snapshot, and a separate empty annotations file, then
inspect that package read-only by validating schema markers and printing summary
counts. This is not a full editable project database. Future `.kaiju`
persistence should keep user annotations separate from regenerated analysis
facts.
