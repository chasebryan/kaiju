# Roadmap

## v0.1 - Headless Loader and Disassembler

- Core types.
- Loader abstraction.
- ELF and PE detection/loading.
- Raw loader fallback.
- Memory map.
- Strings extraction.
- x86-64 disassembly.
- CLI.

## v0.2 - CFG and Project State

- Basic block discovery.
- Direct branch CFG.
- Function model.
- Project facts.
- DOT export.

## v0.3 - IR Foundation

- IR model.
- IR pretty printer.
- Manual IR construction tests.
- Basic serialization.

## v0.4 - Minimal x86-64 Lifting

- Small instruction subset.
- Unknown instruction handling.
- Register model.
- Flags placeholder.
- Basic lifted output.

## v0.5 - Analysis Passes

- Analysis framework.
- Cross-references.
- Function discovery.
- String references.
- Symbol propagation.

## v0.6 - Plugins and Scripting

- Plugin API traits.
- Built-in pass registration.
- Script model design.
- Sandbox plan.

## v0.7 - GUI Prototype

- Project browser.
- Disassembly view.
- Strings view.
- CFG view.
- IR view.

## Current Progress Notes

Phase 8 introduced the first in-memory project state model. It stores loaded
binary metadata plus labels, comments, functions, basic block summaries, CFG
edges, extracted strings, loader symbols, cross-references, and simple analysis
facts. Persistence and default analysis-pass orchestration remain future work.

Phase 9 through Phase 13 added the first IR crate and pretty printer, a minimal
x86-64 lifter, default analysis-pass orchestration, a plugin API skeleton, and a
documented scripting plan. Scripting execution remains intentionally unbuilt
until the core project, analysis, IR, plugin, and serialization APIs stabilize.

Phase 14 through Phase 45 are now tracked in `docs/phase-14-45.md`. The current
safe implementation slice adds architecture descriptors, project query APIs,
deterministic JSON snapshots, read-only CLI fact views, and documentation for
future GUI, plugin, scripting, fuzzing, snapshot, and release-readiness gates.

The post-Phase-45 foundation slice added library-consumer examples under
`examples/basic-load` and `examples/basic-disasm`, plus a dedicated loader model
document at `docs/loader-model.md`.

The next infrastructure slice added a GitHub Actions quality gate and a
source-tracked release checklist so future publication can use the same commands
that are verified locally.

The snapshot-testing slice added exact raw-fixture CLI snapshots under
`tests/snapshots/` and documents the normalization policy in
`docs/snapshot-testing.md`.

The loader diagnostics slice added normalized diagnostics on `LoadedBinary` and
a read-only `kaiju diagnostics <file>` command. This keeps conservative loader
behavior visible without changing the stable `info` or `map` summaries.

The Mach-O loader slice replaced magic-only handling for thin Mach-O files with
limited CPU/endian metadata parsing, `LC_SEGMENT` / `LC_SEGMENT_64` memory maps,
section metadata, `LC_MAIN` entrypoint translation, and malformed command/segment
tests while keeping universal/fat binaries conservative.

The ELF symbol slice added defensive `.symtab` / `.dynsym` extraction through
linked string tables, malformed symbol-table tests, and CLI coverage for symbol
counts without claiming imports or relocations.

The PE import slice added bounded PE32/PE32+ import-directory parsing, named and
ordinal import rows, malformed import-table tests, project import coverage, and
a read-only `kaiju imports <file>` command without claiming PE exports or
relocations.

The PE export slice added bounded export-directory parsing for module names,
named exports, ordinal-only exports, and forwarded exports, plus malformed
export-table tests, project export coverage, and a read-only
`kaiju exports <file>` command without claiming PE base relocations or COFF
symbols.

The PE relocation slice added bounded base-relocation directory parsing for
relocation blocks, ABSOLUTE padding, DIR64/HIGHLOW/HIGH entries, and unknown
nonzero relocation types, plus malformed relocation-block tests, project
relocation coverage, and a read-only `kaiju relocations <file>` command without
claiming PE COFF symbols.

The ELF dynamic relocation slice added bounded REL/RELA relocation-table
parsing, undefined `.dynsym` import rows, relocation-to-import thunk linking,
malformed relocation-table tests, and CLI coverage for ELF imports and
relocations without claiming dependency/version resolution.

The PE COFF symbol slice added bounded COFF symbol-table parsing for inline and
string-table names, auxiliary-entry skipping, section-relative symbol addresses,
malformed COFF symbol tests, and CLI coverage for PE symbols without claiming
debug/PDB metadata.

The loader hardening gate slice added a dependency-free integration test over
hostile magic headers and deterministic byte mutations, documented the direct
`cargo test -p kaiju-loader --test hardening` gate, and made CI run that gate
by name alongside the full workspace tests.

The Mach-O symbol slice added bounded `LC_SYMTAB` parsing for nlist32/nlist64
rows, string-table-backed symbol names, undefined external import rows,
malformed symbol/string-table tests, and CLI coverage for Mach-O `symbols` and
`imports` output without claiming relocations, dylib binding metadata, or
universal/fat member selection.

The shared-library dependency slice added normalized dependency rows for ELF
`DT_NEEDED`, PE import DLL names, and Mach-O `LC_LOAD_DYLIB`, plus project
snapshot coverage and a read-only `kaiju dependencies <file>` command without
claiming dependency versioning, delay-load metadata, or dylib binding metadata.

The network capability slice added a dependency-free `kaiju-network` crate plus
`kaiju network` evidence, PCAP, probe, and scan modes. It infers hosts,
services, directed edges, and bounded payload summaries from authorized text
evidence, classic PCAP captures, and explicit TCP socket probes without adding
ambient discovery or privileged live interface sniffing.
