# Project Format

Kaiju can write a conservative `.kaiju` project package. The current package is
still a deterministic snapshot for headless automation and tests, not a full
editable project database.

## Snapshot Command

```bash
kaiju export <file>
```

The command loads a binary, runs the default analysis passes, and prints a
`kaiju.project.v1` JSON object. It includes:

- binary metadata
- summary counts
- loader diagnostics
- loader dependencies
- loader symbols
- loader imports
- loader exports
- loader relocations
- discovered functions from entrypoints, loader metadata, and direct call
  targets
- basic block summaries
- bounded derived IR summaries for discovered CFG blocks
- extracted strings
- flow, call, and conservative RIP-relative data cross-references
- analysis facts

The snapshot is intentionally derived output. It is not a stable editable
project file yet.

IR summaries are exported as top-level `ir_functions` rows and counted under
`summary.ir_functions`. They contain function starts, optional function names,
per-block labels, lifted instruction text, and unknown-instruction counts. The
rows are regenerated analysis output, not user-authored IR and not decompiler
output.

Loader diagnostics are exported as a top-level `diagnostics` array and counted
under `summary.diagnostics`. Diagnostic rows include a normalized severity and
message so headless automation can distinguish normal raw fallback notes from
warnings about conservative or incomplete loader behavior.

## Project Package Command

```bash
kaiju save <file> --out <project-dir>
kaiju package <project-dir>
```

The command loads a binary, runs the default analysis passes, and writes an
initial `kaiju.package.v1` directory. It refuses to write into a non-empty
directory so existing project data is not silently overwritten.

Current package layout:

```text
sample.kaiju/
  manifest.json
  project.json
  annotations.json
```

- `manifest.json` records the package schema, the embedded project snapshot
  schema, source binary metadata, and package file names.
- `project.json` is the same deterministic `kaiju.project.v1` output printed by
  `kaiju export`.
- `annotations.json` is an empty `kaiju.annotations.v1` file reserved for
  user-owned labels and comments.

`kaiju package <project-dir>` is a read-only inspection command. It requires the
three current package files, validates the package, project, and annotations
schema markers, checks the manifest file names, and prints source/project
summary counts. It does not rewrite package contents.

## Network Snapshots

```bash
kaiju network <evidence-file> --format json
kaiju network pcap <pcap-file> --format json
```

These commands print a separate `kaiju.network.v1` JSON object for network
evidence and packet captures. It includes source name, summary counts, hosts,
services, directed edges, observations, provenance line or packet numbers, and
bounded payload summaries when packet bytes are present. It is deterministic
derived output and does not represent a persisted project database.

```bash
kaiju network probe --target HOST:PORT --format json
kaiju network scan --host HOST --ports LIST --format json
```

These commands print `kaiju.network.probe.v1` JSON for explicit live TCP probe
or scan results. Rows include target, status, resolved remote address, elapsed
time, sent byte count, bounded received-payload summary, and any nonfatal error.

## Future `.kaiju` Package

A later package layout may split regenerated analysis data into additional
files:

```text
sample.kaiju/
  manifest.json
  project.json
  binary.meta.json
  analysis.json
  annotations.json
  symbols.json
  cache/
```

Future persistence must preserve user annotations separately from regenerated
analysis facts so re-analysis cannot silently destroy labels or comments.
