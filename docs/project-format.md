# Project Format

Kaiju does not yet write a full `.kaiju` project database. The current format
work is a deterministic JSON snapshot for headless automation and tests.

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
- discovered functions
- basic block summaries
- extracted strings
- cross-references
- analysis facts

The snapshot is intentionally derived output. It is not a stable editable
project file yet.

Loader diagnostics are exported as a top-level `diagnostics` array and counted
under `summary.diagnostics`. Diagnostic rows include a normalized severity and
message so headless automation can distinguish normal raw fallback notes from
warnings about conservative or incomplete loader behavior.

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

A later package layout may look like:

```text
sample.kaiju/
  project.json
  binary.meta.json
  analysis.json
  comments.json
  symbols.json
  cache/
```

Future persistence must preserve user annotations separately from regenerated
analysis facts so re-analysis cannot silently destroy labels or comments.
