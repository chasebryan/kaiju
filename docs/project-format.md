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
