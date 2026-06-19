# Snapshot Testing

Kaiju uses small source-tracked CLI snapshots for stable headless output.

Current snapshots live under `tests/snapshots/` and cover:

- raw `info`
- raw `map`
- raw `diagnostics`
- raw `strings`
- raw `analyze`
- raw `export`
- raw `imports`
- built-in `arch`

The CLI integration tests normalize the raw fixture path to `<RAW_FIXTURE>` so
snapshots are stable across machines and checkout locations.

## Rules

- Keep snapshots small and focused.
- Normalize paths, timestamps, and other host-specific values.
- Prefer exact snapshots for stable automation surfaces.
- Keep broader semantic assertions for outputs that are still intentionally
  evolving.

When CLI output changes intentionally, update the matching file in
`tests/snapshots/` in the same change.
