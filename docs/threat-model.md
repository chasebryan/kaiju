# Threat Model

Kaiju parses hostile, malformed, truncated, and intentionally confusing
binaries. The default stance is defensive parsing.

## Assets

- User workstation integrity.
- Analysis project integrity.
- Trustworthy analysis output.
- Availability of the headless CLI.

## Input Risks

- Truncated headers.
- Integer overflow in offsets or virtual addresses.
- Overlapping or contradictory regions.
- Large allocation requests.
- Invalid encodings.
- Future parser backend bugs.

## Current Controls

- No unsafe code in current crates.
- No unchecked indexing in loader detection.
- Typed error kinds for invalid and unmapped addresses.
- Raw fallback for unknown files.
- Unit and integration tests for malformed-adjacent boundaries.
- Bounded PE import descriptor, thunk, DLL-name, and import-name parsing tests.

## Required Rules

- No panics on malformed parser input.
- No `unwrap()` or `expect()` in parser paths.
- Bounds-check all offsets before reading.
- Use checked arithmetic for address and offset math.
- Add malformed-input tests with every parser expansion.

## Future Controls

- Fuzz targets for format detection, ELF loading, PE loading, string extraction,
  and address translation.
- Snapshot tests for deterministic project export and CLI fact views.
- Explicit separation between regenerated analysis facts and future user-owned
  annotations.
- Sandboxed plugin execution, preferably through WASM with explicit
  capabilities.
- Restricted scripting with no default filesystem, process, or network access.
- Deterministic analysis mode for reproducible automation.
