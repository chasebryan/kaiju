# Threat Model

Kaiju parses hostile, malformed, truncated, and intentionally confusing
binaries. The default stance is defensive parsing.

## Assets

- User workstation integrity.
- Analysis project integrity.
- Trustworthy analysis output.
- Availability of the headless CLI.
- Clear separation between passive network evidence, packet-capture import,
  explicit TCP probing, and future privileged capture backends.

## Input Risks

- Truncated headers.
- Integer overflow in offsets or virtual addresses.
- Overlapping or contradictory regions.
- Large allocation requests.
- Invalid encodings.
- Ambiguous, noisy, or misleading network evidence lines.
- Unauthorized, overly broad, or accidentally expensive live network targets.
- Packet payloads that may contain secrets or sensitive content.
- Future parser backend bugs.

## Current Controls

- No unsafe code in current crates.
- No unchecked indexing in loader detection.
- Typed error kinds for invalid and unmapped addresses.
- Raw fallback for unknown files.
- Unit and integration tests for malformed-adjacent boundaries.
- Deterministic loader hardening test over hostile magic headers and mutated
  byte inputs.
- Network facts retain source line or packet record numbers and ignored-record
  counts so inferred topology stays auditable.
- Live TCP probe and scan commands require explicit command-line targets, use
  per-target timeouts, enforce target and byte limits, and have parser,
  validation, and report serialization tests that do not require live targets.
- Payload inspection stores bounded previews, not unbounded payload archives.
- Bounded ELF relocation table, linked symbol-table, entry-size, and
  symbol-index parsing tests.
- Bounded PE import descriptor, thunk, DLL-name, and import-name parsing tests.
- Bounded PE export directory, address-table, name-table, ordinal-table, and
  forwarder parsing tests.
- Bounded PE base relocation directory, block-size, entry-alignment, and
  block-overrun parsing tests.
- Bounded PE COFF symbol table, string-table name, section-index, and
  auxiliary-entry parsing tests.
- Bounded Mach-O load-command, segment, symbol-table, and string-table parsing
  tests.

## Required Rules

- No panics on malformed parser input.
- No `unwrap()` or `expect()` in parser paths.
- Bounds-check all offsets before reading.
- Use checked arithmetic for address and offset math.
- Add malformed-input tests with every parser expansion.
- Keep active network operations explicit, target-scoped, bounded by timeout
  and byte limits, and free of credential capture, exploitation, evasion, or
  persistence behavior.

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
- Structured importers for specific network log formats with preserved record
  provenance.
- A privileged live interface capture backend only after a capability and
  redaction model exists.
