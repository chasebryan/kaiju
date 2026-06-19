# Fuzzing Plan

Kaiju parses hostile and malformed binaries, so fuzzing is part of the project
plan. A deterministic loader hardening harness is checked in at
`crates/kaiju-loader/tests/hardening.rs` and runs under normal `cargo test`.
It exercises hostile magic headers plus deterministic mutations and asserts that
the public loader API returns explicit errors or conservative loading results
without panics.

Run the checked-in hardening gate directly with:

```bash
cargo test -p kaiju-loader --test hardening
```

Future coverage-driven fuzz targets should cover:

- format detection
- ELF loader boundaries
- PE loader boundaries
- Mach-O loader boundaries
- string extraction
- memory map virtual-to-file translation
- project JSON snapshot generation from analysis facts

Fuzz harnesses should assert that malformed inputs return explicit errors or
conservative loading results without panics.
