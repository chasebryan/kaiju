# Fuzzing Plan

Kaiju parses hostile and malformed binaries, so fuzzing is part of the project
plan. No fuzz harness is checked in yet.

Initial targets should cover:

- format detection
- ELF loader boundaries
- PE loader boundaries
- string extraction
- memory map virtual-to-file translation
- project JSON snapshot generation from analysis facts

Harnesses should assert that malformed inputs return explicit errors or
conservative raw loading results without panics.
