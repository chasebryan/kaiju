# Scripting Plan

Scripting is a Phase 13 planning milestone. Kaiju does not execute user scripts
yet.

## Goals

Future scripts should be able to:

- list functions
- inspect labels, comments, symbols, strings, and xrefs
- inspect instructions and CFG blocks
- run simple analysis queries
- rename symbols
- add labels and comments
- invoke approved analysis passes

## Candidate Languages

Python is the most familiar option for reverse-engineering users. Lua or Rhai
may be useful for lightweight embedded scripting. Rust plugins remain the path
for native performance and deeper integration.

## Safety Rules

Scripts should start with restricted project access, not arbitrary host access.
The initial scripting host should avoid default filesystem, process, and network
capabilities. Mutating operations should go through explicit Kaiju APIs so they
can be audited, logged, and eventually permissioned.

## Implementation Order

The scripting layer should wait until these APIs are stable enough:

1. project facts
2. analysis pass reports
3. IR values and pretty printing
4. plugin capability declarations
5. serialization format

The first implementation should be read-mostly and deterministic. Write access
can follow once labels, comments, and symbol updates have stable semantics.
