# Phase 14-45 Plan

This plan extends Kaiju beyond the initial Phase 0-13 foundation. The goal is
to keep the project moving through safe, headless, testable foundations before
building GUI, scripting execution, dynamic plugins, or decompiler claims.

## Phase Map

14. GUI plan boundary: keep GUI deferred until headless APIs are stable.
15. Project snapshot model: export stable project summaries and facts.
16. Project query APIs: functions, strings, xrefs, and analysis facts.
17. Architecture crate: trait, built-in architecture descriptors, register
    placeholders.
18. CLI project export: print deterministic project JSON.
19. CLI fact views: functions and cross-reference listings.
20. Analysis report contract: pass summaries, facts added, warnings.
21. Cross-reference provenance plan: distinguish flow, call, data, read, write.
22. Label/comment persistence plan: store user annotations in future project
    files.
23. Symbol and import expansion plan: normalize richer loader metadata later.
24. Data discovery plan: strings and conservative references first, then typed
    data.
25. Loader diagnostics plan: preserve parser notes and skipped structures.
26. Mach-O parser milestone: replace detection-only handling.
27. ELF hardening milestone: expand symbols, relocations, and malformed cases.
28. PE hardening milestone: imports, exports, relocations, and malformed cases.
29. Disassembly backend expansion: broader x86-64 and non-x86 architectures.
30. Architecture registry milestone: backend selection through architecture
    descriptors.
31. IR validation milestone: validate block labels, branch targets, and values.
32. SSA plan: add SSA only after IR and CFG semantics settle.
33. Data-flow plan: use IR and CFG facts for read/write propagation.
34. Function discovery expansion: recursive descent, symbols, prologues, and
    executable region seeds.
35. Xref expansion: direct code xrefs and conservative RIP-relative data xrefs
    first, richer data xrefs later.
36. Project package plan: future `.kaiju` directory layout.
37. Plugin capability hardening: explicit plugin permissions.
38. WASM plugin research boundary: no untrusted native loading by default.
39. Scripting host plan: read-mostly scripting before mutations.
40. Sandbox policy: no default filesystem, process, or network access.
41. Fuzzing targets: loaders, string extraction, and memory translation.
42. Snapshot testing: normalize paths and keep CLI output stable.
43. API stability notes: document public API contracts before versioning claims.
44. Release checklist: quality gate, docs, threat model, and command smoke
    checks.
45. Integration readiness gate: confirm all headless foundation surfaces are
    wired, tested, and documented before GUI or decompiler work.

## Current Phase 45 Boundary

The current repository reaches the Phase 45 planning boundary by implementing
the safe headless pieces that do not require premature GUI, dynamic plugin,
scripting runtime, or decompiler work:

- `kaiju-arch` built-in architecture descriptors.
- project summaries, query APIs, and deterministic JSON export.
- CLI `export`, `functions`, `xrefs`, and `arch` commands.
- conservative function discovery and RIP-relative data/string xrefs.
- documented future boundaries for GUI, plugins, scripting, fuzzing, snapshots,
  and release readiness.

This does not mean Kaiju is feature-complete. It means the roadmap through
Phase 45 is source-tracked and the safe foundation slices are implemented.
