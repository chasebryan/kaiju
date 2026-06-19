# Security Policy

Kaiju RE is intended for legitimate reverse engineering, malware analysis in
controlled environments, interoperability research, education, and defensive
security work.

The project parses untrusted input by design. Security-sensitive rules:

- Do not panic on malformed binaries.
- Avoid unchecked indexing and parser-path `unwrap()` or `expect()`.
- Prefer explicit, typed errors.
- Keep unsafe code out of the codebase unless there is a narrow, documented
  justification.
- Add malformed-input tests when adding parsers or analysis passes.
- Keep active network operations explicit, target-scoped, bounded by timeout
  and byte limits, and free of credential capture, exploitation, evasion, or
  persistence behavior.

Please report suspected security issues privately to the project maintainers
once a real project contact is established.
