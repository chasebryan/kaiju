# Contributing

Kaiju RE is early. Contributions should keep the foundation small, explicit,
and testable.

Guidelines:

- Use stable Rust.
- Keep crates focused.
- Avoid panics in library code.
- Avoid backend-specific types in public wrapper APIs.
- Add tests for meaningful behavior.
- Run the quality gate before submitting changes:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The GitHub Actions workflow runs the same gate plus raw-fixture smoke checks.
Before a release, also follow `docs/release-checklist.md`.

Do not copy code, class names, internal file formats, or non-generic structure
from Ghidra or any other reverse-engineering platform.
