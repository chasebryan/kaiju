# Release Checklist

Kaiju is still early. A release should only claim behavior that is implemented,
tested, and represented in the CLI.

## Local Quality Gate

Run:

```bash
cargo check --workspace
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test -p kaiju-loader --test hardening
```

## CLI Smoke Checks

Run:

```bash
cargo run -p kaiju-cli -- info tests/fixtures/raw.bin
cargo run -p kaiju-cli -- map tests/fixtures/raw.bin
cargo run -p kaiju-cli -- diagnostics tests/fixtures/raw.bin
cargo run -p kaiju-cli -- strings tests/fixtures/raw.bin
cargo run -p kaiju-cli -- analyze tests/fixtures/raw.bin
cargo run -p kaiju-cli -- export tests/fixtures/raw.bin
cargo run -p kaiju-cli -- symbols tests/fixtures/raw.bin
cargo run -p kaiju-cli -- dependencies tests/fixtures/raw.bin
cargo run -p kaiju-cli -- imports tests/fixtures/raw.bin
cargo run -p kaiju-cli -- exports tests/fixtures/raw.bin
cargo run -p kaiju-cli -- relocations tests/fixtures/raw.bin
cargo run -p kaiju-cli -- network tests/fixtures/network-evidence.txt
cargo run -p kaiju-cli -- arch
```

Run the examples:

```bash
cargo run -p kaiju-example-basic-load -- tests/fixtures/raw.bin
cargo run -p kaiju-example-basic-disasm -- tests/fixtures/raw.bin
```

The basic disassembly example is expected to fail cleanly on the raw fixture
because raw input has no entrypoint and no known architecture.

## Documentation Checks

- README status addenda match implemented behavior.
- `docs/architecture.md` matches crate boundaries.
- `docs/loader-model.md` matches loader behavior.
- `docs/project-format.md` matches `kaiju export` output.
- `docs/network-model.md` matches `kaiju network` output.
- `docs/snapshot-testing.md` matches the fixtures in `tests/snapshots/`.
- `docs/threat-model.md` covers new parser or execution surfaces.
- No GUI, decompiler, dynamic plugin loading, or script execution is claimed
  before it exists.

## Security Checks

- Parser changes include malformed-input tests.
- Loader parser changes are covered by
  `cargo test -p kaiju-loader --test hardening`.
- New analysis paths return explicit errors or warnings.
- No `unsafe` is introduced without a narrow documented reason.
- No new feature enables malware deployment, evasion, credential theft,
  persistence, or unauthorized live target interaction.

## CI

GitHub Actions runs the same Rust quality gate and raw-fixture smoke checks via
`.github/workflows/ci.yml`.
