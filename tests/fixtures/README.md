# Test Fixtures

Fixtures in this directory are intentionally tiny. They support CLI smoke tests
without requiring real executable samples in the repository.

`raw.bin` is arbitrary bytes and should be detected as unknown input, then
loaded through the raw loader fallback.

