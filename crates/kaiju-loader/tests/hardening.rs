use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

use kaiju_core::KaijuErrorKind;
use kaiju_loader::{load_bytes, BinaryFormat};

#[test]
fn hostile_magic_headers_return_clean_results_without_panics() {
    let cases: Vec<(&str, Vec<u8>, ExpectedResult)> = vec![
        (
            "empty",
            Vec::new(),
            ExpectedResult::Loaded(BinaryFormat::Raw),
        ),
        (
            "unknown-bytes",
            b"not an executable".to_vec(),
            ExpectedResult::Loaded(BinaryFormat::Raw),
        ),
        (
            "truncated-elf-ident",
            b"\x7fELF".to_vec(),
            ExpectedResult::Malformed,
        ),
        (
            "unsupported-elf-class",
            b"\x7fELF\xff\x01\x01\x00".to_vec(),
            ExpectedResult::Malformed,
        ),
        (
            "unsupported-elf-endian",
            b"\x7fELF\x02\xff\x01\x00".to_vec(),
            ExpectedResult::Malformed,
        ),
        (
            "weak-dos-header",
            b"MZ".to_vec(),
            ExpectedResult::Loaded(BinaryFormat::Raw),
        ),
        (
            "missing-pe-signature",
            minimal_dos_with_lfanew().to_vec(),
            ExpectedResult::Loaded(BinaryFormat::Raw),
        ),
        (
            "truncated-pe-coff",
            minimal_pe_signature(),
            ExpectedResult::Malformed,
        ),
        (
            "truncated-mach-o",
            vec![0xcf, 0xfa, 0xed, 0xfe],
            ExpectedResult::Malformed,
        ),
        (
            "truncated-fat-mach-o",
            vec![0xca, 0xfe, 0xba, 0xbe],
            ExpectedResult::Loaded(BinaryFormat::MachO),
        ),
    ];

    for (name, bytes, expected) in &cases {
        let result = load_without_panic(name, bytes);
        match *expected {
            ExpectedResult::Loaded(format) => {
                let binary = result.expect("input should load conservatively");
                assert_eq!(binary.format, format, "{name}");
                assert_eq!(binary.file_size, bytes.len() as u64, "{name}");
                assert_eq!(&binary.bytes, bytes, "{name}");
            }
            ExpectedResult::Malformed => {
                let error = result.expect_err("recognized malformed input should fail");
                assert_eq!(error.kind(), KaijuErrorKind::MalformedBinary, "{name}");
            }
        }
    }
}

#[test]
fn deterministic_mutation_sweep_never_panics() {
    for (seed_name, seed) in mutation_seeds() {
        for mutation in mutate(&seed) {
            let name = format!("{seed_name}-{}", mutation.name);
            let result = load_without_panic(&name, &mutation.bytes);
            if let Ok(binary) = result {
                assert_eq!(binary.file_size, mutation.bytes.len() as u64, "{name}");
                assert_eq!(binary.bytes, mutation.bytes, "{name}");
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum ExpectedResult {
    Loaded(BinaryFormat),
    Malformed,
}

struct Mutation {
    name: String,
    bytes: Vec<u8>,
}

fn load_without_panic(
    name: &str,
    bytes: &[u8],
) -> Result<kaiju_loader::LoadedBinary, kaiju_core::KaijuError> {
    catch_unwind(AssertUnwindSafe(|| {
        load_bytes(PathBuf::from(format!("{name}.bin")), bytes)
    }))
    .unwrap_or_else(|_| panic!("loader panicked for {name}"))
}

fn mutation_seeds() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("empty", Vec::new()),
        ("ascii", b"Kaiju raw fixture".to_vec()),
        ("elf-ident", b"\x7fELF\x02\x01\x01".to_vec()),
        ("pe-dos", b"MZ".to_vec()),
        ("mach-o-le64", vec![0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0]),
        ("mach-o-fat", vec![0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0]),
        ("zero-page", vec![0; 128]),
        ("ff-page", vec![0xff; 128]),
    ]
}

fn mutate(seed: &[u8]) -> Vec<Mutation> {
    let mut cases = Vec::new();
    cases.push(Mutation {
        name: "identity".to_string(),
        bytes: seed.to_vec(),
    });

    for len in [0, 1, 2, 3, 4, 8, 16, 32, seed.len()] {
        let take = len.min(seed.len());
        cases.push(Mutation {
            name: format!("trunc-{take}"),
            bytes: seed[..take].to_vec(),
        });
    }

    for index in 0..seed.len().min(32) {
        let mut bytes = seed.to_vec();
        bytes[index] ^= 0xff;
        cases.push(Mutation {
            name: format!("flip-{index}"),
            bytes,
        });
    }

    for len in [1, 2, 4, 8, 16, 64, 256] {
        let mut bytes = seed.to_vec();
        bytes.extend((0..len).map(|index| deterministic_byte(seed.len(), index)));
        cases.push(Mutation {
            name: format!("extend-{len}"),
            bytes,
        });
    }

    cases
}

fn deterministic_byte(seed_len: usize, index: usize) -> u8 {
    let value = seed_len
        .wrapping_mul(1_103_515_245)
        .wrapping_add(index.wrapping_mul(12_345))
        .wrapping_add(0xa5);
    (value & 0xff) as u8
}

fn minimal_dos_with_lfanew() -> &'static [u8] {
    &[
        b'M', b'Z', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0x40, 0, 0, 0,
    ]
}

fn minimal_pe_signature() -> Vec<u8> {
    let mut bytes = vec![0; 0x44];
    bytes[0] = b'M';
    bytes[1] = b'Z';
    bytes[0x3c] = 0x40;
    bytes[0x40..0x44].copy_from_slice(b"PE\0\0");
    bytes
}
