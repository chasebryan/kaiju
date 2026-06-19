#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;

pub type Result<T> = std::result::Result<T, KaijuError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address(u64);

impl Address {
    pub const ZERO: Self = Self(0);
    pub const MAX: Self = Self(u64::MAX);

    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    #[must_use]
    pub fn checked_add(self, offset: u64) -> Option<Self> {
        self.0.checked_add(offset).map(Self)
    }

    #[must_use]
    pub fn checked_sub(self, offset: u64) -> Option<Self> {
        self.0.checked_sub(offset).map(Self)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "0x{:016x}", self.0)
    }
}

impl From<u64> for Address {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressRange {
    start: Address,
    size: u64,
}

impl AddressRange {
    #[must_use]
    pub const fn new(start: Address, size: u64) -> Self {
        Self { start, size }
    }

    #[must_use]
    pub const fn start(self) -> Address {
        self.start
    }

    #[must_use]
    pub const fn size(self) -> u64 {
        self.size
    }

    #[must_use]
    pub fn end(self) -> Option<Address> {
        self.start.checked_add(self.size)
    }

    #[must_use]
    pub fn contains(self, address: Address) -> bool {
        if address.value() < self.start.value() {
            return false;
        }

        address.value() - self.start.value() < self.size
    }

    #[must_use]
    pub fn contains_range(self, start: Address, size: u64) -> bool {
        if size == 0 {
            return start.value() >= self.start.value()
                && start.value() <= self.start.value().saturating_add(self.size);
        }

        let Some(last_offset) = size.checked_sub(1) else {
            return false;
        };
        let Some(last_address) = start.checked_add(last_offset) else {
            return false;
        };

        self.contains(start) && self.contains(last_address)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
    Unknown,
}

impl fmt::Display for Endian {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Little => formatter.write_str("Little"),
            Self::Big => formatter.write_str("Big"),
            Self::Unknown => formatter.write_str("Unknown"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchitectureId {
    X86,
    X86_64,
    Arm,
    Aarch64,
    Unknown,
}

impl fmt::Display for ArchitectureId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X86 => formatter.write_str("x86"),
            Self::X86_64 => formatter.write_str("x86_64"),
            Self::Arm => formatter.write_str("arm"),
            Self::Aarch64 => formatter.write_str("aarch64"),
            Self::Unknown => formatter.write_str("Unknown"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteSpan {
    offset: u64,
    len: u64,
}

impl ByteSpan {
    #[must_use]
    pub const fn new(offset: u64, len: u64) -> Self {
        Self { offset, len }
    }

    #[must_use]
    pub const fn offset(self) -> u64 {
        self.offset
    }

    #[must_use]
    pub const fn len(self) -> u64 {
        self.len
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl Permissions {
    #[must_use]
    pub const fn new(read: bool, write: bool, execute: bool) -> Self {
        Self {
            read,
            write,
            execute,
        }
    }

    #[must_use]
    pub const fn read_only() -> Self {
        Self::new(true, false, false)
    }

    #[must_use]
    pub const fn read_execute() -> Self {
        Self::new(true, false, true)
    }
}

impl fmt::Display for Permissions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let read = if self.read { 'r' } else { '-' };
        let write = if self.write { 'w' } else { '-' };
        let execute = if self.execute { 'x' } else { '-' };
        write!(formatter, "{read}{write}{execute}")
    }
}

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub name: String,
    pub address: Address,
    pub file_offset: Option<u64>,
    pub size: u64,
    pub permissions: Permissions,
    pub bytes: Vec<u8>,
}

impl MemoryRegion {
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        address: Address,
        file_offset: Option<u64>,
        permissions: Permissions,
        bytes: Vec<u8>,
    ) -> Self {
        let size = bytes.len() as u64;
        Self {
            name: name.into(),
            address,
            file_offset,
            size,
            permissions,
            bytes,
        }
    }

    pub fn new_with_size(
        name: impl Into<String>,
        address: Address,
        file_offset: Option<u64>,
        size: u64,
        permissions: Permissions,
        bytes: Vec<u8>,
    ) -> Result<Self> {
        let initialized_size = u64::try_from(bytes.len()).map_err(|_| {
            KaijuError::new(
                KaijuErrorKind::InvalidAddress,
                "initialized region byte length does not fit in u64",
            )
        })?;

        if initialized_size > size {
            return Err(KaijuError::new(
                KaijuErrorKind::InvalidAddress,
                "initialized region byte length exceeds declared region size",
            ));
        }

        Ok(Self {
            name: name.into(),
            address,
            file_offset,
            size,
            permissions,
            bytes,
        })
    }

    #[must_use]
    pub const fn range(&self) -> AddressRange {
        AddressRange::new(self.address, self.size)
    }

    #[must_use]
    pub fn contains(&self, address: Address) -> bool {
        self.range().contains(address)
    }

    #[must_use]
    pub fn contains_range(&self, address: Address, size: u64) -> bool {
        self.range().contains_range(address, size)
    }

    pub fn read_range(&self, address: Address, len: usize) -> Result<Vec<u8>> {
        if len == 0 {
            return Ok(Vec::new());
        }

        let len_u64 = u64::try_from(len).map_err(|_| {
            KaijuError::new(
                KaijuErrorKind::InvalidAddress,
                "requested read length does not fit in u64",
            )
        })?;

        if !self.contains_range(address, len_u64) {
            return Err(KaijuError::new(
                KaijuErrorKind::UnmappedAddress,
                format!(
                    "address range starting at {address} with length {len} is outside region {}",
                    self.name
                ),
            ));
        }

        let offset = address
            .value()
            .checked_sub(self.address.value())
            .ok_or_else(|| {
                KaijuError::new(
                    KaijuErrorKind::InvalidAddress,
                    "region-relative address underflow",
                )
            })?;
        let start = usize::try_from(offset).map_err(|_| {
            KaijuError::new(
                KaijuErrorKind::InvalidAddress,
                "region-relative address does not fit in usize",
            )
        })?;
        let end = start.checked_add(len).ok_or_else(|| {
            KaijuError::new(KaijuErrorKind::InvalidAddress, "read length overflow")
        })?;

        if end <= self.bytes.len() {
            let Some(bytes) = self.bytes.get(start..end) else {
                return Err(KaijuError::new(
                    KaijuErrorKind::InternalInvariant,
                    "validated initialized read failed",
                ));
            };

            return Ok(bytes.to_vec());
        }

        let mut result = Vec::with_capacity(len);
        if start < self.bytes.len() {
            let Some(initialized) = self.bytes.get(start..) else {
                return Err(KaijuError::new(
                    KaijuErrorKind::InternalInvariant,
                    "validated partial initialized read failed",
                ));
            };
            result.extend_from_slice(initialized);
        }
        result.resize(len, 0);
        Ok(result)
    }

    #[must_use]
    pub fn translate_to_file_offset(&self, address: Address) -> Option<u64> {
        if !self.contains(address) {
            return None;
        }

        let relative = address.value().checked_sub(self.address.value())?;
        if relative >= u64::try_from(self.bytes.len()).ok()? {
            return None;
        }

        self.file_offset?.checked_add(relative)
    }

    #[must_use]
    pub fn translate_file_offset_to_virtual(&self, file_offset: u64) -> Option<Address> {
        let region_file_offset = self.file_offset?;
        if file_offset < region_file_offset {
            return None;
        }

        let relative = file_offset.checked_sub(region_file_offset)?;
        if relative >= u64::try_from(self.bytes.len()).ok()? {
            return None;
        }

        self.address.checked_add(relative)
    }
}

#[derive(Debug, Clone, Default)]
pub struct MemoryMap {
    regions: Vec<MemoryRegion>,
}

impl MemoryMap {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            regions: Vec::new(),
        }
    }

    pub fn add_region(&mut self, region: MemoryRegion) {
        self.regions.push(region);
        self.regions.sort_by_key(|entry| entry.address);
    }

    #[must_use]
    pub fn regions(&self) -> &[MemoryRegion] {
        &self.regions
    }

    #[must_use]
    pub fn find_region(&self, address: Address) -> Option<&MemoryRegion> {
        self.regions.iter().find(|region| region.contains(address))
    }

    #[must_use]
    pub fn executable_regions(&self) -> Vec<&MemoryRegion> {
        self.regions
            .iter()
            .filter(|region| region.permissions.execute)
            .collect()
    }

    #[must_use]
    pub fn readable_regions(&self) -> Vec<&MemoryRegion> {
        self.regions
            .iter()
            .filter(|region| region.permissions.read)
            .collect()
    }

    pub fn read_byte(&self, address: Address) -> Result<u8> {
        let bytes = self.read_range(address, 1)?;
        bytes.first().copied().ok_or_else(|| {
            KaijuError::new(
                KaijuErrorKind::InternalInvariant,
                "single-byte read returned no bytes",
            )
        })
    }

    pub fn read_range(&self, address: Address, len: usize) -> Result<Vec<u8>> {
        if len == 0 {
            return Ok(Vec::new());
        }

        let region = self.find_region(address).ok_or_else(|| {
            KaijuError::new(
                KaijuErrorKind::UnmappedAddress,
                format!("address {address} is not mapped"),
            )
        })?;

        region.read_range(address, len)
    }

    #[must_use]
    pub fn translate_virtual_to_file_offset(&self, address: Address) -> Option<u64> {
        self.find_region(address)
            .and_then(|region| region.translate_to_file_offset(address))
    }

    #[must_use]
    pub fn translate_file_offset_to_virtual(&self, file_offset: u64) -> Option<Address> {
        self.regions
            .iter()
            .find_map(|region| region.translate_file_offset_to_virtual(file_offset))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KaijuErrorKind {
    Io,
    UnsupportedFormat,
    UnsupportedArchitecture,
    MalformedBinary,
    InvalidAddress,
    UnmappedAddress,
    DecodeError,
    AnalysisLimitExceeded,
    InternalInvariant,
}

#[derive(Debug)]
pub struct KaijuError {
    kind: KaijuErrorKind,
    message: String,
}

impl KaijuError {
    #[must_use]
    pub fn new(kind: KaijuErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> KaijuErrorKind {
        self.kind
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for KaijuError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.kind, self.message)
    }
}

impl Error for KaijuError {}

impl From<std::io::Error> for KaijuError {
    fn from(error: std::io::Error) -> Self {
        Self::new(KaijuErrorKind::Io, error.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub severity: DiagnosticSeverity,
    pub message: String,
}

impl Diagnostic {
    #[must_use]
    pub fn new(severity: DiagnosticSeverity, message: impl Into<String>) -> Self {
        Self {
            severity,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticSeverity {
    Note,
    Warning,
    Error,
}

#[must_use]
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_arithmetic_is_checked() {
        assert_eq!(
            Address::new(0x10).checked_add(0x20),
            Some(Address::new(0x30))
        );
        assert_eq!(Address::MAX.checked_add(1), None);
        assert_eq!(
            Address::new(0x30).checked_sub(0x20),
            Some(Address::new(0x10))
        );
        assert_eq!(Address::ZERO.checked_sub(1), None);
    }

    #[test]
    fn memory_region_contains_addresses() {
        let region = MemoryRegion::new(
            "text",
            Address::new(0x1000),
            Some(0),
            Permissions::read_execute(),
            vec![0x90, 0x90, 0xc3],
        );

        assert!(region.contains(Address::new(0x1000)));
        assert!(region.contains(Address::new(0x1002)));
        assert!(!region.contains(Address::new(0x1003)));
    }

    #[test]
    fn memory_map_finds_region_by_address() {
        let mut map = MemoryMap::new();
        map.add_region(MemoryRegion::new(
            "raw",
            Address::new(0),
            Some(0),
            Permissions::read_only(),
            b"kaiju".to_vec(),
        ));

        let region = map
            .find_region(Address::new(2))
            .expect("region should exist");
        assert_eq!(region.name, "raw");
        assert!(map.find_region(Address::new(5)).is_none());
    }

    #[test]
    fn memory_map_reads_bytes() {
        let mut map = MemoryMap::new();
        map.add_region(MemoryRegion::new(
            "raw",
            Address::new(0x10),
            Some(0),
            Permissions::read_only(),
            vec![1, 2, 3, 4],
        ));

        assert_eq!(map.read_byte(Address::new(0x11)).expect("read"), 2);
        assert_eq!(
            map.read_range(Address::new(0x12), 2).expect("read range"),
            vec![3, 4]
        );
    }

    #[test]
    fn memory_map_reads_zero_fill_inside_declared_region() {
        let mut map = MemoryMap::new();
        map.add_region(
            MemoryRegion::new_with_size(
                "bss",
                Address::new(0x20),
                Some(0x100),
                4,
                Permissions::read_only(),
                vec![1, 2],
            )
            .expect("region should be valid"),
        );

        assert_eq!(
            map.read_range(Address::new(0x20), 4)
                .expect("read zero-filled range"),
            vec![1, 2, 0, 0]
        );
        assert_eq!(
            map.translate_virtual_to_file_offset(Address::new(0x21)),
            Some(0x101)
        );
        assert_eq!(
            map.translate_virtual_to_file_offset(Address::new(0x22)),
            None
        );
        assert_eq!(
            map.translate_file_offset_to_virtual(0x101),
            Some(Address::new(0x21))
        );
        assert_eq!(map.translate_file_offset_to_virtual(0x102), None);
    }

    #[test]
    fn memory_map_rejects_out_of_range_read() {
        let mut map = MemoryMap::new();
        map.add_region(MemoryRegion::new(
            "raw",
            Address::new(0),
            Some(0),
            Permissions::read_only(),
            vec![1, 2, 3, 4],
        ));

        let error = map
            .read_range(Address::new(3), 2)
            .expect_err("read should fail");
        assert_eq!(error.kind(), KaijuErrorKind::UnmappedAddress);
    }
}
