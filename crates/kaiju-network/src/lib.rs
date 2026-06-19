#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::{Duration, Instant};

use kaiju_core::{KaijuError, KaijuErrorKind, Result};

pub const DEFAULT_PROBE_TIMEOUT_MS: u64 = 1_000;
pub const DEFAULT_PROBE_READ_BYTES: usize = 256;
pub const MAX_PROBE_TARGETS: usize = 1_024;
pub const MAX_PORT_SCAN_PORTS: usize = 1_024;
pub const MAX_PROBE_PAYLOAD_BYTES: usize = 4_096;
pub const MAX_CAPTURE_PAYLOAD_BYTES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkMap {
    source_name: String,
    hosts: Vec<NetworkHost>,
    services: Vec<NetworkService>,
    edges: Vec<NetworkEdge>,
    observations: Vec<NetworkObservation>,
    ignored_lines: usize,
}

impl NetworkMap {
    #[must_use]
    pub fn source_name(&self) -> &str {
        &self.source_name
    }

    #[must_use]
    pub fn hosts(&self) -> &[NetworkHost] {
        &self.hosts
    }

    #[must_use]
    pub fn services(&self) -> &[NetworkService] {
        &self.services
    }

    #[must_use]
    pub fn edges(&self) -> &[NetworkEdge] {
        &self.edges
    }

    #[must_use]
    pub fn observations(&self) -> &[NetworkObservation] {
        &self.observations
    }

    #[must_use]
    pub const fn ignored_lines(&self) -> usize {
        self.ignored_lines
    }

    #[must_use]
    pub fn summary(&self) -> NetworkSummary {
        NetworkSummary {
            hosts: self.hosts.len(),
            services: self.services.len(),
            edges: self.edges.len(),
            observations: self.observations.len(),
            ignored_lines: self.ignored_lines,
        }
    }

    #[must_use]
    pub fn to_json_pretty(&self) -> String {
        let summary = self.summary();
        let mut json = String::new();
        json.push_str("{\n");
        json.push_str("  \"schema\": \"kaiju.network.v1\",\n");
        push_json_field(&mut json, 2, "source", self.source_name(), true);
        json.push_str("  \"summary\": {\n");
        push_json_usize_field(&mut json, 4, "hosts", summary.hosts, true);
        push_json_usize_field(&mut json, 4, "services", summary.services, true);
        push_json_usize_field(&mut json, 4, "edges", summary.edges, true);
        push_json_usize_field(&mut json, 4, "observations", summary.observations, true);
        push_json_usize_field(&mut json, 4, "ignored_lines", summary.ignored_lines, false);
        json.push_str("  },\n");
        push_hosts_json(&mut json, self);
        json.push_str(",\n");
        push_services_json(&mut json, self);
        json.push_str(",\n");
        push_edges_json(&mut json, self);
        json.push_str(",\n");
        push_observations_json(&mut json, self);
        json.push('\n');
        json.push('}');
        json
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkSummary {
    pub hosts: usize,
    pub services: usize,
    pub edges: usize,
    pub observations: usize,
    pub ignored_lines: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkHost {
    pub id: String,
    pub kind: NetworkHostKind,
    pub observation_lines: Vec<usize>,
}

impl NetworkHost {
    #[must_use]
    pub fn observation_count(&self) -> usize {
        self.observation_lines.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NetworkHostKind {
    Ipv4,
    Ipv6,
    Domain,
    Hostname,
}

impl fmt::Display for NetworkHostKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipv4 => formatter.write_str("ipv4"),
            Self::Ipv6 => formatter.write_str("ipv6"),
            Self::Domain => formatter.write_str("domain"),
            Self::Hostname => formatter.write_str("hostname"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkService {
    pub host: String,
    pub port: u16,
    pub protocol: Option<NetworkProtocol>,
    pub observation_lines: Vec<usize>,
}

impl NetworkService {
    #[must_use]
    pub fn observation_count(&self) -> usize {
        self.observation_lines.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkEdge {
    pub source: String,
    pub destination: String,
    pub protocol: Option<NetworkProtocol>,
    pub port: Option<u16>,
    pub observation_lines: Vec<usize>,
}

impl NetworkEdge {
    #[must_use]
    pub fn observation_count(&self) -> usize {
        self.observation_lines.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkObservation {
    pub line: usize,
    pub source: Option<NetworkEndpoint>,
    pub destination: NetworkEndpoint,
    pub protocol: Option<NetworkProtocol>,
    pub payload: Option<PayloadInspection>,
    pub evidence: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkEndpoint {
    pub host: String,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Icmp,
    Http,
    Https,
    Dns,
    Other(String),
}

impl fmt::Display for NetworkProtocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => formatter.write_str("tcp"),
            Self::Udp => formatter.write_str("udp"),
            Self::Icmp => formatter.write_str("icmp"),
            Self::Http => formatter.write_str("http"),
            Self::Https => formatter.write_str("https"),
            Self::Dns => formatter.write_str("dns"),
            Self::Other(value) => formatter.write_str(value),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadInspection {
    pub byte_len: usize,
    pub captured_len: usize,
    pub kind: PayloadKind,
    pub ascii_preview: String,
    pub hex_prefix: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PayloadKind {
    Empty,
    Http,
    Tls,
    Text,
    Binary,
}

impl fmt::Display for PayloadKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("empty"),
            Self::Http => formatter.write_str("http"),
            Self::Tls => formatter.write_str("tls"),
            Self::Text => formatter.write_str("text"),
            Self::Binary => formatter.write_str("binary"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeTarget {
    pub host: String,
    pub port: u16,
}

impl ProbeTarget {
    #[must_use]
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    #[must_use]
    pub fn label(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    fn socket_spec(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeOptions {
    pub timeout_ms: u64,
    pub read_bytes: usize,
    pub payload: Vec<u8>,
}

impl Default for ProbeOptions {
    fn default() -> Self {
        Self {
            timeout_ms: DEFAULT_PROBE_TIMEOUT_MS,
            read_bytes: DEFAULT_PROBE_READ_BYTES,
            payload: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeReport {
    pub mode: ProbeMode,
    pub results: Vec<ProbeResult>,
}

impl ProbeReport {
    #[must_use]
    pub fn to_json_pretty(&self) -> String {
        let mut json = String::new();
        json.push_str("{\n");
        json.push_str("  \"schema\": \"kaiju.network.probe.v1\",\n");
        push_json_field(&mut json, 2, "mode", &self.mode.to_string(), true);
        push_json_usize_field(&mut json, 2, "targets", self.results.len(), true);
        push_json_usize_field(&mut json, 2, "open", self.open_count(), true);
        push_json_usize_field(&mut json, 2, "closed", self.closed_count(), true);
        push_json_usize_field(&mut json, 2, "errors", self.error_count(), true);
        push_probe_results_json(&mut json, self);
        json.push('\n');
        json.push('}');
        json
    }

    #[must_use]
    pub fn open_count(&self) -> usize {
        self.results
            .iter()
            .filter(|result| result.status == ProbeStatus::Open)
            .count()
    }

    #[must_use]
    pub fn closed_count(&self) -> usize {
        self.results
            .iter()
            .filter(|result| result.status == ProbeStatus::Closed)
            .count()
    }

    #[must_use]
    pub fn error_count(&self) -> usize {
        self.results
            .iter()
            .filter(|result| {
                matches!(
                    result.status,
                    ProbeStatus::Timeout | ProbeStatus::ResolveFailed | ProbeStatus::Error
                )
            })
            .count()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeMode {
    Probe,
    Scan,
}

impl fmt::Display for ProbeMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Probe => formatter.write_str("probe"),
            Self::Scan => formatter.write_str("scan"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResult {
    pub target: ProbeTarget,
    pub status: ProbeStatus,
    pub remote_addr: Option<String>,
    pub elapsed_ms: u128,
    pub sent_bytes: usize,
    pub received: PayloadInspection,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProbeStatus {
    Open,
    Closed,
    Timeout,
    ResolveFailed,
    Error,
}

impl fmt::Display for ProbeStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open => formatter.write_str("open"),
            Self::Closed => formatter.write_str("closed"),
            Self::Timeout => formatter.write_str("timeout"),
            Self::ResolveFailed => formatter.write_str("resolve-failed"),
            Self::Error => formatter.write_str("error"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedEndpoint {
    endpoint: NetworkEndpoint,
    protocol_hint: Option<NetworkProtocol>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PcapHeader {
    endian: PcapEndian,
    link_type: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PcapEndian {
    Little,
    Big,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ServiceKey {
    host: String,
    port: u16,
    protocol: Option<NetworkProtocol>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct EdgeKey {
    source: String,
    destination: String,
    protocol: Option<NetworkProtocol>,
    port: Option<u16>,
}

#[derive(Debug, Clone)]
struct NetworkMapBuilder {
    source_name: String,
    hosts: BTreeMap<String, NetworkHost>,
    services: BTreeMap<ServiceKey, NetworkService>,
    edges: BTreeMap<EdgeKey, NetworkEdge>,
    observations: Vec<NetworkObservation>,
    ignored_lines: usize,
}

impl NetworkMapBuilder {
    fn new(source_name: impl Into<String>) -> Self {
        Self {
            source_name: source_name.into(),
            hosts: BTreeMap::new(),
            services: BTreeMap::new(),
            edges: BTreeMap::new(),
            observations: Vec::new(),
            ignored_lines: 0,
        }
    }

    fn add_observation(&mut self, observation: NetworkObservation) {
        self.add_endpoint(&observation.destination, observation.line);
        if let Some(source) = &observation.source {
            self.add_endpoint(source, observation.line);
            self.add_edge(source, &observation);
        }
        self.add_service(
            &observation.destination,
            observation.protocol.clone(),
            observation.line,
        );
        self.observations.push(observation);
    }

    fn add_endpoint(&mut self, endpoint: &NetworkEndpoint, line: usize) {
        let host = endpoint.host.clone();
        let entry = self
            .hosts
            .entry(host.clone())
            .or_insert_with(|| NetworkHost {
                kind: classify_host(&host),
                id: host,
                observation_lines: Vec::new(),
            });
        push_unique_line(&mut entry.observation_lines, line);
    }

    fn add_service(
        &mut self,
        endpoint: &NetworkEndpoint,
        protocol: Option<NetworkProtocol>,
        line: usize,
    ) {
        let Some(port) = endpoint.port else {
            return;
        };
        let key = ServiceKey {
            host: endpoint.host.clone(),
            port,
            protocol: protocol.clone(),
        };
        let entry = self.services.entry(key).or_insert_with(|| NetworkService {
            host: endpoint.host.clone(),
            port,
            protocol,
            observation_lines: Vec::new(),
        });
        push_unique_line(&mut entry.observation_lines, line);
    }

    fn add_edge(&mut self, source: &NetworkEndpoint, observation: &NetworkObservation) {
        let key = EdgeKey {
            source: source.host.clone(),
            destination: observation.destination.host.clone(),
            protocol: observation.protocol.clone(),
            port: observation.destination.port,
        };
        let entry = self.edges.entry(key).or_insert_with(|| NetworkEdge {
            source: source.host.clone(),
            destination: observation.destination.host.clone(),
            protocol: observation.protocol.clone(),
            port: observation.destination.port,
            observation_lines: Vec::new(),
        });
        push_unique_line(&mut entry.observation_lines, observation.line);
    }

    fn finish(self) -> NetworkMap {
        NetworkMap {
            source_name: self.source_name,
            hosts: self.hosts.into_values().collect(),
            services: self.services.into_values().collect(),
            edges: self.edges.into_values().collect(),
            observations: self.observations,
            ignored_lines: self.ignored_lines,
        }
    }
}

pub fn load_network_evidence(path: impl AsRef<Path>) -> Result<NetworkMap> {
    let path = path.as_ref();
    let text = fs::read_to_string(path).map_err(|error| {
        KaijuError::new(
            KaijuErrorKind::Io,
            format!(
                "failed to read network evidence {}: {error}",
                path.display()
            ),
        )
    })?;
    Ok(parse_network_evidence(path.display().to_string(), &text))
}

pub fn probe_targets(targets: Vec<ProbeTarget>, options: ProbeOptions) -> Result<ProbeReport> {
    validate_probe_request(&targets, &options)?;
    let results = targets
        .iter()
        .map(|target| probe_target(target, &options))
        .collect();
    Ok(ProbeReport {
        mode: ProbeMode::Probe,
        results,
    })
}

pub fn scan_ports(
    host: impl Into<String>,
    ports: Vec<u16>,
    options: ProbeOptions,
) -> Result<ProbeReport> {
    if ports.is_empty() {
        return Err(KaijuError::new(
            KaijuErrorKind::InvalidAddress,
            "network scan requires at least one port",
        ));
    }
    if ports.len() > MAX_PORT_SCAN_PORTS {
        return Err(KaijuError::new(
            KaijuErrorKind::AnalysisLimitExceeded,
            format!(
                "network scan has {} ports, limit is {MAX_PORT_SCAN_PORTS}",
                ports.len()
            ),
        ));
    }

    let host = host.into();
    let targets = ports
        .into_iter()
        .map(|port| ProbeTarget::new(host.clone(), port))
        .collect::<Vec<_>>();
    validate_probe_request(&targets, &options)?;
    let results = targets
        .iter()
        .map(|target| probe_target(target, &options))
        .collect();
    Ok(ProbeReport {
        mode: ProbeMode::Scan,
        results,
    })
}

pub fn load_pcap_evidence(path: impl AsRef<Path>) -> Result<NetworkMap> {
    let path = path.as_ref();
    let bytes = fs::read(path).map_err(|error| {
        KaijuError::new(
            KaijuErrorKind::Io,
            format!("failed to read packet capture {}: {error}", path.display()),
        )
    })?;
    parse_pcap_evidence(path.display().to_string(), &bytes)
}

pub fn parse_pcap_evidence(source_name: impl Into<String>, bytes: &[u8]) -> Result<NetworkMap> {
    let header = parse_pcap_header(bytes)?;
    if header.link_type != 1 {
        return Err(KaijuError::new(
            KaijuErrorKind::UnsupportedFormat,
            format!(
                "unsupported pcap link type {}, only Ethernet is supported",
                header.link_type
            ),
        ));
    }

    let mut builder = NetworkMapBuilder::new(source_name);
    let mut offset = 24;
    let mut packet_index = 0;
    while offset < bytes.len() {
        packet_index += 1;
        if bytes.len().saturating_sub(offset) < 16 {
            return Err(KaijuError::new(
                KaijuErrorKind::MalformedBinary,
                "truncated pcap packet header",
            ));
        }

        let included_len = read_pcap_u32(bytes, offset + 8, header.endian)? as usize;
        let record_start = offset + 16;
        let record_end = record_start.checked_add(included_len).ok_or_else(|| {
            KaijuError::new(
                KaijuErrorKind::AnalysisLimitExceeded,
                "pcap packet length overflow",
            )
        })?;
        if record_end > bytes.len() {
            return Err(KaijuError::new(
                KaijuErrorKind::MalformedBinary,
                "pcap packet data extends past end of file",
            ));
        }

        let packet = &bytes[record_start..record_end];
        match parse_ethernet_packet(packet_index, packet) {
            Some(observation) => builder.add_observation(observation),
            None => builder.ignored_lines += 1,
        }
        offset = record_end;
    }

    Ok(builder.finish())
}

#[must_use]
pub fn parse_probe_target(value: &str) -> Option<ProbeTarget> {
    let endpoint = parse_endpoint_token(value, true)?.endpoint;
    Some(ProbeTarget {
        host: endpoint.host,
        port: endpoint.port?,
    })
}

pub fn parse_port_spec(value: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();
    for raw_part in value.split(',') {
        let part = raw_part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start, end)) = part.split_once('-') {
            let start = parse_scan_port(start)?;
            let end = parse_scan_port(end)?;
            if start > end {
                return Err(KaijuError::new(
                    KaijuErrorKind::InvalidAddress,
                    format!("invalid descending port range: {part}"),
                ));
            }
            for port in start..=end {
                push_unique_port(&mut ports, port);
            }
        } else {
            push_unique_port(&mut ports, parse_scan_port(part)?);
        }
        if ports.len() > MAX_PORT_SCAN_PORTS {
            return Err(KaijuError::new(
                KaijuErrorKind::AnalysisLimitExceeded,
                format!(
                    "port list has {} ports, limit is {MAX_PORT_SCAN_PORTS}",
                    ports.len()
                ),
            ));
        }
    }

    if ports.is_empty() {
        return Err(KaijuError::new(
            KaijuErrorKind::InvalidAddress,
            "port list is empty",
        ));
    }
    ports.sort_unstable();
    Ok(ports)
}

pub fn parse_hex_payload(value: &str) -> Result<Vec<u8>> {
    let hex = value
        .chars()
        .filter(|character| !character.is_whitespace() && *character != ':')
        .collect::<String>();
    if hex.len() % 2 != 0 {
        return Err(KaijuError::new(
            KaijuErrorKind::MalformedBinary,
            "hex payload has an odd number of digits",
        ));
    }
    let mut bytes = Vec::new();
    for pair in hex.as_bytes().chunks(2) {
        let text = std::str::from_utf8(pair).map_err(|error| {
            KaijuError::new(
                KaijuErrorKind::MalformedBinary,
                format!("hex payload is not valid UTF-8: {error}"),
            )
        })?;
        let byte = u8::from_str_radix(text, 16).map_err(|_| {
            KaijuError::new(
                KaijuErrorKind::MalformedBinary,
                format!("invalid hex payload byte: {text}"),
            )
        })?;
        bytes.push(byte);
    }
    Ok(bytes)
}

#[must_use]
pub fn inspect_payload(bytes: &[u8], max_preview_bytes: usize) -> PayloadInspection {
    let captured_len = bytes.len().min(max_preview_bytes);
    let captured = &bytes[..captured_len];
    PayloadInspection {
        byte_len: bytes.len(),
        captured_len,
        kind: classify_payload(bytes),
        ascii_preview: ascii_preview(captured),
        hex_prefix: hex_prefix(captured),
    }
}

fn validate_probe_request(targets: &[ProbeTarget], options: &ProbeOptions) -> Result<()> {
    if targets.is_empty() {
        return Err(KaijuError::new(
            KaijuErrorKind::InvalidAddress,
            "network probe requires at least one target",
        ));
    }
    if targets.len() > MAX_PROBE_TARGETS {
        return Err(KaijuError::new(
            KaijuErrorKind::AnalysisLimitExceeded,
            format!(
                "network probe has {} targets, limit is {MAX_PROBE_TARGETS}",
                targets.len()
            ),
        ));
    }
    if options.timeout_ms == 0 {
        return Err(KaijuError::new(
            KaijuErrorKind::InvalidAddress,
            "network probe timeout must be greater than zero",
        ));
    }
    if options.read_bytes > MAX_PROBE_PAYLOAD_BYTES {
        return Err(KaijuError::new(
            KaijuErrorKind::AnalysisLimitExceeded,
            format!(
                "network probe reads {} bytes, limit is {MAX_PROBE_PAYLOAD_BYTES}",
                options.read_bytes
            ),
        ));
    }
    if options.payload.len() > MAX_PROBE_PAYLOAD_BYTES {
        return Err(KaijuError::new(
            KaijuErrorKind::AnalysisLimitExceeded,
            format!(
                "network probe payload has {} bytes, limit is {MAX_PROBE_PAYLOAD_BYTES}",
                options.payload.len()
            ),
        ));
    }
    for target in targets {
        if target.host.trim().is_empty() || target.port == 0 {
            return Err(KaijuError::new(
                KaijuErrorKind::InvalidAddress,
                format!("invalid network probe target: {}", target.label()),
            ));
        }
    }
    Ok(())
}

fn probe_target(target: &ProbeTarget, options: &ProbeOptions) -> ProbeResult {
    let started = Instant::now();
    let timeout = Duration::from_millis(options.timeout_ms);
    let addresses = match target.socket_spec().to_socket_addrs() {
        Ok(addresses) => addresses.collect::<Vec<_>>(),
        Err(error) => {
            return probe_result(
                target,
                ProbeStatus::ResolveFailed,
                None,
                started,
                0,
                Vec::new(),
                Some(error.to_string()),
            );
        }
    };

    if addresses.is_empty() {
        return probe_result(
            target,
            ProbeStatus::ResolveFailed,
            None,
            started,
            0,
            Vec::new(),
            Some("no socket addresses resolved".to_string()),
        );
    }

    let mut last_result = None;
    for address in addresses {
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(mut stream) => {
                let _ = stream.set_read_timeout(Some(timeout));
                let _ = stream.set_write_timeout(Some(timeout));
                if let Err(error) = stream.write_all(&options.payload) {
                    return probe_result(
                        target,
                        status_from_io_error(&error),
                        Some(address),
                        started,
                        0,
                        Vec::new(),
                        Some(format!("write failed: {error}")),
                    );
                }

                let mut received = vec![0; options.read_bytes];
                let mut read_error = None;
                let read_len = if received.is_empty() {
                    0
                } else {
                    match stream.read(&mut received) {
                        Ok(size) => size,
                        Err(error)
                            if matches!(
                                error.kind(),
                                ErrorKind::WouldBlock | ErrorKind::TimedOut
                            ) =>
                        {
                            0
                        }
                        Err(error) => {
                            read_error = Some(format!("read failed: {error}"));
                            0
                        }
                    }
                };
                received.truncate(read_len);
                return probe_result(
                    target,
                    ProbeStatus::Open,
                    Some(address),
                    started,
                    options.payload.len(),
                    received,
                    read_error,
                );
            }
            Err(error) => {
                last_result = Some(probe_result(
                    target,
                    status_from_io_error(&error),
                    Some(address),
                    started,
                    0,
                    Vec::new(),
                    Some(error.to_string()),
                ));
            }
        }
    }

    last_result.unwrap_or_else(|| {
        probe_result(
            target,
            ProbeStatus::Error,
            None,
            started,
            0,
            Vec::new(),
            Some("probe did not attempt any address".to_string()),
        )
    })
}

fn probe_result(
    target: &ProbeTarget,
    status: ProbeStatus,
    remote_addr: Option<SocketAddr>,
    started: Instant,
    sent_bytes: usize,
    received: Vec<u8>,
    error: Option<String>,
) -> ProbeResult {
    ProbeResult {
        target: target.clone(),
        status,
        remote_addr: remote_addr.map(|address| address.to_string()),
        elapsed_ms: started.elapsed().as_millis(),
        sent_bytes,
        received: inspect_payload(&received, MAX_CAPTURE_PAYLOAD_BYTES),
        error,
    }
}

fn status_from_io_error(error: &std::io::Error) -> ProbeStatus {
    match error.kind() {
        ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset | ErrorKind::NotConnected => {
            ProbeStatus::Closed
        }
        ErrorKind::TimedOut | ErrorKind::WouldBlock => ProbeStatus::Timeout,
        _ => ProbeStatus::Error,
    }
}

fn parse_scan_port(value: &str) -> Result<u16> {
    parse_port(value).ok_or_else(|| {
        KaijuError::new(
            KaijuErrorKind::InvalidAddress,
            format!("invalid port: {}", value.trim()),
        )
    })
}

fn push_unique_port(ports: &mut Vec<u16>, port: u16) {
    if !ports.contains(&port) {
        ports.push(port);
    }
}

fn parse_pcap_header(bytes: &[u8]) -> Result<PcapHeader> {
    if bytes.len() < 24 {
        return Err(KaijuError::new(
            KaijuErrorKind::MalformedBinary,
            "pcap header is truncated",
        ));
    }

    let endian = match bytes[0..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => PcapEndian::Little,
        [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => PcapEndian::Big,
        _ => {
            return Err(KaijuError::new(
                KaijuErrorKind::UnsupportedFormat,
                "input is not a pcap capture",
            ))
        }
    };

    Ok(PcapHeader {
        endian,
        link_type: read_pcap_u32(bytes, 20, endian)?,
    })
}

fn read_pcap_u32(bytes: &[u8], offset: usize, endian: PcapEndian) -> Result<u32> {
    let end = offset.checked_add(4).ok_or_else(|| {
        KaijuError::new(
            KaijuErrorKind::AnalysisLimitExceeded,
            "pcap offset overflow",
        )
    })?;
    let Some(slice) = bytes.get(offset..end) else {
        return Err(KaijuError::new(
            KaijuErrorKind::MalformedBinary,
            "pcap u32 read extends past end of file",
        ));
    };
    let value = [slice[0], slice[1], slice[2], slice[3]];
    Ok(match endian {
        PcapEndian::Little => u32::from_le_bytes(value),
        PcapEndian::Big => u32::from_be_bytes(value),
    })
}

fn parse_ethernet_packet(packet_index: usize, packet: &[u8]) -> Option<NetworkObservation> {
    if packet.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([packet[12], packet[13]]);
    match ethertype {
        0x0800 => parse_ipv4_packet(packet_index, &packet[14..]),
        0x86dd => parse_ipv6_packet(packet_index, &packet[14..]),
        _ => None,
    }
}

fn parse_ipv4_packet(packet_index: usize, packet: &[u8]) -> Option<NetworkObservation> {
    if packet.len() < 20 {
        return None;
    }
    let version = packet[0] >> 4;
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if version != 4 || header_len < 20 || packet.len() < header_len {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < header_len || total_len > packet.len() {
        return None;
    }

    let source = format!(
        "{}.{}.{}.{}",
        packet[12], packet[13], packet[14], packet[15]
    );
    let destination = format!(
        "{}.{}.{}.{}",
        packet[16], packet[17], packet[18], packet[19]
    );
    parse_transport_observation(
        packet_index,
        &source,
        &destination,
        packet[9],
        &packet[header_len..total_len],
    )
}

fn parse_ipv6_packet(packet_index: usize, packet: &[u8]) -> Option<NetworkObservation> {
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let end = 40usize.checked_add(payload_len)?;
    if end > packet.len() {
        return None;
    }
    let source = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?);
    let destination = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?);
    parse_transport_observation(
        packet_index,
        &source.to_string(),
        &destination.to_string(),
        packet[6],
        &packet[40..end],
    )
}

fn parse_transport_observation(
    packet_index: usize,
    source_host: &str,
    destination_host: &str,
    protocol_number: u8,
    bytes: &[u8],
) -> Option<NetworkObservation> {
    let (protocol, source_port, destination_port, payload) = match protocol_number {
        6 => {
            if bytes.len() < 20 {
                return None;
            }
            let source_port = u16::from_be_bytes([bytes[0], bytes[1]]);
            let destination_port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let header_len = usize::from(bytes[12] >> 4) * 4;
            if header_len < 20 || header_len > bytes.len() {
                return None;
            }
            (
                Some(NetworkProtocol::Tcp),
                Some(source_port),
                Some(destination_port),
                &bytes[header_len..],
            )
        }
        17 => {
            if bytes.len() < 8 {
                return None;
            }
            let source_port = u16::from_be_bytes([bytes[0], bytes[1]]);
            let destination_port = u16::from_be_bytes([bytes[2], bytes[3]]);
            (
                Some(NetworkProtocol::Udp),
                Some(source_port),
                Some(destination_port),
                &bytes[8..],
            )
        }
        1 | 58 => (Some(NetworkProtocol::Icmp), None, None, bytes),
        _ => (
            Some(NetworkProtocol::Other(format!("proto-{protocol_number}"))),
            None,
            None,
            bytes,
        ),
    };

    Some(NetworkObservation {
        line: packet_index,
        source: Some(NetworkEndpoint {
            host: source_host.to_string(),
            port: source_port,
        }),
        destination: NetworkEndpoint {
            host: destination_host.to_string(),
            port: destination_port,
        },
        protocol,
        payload: Some(inspect_payload(payload, MAX_CAPTURE_PAYLOAD_BYTES)),
        evidence: format!("pcap packet {packet_index}"),
    })
}

fn classify_payload(bytes: &[u8]) -> PayloadKind {
    if bytes.is_empty() {
        return PayloadKind::Empty;
    }
    if bytes.starts_with(b"GET ")
        || bytes.starts_with(b"POST ")
        || bytes.starts_with(b"PUT ")
        || bytes.starts_with(b"DELETE ")
        || bytes.starts_with(b"HEAD ")
        || bytes.starts_with(b"OPTIONS ")
        || bytes.starts_with(b"PATCH ")
        || bytes.starts_with(b"HTTP/")
    {
        return PayloadKind::Http;
    }
    if bytes.len() >= 3 && bytes[0] == 0x16 && bytes[1] == 0x03 && bytes[2] <= 0x04 {
        return PayloadKind::Tls;
    }
    let printable = bytes
        .iter()
        .filter(|byte| byte.is_ascii_graphic() || byte.is_ascii_whitespace())
        .count();
    if printable * 100 / bytes.len() >= 85 {
        PayloadKind::Text
    } else {
        PayloadKind::Binary
    }
}

fn ascii_preview(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| match *byte {
            b'\n' => ' ',
            b'\r' => ' ',
            b'\t' => ' ',
            0x20..=0x7e => char::from(*byte),
            _ => '.',
        })
        .collect()
}

fn hex_prefix(bytes: &[u8]) -> String {
    let mut hex = String::new();
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            hex.push(' ');
        }
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

#[must_use]
pub fn parse_network_evidence(source_name: impl Into<String>, text: &str) -> NetworkMap {
    let mut builder = NetworkMapBuilder::new(source_name);
    for (index, raw_line) in text.lines().enumerate() {
        let line_number = index + 1;
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let observations = parse_network_line(line_number, trimmed);
        if observations.is_empty() {
            builder.ignored_lines += 1;
        }
        for observation in observations {
            builder.add_observation(observation);
        }
    }
    builder.finish()
}

fn parse_network_line(line_number: usize, line: &str) -> Vec<NetworkObservation> {
    if let Some((left, right)) = split_arrow(line) {
        let source = first_endpoint(left, true);
        let destination = first_endpoint(right, true);
        if let Some(destination) = destination {
            let protocol = protocol_from_line(line)
                .or_else(|| destination.protocol_hint.clone())
                .or_else(|| {
                    source
                        .as_ref()
                        .and_then(|endpoint| endpoint.protocol_hint.clone())
                });
            return vec![NetworkObservation {
                line: line_number,
                source: source.map(|endpoint| endpoint.endpoint),
                destination: destination.endpoint,
                protocol,
                payload: None,
                evidence: line.to_string(),
            }];
        }
    }

    let endpoints = endpoints_from_line(line, false);
    if endpoints.len() >= 2 {
        let source = endpoints[0].endpoint.clone();
        let destination = endpoints[1].endpoint.clone();
        let protocol = protocol_from_line(line)
            .or_else(|| endpoints[1].protocol_hint.clone())
            .or_else(|| endpoints[0].protocol_hint.clone());
        return vec![NetworkObservation {
            line: line_number,
            source: Some(source),
            destination,
            protocol,
            payload: None,
            evidence: line.to_string(),
        }];
    }

    if let Some(endpoint) = endpoints.into_iter().next() {
        let protocol = protocol_from_line(line).or(endpoint.protocol_hint.clone());
        return vec![NetworkObservation {
            line: line_number,
            source: None,
            destination: endpoint.endpoint,
            protocol,
            payload: None,
            evidence: line.to_string(),
        }];
    }

    Vec::new()
}

fn split_arrow(line: &str) -> Option<(&str, &str)> {
    for delimiter in ["->", "=>", "-->", "to "] {
        if let Some(index) = line.find(delimiter) {
            let left = &line[..index];
            let right = &line[index + delimiter.len()..];
            return Some((left, right));
        }
    }
    None
}

fn first_endpoint(text: &str, accept_bare_hosts: bool) -> Option<ParsedEndpoint> {
    endpoints_from_line(text, accept_bare_hosts)
        .into_iter()
        .next()
}

fn endpoints_from_line(line: &str, accept_bare_hosts: bool) -> Vec<ParsedEndpoint> {
    let mut endpoints = Vec::new();
    let mut seen = BTreeSet::new();
    for token in line.split(is_token_separator) {
        if let Some(endpoint) = parse_endpoint_token(token, accept_bare_hosts) {
            let key = endpoint_key(&endpoint.endpoint);
            if seen.insert(key) {
                endpoints.push(endpoint);
            }
        }
    }
    endpoints
}

fn is_token_separator(character: char) -> bool {
    character.is_whitespace()
        || matches!(
            character,
            ',' | ';' | '"' | '\'' | '(' | ')' | '{' | '}' | '<' | '>'
        )
}

fn parse_endpoint_token(token: &str, accept_bare_hosts: bool) -> Option<ParsedEndpoint> {
    let token = strip_token_wrappers(token);
    if token.is_empty() {
        return None;
    }
    let token = strip_assignment_prefix(token);

    if let Some(parsed) = parse_url_endpoint(token) {
        return Some(parsed);
    }

    let endpoint = if token.starts_with('[') {
        parse_bracketed_endpoint(token)?
    } else {
        parse_host_port_or_bare(token, accept_bare_hosts)?
    };

    Some(ParsedEndpoint {
        endpoint,
        protocol_hint: None,
    })
}

fn strip_token_wrappers(token: &str) -> &str {
    token.trim_matches(|character: char| {
        matches!(
            character,
            ',' | ';' | '"' | '\'' | '(' | ')' | '{' | '}' | '<' | '>'
        )
    })
}

fn strip_assignment_prefix(token: &str) -> &str {
    if let Some((prefix, value)) = token.split_once('=') {
        if matches!(
            prefix.to_ascii_lowercase().as_str(),
            "src" | "source" | "dst" | "dest" | "destination" | "local" | "remote" | "host" | "url"
        ) {
            return value;
        }
    }
    token
}

fn parse_url_endpoint(token: &str) -> Option<ParsedEndpoint> {
    let (scheme, rest) = token.split_once("://")?;
    let protocol = protocol_from_name(scheme);
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .rsplit('@')
        .next()
        .unwrap_or_default();
    let mut parsed = parse_endpoint_token(authority, true)?;
    if parsed.endpoint.port.is_none() {
        parsed.endpoint.port = default_port_for_protocol(protocol.as_ref());
    }
    parsed.protocol_hint = protocol;
    Some(parsed)
}

fn parse_bracketed_endpoint(token: &str) -> Option<NetworkEndpoint> {
    let end = token.find(']')?;
    let host = normalize_host(&token[1..end])?;
    let remainder = &token[end + 1..];
    let port = if let Some(port_text) = remainder.strip_prefix(':') {
        Some(parse_port(port_text)?)
    } else {
        None
    };
    if port.is_none() && !host.contains(':') {
        return None;
    }
    Some(NetworkEndpoint { host, port })
}

fn parse_host_port_or_bare(token: &str, accept_bare_hosts: bool) -> Option<NetworkEndpoint> {
    let stripped = token.trim_matches(|character: char| matches!(character, '/' | '.'));
    if stripped.is_empty() {
        return None;
    }

    if let Some((host, port_text)) = stripped.rsplit_once(':') {
        if host.contains(':') {
            let host = normalize_host(stripped)?;
            return Some(NetworkEndpoint { host, port: None });
        }
        let host = normalize_host(host)?;
        let port = parse_port(port_text)?;
        return Some(NetworkEndpoint {
            host,
            port: Some(port),
        });
    }

    let host = normalize_host(stripped)?;
    if accept_bare_hosts || is_ip_or_domain(&host) {
        return Some(NetworkEndpoint { host, port: None });
    }
    None
}

fn parse_port(value: &str) -> Option<u16> {
    let port_text = value.trim_matches(|character: char| !character.is_ascii_digit());
    if port_text.is_empty() {
        return None;
    }
    let port = port_text.parse::<u16>().ok()?;
    if port == 0 {
        return None;
    }
    Some(port)
}

fn normalize_host(value: &str) -> Option<String> {
    let host = value
        .trim()
        .trim_matches(|character: char| matches!(character, '/' | '.' | '[' | ']'))
        .to_ascii_lowercase();
    if host.is_empty() || !is_host_like(&host) {
        return None;
    }
    Some(host)
}

fn is_host_like(host: &str) -> bool {
    host.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_' | ':' | '%')
    }) && host
        .chars()
        .any(|character| character.is_ascii_alphabetic() || matches!(character, '.' | ':'))
}

fn is_ip_or_domain(host: &str) -> bool {
    classify_host(host) != NetworkHostKind::Hostname || host == "localhost"
}

fn classify_host(host: &str) -> NetworkHostKind {
    if is_ipv4(host) {
        NetworkHostKind::Ipv4
    } else if host.contains(':') {
        NetworkHostKind::Ipv6
    } else if host.contains('.') {
        NetworkHostKind::Domain
    } else {
        NetworkHostKind::Hostname
    }
}

fn is_ipv4(host: &str) -> bool {
    let mut count = 0;
    for part in host.split('.') {
        count += 1;
        if part.is_empty() || part.parse::<u8>().is_err() {
            return false;
        }
    }
    count == 4
}

fn protocol_from_line(line: &str) -> Option<NetworkProtocol> {
    for token in line.split(is_token_separator) {
        let token = token
            .trim_matches(|character: char| !character.is_ascii_alphanumeric() && character != '-')
            .to_ascii_lowercase();
        if let Some(protocol) = protocol_from_name(&token) {
            return Some(protocol);
        }
    }
    None
}

fn protocol_from_name(name: &str) -> Option<NetworkProtocol> {
    match name.to_ascii_lowercase().as_str() {
        "tcp" => Some(NetworkProtocol::Tcp),
        "udp" => Some(NetworkProtocol::Udp),
        "icmp" => Some(NetworkProtocol::Icmp),
        "http" => Some(NetworkProtocol::Http),
        "https" => Some(NetworkProtocol::Https),
        "dns" => Some(NetworkProtocol::Dns),
        value if value.starts_with("proto-") => Some(NetworkProtocol::Other(value.to_string())),
        _ => None,
    }
}

fn default_port_for_protocol(protocol: Option<&NetworkProtocol>) -> Option<u16> {
    match protocol {
        Some(NetworkProtocol::Http) => Some(80),
        Some(NetworkProtocol::Https) => Some(443),
        Some(NetworkProtocol::Dns) => Some(53),
        _ => None,
    }
}

fn endpoint_key(endpoint: &NetworkEndpoint) -> String {
    match endpoint.port {
        Some(port) => format!("{}:{port}", endpoint.host),
        None => endpoint.host.clone(),
    }
}

fn push_unique_line(lines: &mut Vec<usize>, line: usize) {
    if !lines.contains(&line) {
        lines.push(line);
        lines.sort_unstable();
    }
}

fn push_hosts_json(json: &mut String, network: &NetworkMap) {
    json.push_str("  \"hosts\": [");
    if network.hosts.is_empty() {
        json.push(']');
        return;
    }
    json.push('\n');
    for (index, host) in network.hosts.iter().enumerate() {
        let comma = if index + 1 == network.hosts.len() {
            ""
        } else {
            ","
        };
        json.push_str("    {\n");
        push_json_field(json, 6, "id", &host.id, true);
        push_json_field(json, 6, "kind", &host.kind.to_string(), true);
        push_json_usize_field(json, 6, "observations", host.observation_count(), true);
        push_line_array_field(json, 6, "lines", &host.observation_lines, false);
        json.push_str("    }");
        json.push_str(comma);
        json.push('\n');
    }
    json.push_str("  ]");
}

fn push_services_json(json: &mut String, network: &NetworkMap) {
    json.push_str("  \"services\": [");
    if network.services.is_empty() {
        json.push(']');
        return;
    }
    json.push('\n');
    for (index, service) in network.services.iter().enumerate() {
        let comma = if index + 1 == network.services.len() {
            ""
        } else {
            ","
        };
        json.push_str("    {\n");
        push_json_field(json, 6, "host", &service.host, true);
        push_json_u16_field(json, 6, "port", service.port, true);
        push_protocol_field(json, 6, "protocol", service.protocol.as_ref(), true);
        push_json_usize_field(json, 6, "observations", service.observation_count(), true);
        push_line_array_field(json, 6, "lines", &service.observation_lines, false);
        json.push_str("    }");
        json.push_str(comma);
        json.push('\n');
    }
    json.push_str("  ]");
}

fn push_edges_json(json: &mut String, network: &NetworkMap) {
    json.push_str("  \"edges\": [");
    if network.edges.is_empty() {
        json.push(']');
        return;
    }
    json.push('\n');
    for (index, edge) in network.edges.iter().enumerate() {
        let comma = if index + 1 == network.edges.len() {
            ""
        } else {
            ","
        };
        json.push_str("    {\n");
        push_json_field(json, 6, "source", &edge.source, true);
        push_json_field(json, 6, "destination", &edge.destination, true);
        push_protocol_field(json, 6, "protocol", edge.protocol.as_ref(), true);
        push_optional_u16_field(json, 6, "port", edge.port, true);
        push_json_usize_field(json, 6, "observations", edge.observation_count(), true);
        push_line_array_field(json, 6, "lines", &edge.observation_lines, false);
        json.push_str("    }");
        json.push_str(comma);
        json.push('\n');
    }
    json.push_str("  ]");
}

fn push_observations_json(json: &mut String, network: &NetworkMap) {
    json.push_str("  \"observations\": [");
    if network.observations.is_empty() {
        json.push(']');
        return;
    }
    json.push('\n');
    for (index, observation) in network.observations.iter().enumerate() {
        let comma = if index + 1 == network.observations.len() {
            ""
        } else {
            ","
        };
        json.push_str("    {\n");
        push_json_usize_field(json, 6, "line", observation.line, true);
        match &observation.source {
            Some(source) => {
                json.push_str("      \"source\": {\n");
                push_json_field(json, 8, "host", &source.host, true);
                push_optional_u16_field(json, 8, "port", source.port, false);
                json.push_str("      },\n");
            }
            None => push_json_null_field(json, 6, "source", true),
        }
        json.push_str("      \"destination\": {\n");
        push_json_field(json, 8, "host", &observation.destination.host, true);
        push_optional_u16_field(json, 8, "port", observation.destination.port, false);
        json.push_str("      },\n");
        push_protocol_field(json, 6, "protocol", observation.protocol.as_ref(), true);
        push_payload_field(json, 6, "payload", observation.payload.as_ref(), true);
        push_json_field(json, 6, "evidence", &observation.evidence, false);
        json.push_str("    }");
        json.push_str(comma);
        json.push('\n');
    }
    json.push_str("  ]");
}

fn push_probe_results_json(json: &mut String, report: &ProbeReport) {
    json.push_str("  \"results\": [");
    if report.results.is_empty() {
        json.push(']');
        return;
    }
    json.push('\n');
    for (index, result) in report.results.iter().enumerate() {
        let comma = if index + 1 == report.results.len() {
            ""
        } else {
            ","
        };
        json.push_str("    {\n");
        push_json_field(json, 6, "target", &result.target.label(), true);
        push_json_field(json, 6, "host", &result.target.host, true);
        push_json_u16_field(json, 6, "port", result.target.port, true);
        push_json_field(json, 6, "status", &result.status.to_string(), true);
        match &result.remote_addr {
            Some(remote_addr) => push_json_field(json, 6, "remote_addr", remote_addr, true),
            None => push_json_null_field(json, 6, "remote_addr", true),
        }
        push_json_u128_field(json, 6, "elapsed_ms", result.elapsed_ms, true);
        push_json_usize_field(json, 6, "sent_bytes", result.sent_bytes, true);
        push_payload_field(json, 6, "received", Some(&result.received), true);
        match &result.error {
            Some(error) => push_json_field(json, 6, "error", error, false),
            None => push_json_null_field(json, 6, "error", false),
        }
        json.push_str("    }");
        json.push_str(comma);
        json.push('\n');
    }
    json.push_str("  ]");
}

fn push_json_field(
    json: &mut String,
    indent: usize,
    name: &str,
    value: &str,
    trailing_comma: bool,
) {
    push_indent(json, indent);
    json.push('"');
    json.push_str(name);
    json.push_str("\": ");
    json.push_str(&json_string(value));
    push_comma_newline(json, trailing_comma);
}

fn push_json_usize_field(
    json: &mut String,
    indent: usize,
    name: &str,
    value: usize,
    trailing_comma: bool,
) {
    push_indent(json, indent);
    json.push('"');
    json.push_str(name);
    json.push_str("\": ");
    json.push_str(&value.to_string());
    push_comma_newline(json, trailing_comma);
}

fn push_json_u16_field(
    json: &mut String,
    indent: usize,
    name: &str,
    value: u16,
    trailing_comma: bool,
) {
    push_indent(json, indent);
    json.push('"');
    json.push_str(name);
    json.push_str("\": ");
    json.push_str(&value.to_string());
    push_comma_newline(json, trailing_comma);
}

fn push_json_u128_field(
    json: &mut String,
    indent: usize,
    name: &str,
    value: u128,
    trailing_comma: bool,
) {
    push_indent(json, indent);
    json.push('"');
    json.push_str(name);
    json.push_str("\": ");
    json.push_str(&value.to_string());
    push_comma_newline(json, trailing_comma);
}

fn push_optional_u16_field(
    json: &mut String,
    indent: usize,
    name: &str,
    value: Option<u16>,
    trailing_comma: bool,
) {
    push_indent(json, indent);
    json.push('"');
    json.push_str(name);
    json.push_str("\": ");
    if let Some(value) = value {
        json.push_str(&value.to_string());
    } else {
        json.push_str("null");
    }
    push_comma_newline(json, trailing_comma);
}

fn push_protocol_field(
    json: &mut String,
    indent: usize,
    name: &str,
    value: Option<&NetworkProtocol>,
    trailing_comma: bool,
) {
    match value {
        Some(protocol) => {
            push_json_field(json, indent, name, &protocol.to_string(), trailing_comma)
        }
        None => push_json_null_field(json, indent, name, trailing_comma),
    }
}

fn push_payload_field(
    json: &mut String,
    indent: usize,
    name: &str,
    value: Option<&PayloadInspection>,
    trailing_comma: bool,
) {
    push_indent(json, indent);
    json.push('"');
    json.push_str(name);
    json.push_str("\": ");
    let Some(payload) = value else {
        json.push_str("null");
        push_comma_newline(json, trailing_comma);
        return;
    };

    json.push_str("{\n");
    push_json_usize_field(json, indent + 2, "byte_len", payload.byte_len, true);
    push_json_usize_field(json, indent + 2, "captured_len", payload.captured_len, true);
    push_json_field(json, indent + 2, "kind", &payload.kind.to_string(), true);
    push_json_field(
        json,
        indent + 2,
        "ascii_preview",
        &payload.ascii_preview,
        true,
    );
    push_json_field(json, indent + 2, "hex_prefix", &payload.hex_prefix, false);
    push_indent(json, indent);
    json.push('}');
    push_comma_newline(json, trailing_comma);
}

fn push_json_null_field(json: &mut String, indent: usize, name: &str, trailing_comma: bool) {
    push_indent(json, indent);
    json.push('"');
    json.push_str(name);
    json.push_str("\": null");
    push_comma_newline(json, trailing_comma);
}

fn push_line_array_field(
    json: &mut String,
    indent: usize,
    name: &str,
    lines: &[usize],
    trailing_comma: bool,
) {
    push_indent(json, indent);
    json.push('"');
    json.push_str(name);
    json.push_str("\": [");
    for (index, line) in lines.iter().enumerate() {
        if index > 0 {
            json.push_str(", ");
        }
        json.push_str(&line.to_string());
    }
    json.push(']');
    push_comma_newline(json, trailing_comma);
}

fn push_indent(json: &mut String, indent: usize) {
    for _ in 0..indent {
        json.push(' ');
    }
}

fn push_comma_newline(json: &mut String, trailing_comma: bool) {
    if trailing_comma {
        json.push(',');
    }
    json.push('\n');
}

fn json_string(value: &str) -> String {
    let mut escaped = String::from("\"");
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                escaped.push_str(&format!("\\u{:04x}", u32::from(character)))
            }
            character => escaped.push(character),
        }
    }
    escaped.push('"');
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_arrows_urls_and_socket_pairs() {
        let network = parse_network_evidence(
            "sample",
            "\
workstation.local -> https://api.internal.example/v1
api.internal.example -> db.internal:5432 tcp
tcp 10.0.0.4:51110 10.0.0.8:443 ESTABLISHED
ignored words only
",
        );

        assert_eq!(network.summary().hosts, 5);
        assert_eq!(network.summary().services, 3);
        assert_eq!(network.summary().edges, 3);
        assert_eq!(network.summary().observations, 3);
        assert_eq!(network.summary().ignored_lines, 1);
        assert!(network
            .services()
            .iter()
            .any(|service| service.host == "api.internal.example"
                && service.port == 443
                && service.protocol == Some(NetworkProtocol::Https)));
        assert!(network
            .edges()
            .iter()
            .any(|edge| edge.source == "api.internal.example"
                && edge.destination == "db.internal"
                && edge.port == Some(5432)));
    }

    #[test]
    fn exports_deterministic_json() {
        let network = parse_network_evidence("sample", "client -> server.local:53 udp\n");
        let json = network.to_json_pretty();

        assert!(json.contains("\"schema\": \"kaiju.network.v1\""));
        assert!(json.contains("\"source\": \"client\""));
        assert!(json.contains("\"destination\": \"server.local\""));
        assert!(json.contains("\"protocol\": \"udp\""));
    }

    #[test]
    fn parses_bracketed_ipv6_endpoint() {
        let network = parse_network_evidence("sample", "client.local -> [::1]:8443 tcp\n");

        assert!(network
            .hosts()
            .iter()
            .any(|host| host.id == "::1" && host.kind == NetworkHostKind::Ipv6));
        assert!(network
            .services()
            .iter()
            .any(|service| service.host == "::1" && service.port == 8443));
    }

    #[test]
    fn parses_port_specs() {
        assert_eq!(
            parse_port_spec("80,443,8000-8002").expect("parse port spec"),
            vec![80, 443, 8000, 8001, 8002]
        );
        assert!(parse_port_spec("10-8").is_err());
    }

    #[test]
    fn parses_probe_targets_and_hex_payloads() {
        let target = parse_probe_target("[::1]:8443").expect("parse probe target");

        assert_eq!(target.host, "::1");
        assert_eq!(target.port, 8443);
        assert_eq!(target.label(), "[::1]:8443");
        assert_eq!(parse_hex_payload("47 45:54").unwrap(), b"GET");
        assert!(parse_hex_payload("abc").is_err());
    }

    #[test]
    fn inspects_payload_kind_and_preview() {
        let payload = inspect_payload(b"HTTP/1.1 200 OK\r\n\r\nkaiju", 12);

        assert_eq!(payload.kind, PayloadKind::Http);
        assert_eq!(payload.byte_len, 24);
        assert_eq!(payload.captured_len, 12);
        assert!(payload.ascii_preview.contains("HTTP/1.1"));
        assert!(payload.hex_prefix.starts_with("48 54 54 50"));
    }

    #[test]
    fn parses_pcap_tcp_payload() {
        let network =
            parse_pcap_evidence("sample.pcap", &synthetic_pcap_tcp_http()).expect("parse pcap");

        assert_eq!(network.summary().hosts, 2);
        assert_eq!(network.summary().services, 1);
        assert_eq!(network.summary().edges, 1);
        let observation = &network.observations()[0];
        assert_eq!(observation.protocol, Some(NetworkProtocol::Tcp));
        let payload = observation.payload.as_ref().expect("payload inspection");
        assert_eq!(payload.kind, PayloadKind::Http);
        assert!(payload.ascii_preview.contains("GET /"));
    }

    #[test]
    fn validates_probe_requests_and_serializes_reports() {
        let options = ProbeOptions {
            read_bytes: MAX_PROBE_PAYLOAD_BYTES + 1,
            ..ProbeOptions::default()
        };

        assert!(probe_targets(Vec::new(), ProbeOptions::default()).is_err());
        assert!(probe_targets(vec![ProbeTarget::new("127.0.0.1", 80)], options).is_err());

        let report = ProbeReport {
            mode: ProbeMode::Probe,
            results: vec![ProbeResult {
                target: ProbeTarget::new("127.0.0.1", 80),
                status: ProbeStatus::Open,
                remote_addr: Some("127.0.0.1:80".to_string()),
                elapsed_ms: 7,
                sent_bytes: 4,
                received: inspect_payload(b"HTTP/1.1 200 OK\r\n\r\n", 64),
                error: None,
            }],
        };

        assert_eq!(report.open_count(), 1);
        assert_eq!(report.closed_count(), 0);
        assert_eq!(report.error_count(), 0);
        assert_eq!(report.results[0].status, ProbeStatus::Open);
        assert_eq!(report.results[0].sent_bytes, 4);
        assert_eq!(report.results[0].received.kind, PayloadKind::Http);
        assert!(report.results[0]
            .received
            .ascii_preview
            .contains("HTTP/1.1 200 OK"));
        assert!(report
            .to_json_pretty()
            .contains("\"schema\": \"kaiju.network.probe.v1\""));
    }

    fn synthetic_pcap_tcp_http() -> Vec<u8> {
        let payload = b"GET / HTTP/1.1\r\n\r\n";
        let tcp_len = 20 + payload.len();
        let ip_total_len = 20 + tcp_len;
        let frame_len = 14 + ip_total_len;
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
        bytes.extend_from_slice(&2_u16.to_le_bytes());
        bytes.extend_from_slice(&4_u16.to_le_bytes());
        bytes.extend_from_slice(&0_i32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&65_535_u32.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&(frame_len as u32).to_le_bytes());
        bytes.extend_from_slice(&(frame_len as u32).to_le_bytes());

        bytes.extend_from_slice(&[0, 1, 2, 3, 4, 5]);
        bytes.extend_from_slice(&[6, 7, 8, 9, 10, 11]);
        bytes.extend_from_slice(&0x0800_u16.to_be_bytes());

        bytes.push(0x45);
        bytes.push(0);
        bytes.extend_from_slice(&(ip_total_len as u16).to_be_bytes());
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        bytes.push(64);
        bytes.push(6);
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        bytes.extend_from_slice(&[10, 0, 0, 4]);
        bytes.extend_from_slice(&[10, 0, 0, 8]);

        bytes.extend_from_slice(&51_110_u16.to_be_bytes());
        bytes.extend_from_slice(&80_u16.to_be_bytes());
        bytes.extend_from_slice(&0_u32.to_be_bytes());
        bytes.extend_from_slice(&0_u32.to_be_bytes());
        bytes.push(0x50);
        bytes.push(0x18);
        bytes.extend_from_slice(&1024_u16.to_be_bytes());
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        bytes.extend_from_slice(payload);

        bytes
    }
}
