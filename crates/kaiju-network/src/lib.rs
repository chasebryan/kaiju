#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::Path;

use kaiju_core::{KaijuError, KaijuErrorKind, Result};

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
struct ParsedEndpoint {
    endpoint: NetworkEndpoint,
    protocol_hint: Option<NetworkProtocol>,
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
        push_json_field(json, 6, "evidence", &observation.evidence, false);
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
}
