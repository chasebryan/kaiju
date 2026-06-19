#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use kaiju_core::{Address, DiagnosticSeverity};
use kaiju_loader::{LoadedBinary, Symbol};

#[derive(Debug, Clone)]
pub struct Project {
    pub binary: LoadedBinary,
    labels: BTreeMap<Address, String>,
    comments: BTreeMap<Address, Vec<String>>,
    functions: BTreeMap<Address, ProjectFunction>,
    basic_blocks: BTreeMap<Address, ProjectBasicBlock>,
    cfg_edges: BTreeSet<ProjectCfgEdge>,
    strings: Vec<ProjectString>,
    symbols: Vec<ProjectSymbol>,
    xrefs: BTreeSet<CrossReference>,
    analysis_facts: Vec<AnalysisFact>,
}

impl Project {
    #[must_use]
    pub fn from_loaded_binary(binary: LoadedBinary) -> Self {
        let symbols = binary.symbols.iter().map(ProjectSymbol::from).collect();

        Self {
            binary,
            labels: BTreeMap::new(),
            comments: BTreeMap::new(),
            functions: BTreeMap::new(),
            basic_blocks: BTreeMap::new(),
            cfg_edges: BTreeSet::new(),
            strings: Vec::new(),
            symbols,
            xrefs: BTreeSet::new(),
            analysis_facts: Vec::new(),
        }
    }

    #[must_use]
    pub fn new(binary: LoadedBinary) -> Self {
        Self::from_loaded_binary(binary)
    }

    pub fn add_label(&mut self, address: Address, label: impl Into<String>) {
        self.labels.insert(address, label.into());
    }

    pub fn set_label(&mut self, address: Address, label: impl Into<String>) {
        self.add_label(address, label);
    }

    #[must_use]
    pub fn label_at(&self, address: Address) -> Option<&str> {
        self.labels.get(&address).map(String::as_str)
    }

    #[must_use]
    pub const fn labels(&self) -> &BTreeMap<Address, String> {
        &self.labels
    }

    pub fn add_comment(&mut self, address: Address, comment: impl Into<String>) {
        self.comments
            .entry(address)
            .or_default()
            .push(comment.into());
    }

    pub fn set_comment(&mut self, address: Address, comment: impl Into<String>) {
        self.comments.insert(address, vec![comment.into()]);
    }

    #[must_use]
    pub fn comments_at(&self, address: Address) -> &[String] {
        self.comments.get(&address).map_or(&[], Vec::as_slice)
    }

    #[must_use]
    pub const fn comments(&self) -> &BTreeMap<Address, Vec<String>> {
        &self.comments
    }

    pub fn add_function(&mut self, start: Address) -> &mut ProjectFunction {
        self.functions
            .entry(start)
            .or_insert_with(|| ProjectFunction::new(start))
    }

    #[must_use]
    pub fn function(&self, start: Address) -> Option<&ProjectFunction> {
        self.functions.get(&start)
    }

    #[must_use]
    pub const fn functions(&self) -> &BTreeMap<Address, ProjectFunction> {
        &self.functions
    }

    pub fn add_basic_block(&mut self, block: ProjectBasicBlock) {
        self.basic_blocks.insert(block.start, block);
    }

    #[must_use]
    pub fn basic_block(&self, start: Address) -> Option<&ProjectBasicBlock> {
        self.basic_blocks.get(&start)
    }

    #[must_use]
    pub const fn basic_blocks(&self) -> &BTreeMap<Address, ProjectBasicBlock> {
        &self.basic_blocks
    }

    pub fn add_string(&mut self, string: ProjectString) {
        if !self.strings.contains(&string) {
            self.strings.push(string);
            self.strings.sort_by_key(|entry| {
                (
                    entry.file_offset,
                    entry.virtual_address,
                    entry.encoding.clone(),
                    entry.value.clone(),
                )
            });
        }
    }

    #[must_use]
    pub fn strings(&self) -> &[ProjectString] {
        &self.strings
    }

    pub fn add_symbol(&mut self, symbol: ProjectSymbol) {
        if !self.symbols.contains(&symbol) {
            self.symbols.push(symbol);
            self.symbols
                .sort_by_key(|entry| (entry.address, entry.name.clone()));
        }
    }

    #[must_use]
    pub fn symbols(&self) -> &[ProjectSymbol] {
        &self.symbols
    }

    pub fn add_xref(&mut self, xref: CrossReference) {
        self.xrefs.insert(xref);
    }

    #[must_use]
    pub const fn xrefs(&self) -> &BTreeSet<CrossReference> {
        &self.xrefs
    }

    pub fn add_analysis_fact(&mut self, fact: AnalysisFact) {
        if !self.analysis_facts.contains(&fact) {
            self.analysis_facts.push(fact);
            self.analysis_facts
                .sort_by_key(|entry| (entry.namespace.clone(), entry.key.clone()));
        }
    }

    #[must_use]
    pub fn analysis_facts(&self) -> &[AnalysisFact] {
        &self.analysis_facts
    }

    pub fn add_cfg(&mut self, cfg: ProjectCfg) {
        let block_starts = cfg
            .blocks
            .iter()
            .map(|block| block.start)
            .collect::<Vec<_>>();

        {
            let function = self.add_function(cfg.function_start);
            merge_addresses(&mut function.block_starts, block_starts);
        }

        for block in cfg.blocks {
            self.add_basic_block(block);
        }

        for edge in cfg.edges {
            self.add_xref(CrossReference {
                from: edge.from,
                to: edge.to,
                kind: edge.kind.into(),
            });
            self.cfg_edges.insert(edge);
        }
    }

    #[must_use]
    pub const fn cfg_edges(&self) -> &BTreeSet<ProjectCfgEdge> {
        &self.cfg_edges
    }

    #[must_use]
    pub fn summary(&self) -> ProjectSummary {
        ProjectSummary {
            path: self.binary.path.display().to_string(),
            file_size: self.binary.file_size,
            format: self.binary.format.to_string(),
            architecture: self.binary.arch.to_string(),
            endian: self.binary.endian.to_string(),
            entrypoint: self.binary.entrypoint,
            region_count: self.binary.memory_map.regions().len(),
            section_count: self.binary.sections.len(),
            symbol_count: self.symbols.len(),
            diagnostic_count: self.binary.diagnostics.len(),
            string_count: self.strings.len(),
            function_count: self.functions.len(),
            block_count: self.basic_blocks.len(),
            xref_count: self.xrefs.len(),
            analysis_fact_count: self.analysis_facts.len(),
        }
    }

    #[must_use]
    pub fn strings_containing(&self, needle: &str) -> Vec<&ProjectString> {
        self.strings
            .iter()
            .filter(|string| string.value.contains(needle))
            .collect()
    }

    #[must_use]
    pub fn functions_in_range(&self, start: Address, end: Address) -> Vec<&ProjectFunction> {
        self.functions
            .range(start..end)
            .map(|(_, function)| function)
            .collect()
    }

    #[must_use]
    pub fn xrefs_from(&self, from: Address) -> Vec<CrossReference> {
        self.xrefs
            .iter()
            .copied()
            .filter(|xref| xref.from == from)
            .collect()
    }

    #[must_use]
    pub fn xrefs_to(&self, to: Address) -> Vec<CrossReference> {
        self.xrefs
            .iter()
            .copied()
            .filter(|xref| xref.to == to)
            .collect()
    }

    #[must_use]
    pub fn to_json_pretty(&self) -> String {
        let summary = self.summary();
        let mut json = String::new();
        json.push_str("{\n");
        json.push_str("  \"schema\": \"kaiju.project.v1\",\n");
        json.push_str("  \"binary\": {\n");
        push_json_field(&mut json, 4, "path", &summary.path, true);
        push_json_u64_field(&mut json, 4, "file_size", summary.file_size, true);
        push_json_field(&mut json, 4, "format", &summary.format, true);
        push_json_field(&mut json, 4, "architecture", &summary.architecture, true);
        push_json_field(&mut json, 4, "endian", &summary.endian, true);
        push_json_address_field(&mut json, 4, "entrypoint", summary.entrypoint, false);
        json.push_str("  },\n");
        json.push_str("  \"summary\": {\n");
        push_json_usize_field(&mut json, 4, "regions", summary.region_count, true);
        push_json_usize_field(&mut json, 4, "sections", summary.section_count, true);
        push_json_usize_field(&mut json, 4, "symbols", summary.symbol_count, true);
        push_json_usize_field(&mut json, 4, "diagnostics", summary.diagnostic_count, true);
        push_json_usize_field(&mut json, 4, "strings", summary.string_count, true);
        push_json_usize_field(&mut json, 4, "functions", summary.function_count, true);
        push_json_usize_field(&mut json, 4, "blocks", summary.block_count, true);
        push_json_usize_field(&mut json, 4, "xrefs", summary.xref_count, true);
        push_json_usize_field(
            &mut json,
            4,
            "analysis_facts",
            summary.analysis_fact_count,
            false,
        );
        json.push_str("  },\n");
        push_functions_json(&mut json, self);
        json.push_str(",\n");
        push_blocks_json(&mut json, self);
        json.push_str(",\n");
        push_diagnostics_json(&mut json, self);
        json.push_str(",\n");
        push_strings_json(&mut json, self);
        json.push_str(",\n");
        push_xrefs_json(&mut json, self);
        json.push_str(",\n");
        push_analysis_facts_json(&mut json, self);
        json.push('\n');
        json.push('}');
        json
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectSummary {
    pub path: String,
    pub file_size: u64,
    pub format: String,
    pub architecture: String,
    pub endian: String,
    pub entrypoint: Option<Address>,
    pub region_count: usize,
    pub section_count: usize,
    pub symbol_count: usize,
    pub diagnostic_count: usize,
    pub string_count: usize,
    pub function_count: usize,
    pub block_count: usize,
    pub xref_count: usize,
    pub analysis_fact_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectFunction {
    pub start: Address,
    pub name: Option<String>,
    pub block_starts: Vec<Address>,
}

impl ProjectFunction {
    #[must_use]
    pub const fn new(start: Address) -> Self {
        Self {
            start,
            name: None,
            block_starts: Vec::new(),
        }
    }

    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = Some(name.into());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectBasicBlock {
    pub start: Address,
    pub end: Address,
    pub instruction_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectCfg {
    pub function_start: Address,
    pub blocks: Vec<ProjectBasicBlock>,
    pub edges: Vec<ProjectCfgEdge>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProjectCfgEdge {
    pub from: Address,
    pub to: Address,
    pub kind: ProjectCfgEdgeKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProjectCfgEdgeKind {
    Fallthrough,
    Jump,
    ConditionalTaken,
    ConditionalNotTaken,
    Call,
    Return,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectString {
    pub file_offset: u64,
    pub virtual_address: Option<Address>,
    pub encoding: ProjectStringEncoding,
    pub char_len: usize,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProjectStringEncoding {
    Ascii,
    Utf16Le,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectSymbol {
    pub name: String,
    pub address: Option<Address>,
}

impl From<&Symbol> for ProjectSymbol {
    fn from(symbol: &Symbol) -> Self {
        Self {
            name: symbol.name.clone(),
            address: symbol.address,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CrossReference {
    pub from: Address,
    pub to: Address,
    pub kind: CrossReferenceKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CrossReferenceKind {
    Flow,
    Call,
    Data,
    Read,
    Write,
    Unknown,
}

impl From<ProjectCfgEdgeKind> for CrossReferenceKind {
    fn from(kind: ProjectCfgEdgeKind) -> Self {
        match kind {
            ProjectCfgEdgeKind::Call => Self::Call,
            ProjectCfgEdgeKind::Unknown => Self::Unknown,
            ProjectCfgEdgeKind::Fallthrough
            | ProjectCfgEdgeKind::Jump
            | ProjectCfgEdgeKind::ConditionalTaken
            | ProjectCfgEdgeKind::ConditionalNotTaken
            | ProjectCfgEdgeKind::Return => Self::Flow,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisFact {
    pub namespace: String,
    pub key: String,
    pub value: String,
}

impl AnalysisFact {
    #[must_use]
    pub fn new(
        namespace: impl Into<String>,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            key: key.into(),
            value: value.into(),
        }
    }
}

fn merge_addresses(existing: &mut Vec<Address>, incoming: Vec<Address>) {
    existing.extend(incoming);
    existing.sort_unstable();
    existing.dedup();
}

fn push_functions_json(json: &mut String, project: &Project) {
    json.push_str("  \"functions\": [");
    if project.functions.is_empty() {
        json.push(']');
        return;
    }
    json.push('\n');
    for (index, function) in project.functions.values().enumerate() {
        let comma = if index + 1 == project.functions.len() {
            ""
        } else {
            ","
        };
        json.push_str("    {\n");
        push_json_address_field(json, 6, "start", Some(function.start), true);
        match &function.name {
            Some(name) => push_json_field(json, 6, "name", name, true),
            None => push_json_null_field(json, 6, "name", true),
        }
        push_address_array_field(json, 6, "blocks", &function.block_starts, false);
        json.push_str("    }");
        json.push_str(comma);
        json.push('\n');
    }
    json.push_str("  ]");
}

fn push_blocks_json(json: &mut String, project: &Project) {
    json.push_str("  \"blocks\": [");
    if project.basic_blocks.is_empty() {
        json.push(']');
        return;
    }
    json.push('\n');
    for (index, block) in project.basic_blocks.values().enumerate() {
        let comma = if index + 1 == project.basic_blocks.len() {
            ""
        } else {
            ","
        };
        json.push_str("    {\n");
        push_json_address_field(json, 6, "start", Some(block.start), true);
        push_json_address_field(json, 6, "end", Some(block.end), true);
        push_json_usize_field(json, 6, "instruction_count", block.instruction_count, false);
        json.push_str("    }");
        json.push_str(comma);
        json.push('\n');
    }
    json.push_str("  ]");
}

fn push_diagnostics_json(json: &mut String, project: &Project) {
    json.push_str("  \"diagnostics\": [");
    if project.binary.diagnostics.is_empty() {
        json.push(']');
        return;
    }
    json.push('\n');
    for (index, diagnostic) in project.binary.diagnostics.iter().enumerate() {
        let comma = if index + 1 == project.binary.diagnostics.len() {
            ""
        } else {
            ","
        };
        json.push_str("    {\n");
        push_json_field(
            json,
            6,
            "severity",
            diagnostic_severity_name(diagnostic.severity),
            true,
        );
        push_json_field(json, 6, "message", &diagnostic.message, false);
        json.push_str("    }");
        json.push_str(comma);
        json.push('\n');
    }
    json.push_str("  ]");
}

fn push_strings_json(json: &mut String, project: &Project) {
    json.push_str("  \"strings\": [");
    if project.strings.is_empty() {
        json.push(']');
        return;
    }
    json.push('\n');
    for (index, string) in project.strings.iter().enumerate() {
        let comma = if index + 1 == project.strings.len() {
            ""
        } else {
            ","
        };
        json.push_str("    {\n");
        push_json_u64_field(json, 6, "file_offset", string.file_offset, true);
        push_json_address_field(json, 6, "virtual_address", string.virtual_address, true);
        push_json_field(
            json,
            6,
            "encoding",
            project_string_encoding_name(&string.encoding),
            true,
        );
        push_json_usize_field(json, 6, "char_len", string.char_len, true);
        push_json_field(json, 6, "value", &string.value, false);
        json.push_str("    }");
        json.push_str(comma);
        json.push('\n');
    }
    json.push_str("  ]");
}

fn push_xrefs_json(json: &mut String, project: &Project) {
    json.push_str("  \"xrefs\": [");
    if project.xrefs.is_empty() {
        json.push(']');
        return;
    }
    json.push('\n');
    for (index, xref) in project.xrefs.iter().enumerate() {
        let comma = if index + 1 == project.xrefs.len() {
            ""
        } else {
            ","
        };
        json.push_str("    {\n");
        push_json_address_field(json, 6, "from", Some(xref.from), true);
        push_json_address_field(json, 6, "to", Some(xref.to), true);
        push_json_field(json, 6, "kind", cross_reference_kind_name(xref.kind), false);
        json.push_str("    }");
        json.push_str(comma);
        json.push('\n');
    }
    json.push_str("  ]");
}

fn push_analysis_facts_json(json: &mut String, project: &Project) {
    json.push_str("  \"analysis_facts\": [");
    if project.analysis_facts.is_empty() {
        json.push(']');
        return;
    }
    json.push('\n');
    for (index, fact) in project.analysis_facts.iter().enumerate() {
        let comma = if index + 1 == project.analysis_facts.len() {
            ""
        } else {
            ","
        };
        json.push_str("    {\n");
        push_json_field(json, 6, "namespace", &fact.namespace, true);
        push_json_field(json, 6, "key", &fact.key, true);
        push_json_field(json, 6, "value", &fact.value, false);
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

fn push_json_u64_field(
    json: &mut String,
    indent: usize,
    name: &str,
    value: u64,
    trailing_comma: bool,
) {
    push_indent(json, indent);
    json.push('"');
    json.push_str(name);
    json.push_str("\": ");
    json.push_str(&value.to_string());
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

fn push_json_address_field(
    json: &mut String,
    indent: usize,
    name: &str,
    value: Option<Address>,
    trailing_comma: bool,
) {
    push_indent(json, indent);
    json.push('"');
    json.push_str(name);
    json.push_str("\": ");
    if let Some(address) = value {
        json.push_str(&json_string(&address.to_string()));
    } else {
        json.push_str("null");
    }
    push_comma_newline(json, trailing_comma);
}

fn push_json_null_field(json: &mut String, indent: usize, name: &str, trailing_comma: bool) {
    push_indent(json, indent);
    json.push('"');
    json.push_str(name);
    json.push_str("\": null");
    push_comma_newline(json, trailing_comma);
}

fn push_address_array_field(
    json: &mut String,
    indent: usize,
    name: &str,
    addresses: &[Address],
    trailing_comma: bool,
) {
    push_indent(json, indent);
    json.push('"');
    json.push_str(name);
    json.push_str("\": [");
    for (index, address) in addresses.iter().enumerate() {
        if index > 0 {
            json.push_str(", ");
        }
        json.push_str(&json_string(&address.to_string()));
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

fn project_string_encoding_name(encoding: &ProjectStringEncoding) -> &str {
    match encoding {
        ProjectStringEncoding::Ascii => "ASCII",
        ProjectStringEncoding::Utf16Le => "UTF-16LE",
        ProjectStringEncoding::Other(name) => name,
    }
}

fn diagnostic_severity_name(severity: DiagnosticSeverity) -> &'static str {
    match severity {
        DiagnosticSeverity::Note => "note",
        DiagnosticSeverity::Warning => "warning",
        DiagnosticSeverity::Error => "error",
    }
}

fn cross_reference_kind_name(kind: CrossReferenceKind) -> &'static str {
    match kind {
        CrossReferenceKind::Flow => "flow",
        CrossReferenceKind::Call => "call",
        CrossReferenceKind::Data => "data",
        CrossReferenceKind::Read => "read",
        CrossReferenceKind::Write => "write",
        CrossReferenceKind::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaiju_core::{
        ArchitectureId, Diagnostic, DiagnosticSeverity, Endian, MemoryMap, MemoryRegion,
        Permissions,
    };
    use kaiju_loader::{BinaryFormat, LoadedBinary};
    use std::path::PathBuf;

    #[test]
    fn creates_project_from_loaded_binary_and_preserves_symbols() {
        let mut binary = test_binary();
        binary.symbols.push(Symbol {
            name: "entry".to_string(),
            address: Some(Address::new(0x1000)),
        });

        let project = Project::from_loaded_binary(binary);

        assert_eq!(project.binary.format, BinaryFormat::Raw);
        assert_eq!(project.symbols().len(), 1);
        assert_eq!(project.symbols()[0].name, "entry");
        assert_eq!(project.symbols()[0].address, Some(Address::new(0x1000)));
    }

    #[test]
    fn stores_labels_and_comments_by_address() {
        let mut project = Project::from_loaded_binary(test_binary());

        project.add_label(Address::new(0x1000), "entry");
        project.add_comment(Address::new(0x1000), "first note");
        project.add_comment(Address::new(0x1000), "second note");

        assert_eq!(project.label_at(Address::new(0x1000)), Some("entry"));
        assert_eq!(
            project.comments_at(Address::new(0x1000)),
            &["first note".to_string(), "second note".to_string()]
        );
        assert!(project.comments_at(Address::new(0x2000)).is_empty());
    }

    #[test]
    fn stores_strings_in_stable_offset_order() {
        let mut project = Project::from_loaded_binary(test_binary());

        project.add_string(ProjectString {
            file_offset: 8,
            virtual_address: Some(Address::new(0x1008)),
            encoding: ProjectStringEncoding::Ascii,
            char_len: 4,
            value: "tail".to_string(),
        });
        project.add_string(ProjectString {
            file_offset: 0,
            virtual_address: Some(Address::new(0x1000)),
            encoding: ProjectStringEncoding::Utf16Le,
            char_len: 4,
            value: "head".to_string(),
        });

        assert_eq!(project.strings()[0].file_offset, 0);
        assert_eq!(project.strings()[1].file_offset, 8);
    }

    #[test]
    fn stores_cfg_as_function_blocks_edges_and_xrefs() {
        let mut project = Project::from_loaded_binary(test_binary());

        project.add_cfg(ProjectCfg {
            function_start: Address::new(0x1000),
            blocks: vec![
                ProjectBasicBlock {
                    start: Address::new(0x1000),
                    end: Address::new(0x1002),
                    instruction_count: 1,
                },
                ProjectBasicBlock {
                    start: Address::new(0x1002),
                    end: Address::new(0x1003),
                    instruction_count: 1,
                },
            ],
            edges: vec![ProjectCfgEdge {
                from: Address::new(0x1000),
                to: Address::new(0x1002),
                kind: ProjectCfgEdgeKind::ConditionalNotTaken,
            }],
        });

        let function = project
            .function(Address::new(0x1000))
            .expect("function should be recorded");
        assert_eq!(
            function.block_starts,
            vec![Address::new(0x1000), Address::new(0x1002)]
        );
        assert_eq!(project.basic_blocks().len(), 2);
        assert_eq!(project.cfg_edges().len(), 1);
        assert!(project.xrefs().contains(&CrossReference {
            from: Address::new(0x1000),
            to: Address::new(0x1002),
            kind: CrossReferenceKind::Flow,
        }));
    }

    #[test]
    fn summarizes_project_counts() {
        let mut project = Project::from_loaded_binary(test_binary());
        project.add_string(ProjectString {
            file_offset: 0,
            virtual_address: Some(Address::new(0x1000)),
            encoding: ProjectStringEncoding::Ascii,
            char_len: 5,
            value: "kaiju".to_string(),
        });
        project.add_function(Address::new(0x1000));
        project.add_analysis_fact(AnalysisFact::new("test", "fact", "value"));

        let summary = project.summary();

        assert_eq!(summary.format, "Raw");
        assert_eq!(summary.architecture, "x86_64");
        assert_eq!(summary.region_count, 1);
        assert_eq!(summary.diagnostic_count, 0);
        assert_eq!(summary.string_count, 1);
        assert_eq!(summary.function_count, 1);
        assert_eq!(summary.analysis_fact_count, 1);
    }

    #[test]
    fn queries_strings_functions_and_xrefs() {
        let mut project = Project::from_loaded_binary(test_binary());
        project.add_string(ProjectString {
            file_offset: 0,
            virtual_address: Some(Address::new(0x1000)),
            encoding: ProjectStringEncoding::Ascii,
            char_len: 11,
            value: "kaiju-query".to_string(),
        });
        project.add_function(Address::new(0x1000));
        project.add_function(Address::new(0x2000));
        project.add_xref(CrossReference {
            from: Address::new(0x1000),
            to: Address::new(0x2000),
            kind: CrossReferenceKind::Call,
        });

        assert_eq!(project.strings_containing("query").len(), 1);
        assert_eq!(
            project
                .functions_in_range(Address::new(0x1000), Address::new(0x1800))
                .len(),
            1
        );
        assert_eq!(project.xrefs_from(Address::new(0x1000)).len(), 1);
        assert_eq!(project.xrefs_to(Address::new(0x2000)).len(), 1);
    }

    #[test]
    fn exports_stable_project_json() {
        let mut project = Project::from_loaded_binary(test_binary());
        project.add_string(ProjectString {
            file_offset: 0,
            virtual_address: Some(Address::new(0x1000)),
            encoding: ProjectStringEncoding::Ascii,
            char_len: 13,
            value: "kaiju \"json\"".to_string(),
        });
        project.add_analysis_fact(AnalysisFact::new("json", "escaped", "line\nbreak"));

        let json = project.to_json_pretty();

        assert!(json.contains("\"schema\": \"kaiju.project.v1\""));
        assert!(json.contains("\"format\": \"Raw\""));
        assert!(json.contains("\"architecture\": \"x86_64\""));
        assert!(json.contains("kaiju \\\"json\\\""));
        assert!(json.contains("line\\nbreak"));
    }

    #[test]
    fn exports_loader_diagnostics_in_project_json() {
        let mut binary = test_binary();
        binary.diagnostics.push(Diagnostic::new(
            DiagnosticSeverity::Warning,
            "limited loader coverage",
        ));
        let project = Project::from_loaded_binary(binary);

        let summary = project.summary();
        let json = project.to_json_pretty();

        assert_eq!(summary.diagnostic_count, 1);
        assert!(json.contains("\"diagnostics\": 1"));
        assert!(json.contains("\"diagnostics\": ["));
        assert!(json.contains("\"severity\": \"warning\""));
        assert!(json.contains("\"message\": \"limited loader coverage\""));
    }

    fn test_binary() -> LoadedBinary {
        let mut memory_map = MemoryMap::new();
        memory_map.add_region(MemoryRegion::new(
            "text",
            Address::new(0x1000),
            Some(0),
            Permissions::read_execute(),
            vec![0xc3],
        ));

        LoadedBinary {
            path: PathBuf::from("test.bin"),
            file_size: 1,
            bytes: vec![0xc3],
            format: BinaryFormat::Raw,
            arch: ArchitectureId::X86_64,
            endian: Endian::Little,
            entrypoint: Some(Address::new(0x1000)),
            memory_map,
            sections: Vec::new(),
            symbols: Vec::new(),
            diagnostics: Vec::new(),
        }
    }
}
