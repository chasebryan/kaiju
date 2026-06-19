#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use kaiju_core::{Address, DiagnosticSeverity};
use kaiju_loader::{Dependency, Export, Import, LoadedBinary, Relocation, Symbol};

#[derive(Debug, Clone)]
pub struct Project {
    pub binary: LoadedBinary,
    labels: BTreeMap<Address, String>,
    comments: BTreeMap<Address, Vec<String>>,
    functions: BTreeMap<Address, ProjectFunction>,
    basic_blocks: BTreeMap<Address, ProjectBasicBlock>,
    ir_functions: BTreeMap<Address, ProjectIrFunction>,
    cfg_edges: BTreeSet<ProjectCfgEdge>,
    strings: Vec<ProjectString>,
    dependencies: Vec<ProjectDependency>,
    symbols: Vec<ProjectSymbol>,
    imports: Vec<ProjectImport>,
    exports: Vec<ProjectExport>,
    relocations: Vec<ProjectRelocation>,
    xrefs: BTreeSet<CrossReference>,
    analysis_facts: Vec<AnalysisFact>,
}

impl Project {
    #[must_use]
    pub fn from_loaded_binary(binary: LoadedBinary) -> Self {
        let symbols = binary.symbols.iter().map(ProjectSymbol::from).collect();
        let dependencies = binary
            .dependencies
            .iter()
            .map(ProjectDependency::from)
            .collect();
        let imports = binary.imports.iter().map(ProjectImport::from).collect();
        let exports = binary.exports.iter().map(ProjectExport::from).collect();
        let relocations = binary
            .relocations
            .iter()
            .map(ProjectRelocation::from)
            .collect();

        Self {
            binary,
            labels: BTreeMap::new(),
            comments: BTreeMap::new(),
            functions: BTreeMap::new(),
            basic_blocks: BTreeMap::new(),
            ir_functions: BTreeMap::new(),
            cfg_edges: BTreeSet::new(),
            strings: Vec::new(),
            dependencies,
            symbols,
            imports,
            exports,
            relocations,
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

    pub fn add_ir_function(&mut self, function: ProjectIrFunction) {
        self.ir_functions.insert(function.start, function);
    }

    #[must_use]
    pub fn ir_function(&self, start: Address) -> Option<&ProjectIrFunction> {
        self.ir_functions.get(&start)
    }

    #[must_use]
    pub const fn ir_functions(&self) -> &BTreeMap<Address, ProjectIrFunction> {
        &self.ir_functions
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

    pub fn add_dependency(&mut self, dependency: ProjectDependency) {
        if !self.dependencies.contains(&dependency) {
            self.dependencies.push(dependency);
            self.dependencies.sort_by_key(|entry| entry.name.clone());
        }
    }

    #[must_use]
    pub fn dependencies(&self) -> &[ProjectDependency] {
        &self.dependencies
    }

    pub fn add_import(&mut self, import: ProjectImport) {
        if !self.imports.contains(&import) {
            self.imports.push(import);
            self.imports.sort_by_key(|entry| {
                (
                    entry.library.clone(),
                    entry.name.clone(),
                    entry.ordinal,
                    entry.thunk,
                )
            });
        }
    }

    #[must_use]
    pub fn imports(&self) -> &[ProjectImport] {
        &self.imports
    }

    pub fn add_export(&mut self, export: ProjectExport) {
        if !self.exports.contains(&export) {
            self.exports.push(export);
            self.exports.sort_by_key(|entry| {
                (
                    entry.module.clone(),
                    entry.name.clone(),
                    entry.ordinal,
                    entry.address,
                    entry.forwarder.clone(),
                )
            });
        }
    }

    #[must_use]
    pub fn exports(&self) -> &[ProjectExport] {
        &self.exports
    }

    pub fn add_relocation(&mut self, relocation: ProjectRelocation) {
        if !self.relocations.contains(&relocation) {
            self.relocations.push(relocation);
            self.relocations
                .sort_by_key(|entry| (entry.address, entry.kind.clone()));
        }
    }

    #[must_use]
    pub fn relocations(&self) -> &[ProjectRelocation] {
        &self.relocations
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
            dependency_count: self.dependencies.len(),
            symbol_count: self.symbols.len(),
            import_count: self.imports.len(),
            export_count: self.exports.len(),
            relocation_count: self.relocations.len(),
            diagnostic_count: self.binary.diagnostics.len(),
            string_count: self.strings.len(),
            function_count: self.functions.len(),
            block_count: self.basic_blocks.len(),
            ir_function_count: self.ir_functions.len(),
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
        push_json_usize_field(&mut json, 4, "dependencies", summary.dependency_count, true);
        push_json_usize_field(&mut json, 4, "symbols", summary.symbol_count, true);
        push_json_usize_field(&mut json, 4, "imports", summary.import_count, true);
        push_json_usize_field(&mut json, 4, "exports", summary.export_count, true);
        push_json_usize_field(&mut json, 4, "relocations", summary.relocation_count, true);
        push_json_usize_field(&mut json, 4, "diagnostics", summary.diagnostic_count, true);
        push_json_usize_field(&mut json, 4, "strings", summary.string_count, true);
        push_json_usize_field(&mut json, 4, "functions", summary.function_count, true);
        push_json_usize_field(&mut json, 4, "blocks", summary.block_count, true);
        push_json_usize_field(
            &mut json,
            4,
            "ir_functions",
            summary.ir_function_count,
            true,
        );
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
        push_ir_functions_json(&mut json, self);
        json.push_str(",\n");
        push_diagnostics_json(&mut json, self);
        json.push_str(",\n");
        push_symbols_json(&mut json, self);
        json.push_str(",\n");
        push_dependencies_json(&mut json, self);
        json.push_str(",\n");
        push_imports_json(&mut json, self);
        json.push_str(",\n");
        push_exports_json(&mut json, self);
        json.push_str(",\n");
        push_relocations_json(&mut json, self);
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
    pub dependency_count: usize,
    pub symbol_count: usize,
    pub import_count: usize,
    pub export_count: usize,
    pub relocation_count: usize,
    pub diagnostic_count: usize,
    pub string_count: usize,
    pub function_count: usize,
    pub block_count: usize,
    pub ir_function_count: usize,
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
pub struct ProjectIrFunction {
    pub start: Address,
    pub name: Option<String>,
    pub instruction_count: usize,
    pub unknown_count: usize,
    pub blocks: Vec<ProjectIrBlock>,
}

impl ProjectIrFunction {
    #[must_use]
    pub const fn new(start: Address) -> Self {
        Self {
            start,
            name: None,
            instruction_count: 0,
            unknown_count: 0,
            blocks: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectIrBlock {
    pub start: Address,
    pub label: String,
    pub instructions: Vec<ProjectIrInstruction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectIrInstruction {
    pub address: Address,
    pub text: String,
    pub unknown: bool,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectDependency {
    pub name: String,
}

impl From<&Dependency> for ProjectDependency {
    fn from(dependency: &Dependency) -> Self {
        Self {
            name: dependency.name.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectImport {
    pub library: String,
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    pub thunk: Option<Address>,
}

impl From<&Import> for ProjectImport {
    fn from(import: &Import) -> Self {
        Self {
            library: import.library.clone(),
            name: import.name.clone(),
            ordinal: import.ordinal,
            thunk: import.thunk,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectExport {
    pub module: Option<String>,
    pub name: Option<String>,
    pub ordinal: u32,
    pub address: Option<Address>,
    pub forwarder: Option<String>,
}

impl From<&Export> for ProjectExport {
    fn from(export: &Export) -> Self {
        Self {
            module: export.module.clone(),
            name: export.name.clone(),
            ordinal: export.ordinal,
            address: export.address,
            forwarder: export.forwarder.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectRelocation {
    pub address: Address,
    pub kind: String,
}

impl From<&Relocation> for ProjectRelocation {
    fn from(relocation: &Relocation) -> Self {
        Self {
            address: relocation.address,
            kind: relocation.kind.clone(),
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

fn push_ir_functions_json(json: &mut String, project: &Project) {
    json.push_str("  \"ir_functions\": [");
    if project.ir_functions.is_empty() {
        json.push(']');
        return;
    }
    json.push('\n');
    for (index, function) in project.ir_functions.values().enumerate() {
        let comma = if index + 1 == project.ir_functions.len() {
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
        push_json_usize_field(
            json,
            6,
            "instruction_count",
            function.instruction_count,
            true,
        );
        push_json_usize_field(json, 6, "unknown_count", function.unknown_count, true);
        push_ir_blocks_json(json, 6, "blocks", &function.blocks, false);
        json.push_str("    }");
        json.push_str(comma);
        json.push('\n');
    }
    json.push_str("  ]");
}

fn push_ir_blocks_json(
    json: &mut String,
    indent: usize,
    name: &str,
    blocks: &[ProjectIrBlock],
    trailing_comma: bool,
) {
    push_indent(json, indent);
    json.push('"');
    json.push_str(name);
    json.push_str("\": [");
    if blocks.is_empty() {
        json.push(']');
        push_comma_newline(json, trailing_comma);
        return;
    }
    json.push('\n');
    for (index, block) in blocks.iter().enumerate() {
        let comma = if index + 1 == blocks.len() { "" } else { "," };
        push_indent(json, indent + 2);
        json.push_str("{\n");
        push_json_address_field(json, indent + 4, "start", Some(block.start), true);
        push_json_field(json, indent + 4, "label", &block.label, true);
        push_ir_instructions_json(json, indent + 4, "instructions", &block.instructions, false);
        push_indent(json, indent + 2);
        json.push('}');
        json.push_str(comma);
        json.push('\n');
    }
    push_indent(json, indent);
    json.push(']');
    push_comma_newline(json, trailing_comma);
}

fn push_ir_instructions_json(
    json: &mut String,
    indent: usize,
    name: &str,
    instructions: &[ProjectIrInstruction],
    trailing_comma: bool,
) {
    push_indent(json, indent);
    json.push('"');
    json.push_str(name);
    json.push_str("\": [");
    if instructions.is_empty() {
        json.push(']');
        push_comma_newline(json, trailing_comma);
        return;
    }
    json.push('\n');
    for (index, instruction) in instructions.iter().enumerate() {
        let comma = if index + 1 == instructions.len() {
            ""
        } else {
            ","
        };
        push_indent(json, indent + 2);
        json.push_str("{\n");
        push_json_address_field(json, indent + 4, "address", Some(instruction.address), true);
        push_json_field(json, indent + 4, "text", &instruction.text, true);
        push_json_bool_field(json, indent + 4, "unknown", instruction.unknown, false);
        push_indent(json, indent + 2);
        json.push('}');
        json.push_str(comma);
        json.push('\n');
    }
    push_indent(json, indent);
    json.push(']');
    push_comma_newline(json, trailing_comma);
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

fn push_symbols_json(json: &mut String, project: &Project) {
    json.push_str("  \"symbols\": [");
    if project.symbols.is_empty() {
        json.push(']');
        return;
    }
    json.push('\n');
    for (index, symbol) in project.symbols.iter().enumerate() {
        let comma = if index + 1 == project.symbols.len() {
            ""
        } else {
            ","
        };
        json.push_str("    {\n");
        push_json_field(json, 6, "name", &symbol.name, true);
        push_json_address_field(json, 6, "address", symbol.address, false);
        json.push_str("    }");
        json.push_str(comma);
        json.push('\n');
    }
    json.push_str("  ]");
}

fn push_dependencies_json(json: &mut String, project: &Project) {
    json.push_str("  \"dependencies\": [");
    if project.dependencies.is_empty() {
        json.push(']');
        return;
    }
    json.push('\n');
    for (index, dependency) in project.dependencies.iter().enumerate() {
        let comma = if index + 1 == project.dependencies.len() {
            ""
        } else {
            ","
        };
        json.push_str("    {\n");
        push_json_field(json, 6, "name", &dependency.name, false);
        json.push_str("    }");
        json.push_str(comma);
        json.push('\n');
    }
    json.push_str("  ]");
}

fn push_imports_json(json: &mut String, project: &Project) {
    json.push_str("  \"imports\": [");
    if project.imports.is_empty() {
        json.push(']');
        return;
    }
    json.push('\n');
    for (index, import) in project.imports.iter().enumerate() {
        let comma = if index + 1 == project.imports.len() {
            ""
        } else {
            ","
        };
        json.push_str("    {\n");
        push_json_field(json, 6, "library", &import.library, true);
        match &import.name {
            Some(name) => push_json_field(json, 6, "name", name, true),
            None => push_json_null_field(json, 6, "name", true),
        }
        push_json_optional_u16_field(json, 6, "ordinal", import.ordinal, true);
        push_json_address_field(json, 6, "thunk", import.thunk, false);
        json.push_str("    }");
        json.push_str(comma);
        json.push('\n');
    }
    json.push_str("  ]");
}

fn push_exports_json(json: &mut String, project: &Project) {
    json.push_str("  \"exports\": [");
    if project.exports.is_empty() {
        json.push(']');
        return;
    }
    json.push('\n');
    for (index, export) in project.exports.iter().enumerate() {
        let comma = if index + 1 == project.exports.len() {
            ""
        } else {
            ","
        };
        json.push_str("    {\n");
        match &export.module {
            Some(module) => push_json_field(json, 6, "module", module, true),
            None => push_json_null_field(json, 6, "module", true),
        }
        match &export.name {
            Some(name) => push_json_field(json, 6, "name", name, true),
            None => push_json_null_field(json, 6, "name", true),
        }
        push_json_u32_field(json, 6, "ordinal", export.ordinal, true);
        push_json_address_field(json, 6, "address", export.address, true);
        match &export.forwarder {
            Some(forwarder) => push_json_field(json, 6, "forwarder", forwarder, false),
            None => push_json_null_field(json, 6, "forwarder", false),
        }
        json.push_str("    }");
        json.push_str(comma);
        json.push('\n');
    }
    json.push_str("  ]");
}

fn push_relocations_json(json: &mut String, project: &Project) {
    json.push_str("  \"relocations\": [");
    if project.relocations.is_empty() {
        json.push(']');
        return;
    }
    json.push('\n');
    for (index, relocation) in project.relocations.iter().enumerate() {
        let comma = if index + 1 == project.relocations.len() {
            ""
        } else {
            ","
        };
        json.push_str("    {\n");
        push_json_address_field(json, 6, "address", Some(relocation.address), true);
        push_json_field(json, 6, "kind", &relocation.kind, false);
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

fn push_json_u32_field(
    json: &mut String,
    indent: usize,
    name: &str,
    value: u32,
    trailing_comma: bool,
) {
    push_indent(json, indent);
    json.push('"');
    json.push_str(name);
    json.push_str("\": ");
    json.push_str(&value.to_string());
    push_comma_newline(json, trailing_comma);
}

fn push_json_bool_field(
    json: &mut String,
    indent: usize,
    name: &str,
    value: bool,
    trailing_comma: bool,
) {
    push_indent(json, indent);
    json.push('"');
    json.push_str(name);
    json.push_str("\": ");
    json.push_str(if value { "true" } else { "false" });
    push_comma_newline(json, trailing_comma);
}

fn push_json_optional_u16_field(
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
    match value {
        Some(value) => json.push_str(&value.to_string()),
        None => json.push_str("null"),
    }
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
    use kaiju_loader::{BinaryFormat, Dependency, LoadedBinary};
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
        let json = project.to_json_pretty();
        assert!(json.contains("\"symbols\": ["));
        assert!(json.contains("\"name\": \"entry\""));
        assert!(json.contains("\"address\": \"0x0000000000001000\""));
    }

    #[test]
    fn creates_project_from_loaded_binary_and_preserves_imports() {
        let mut binary = test_binary();
        binary.imports.push(Import {
            library: "KERNEL32.dll".to_string(),
            name: Some("ExitProcess".to_string()),
            ordinal: None,
            thunk: Some(Address::new(0x1400020a0)),
        });
        binary.imports.push(Import {
            library: "KERNEL32.dll".to_string(),
            name: None,
            ordinal: Some(7),
            thunk: Some(Address::new(0x1400020a8)),
        });

        let project = Project::from_loaded_binary(binary);

        assert_eq!(project.imports().len(), 2);
        assert_eq!(project.imports()[0].library, "KERNEL32.dll");
        assert_eq!(project.imports()[0].name.as_deref(), Some("ExitProcess"));
        assert_eq!(project.imports()[0].ordinal, None);
        assert_eq!(project.imports()[1].name, None);
        assert_eq!(project.imports()[1].ordinal, Some(7));
        let json = project.to_json_pretty();
        assert!(json.contains("\"imports\": 2"));
        assert!(json.contains("\"imports\": ["));
        assert!(json.contains("\"library\": \"KERNEL32.dll\""));
        assert!(json.contains("\"name\": \"ExitProcess\""));
        assert!(json.contains("\"ordinal\": 7"));
        assert!(json.contains("\"thunk\": \"0x00000001400020a8\""));
    }

    #[test]
    fn creates_project_from_loaded_binary_and_preserves_dependencies() {
        let mut binary = test_binary();
        binary.dependencies.push(Dependency {
            name: "libc.so.6".to_string(),
        });
        binary.dependencies.push(Dependency {
            name: "libssl.so.3".to_string(),
        });

        let project = Project::from_loaded_binary(binary);

        assert_eq!(project.dependencies().len(), 2);
        assert_eq!(project.dependencies()[0].name, "libc.so.6");
        assert_eq!(project.dependencies()[1].name, "libssl.so.3");
        let json = project.to_json_pretty();
        assert!(json.contains("\"dependencies\": 2"));
        assert!(json.contains("\"dependencies\": ["));
        assert!(json.contains("\"name\": \"libc.so.6\""));
        assert!(json.contains("\"name\": \"libssl.so.3\""));
    }

    #[test]
    fn creates_project_from_loaded_binary_and_preserves_exports() {
        let mut binary = test_binary();
        binary.exports.push(Export {
            module: Some("sample.dll".to_string()),
            name: Some("ExportedFunc".to_string()),
            ordinal: 1,
            address: Some(Address::new(0x140001000)),
            forwarder: None,
        });
        binary.exports.push(Export {
            module: Some("sample.dll".to_string()),
            name: Some("ForwardedFunc".to_string()),
            ordinal: 2,
            address: None,
            forwarder: Some("OTHER.Forward".to_string()),
        });
        binary.exports.push(Export {
            module: Some("sample.dll".to_string()),
            name: None,
            ordinal: 3,
            address: Some(Address::new(0x140001010)),
            forwarder: None,
        });

        let project = Project::from_loaded_binary(binary);

        assert_eq!(project.exports().len(), 3);
        assert_eq!(project.exports()[0].module.as_deref(), Some("sample.dll"));
        assert_eq!(project.exports()[0].name.as_deref(), Some("ExportedFunc"));
        assert_eq!(project.exports()[0].ordinal, 1);
        assert_eq!(
            project.exports()[1].forwarder.as_deref(),
            Some("OTHER.Forward")
        );
        assert_eq!(project.exports()[2].name, None);
        let json = project.to_json_pretty();
        assert!(json.contains("\"exports\": 3"));
        assert!(json.contains("\"exports\": ["));
        assert!(json.contains("\"module\": \"sample.dll\""));
        assert!(json.contains("\"name\": \"ExportedFunc\""));
        assert!(json.contains("\"ordinal\": 3"));
        assert!(json.contains("\"forwarder\": \"OTHER.Forward\""));
    }

    #[test]
    fn creates_project_from_loaded_binary_and_preserves_relocations() {
        let mut binary = test_binary();
        binary.relocations.push(Relocation {
            address: Address::new(0x140001008),
            kind: "pe-dir64".to_string(),
        });
        binary.relocations.push(Relocation {
            address: Address::new(0x140001020),
            kind: "pe-highlow".to_string(),
        });

        let project = Project::from_loaded_binary(binary);

        assert_eq!(project.relocations().len(), 2);
        assert_eq!(project.relocations()[0].address, Address::new(0x140001008));
        assert_eq!(project.relocations()[0].kind, "pe-dir64");
        assert_eq!(project.relocations()[1].address, Address::new(0x140001020));
        assert_eq!(project.relocations()[1].kind, "pe-highlow");
        let json = project.to_json_pretty();
        assert!(json.contains("\"relocations\": 2"));
        assert!(json.contains("\"relocations\": ["));
        assert!(json.contains("\"address\": \"0x0000000140001008\""));
        assert!(json.contains("\"kind\": \"pe-highlow\""));
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
    fn stores_ir_summaries_in_project_json() {
        let mut project = Project::from_loaded_binary(test_binary());

        project.add_ir_function(ProjectIrFunction {
            start: Address::new(0x1000),
            name: Some("entry".to_string()),
            instruction_count: 2,
            unknown_count: 1,
            blocks: vec![ProjectIrBlock {
                start: Address::new(0x1000),
                label: "block_1000".to_string(),
                instructions: vec![
                    ProjectIrInstruction {
                        address: Address::new(0x1000),
                        text: "rax = 0x1".to_string(),
                        unknown: false,
                    },
                    ProjectIrInstruction {
                        address: Address::new(0x1005),
                        text: "unknown".to_string(),
                        unknown: true,
                    },
                ],
            }],
        });

        let summary = project.summary();
        let json = project.to_json_pretty();

        assert_eq!(summary.ir_function_count, 1);
        assert_eq!(
            project
                .ir_function(Address::new(0x1000))
                .unwrap()
                .unknown_count,
            1
        );
        assert!(json.contains("\"ir_functions\": 1"));
        assert!(json.contains("\"ir_functions\": ["));
        assert!(json.contains("\"label\": \"block_1000\""));
        assert!(json.contains("\"text\": \"rax = 0x1\""));
        assert!(json.contains("\"unknown\": true"));
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
        assert_eq!(summary.dependency_count, 0);
        assert_eq!(summary.import_count, 0);
        assert_eq!(summary.export_count, 0);
        assert_eq!(summary.relocation_count, 0);
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
        assert!(json.contains("\"dependencies\": 0"));
        assert!(json.contains("\"dependencies\": []"));
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
            dependencies: Vec::new(),
            symbols: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            relocations: Vec::new(),
            diagnostics: Vec::new(),
        }
    }
}
