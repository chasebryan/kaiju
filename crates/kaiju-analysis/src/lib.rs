#![forbid(unsafe_code)]

use std::collections::{BTreeSet, VecDeque};
use std::fmt;

use kaiju_core::{Address, KaijuError, KaijuErrorKind, Result};
use kaiju_disasm::{disassembler_for_architecture, Disassembler, FlowKind, Instruction};
use kaiju_loader::LoadedBinary;
use kaiju_project::{
    Project, ProjectBasicBlock, ProjectCfg, ProjectCfgEdge, ProjectCfgEdgeKind, ProjectString,
    ProjectStringEncoding,
};

const MAX_INSTRUCTION_BYTES: usize = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringEncoding {
    Ascii,
    Utf16Le,
}

impl fmt::Display for StringEncoding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ascii => formatter.write_str("ASCII"),
            Self::Utf16Le => formatter.write_str("UTF-16LE"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedString {
    pub file_offset: u64,
    pub virtual_address: Option<Address>,
    pub encoding: StringEncoding,
    pub char_len: usize,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisReport {
    pub pass_name: String,
    pub facts_added: usize,
    pub warnings: Vec<String>,
}

impl AnalysisReport {
    #[must_use]
    pub fn new(pass_name: impl Into<String>) -> Self {
        Self {
            pass_name: pass_name.into(),
            facts_added: 0,
            warnings: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_facts(mut self, facts_added: usize) -> Self {
        self.facts_added = facts_added;
        self
    }

    #[must_use]
    pub fn with_warning(mut self, warning: impl Into<String>) -> Self {
        self.warnings.push(warning.into());
        self
    }
}

pub trait AnalysisPass {
    fn name(&self) -> &'static str;

    fn run(&self, project: &mut Project) -> Result<AnalysisReport>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalysisConfig {
    pub min_string_len: usize,
    pub cfg_options: CfgOptions,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            min_string_len: 4,
            cfg_options: CfgOptions::default(),
        }
    }
}

#[must_use]
pub fn default_analysis_passes(config: AnalysisConfig) -> Vec<Box<dyn AnalysisPass>> {
    vec![
        Box::new(StringsPass {
            min_len: config.min_string_len,
        }),
        Box::new(EntrypointFunctionPass),
        Box::new(EntrypointCfgPass {
            options: config.cfg_options,
        }),
        Box::new(CrossReferenceSummaryPass),
    ]
}

pub fn run_default_passes(
    project: &mut Project,
    config: AnalysisConfig,
) -> Result<Vec<AnalysisReport>> {
    let mut reports = Vec::new();
    for pass in default_analysis_passes(config) {
        reports.push(pass.run(project)?);
    }
    Ok(reports)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StringsPass {
    pub min_len: usize,
}

impl AnalysisPass for StringsPass {
    fn name(&self) -> &'static str {
        "strings"
    }

    fn run(&self, project: &mut Project) -> Result<AnalysisReport> {
        let count = extract_strings_into_project(project, self.min_len);
        project.add_analysis_fact(kaiju_project::AnalysisFact::new(
            self.name(),
            "strings",
            count.to_string(),
        ));
        Ok(AnalysisReport::new(self.name()).with_facts(count))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntrypointFunctionPass;

impl AnalysisPass for EntrypointFunctionPass {
    fn name(&self) -> &'static str {
        "entrypoint-function"
    }

    fn run(&self, project: &mut Project) -> Result<AnalysisReport> {
        let Some(entrypoint) = project.binary.entrypoint else {
            return Ok(AnalysisReport::new(self.name())
                .with_warning("binary does not define an entrypoint"));
        };

        project.add_function(entrypoint);
        project.add_analysis_fact(kaiju_project::AnalysisFact::new(
            self.name(),
            "entrypoint",
            entrypoint.to_string(),
        ));
        Ok(AnalysisReport::new(self.name()).with_facts(1))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntrypointCfgPass {
    pub options: CfgOptions,
}

impl AnalysisPass for EntrypointCfgPass {
    fn name(&self) -> &'static str {
        "entrypoint-cfg"
    }

    fn run(&self, project: &mut Project) -> Result<AnalysisReport> {
        let Some(entrypoint) = project.binary.entrypoint else {
            return Ok(AnalysisReport::new(self.name())
                .with_warning("binary does not define an entrypoint"));
        };

        let graph = match build_cfg(&project.binary, entrypoint, self.options) {
            Ok(graph) => graph,
            Err(error) => {
                return Ok(
                    AnalysisReport::new(self.name()).with_warning(format!("CFG skipped: {error}"))
                )
            }
        };
        let facts = 1 + graph.blocks.len() + graph.edges.len();
        record_cfg(project, &graph);
        project.add_analysis_fact(kaiju_project::AnalysisFact::new(
            self.name(),
            "blocks",
            graph.blocks.len().to_string(),
        ));

        Ok(AnalysisReport::new(self.name()).with_facts(facts))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrossReferenceSummaryPass;

impl AnalysisPass for CrossReferenceSummaryPass {
    fn name(&self) -> &'static str {
        "xref-summary"
    }

    fn run(&self, project: &mut Project) -> Result<AnalysisReport> {
        let count = project.xrefs().len();
        project.add_analysis_fact(kaiju_project::AnalysisFact::new(
            self.name(),
            "xrefs",
            count.to_string(),
        ));
        Ok(AnalysisReport::new(self.name()).with_facts(1))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlFlowGraph {
    pub function_start: Address,
    pub blocks: Vec<BasicBlock>,
    pub edges: Vec<CfgEdge>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicBlock {
    pub start: Address,
    pub end: Address,
    pub instructions: Vec<Instruction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgEdge {
    pub from: Address,
    pub to: Address,
    pub kind: EdgeKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeKind {
    Fallthrough,
    Jump,
    ConditionalTaken,
    ConditionalNotTaken,
    Call,
    Return,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CfgOptions {
    pub max_instructions: usize,
    pub max_blocks: usize,
}

impl Default for CfgOptions {
    fn default() -> Self {
        Self {
            max_instructions: 256,
            max_blocks: 128,
        }
    }
}

pub fn build_cfg(
    binary: &LoadedBinary,
    function_start: Address,
    options: CfgOptions,
) -> Result<ControlFlowGraph> {
    if options.max_instructions == 0 || options.max_blocks == 0 {
        return Err(KaijuError::new(
            KaijuErrorKind::AnalysisLimitExceeded,
            "CFG limits must be greater than zero",
        ));
    }

    let disassembler = disassembler_for_architecture(binary.arch)?;
    ensure_mapped(binary, function_start)?;

    let mut graph = ControlFlowGraph {
        function_start,
        blocks: Vec::new(),
        edges: Vec::new(),
    };
    let mut worklist = VecDeque::from([function_start]);
    let mut visited = BTreeSet::new();
    let mut decoded_instructions = 0_usize;

    while let Some(block_start) = worklist.pop_front() {
        if graph.blocks.len() >= options.max_blocks
            || decoded_instructions >= options.max_instructions
            || !visited.insert(block_start)
        {
            continue;
        }

        if !is_mapped(binary, block_start) {
            continue;
        }

        let mut instructions = Vec::new();
        let mut current = block_start;
        let mut block_end = block_start;

        loop {
            if decoded_instructions >= options.max_instructions {
                break;
            }

            let bytes = read_instruction_window(binary, current)?;
            let instruction = disassembler.disassemble_one(&bytes, current)?;
            let Some(next_address) = current.checked_add(u64::from(instruction.size)) else {
                graph.edges.push(CfgEdge {
                    from: block_start,
                    to: current,
                    kind: EdgeKind::Unknown,
                });
                block_end = current;
                instructions.push(instruction);
                decoded_instructions += 1;
                break;
            };

            let flow = instruction.flow.clone();
            instructions.push(instruction);
            decoded_instructions += 1;
            block_end = next_address;

            match flow {
                FlowKind::Normal => {
                    if !is_mapped(binary, next_address) {
                        break;
                    }
                    current = next_address;
                }
                FlowKind::Call { target } => {
                    if let Some(target) = target {
                        graph.edges.push(CfgEdge {
                            from: block_start,
                            to: target,
                            kind: EdgeKind::Call,
                        });
                    }
                    if !is_mapped(binary, next_address) {
                        break;
                    }
                    current = next_address;
                }
                FlowKind::Jump { target } => {
                    if let Some(target) = target {
                        graph.edges.push(CfgEdge {
                            from: block_start,
                            to: target,
                            kind: EdgeKind::Jump,
                        });
                        enqueue_if_mapped(binary, target, &visited, &mut worklist);
                    }
                    break;
                }
                FlowKind::ConditionalJump { target } => {
                    if let Some(target) = target {
                        graph.edges.push(CfgEdge {
                            from: block_start,
                            to: target,
                            kind: EdgeKind::ConditionalTaken,
                        });
                        enqueue_if_mapped(binary, target, &visited, &mut worklist);
                    }
                    graph.edges.push(CfgEdge {
                        from: block_start,
                        to: next_address,
                        kind: EdgeKind::ConditionalNotTaken,
                    });
                    enqueue_if_mapped(binary, next_address, &visited, &mut worklist);
                    break;
                }
                FlowKind::Return => {
                    graph.edges.push(CfgEdge {
                        from: block_start,
                        to: current,
                        kind: EdgeKind::Return,
                    });
                    break;
                }
                FlowKind::Trap | FlowKind::Unknown => {
                    graph.edges.push(CfgEdge {
                        from: block_start,
                        to: current,
                        kind: EdgeKind::Unknown,
                    });
                    break;
                }
            }
        }

        if !instructions.is_empty() {
            graph.blocks.push(BasicBlock {
                start: block_start,
                end: block_end,
                instructions,
            });
        }
    }

    Ok(graph)
}

pub fn record_strings(project: &mut Project, strings: &[ExtractedString]) {
    for string in strings {
        project.add_string(ProjectString {
            file_offset: string.file_offset,
            virtual_address: string.virtual_address,
            encoding: project_string_encoding(string.encoding),
            char_len: string.char_len,
            value: string.value.clone(),
        });
    }
}

pub fn extract_strings_into_project(project: &mut Project, min_len: usize) -> usize {
    let strings = extract_strings(&project.binary, min_len);
    let count = strings.len();
    record_strings(project, &strings);
    count
}

pub fn record_cfg(project: &mut Project, graph: &ControlFlowGraph) {
    project.add_cfg(ProjectCfg {
        function_start: graph.function_start,
        blocks: graph
            .blocks
            .iter()
            .map(|block| ProjectBasicBlock {
                start: block.start,
                end: block.end,
                instruction_count: block.instructions.len(),
            })
            .collect(),
        edges: graph
            .edges
            .iter()
            .map(|edge| ProjectCfgEdge {
                from: edge.from,
                to: edge.to,
                kind: project_cfg_edge_kind(edge.kind),
            })
            .collect(),
    });
}

fn read_instruction_window(binary: &LoadedBinary, address: Address) -> Result<Vec<u8>> {
    let region = binary.memory_map.find_region(address).ok_or_else(|| {
        KaijuError::new(
            KaijuErrorKind::UnmappedAddress,
            format!("address {address} is not mapped"),
        )
    })?;
    let relative = address
        .value()
        .checked_sub(region.address.value())
        .ok_or_else(|| {
            KaijuError::new(
                KaijuErrorKind::InvalidAddress,
                "region-relative address underflow",
            )
        })?;
    let available = region.size.checked_sub(relative).ok_or_else(|| {
        KaijuError::new(
            KaijuErrorKind::InvalidAddress,
            "region-relative address exceeds region size",
        )
    })?;
    let len = usize::try_from(available.min(MAX_INSTRUCTION_BYTES as u64)).map_err(|_| {
        KaijuError::new(
            KaijuErrorKind::AnalysisLimitExceeded,
            "mapped instruction window does not fit in memory",
        )
    })?;

    binary.memory_map.read_range(address, len)
}

fn ensure_mapped(binary: &LoadedBinary, address: Address) -> Result<()> {
    if is_mapped(binary, address) {
        Ok(())
    } else {
        Err(KaijuError::new(
            KaijuErrorKind::UnmappedAddress,
            format!("address {address} is not mapped"),
        ))
    }
}

fn is_mapped(binary: &LoadedBinary, address: Address) -> bool {
    binary.memory_map.find_region(address).is_some()
}

fn enqueue_if_mapped(
    binary: &LoadedBinary,
    address: Address,
    visited: &BTreeSet<Address>,
    worklist: &mut VecDeque<Address>,
) {
    if is_mapped(binary, address) && !visited.contains(&address) && !worklist.contains(&address) {
        worklist.push_back(address);
    }
}

#[must_use]
pub fn extract_strings(binary: &LoadedBinary, min_len: usize) -> Vec<ExtractedString> {
    let effective_min_len = min_len.max(1);
    let mut strings = extract_strings_from_bytes(&binary.bytes, effective_min_len);
    for string in &mut strings {
        string.virtual_address = binary
            .memory_map
            .translate_file_offset_to_virtual(string.file_offset);
    }
    strings.sort_by_key(|string| {
        (
            string.file_offset,
            match string.encoding {
                StringEncoding::Ascii => 0_u8,
                StringEncoding::Utf16Le => 1_u8,
            },
        )
    });
    strings
}

#[must_use]
pub fn extract_strings_from_bytes(bytes: &[u8], min_len: usize) -> Vec<ExtractedString> {
    let effective_min_len = min_len.max(1);
    let mut strings = extract_ascii_strings(bytes, effective_min_len);
    strings.extend(extract_utf16le_strings(bytes, effective_min_len));
    strings.sort_by_key(|string| {
        (
            string.file_offset,
            match string.encoding {
                StringEncoding::Ascii => 0_u8,
                StringEncoding::Utf16Le => 1_u8,
            },
        )
    });
    strings
}

fn extract_ascii_strings(bytes: &[u8], min_len: usize) -> Vec<ExtractedString> {
    let mut strings = Vec::new();
    let mut index = 0;

    while index < bytes.len() {
        if !is_printable_ascii(bytes[index]) {
            index += 1;
            continue;
        }

        let start = index;
        while index < bytes.len() && is_printable_ascii(bytes[index]) {
            index += 1;
        }

        if index - start >= min_len {
            let value = String::from_utf8_lossy(&bytes[start..index]).into_owned();
            strings.push(ExtractedString {
                file_offset: start as u64,
                virtual_address: None,
                encoding: StringEncoding::Ascii,
                char_len: index - start,
                value,
            });
        }
    }

    strings
}

fn extract_utf16le_strings(bytes: &[u8], min_len: usize) -> Vec<ExtractedString> {
    let mut strings = Vec::new();
    let mut index = 0;

    while index + 1 < bytes.len() {
        if !is_printable_utf16le_pair(bytes[index], bytes[index + 1]) {
            index += 1;
            continue;
        }

        let start = index;
        let mut chars = Vec::new();
        while index + 1 < bytes.len() && is_printable_utf16le_pair(bytes[index], bytes[index + 1]) {
            chars.push(char::from(bytes[index]));
            index += 2;
        }

        if chars.len() >= min_len {
            strings.push(ExtractedString {
                file_offset: start as u64,
                virtual_address: None,
                encoding: StringEncoding::Utf16Le,
                char_len: chars.len(),
                value: chars.into_iter().collect(),
            });
        }
    }

    strings
}

fn is_printable_ascii(byte: u8) -> bool {
    matches!(byte, b'\t' | b' '..=b'~')
}

fn is_printable_utf16le_pair(low: u8, high: u8) -> bool {
    high == 0 && is_printable_ascii(low)
}

fn project_string_encoding(encoding: StringEncoding) -> ProjectStringEncoding {
    match encoding {
        StringEncoding::Ascii => ProjectStringEncoding::Ascii,
        StringEncoding::Utf16Le => ProjectStringEncoding::Utf16Le,
    }
}

fn project_cfg_edge_kind(kind: EdgeKind) -> ProjectCfgEdgeKind {
    match kind {
        EdgeKind::Fallthrough => ProjectCfgEdgeKind::Fallthrough,
        EdgeKind::Jump => ProjectCfgEdgeKind::Jump,
        EdgeKind::ConditionalTaken => ProjectCfgEdgeKind::ConditionalTaken,
        EdgeKind::ConditionalNotTaken => ProjectCfgEdgeKind::ConditionalNotTaken,
        EdgeKind::Call => ProjectCfgEdgeKind::Call,
        EdgeKind::Return => ProjectCfgEdgeKind::Return,
        EdgeKind::Unknown => ProjectCfgEdgeKind::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaiju_core::{Address, ArchitectureId, Endian, MemoryMap, MemoryRegion, Permissions};
    use kaiju_loader::{load_bytes, BinaryFormat};
    use kaiju_project::{CrossReference, CrossReferenceKind, Project, ProjectStringEncoding};
    use std::path::PathBuf;

    #[test]
    fn extracts_ascii_strings() {
        let strings = extract_strings_from_bytes(b"\0kaiju\0RE\0monster-class\0", 4);

        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].file_offset, 1);
        assert_eq!(strings[0].encoding, StringEncoding::Ascii);
        assert_eq!(strings[0].char_len, 5);
        assert_eq!(strings[0].value, "kaiju");
        assert_eq!(strings[1].value, "monster-class");
    }

    #[test]
    fn extracts_utf16le_strings() {
        let bytes = [0, b'K', 0, b'a', 0, b'i', 0, b'j', 0, b'u', 0, 0xff];
        let strings = extract_strings_from_bytes(&bytes, 4);

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].file_offset, 1);
        assert_eq!(strings[0].encoding, StringEncoding::Utf16Le);
        assert_eq!(strings[0].char_len, 5);
        assert_eq!(strings[0].value, "Kaiju");
    }

    #[test]
    fn honors_minimum_length() {
        let strings = extract_strings_from_bytes(b"abc\0abcd\0", 4);

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "abcd");
    }

    #[test]
    fn maps_file_offset_to_virtual_address_when_possible() {
        let binary = load_bytes(PathBuf::from("raw.bin"), b"\0kaiju\0").expect("load raw");
        assert_eq!(binary.format, BinaryFormat::Raw);

        let strings = extract_strings(&binary, 4);

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].file_offset, 1);
        assert_eq!(strings[0].virtual_address, Some(Address::new(1)));
    }

    #[test]
    fn skips_unmapped_file_offsets() {
        let binary = LoadedBinary {
            path: PathBuf::from("sparse.bin"),
            file_size: 16,
            bytes: b"header\0kaiju\0".to_vec(),
            format: BinaryFormat::Raw,
            arch: kaiju_core::ArchitectureId::Unknown,
            endian: kaiju_core::Endian::Unknown,
            entrypoint: None,
            memory_map: {
                let mut map = kaiju_core::MemoryMap::new();
                map.add_region(
                    kaiju_core::MemoryRegion::new_with_size(
                        "mapped",
                        Address::new(0x1000),
                        Some(0),
                        6,
                        Permissions::read_only(),
                        b"header".to_vec(),
                    )
                    .expect("valid region"),
                );
                map
            },
            sections: Vec::new(),
            symbols: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            diagnostics: Vec::new(),
        };

        let strings = extract_strings(&binary, 4);

        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].value, "header");
        assert_eq!(strings[0].virtual_address, Some(Address::new(0x1000)));
        assert_eq!(strings[1].value, "kaiju");
        assert_eq!(strings[1].virtual_address, None);
    }

    #[test]
    fn builds_cfg_for_conditional_branch() {
        let binary = test_binary(
            Address::new(0x1000),
            vec![0x75, 0x02, 0xc3, 0x90, 0xc3],
            ArchitectureId::X86_64,
        );

        let graph = build_cfg(
            &binary,
            Address::new(0x1000),
            CfgOptions {
                max_instructions: 16,
                max_blocks: 8,
            },
        )
        .expect("build cfg");

        assert_eq!(graph.function_start, Address::new(0x1000));
        assert_eq!(graph.blocks.len(), 3);
        assert!(graph
            .blocks
            .iter()
            .any(|block| block.start == Address::new(0x1000)));
        assert!(graph
            .blocks
            .iter()
            .any(|block| block.start == Address::new(0x1002)));
        assert!(graph
            .blocks
            .iter()
            .any(|block| block.start == Address::new(0x1004)));
        assert!(graph.edges.iter().any(|edge| {
            edge.from == Address::new(0x1000)
                && edge.to == Address::new(0x1004)
                && edge.kind == EdgeKind::ConditionalTaken
        }));
        assert!(graph.edges.iter().any(|edge| {
            edge.from == Address::new(0x1000)
                && edge.to == Address::new(0x1002)
                && edge.kind == EdgeKind::ConditionalNotTaken
        }));
    }

    #[test]
    fn builds_cfg_for_unconditional_jump() {
        let binary = test_binary(
            Address::new(0x2000),
            vec![0xeb, 0x01, 0xcc, 0xc3],
            ArchitectureId::X86_64,
        );

        let graph =
            build_cfg(&binary, Address::new(0x2000), CfgOptions::default()).expect("build cfg");

        assert!(graph.edges.iter().any(|edge| {
            edge.from == Address::new(0x2000)
                && edge.to == Address::new(0x2003)
                && edge.kind == EdgeKind::Jump
        }));
        assert!(graph
            .blocks
            .iter()
            .any(|block| block.start == Address::new(0x2003)));
    }

    #[test]
    fn cfg_rejects_unmapped_start() {
        let binary = test_binary(Address::new(0x3000), vec![0xc3], ArchitectureId::X86_64);

        let error = build_cfg(&binary, Address::new(0x4000), CfgOptions::default())
            .expect_err("unmapped start should fail");

        assert_eq!(error.kind(), KaijuErrorKind::UnmappedAddress);
    }

    #[test]
    fn records_extracted_strings_in_project() {
        let binary = load_bytes(PathBuf::from("raw.bin"), b"\0kaiju\0").expect("load raw");
        let mut project = Project::from_loaded_binary(binary);

        let count = extract_strings_into_project(&mut project, 4);

        assert_eq!(count, 1);
        assert_eq!(project.strings().len(), 1);
        assert_eq!(project.strings()[0].value, "kaiju");
        assert_eq!(project.strings()[0].encoding, ProjectStringEncoding::Ascii);
        assert_eq!(project.strings()[0].virtual_address, Some(Address::new(1)));
    }

    #[test]
    fn records_cfg_in_project() {
        let binary = test_binary(
            Address::new(0x5000),
            vec![0x75, 0x02, 0xc3, 0x90, 0xc3],
            ArchitectureId::X86_64,
        );
        let graph =
            build_cfg(&binary, Address::new(0x5000), CfgOptions::default()).expect("build cfg");
        let mut project = Project::from_loaded_binary(binary);

        record_cfg(&mut project, &graph);

        assert!(project.function(Address::new(0x5000)).is_some());
        assert_eq!(project.basic_blocks().len(), graph.blocks.len());
        assert_eq!(project.cfg_edges().len(), graph.edges.len());
        assert!(project.xrefs().contains(&CrossReference {
            from: Address::new(0x5000),
            to: Address::new(0x5004),
            kind: CrossReferenceKind::Flow,
        }));
    }

    #[test]
    fn default_analysis_records_project_facts() {
        let binary = test_binary(
            Address::new(0x6000),
            vec![0x75, 0x02, 0xc3, 0x90, 0xc3],
            ArchitectureId::X86_64,
        );
        let mut project = Project::from_loaded_binary(binary);

        let reports = run_default_passes(&mut project, AnalysisConfig::default())
            .expect("run default passes");

        assert_eq!(reports.len(), 4);
        assert!(project.function(Address::new(0x6000)).is_some());
        assert!(!project.basic_blocks().is_empty());
        assert!(!project.xrefs().is_empty());
        assert!(project
            .analysis_facts()
            .iter()
            .any(|fact| fact.namespace == "xref-summary"));
    }

    #[test]
    fn default_analysis_warns_when_cfg_is_unsupported() {
        let binary = test_binary(
            Address::new(0x7000),
            b"Kaiju raw fixture".to_vec(),
            ArchitectureId::Unknown,
        );
        let mut project = Project::from_loaded_binary(binary);

        let reports = run_default_passes(&mut project, AnalysisConfig::default())
            .expect("run default passes");

        let cfg_report = reports
            .iter()
            .find(|report| report.pass_name == "entrypoint-cfg")
            .expect("cfg report");

        assert!(!cfg_report.warnings.is_empty());
        assert_eq!(project.strings().len(), 1);
        assert!(project.function(Address::new(0x7000)).is_some());
    }

    fn test_binary(base: Address, bytes: Vec<u8>, arch: ArchitectureId) -> LoadedBinary {
        let mut memory_map = MemoryMap::new();
        memory_map.add_region(MemoryRegion::new(
            "text",
            base,
            Some(0),
            Permissions::read_execute(),
            bytes.clone(),
        ));

        LoadedBinary {
            path: PathBuf::from("test.bin"),
            file_size: bytes.len() as u64,
            bytes,
            format: BinaryFormat::Raw,
            arch,
            endian: Endian::Little,
            entrypoint: Some(base),
            memory_map,
            sections: Vec::new(),
            symbols: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            diagnostics: Vec::new(),
        }
    }
}
