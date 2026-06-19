#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use eframe::egui;
use kaiju_analysis::{
    build_cfg, run_default_passes, AnalysisConfig, AnalysisReport, CfgEdge, CfgOptions,
    ControlFlowGraph, EdgeKind,
};
use kaiju_core::{Address, KaijuError, KaijuErrorKind, Result};
use kaiju_disasm::{disassembler_for_architecture, Disassembler, Instruction};
use kaiju_ir::lift_instructions;
use kaiju_loader::{load_path, LoadedBinary};
use kaiju_project::{CrossReferenceKind, Project, ProjectStringEncoding};

const MAX_INSTRUCTION_BYTES: usize = 15;
const DEFAULT_INSTRUCTION_COUNT: usize = 64;
const KAIJU_LOGO_URI: &str = "bytes://kaiju-word-banner.svg";
const KAIJU_LOGO_START: &str = "<svg id=\"kaiju-word-banner\"";
const KAIJU_LOGO_END: &str = "</svg>";
const KAIJU_LOGO_SOURCE: &str = include_str!("../../../README.md");

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkbenchLoadRequest {
    Path(PathBuf),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkbenchOptions {
    pub instruction_count: usize,
    pub cfg_options: CfgOptions,
}

impl Default for WorkbenchOptions {
    fn default() -> Self {
        Self {
            instruction_count: DEFAULT_INSTRUCTION_COUNT,
            cfg_options: CfgOptions::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct WorkbenchProject {
    pub project: Project,
    pub reports: Vec<AnalysisReport>,
    pub disassembly: ViewText,
    pub cfg: CfgView,
    pub ir: ViewText,
}

impl WorkbenchProject {
    pub fn load(path: impl AsRef<Path>, options: WorkbenchOptions) -> Result<Self> {
        let binary = load_path(path)?;
        Self::from_binary(binary, options)
    }

    pub fn from_binary(binary: LoadedBinary, options: WorkbenchOptions) -> Result<Self> {
        let mut project = Project::from_loaded_binary(binary);
        let reports = run_default_passes(&mut project, AnalysisConfig::default())?;
        let entry_views = EntryViews::from_binary(&project.binary, options);
        Ok(Self {
            project,
            reports,
            disassembly: entry_views.disassembly,
            cfg: entry_views.cfg,
            ir: entry_views.ir,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EntryViews {
    disassembly: ViewText,
    cfg: CfgView,
    ir: ViewText,
}

impl EntryViews {
    fn from_binary(binary: &LoadedBinary, options: WorkbenchOptions) -> Self {
        let instructions = disassemble_entry(binary, options.instruction_count);
        let graph = binary
            .entrypoint
            .map(|entrypoint| build_cfg(binary, entrypoint, options.cfg_options));

        let disassembly = match &instructions {
            Ok(instructions) if instructions.is_empty() => {
                ViewText::warning("No entrypoint instructions were decoded.")
            }
            Ok(instructions) => ViewText::ready(format_disassembly(instructions)),
            Err(error) => ViewText::warning(format!("Disassembly unavailable: {error}")),
        };

        let ir = match &instructions {
            Ok(instructions) if instructions.is_empty() => {
                ViewText::warning("IR unavailable: no entrypoint instructions were decoded.")
            }
            Ok(instructions) => {
                if let Some(entrypoint) = binary.entrypoint {
                    ViewText::ready(lift_instructions(entrypoint, instructions).to_string())
                } else {
                    ViewText::warning("IR unavailable: binary does not define an entrypoint.")
                }
            }
            Err(error) => ViewText::warning(format!("IR unavailable: {error}")),
        };

        let cfg = match graph {
            Some(Ok(graph)) if graph.blocks.is_empty() => {
                CfgView::warning("CFG unavailable: no basic blocks were discovered.")
            }
            Some(Ok(graph)) => CfgView::ready(graph),
            Some(Err(error)) => CfgView::warning(format!("CFG unavailable: {error}")),
            None => CfgView::warning("CFG unavailable: binary does not define an entrypoint."),
        };

        Self {
            disassembly,
            cfg,
            ir,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewText {
    Ready(String),
    Warning(String),
}

impl ViewText {
    fn ready(value: String) -> Self {
        Self::Ready(value)
    }

    fn warning(value: impl Into<String>) -> Self {
        Self::Warning(value.into())
    }

    fn text(&self) -> &str {
        match self {
            Self::Ready(value) | Self::Warning(value) => value,
        }
    }

    fn is_warning(&self) -> bool {
        matches!(self, Self::Warning(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CfgView {
    Ready {
        graph: ControlFlowGraph,
        text: String,
    },
    Warning(String),
}

impl CfgView {
    fn ready(graph: ControlFlowGraph) -> Self {
        let text = format_cfg_text(&graph);
        Self::Ready { graph, text }
    }

    fn warning(value: impl Into<String>) -> Self {
        Self::Warning(value.into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveView {
    Project,
    Disassembly,
    Strings,
    Cfg,
    Ir,
}

pub struct KaijuWorkbenchApp {
    project: Option<WorkbenchProject>,
    active_view: ActiveView,
    path_input: String,
    status: String,
    options: WorkbenchOptions,
    logo_svg: Arc<[u8]>,
}

impl KaijuWorkbenchApp {
    #[must_use]
    pub fn new(request: Option<WorkbenchLoadRequest>) -> Self {
        let mut app = Self {
            project: None,
            active_view: ActiveView::Project,
            path_input: String::new(),
            status: "Load a binary to begin.".to_string(),
            options: WorkbenchOptions::default(),
            logo_svg: kaiju_logo_svg_bytes(),
        };

        if let Some(WorkbenchLoadRequest::Path(path)) = request {
            app.path_input = path.display().to_string();
            app.load_path(path);
        }

        app
    }

    fn load_path(&mut self, path: PathBuf) {
        match WorkbenchProject::load(&path, self.options) {
            Ok(project) => {
                self.status = format!("Loaded {}", path.display());
                self.project = Some(project);
                self.active_view = ActiveView::Project;
            }
            Err(error) => {
                self.status = format!("Load failed: {error}");
                self.project = None;
            }
        }
    }
}

impl eframe::App for KaijuWorkbenchApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        apply_theme(ctx);

        egui::TopBottomPanel::top("top")
            .exact_height(74.0)
            .show(ctx, |ui| {
                render_topbar(ui, self);
            });

        egui::SidePanel::left("browser")
            .resizable(true)
            .default_width(286.0)
            .width_range(240.0..=420.0)
            .show(ctx, |ui| {
                render_browser(ui, self.project.as_ref());
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            render_tabs(ui, &mut self.active_view);
            ui.add_space(10.0);
            match self.project.as_ref() {
                Some(project) => render_active_view(ui, self.active_view, project),
                None => render_empty_state(ui),
            }
        });
    }
}

fn kaiju_logo_svg_bytes() -> Arc<[u8]> {
    Arc::from(kaiju_logo_svg_source().as_bytes())
}

fn kaiju_logo_svg_source() -> &'static str {
    let start = KAIJU_LOGO_SOURCE
        .find(KAIJU_LOGO_START)
        .expect("README should contain the Kaiju SVG logo");
    let end = KAIJU_LOGO_SOURCE[start..]
        .find(KAIJU_LOGO_END)
        .expect("Kaiju SVG logo should have a closing tag")
        + start
        + KAIJU_LOGO_END.len();

    &KAIJU_LOGO_SOURCE[start..end]
}

fn render_topbar(ui: &mut egui::Ui, app: &mut KaijuWorkbenchApp) {
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            render_kaiju_logo(ui, app.logo_svg.clone());
            ui.label(egui::RichText::new(&app.status).color(egui::Color32::LIGHT_GRAY));
        });

        ui.separator();
        ui.label("Binary");
        let response = ui.add(
            egui::TextEdit::singleline(&mut app.path_input)
                .desired_width(f32::INFINITY)
                .hint_text("/path/to/binary"),
        );
        let enter_pressed =
            response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
        if ui.button("Load").clicked() || enter_pressed {
            let path = PathBuf::from(app.path_input.trim());
            app.load_path(path);
        }
    });
}

fn render_kaiju_logo(ui: &mut egui::Ui, logo_svg: Arc<[u8]>) {
    ui.add(
        egui::Image::from_bytes(KAIJU_LOGO_URI, logo_svg)
            .fit_to_exact_size(egui::vec2(112.0, 47.0)),
    );
}

fn render_browser(ui: &mut egui::Ui, project: Option<&WorkbenchProject>) {
    ui.heading("Project Browser");
    ui.separator();

    let Some(project) = project else {
        ui.label("No project loaded.");
        return;
    };

    let summary = project.project.summary();
    browser_pair(ui, "Format", &summary.format);
    browser_pair(ui, "Arch", &summary.architecture);
    browser_pair(
        ui,
        "Entrypoint",
        &summary
            .entrypoint
            .map_or_else(|| "-".to_string(), |address| address.to_string()),
    );
    browser_pair(ui, "Regions", &summary.region_count.to_string());
    browser_pair(ui, "Sections", &summary.section_count.to_string());
    browser_pair(ui, "Functions", &summary.function_count.to_string());
    browser_pair(ui, "Strings", &summary.string_count.to_string());
    browser_pair(ui, "Xrefs", &summary.xref_count.to_string());

    ui.add_space(14.0);
    ui.heading("Functions");
    ui.separator();
    egui::ScrollArea::vertical().show(ui, |ui| {
        if project.project.functions().is_empty() {
            ui.label("-");
        } else {
            for function in project.project.functions().values() {
                ui.horizontal(|ui| {
                    ui.monospace(function.start.to_string());
                    ui.label(function.name.as_deref().unwrap_or("-"));
                });
            }
        }
    });
}

fn browser_pair(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.set_min_width(220.0);
        ui.label(egui::RichText::new(label).color(egui::Color32::GRAY));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.monospace(value);
        });
    });
}

fn render_tabs(ui: &mut egui::Ui, active: &mut ActiveView) {
    ui.horizontal(|ui| {
        tab_button(ui, active, ActiveView::Project, "Project");
        tab_button(ui, active, ActiveView::Disassembly, "Disassembly");
        tab_button(ui, active, ActiveView::Strings, "Strings");
        tab_button(ui, active, ActiveView::Cfg, "CFG");
        tab_button(ui, active, ActiveView::Ir, "IR");
    });
}

fn tab_button(ui: &mut egui::Ui, active: &mut ActiveView, view: ActiveView, label: &str) {
    if ui.selectable_label(*active == view, label).clicked() {
        *active = view;
    }
}

fn render_active_view(ui: &mut egui::Ui, active: ActiveView, project: &WorkbenchProject) {
    match active {
        ActiveView::Project => render_project_view(ui, project),
        ActiveView::Disassembly => {
            render_text_view(ui, "Entrypoint Disassembly", &project.disassembly)
        }
        ActiveView::Strings => render_strings_view(ui, project),
        ActiveView::Cfg => render_cfg_view(ui, project),
        ActiveView::Ir => render_text_view(ui, "IR", &project.ir),
    }
}

fn render_empty_state(ui: &mut egui::Ui) {
    ui.vertical_centered(|ui| {
        ui.add_space(120.0);
        ui.heading("No binary loaded");
        ui.label("Enter a path in the top bar and press Load.");
    });
}

fn render_project_view(ui: &mut egui::Ui, project: &WorkbenchProject) {
    egui::ScrollArea::vertical().show(ui, |ui| {
        let summary = project.project.summary();
        ui.heading("Binary");
        egui::Grid::new("binary-summary")
            .num_columns(2)
            .striped(true)
            .show(ui, |ui| {
                grid_pair(ui, "Path", &summary.path);
                grid_pair(ui, "Size", &format!("{} bytes", summary.file_size));
                grid_pair(ui, "Format", &summary.format);
                grid_pair(ui, "Architecture", &summary.architecture);
                grid_pair(ui, "Endian", &summary.endian);
                grid_pair(
                    ui,
                    "Entrypoint",
                    &summary
                        .entrypoint
                        .map_or_else(|| "-".to_string(), |address| address.to_string()),
                );
            });

        ui.add_space(18.0);
        ui.heading("Memory Map");
        egui::Grid::new("memory-map")
            .num_columns(5)
            .striped(true)
            .show(ui, |ui| {
                header_row(ui, &["Name", "Address", "Size", "Offset", "Perm"]);
                for region in project.project.binary.memory_map.regions() {
                    ui.label(&region.name);
                    ui.monospace(region.address.to_string());
                    ui.label(region.size.to_string());
                    ui.monospace(
                        region
                            .file_offset
                            .map_or_else(|| "-".to_string(), |offset| format!("0x{offset:x}")),
                    );
                    ui.monospace(region.permissions.to_string());
                    ui.end_row();
                }
            });

        ui.add_space(18.0);
        ui.heading("Analysis Reports");
        egui::Grid::new("analysis-reports")
            .num_columns(3)
            .striped(true)
            .show(ui, |ui| {
                header_row(ui, &["Pass", "Facts", "Warnings"]);
                for report in &project.reports {
                    ui.label(&report.pass_name);
                    ui.label(report.facts_added.to_string());
                    if report.warnings.is_empty() {
                        ui.label("-");
                    } else {
                        ui.label(report.warnings.join("; "));
                    }
                    ui.end_row();
                }
            });

        ui.add_space(18.0);
        ui.heading("Cross References");
        egui::Grid::new("xrefs")
            .num_columns(3)
            .striped(true)
            .show(ui, |ui| {
                header_row(ui, &["From", "To", "Kind"]);
                for xref in project.project.xrefs() {
                    ui.monospace(xref.from.to_string());
                    ui.monospace(xref.to.to_string());
                    ui.label(xref_kind_name(xref.kind));
                    ui.end_row();
                }
            });
    });
}

fn render_text_view(ui: &mut egui::Ui, title: &str, content: &ViewText) {
    ui.heading(title);
    if content.is_warning() {
        ui.colored_label(egui::Color32::from_rgb(255, 57, 57), content.text());
        return;
    }
    egui::ScrollArea::both().show(ui, |ui| {
        ui.monospace(content.text());
    });
}

fn render_strings_view(ui: &mut egui::Ui, project: &WorkbenchProject) {
    ui.heading("Strings");
    egui::ScrollArea::both().show(ui, |ui| {
        egui::Grid::new("strings")
            .num_columns(5)
            .striped(true)
            .show(ui, |ui| {
                header_row(ui, &["Offset", "Address", "Encoding", "Length", "Value"]);
                for string in project.project.strings() {
                    ui.monospace(format!("0x{:x}", string.file_offset));
                    ui.monospace(
                        string
                            .virtual_address
                            .map_or_else(|| "-".to_string(), |address| address.to_string()),
                    );
                    ui.label(project_string_encoding_name(&string.encoding));
                    ui.label(string.char_len.to_string());
                    ui.label(&string.value);
                    ui.end_row();
                }
            });
    });
}

fn render_cfg_view(ui: &mut egui::Ui, project: &WorkbenchProject) {
    ui.heading("Control Flow Graph");
    match &project.cfg {
        CfgView::Warning(message) => {
            ui.colored_label(egui::Color32::from_rgb(255, 57, 57), message);
        }
        CfgView::Ready { graph, text } => {
            ui.columns(2, |columns| {
                egui::ScrollArea::both().show(&mut columns[0], |ui| {
                    ui.monospace(text);
                });
                egui::ScrollArea::both().show(&mut columns[1], |ui| {
                    draw_cfg(ui, graph);
                });
            });
        }
    }
}

fn grid_pair(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.label(egui::RichText::new(label).color(egui::Color32::GRAY));
    ui.monospace(value);
    ui.end_row();
}

fn header_row(ui: &mut egui::Ui, labels: &[&str]) {
    for label in labels {
        ui.label(
            egui::RichText::new(*label)
                .strong()
                .color(egui::Color32::WHITE),
        );
    }
    ui.end_row();
}

fn draw_cfg(ui: &mut egui::Ui, graph: &ControlFlowGraph) {
    let block_width = 260.0;
    let block_height = 58.0;
    let row_gap = 38.0;
    let width = 760.0;
    let height = (block_height + row_gap) * graph.blocks.len() as f32 + 40.0;
    let (rect, _) =
        ui.allocate_exact_size(egui::vec2(width, height.max(160.0)), egui::Sense::hover());
    let painter = ui.painter_at(rect);
    let red = egui::Color32::from_rgb(210, 13, 13);
    let white = egui::Color32::from_rgb(244, 244, 244);
    let panel = egui::Color32::from_rgb(17, 17, 17);

    for (index, block) in graph.blocks.iter().enumerate() {
        let min = rect.min + egui::vec2(20.0, 20.0 + index as f32 * (block_height + row_gap));
        let block_rect = egui::Rect::from_min_size(min, egui::vec2(block_width, block_height));
        painter.rect_filled(block_rect, 4.0, panel);
        painter.rect_stroke(block_rect, 4.0, egui::Stroke::new(1.5, red));
        painter.text(
            block_rect.min + egui::vec2(12.0, 14.0),
            egui::Align2::LEFT_TOP,
            block.start.to_string(),
            egui::FontId::monospace(13.0),
            white,
        );
        painter.text(
            block_rect.min + egui::vec2(12.0, 36.0),
            egui::Align2::LEFT_TOP,
            format!("{} instructions", block.instructions.len()),
            egui::FontId::monospace(12.0),
            egui::Color32::GRAY,
        );
    }

    for edge in &graph.edges {
        draw_cfg_edge(&painter, rect, graph, edge);
    }
}

fn draw_cfg_edge(
    painter: &egui::Painter,
    rect: egui::Rect,
    graph: &ControlFlowGraph,
    edge: &CfgEdge,
) {
    let Some(from_index) = graph
        .blocks
        .iter()
        .position(|block| block.start == edge.from)
    else {
        return;
    };
    let Some(to_index) = graph.blocks.iter().position(|block| block.start == edge.to) else {
        return;
    };
    let block_height = 58.0;
    let row_gap = 38.0;
    let from = rect.min
        + egui::vec2(
            280.0,
            20.0 + from_index as f32 * (block_height + row_gap) + block_height / 2.0,
        );
    let to = rect.min
        + egui::vec2(
            280.0,
            20.0 + to_index as f32 * (block_height + row_gap) + block_height / 2.0,
        );
    let lane = rect.min.x + 360.0 + ((from_index + to_index) % 3) as f32 * 90.0;
    let mid_a = egui::pos2(lane, from.y);
    let mid_b = egui::pos2(lane, to.y);
    let white = egui::Color32::from_rgb(244, 244, 244);
    painter.line_segment([from, mid_a], egui::Stroke::new(1.2, white));
    painter.line_segment([mid_a, mid_b], egui::Stroke::new(1.2, white));
    painter.line_segment([mid_b, to], egui::Stroke::new(1.2, white));
    painter.circle_filled(to, 3.0, white);
    painter.text(
        egui::pos2(lane + 8.0, (from.y + to.y) / 2.0),
        egui::Align2::LEFT_CENTER,
        edge_kind_name(edge.kind),
        egui::FontId::monospace(12.0),
        white,
    );
}

fn apply_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.window_fill = egui::Color32::from_rgb(5, 5, 5);
    visuals.panel_fill = egui::Color32::from_rgb(8, 8, 8);
    visuals.extreme_bg_color = egui::Color32::from_rgb(3, 3, 3);
    visuals.faint_bg_color = egui::Color32::from_rgb(17, 17, 17);
    visuals.selection.bg_fill = egui::Color32::from_rgb(210, 13, 13);
    visuals.hyperlink_color = egui::Color32::from_rgb(255, 57, 57);
    visuals.widgets.active.bg_fill = egui::Color32::from_rgb(210, 13, 13);
    visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(40, 20, 20);
    ctx.set_visuals(visuals);
}

fn disassemble_entry(binary: &LoadedBinary, count: usize) -> Result<Vec<Instruction>> {
    let Some(entrypoint) = binary.entrypoint else {
        return Err(KaijuError::new(
            KaijuErrorKind::InvalidAddress,
            "binary does not define an entrypoint",
        ));
    };
    let bytes = read_instruction_window(binary, entrypoint, count)?;
    let disassembler = disassembler_for_architecture(binary.arch)?;
    disassembler.disassemble_block(&bytes, entrypoint, count)
}

fn read_instruction_window(binary: &LoadedBinary, start: Address, count: usize) -> Result<Vec<u8>> {
    let region = binary.memory_map.find_region(start).ok_or_else(|| {
        KaijuError::new(
            KaijuErrorKind::UnmappedAddress,
            format!("address {start} is not mapped"),
        )
    })?;
    let relative = start
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
    let max_bytes = count.checked_mul(MAX_INSTRUCTION_BYTES).ok_or_else(|| {
        KaijuError::new(
            KaijuErrorKind::AnalysisLimitExceeded,
            "requested instruction byte window is too large",
        )
    })?;
    let len = usize::try_from(available.min(max_bytes as u64)).map_err(|_| {
        KaijuError::new(
            KaijuErrorKind::AnalysisLimitExceeded,
            "mapped instruction window does not fit in memory",
        )
    })?;

    binary.memory_map.read_range(start, len)
}

fn format_disassembly(instructions: &[Instruction]) -> String {
    let mut output = String::new();
    for instruction in instructions {
        writeln!(output, "{}", format_instruction(instruction)).expect("write disassembly");
    }
    output
}

fn format_instruction(instruction: &Instruction) -> String {
    let bytes = instruction
        .bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    let operands = instruction
        .operands
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    if operands.is_empty() {
        format!(
            "{:016x}  {:<24} {}",
            instruction.address.value(),
            bytes,
            instruction.mnemonic
        )
    } else {
        format!(
            "{:016x}  {:<24} {} {}",
            instruction.address.value(),
            bytes,
            instruction.mnemonic,
            operands
        )
    }
}

fn format_cfg_text(graph: &ControlFlowGraph) -> String {
    let mut output = String::new();
    writeln!(output, "Function: {}", graph.function_start).expect("write cfg");
    writeln!(output).expect("write cfg");
    writeln!(output, "Blocks:").expect("write cfg");
    for block in &graph.blocks {
        writeln!(output, "{}..{}", block.start, block.end).expect("write cfg");
        for instruction in &block.instructions {
            writeln!(output, "  {}", format_instruction(instruction)).expect("write cfg");
        }
    }
    writeln!(output).expect("write cfg");
    writeln!(output, "Edges:").expect("write cfg");
    for edge in &graph.edges {
        writeln!(
            output,
            "{} -> {} {}",
            edge.from,
            edge.to,
            edge_kind_name(edge.kind)
        )
        .expect("write cfg");
    }
    output
}

fn edge_kind_name(kind: EdgeKind) -> &'static str {
    match kind {
        EdgeKind::Fallthrough => "fallthrough",
        EdgeKind::Jump => "jump",
        EdgeKind::ConditionalTaken => "conditional-taken",
        EdgeKind::ConditionalNotTaken => "conditional-not-taken",
        EdgeKind::Call => "call",
        EdgeKind::Return => "return",
        EdgeKind::Unknown => "unknown",
    }
}

fn xref_kind_name(kind: CrossReferenceKind) -> &'static str {
    match kind {
        CrossReferenceKind::Flow => "flow",
        CrossReferenceKind::Call => "call",
        CrossReferenceKind::Data => "data",
        CrossReferenceKind::Read => "read",
        CrossReferenceKind::Write => "write",
        CrossReferenceKind::Unknown => "unknown",
    }
}

fn project_string_encoding_name(encoding: &ProjectStringEncoding) -> &str {
    match encoding {
        ProjectStringEncoding::Ascii => "ASCII",
        ProjectStringEncoding::Utf16Le => "UTF-16LE",
        ProjectStringEncoding::Other(value) => value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn loads_raw_project_with_warning_views() {
        let path = temp_file("kaiju-workbench-raw.bin");
        fs::write(&path, b"Kaiju raw fixture").expect("write fixture");

        let workbench = WorkbenchProject::load(&path, WorkbenchOptions::default())
            .expect("load workbench project");

        assert_eq!(workbench.project.strings().len(), 1);
        assert!(matches!(workbench.disassembly, ViewText::Warning(_)));
        assert!(matches!(workbench.cfg, CfgView::Warning(_)));
        assert!(matches!(workbench.ir, ViewText::Warning(_)));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn extracts_kaiju_svg_logo_from_readme() {
        let logo = kaiju_logo_svg_source();

        assert!(logo.starts_with(KAIJU_LOGO_START));
        assert!(logo.ends_with(KAIJU_LOGO_END));
        assert!(logo.contains("kaiju-red-word"));
        assert!(logo.contains("#d20d0d"));
    }

    fn temp_file(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{name}-{unique}"))
    }
}
