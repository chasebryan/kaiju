#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use eframe::egui;
use kaiju_analysis::{
    build_cfg, run_default_passes, AnalysisConfig, AnalysisReport, CfgEdge, CfgOptions,
    ControlFlowGraph, EdgeKind,
};
use kaiju_core::{Address, DiagnosticSeverity, KaijuError, KaijuErrorKind, Result};
use kaiju_disasm::{disassembler_for_architecture, Disassembler, Instruction};
use kaiju_ir::lift_instructions;
use kaiju_loader::{load_path, LoadedBinary};
use kaiju_project::{CrossReferenceKind, Project, ProjectStringEncoding};
use serde_json::{json, Value};

const MAX_PACKAGE_JSON_BYTES: u64 = 16 * 1024 * 1024;
const MAX_INSTRUCTION_BYTES: usize = 15;
const DEFAULT_INSTRUCTION_COUNT: usize = 64;
const MAX_RECENT_ITEMS: usize = 10;
const MAX_LOG_ITEMS: usize = 200;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkbenchSource {
    Binary(PathBuf),
    Package {
        package_dir: PathBuf,
        source_path: PathBuf,
    },
}

impl WorkbenchSource {
    fn display_name(&self) -> String {
        match self {
            Self::Binary(path) => path.display().to_string(),
            Self::Package {
                package_dir,
                source_path,
            } => format!("{} -> {}", package_dir.display(), source_path.display()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectPackageInspection {
    pub directory: PathBuf,
    pub source_path: PathBuf,
    pub file_size: u64,
    pub format: String,
    pub architecture: String,
    pub endian: String,
    pub functions: usize,
    pub blocks: usize,
    pub ir_functions: usize,
    pub xrefs: usize,
    pub analysis_facts: usize,
}

#[derive(Debug, Clone)]
pub struct WorkbenchProject {
    pub project: Project,
    pub reports: Vec<AnalysisReport>,
    pub disassembly: ViewText,
    pub cfg: CfgView,
    pub ir: ViewText,
    pub source: WorkbenchSource,
    pub package: Option<ProjectPackageInspection>,
}

impl WorkbenchProject {
    pub fn load(path: impl AsRef<Path>, options: WorkbenchOptions) -> Result<Self> {
        let path = path.as_ref();
        let binary = load_path(path)?;
        Self::from_binary_with_source(
            binary,
            options,
            WorkbenchSource::Binary(path.to_path_buf()),
            None,
        )
    }

    pub fn load_package(package_dir: impl AsRef<Path>, options: WorkbenchOptions) -> Result<Self> {
        let inspection = inspect_project_package(package_dir.as_ref())?;
        let binary = load_path(&inspection.source_path)?;
        Self::from_binary_with_source(
            binary,
            options,
            WorkbenchSource::Package {
                package_dir: inspection.directory.clone(),
                source_path: inspection.source_path.clone(),
            },
            Some(inspection),
        )
    }

    pub fn from_binary(binary: LoadedBinary, options: WorkbenchOptions) -> Result<Self> {
        let source = WorkbenchSource::Binary(binary.path.clone());
        Self::from_binary_with_source(binary, options, source, None)
    }

    fn from_binary_with_source(
        binary: LoadedBinary,
        options: WorkbenchOptions,
        source: WorkbenchSource,
        package: Option<ProjectPackageInspection>,
    ) -> Result<Self> {
        let mut project = Project::from_loaded_binary(binary);
        let reports = run_default_passes(&mut project, AnalysisConfig::default())?;
        let entry_views = EntryViews::from_binary(&project.binary, options);
        Ok(Self {
            project,
            reports,
            disassembly: entry_views.disassembly,
            cfg: entry_views.cfg,
            ir: entry_views.ir,
            source,
            package,
        })
    }
}

pub fn save_project_package(project: &Project, output_dir: &Path) -> Result<()> {
    prepare_project_package_dir(output_dir)?;
    write_package_file(
        &output_dir.join("manifest.json"),
        &project_package_manifest_json(project)?,
    )?;
    write_package_file(&output_dir.join("project.json"), &project.to_json_pretty())?;
    write_package_file(
        &output_dir.join("annotations.json"),
        &empty_annotations_json()?,
    )?;
    Ok(())
}

pub fn inspect_project_package(package_dir: &Path) -> Result<ProjectPackageInspection> {
    if !package_dir.is_dir() {
        return Err(KaijuError::new(
            KaijuErrorKind::Io,
            format!(
                "project package is not a directory: {}",
                package_dir.display()
            ),
        ));
    }

    let manifest = read_package_json_file(package_dir, "manifest.json")?;
    let project = read_package_json_file(package_dir, "project.json")?;
    let annotations = read_package_json_file(package_dir, "annotations.json")?;

    require_json_string(&manifest, "schema", "kaiju.package.v1", "manifest.json")?;
    require_json_string(
        &manifest,
        "project_schema",
        "kaiju.project.v1",
        "manifest.json",
    )?;
    require_json_string_path(
        &manifest,
        &["files", "project"],
        "project.json",
        "manifest.json",
    )?;
    require_json_string_path(
        &manifest,
        &["files", "annotations"],
        "annotations.json",
        "manifest.json",
    )?;
    require_json_string(&project, "schema", "kaiju.project.v1", "project.json")?;
    require_json_string(
        &annotations,
        "schema",
        "kaiju.annotations.v1",
        "annotations.json",
    )?;

    let source = manifest
        .get("source")
        .ok_or_else(|| malformed_package("manifest.json is missing source object"))?;
    let summary = project
        .get("summary")
        .ok_or_else(|| malformed_package("project.json is missing summary object"))?;
    let source_path = json_path_string(source, &["path"], "manifest.json")?;

    Ok(ProjectPackageInspection {
        directory: package_dir.to_path_buf(),
        source_path: PathBuf::from(source_path),
        file_size: json_path_u64(source, &["file_size"]).unwrap_or(0),
        format: json_path_string(source, &["format"], "manifest.json")?,
        architecture: json_path_string(source, &["architecture"], "manifest.json")?,
        endian: json_path_string(source, &["endian"], "manifest.json")?,
        functions: json_path_usize(summary, &["functions"]).unwrap_or(0),
        blocks: json_path_usize(summary, &["blocks"]).unwrap_or(0),
        ir_functions: json_path_usize(summary, &["ir_functions"]).unwrap_or(0),
        xrefs: json_path_usize(summary, &["xrefs"]).unwrap_or(0),
        analysis_facts: json_path_usize(summary, &["analysis_facts"]).unwrap_or(0),
    })
}

fn prepare_project_package_dir(output_dir: &Path) -> Result<()> {
    if output_dir.exists() {
        if !output_dir.is_dir() {
            return Err(KaijuError::new(
                KaijuErrorKind::Io,
                format!(
                    "project package output is not a directory: {}",
                    output_dir.display()
                ),
            ));
        }

        if fs::read_dir(output_dir)?.next().is_some() {
            return Err(KaijuError::new(
                KaijuErrorKind::Io,
                format!(
                    "project package output directory is not empty: {}",
                    output_dir.display()
                ),
            ));
        }
        return Ok(());
    }

    fs::create_dir_all(output_dir)?;
    Ok(())
}

fn write_package_file(path: &Path, contents: &str) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(contents.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

fn project_package_manifest_json(project: &Project) -> Result<String> {
    let summary = project.summary();
    let manifest = json!({
        "schema": "kaiju.package.v1",
        "project_schema": "kaiju.project.v1",
        "source": {
            "path": summary.path,
            "file_size": summary.file_size,
            "format": summary.format,
            "architecture": summary.architecture,
            "endian": summary.endian,
            "entrypoint": project.binary.entrypoint.map(|address| address.to_string()),
        },
        "files": {
            "project": "project.json",
            "annotations": "annotations.json",
        },
    });

    serde_json::to_string_pretty(&manifest).map_err(|error| {
        KaijuError::new(
            KaijuErrorKind::MalformedBinary,
            format!("failed to encode package manifest: {error}"),
        )
    })
}

fn empty_annotations_json() -> Result<String> {
    serde_json::to_string_pretty(&json!({
        "schema": "kaiju.annotations.v1",
        "labels": [],
        "comments": [],
    }))
    .map_err(|error| {
        KaijuError::new(
            KaijuErrorKind::MalformedBinary,
            format!("failed to encode empty annotations: {error}"),
        )
    })
}

fn read_package_json_file(package_dir: &Path, name: &str) -> Result<Value> {
    let path = package_dir.join(name);
    let metadata = fs::metadata(&path)?;
    if !metadata.is_file() {
        return Err(KaijuError::new(
            KaijuErrorKind::Io,
            format!(
                "project package file is not a regular file: {}",
                path.display()
            ),
        ));
    }
    if metadata.len() > MAX_PACKAGE_JSON_BYTES {
        return Err(KaijuError::new(
            KaijuErrorKind::AnalysisLimitExceeded,
            format!(
                "project package file is too large: {} has {} bytes, limit is {MAX_PACKAGE_JSON_BYTES}",
                path.display(),
                metadata.len()
            ),
        ));
    }

    let text = fs::read_to_string(path)?;
    serde_json::from_str(&text).map_err(|error| {
        KaijuError::new(
            KaijuErrorKind::MalformedBinary,
            format!("{name} is not valid JSON: {error}"),
        )
    })
}

fn require_json_string(value: &Value, field: &str, expected: &str, file_name: &str) -> Result<()> {
    require_json_string_path(value, &[field], expected, file_name)
}

fn require_json_string_path(
    value: &Value,
    path: &[&str],
    expected: &str,
    file_name: &str,
) -> Result<()> {
    let actual = json_path_string(value, path, file_name)?;
    if actual == expected {
        Ok(())
    } else {
        Err(malformed_package(format!(
            "{file_name} has {}={actual}, expected {expected}",
            path.join(".")
        )))
    }
}

fn json_path_string(value: &Value, path: &[&str], file_name: &str) -> Result<String> {
    json_path(value, path)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            malformed_package(format!(
                "{file_name} is missing string field {}",
                path.join(".")
            ))
        })
}

fn json_path_usize(value: &Value, path: &[&str]) -> Option<usize> {
    usize::try_from(json_path_u64(value, path)?).ok()
}

fn json_path_u64(value: &Value, path: &[&str]) -> Option<u64> {
    json_path(value, path)?.as_u64()
}

fn json_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    Some(current)
}

fn malformed_package(message: impl Into<String>) -> KaijuError {
    KaijuError::new(KaijuErrorKind::MalformedBinary, message)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecentKind {
    Binary,
    Package,
}

impl RecentKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Binary => "binary",
            Self::Package => "package",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Binary => "Binary",
            Self::Package => "Package",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "binary" => Some(Self::Binary),
            "package" => Some(Self::Package),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecentItem {
    kind: RecentKind,
    path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkbenchAction {
    SelectFunction(Address),
    SelectAddress(Address),
}

pub struct KaijuWorkbenchApp {
    project: Option<WorkbenchProject>,
    active_view: ActiveView,
    selected_function: Option<Address>,
    selected_address: Option<Address>,
    status: String,
    logs: Vec<String>,
    recent_items: Vec<RecentItem>,
    show_diagnostics: bool,
    show_log: bool,
    options: WorkbenchOptions,
    logo_svg: Arc<[u8]>,
}

impl KaijuWorkbenchApp {
    #[must_use]
    pub fn new(request: Option<WorkbenchLoadRequest>) -> Self {
        let mut app = Self {
            project: None,
            active_view: ActiveView::Project,
            selected_function: None,
            selected_address: None,
            status: "Load a binary to begin.".to_string(),
            logs: Vec::new(),
            recent_items: load_recent_items(),
            show_diagnostics: true,
            show_log: true,
            options: WorkbenchOptions::default(),
            logo_svg: kaiju_logo_svg_bytes(),
        };

        if let Some(WorkbenchLoadRequest::Path(path)) = request {
            app.load_path(path);
        }

        app
    }

    fn load_path(&mut self, path: PathBuf) {
        if path.is_dir() {
            self.open_package(path);
        } else {
            self.open_binary(path);
        }
    }

    fn open_binary_dialog(&mut self) {
        if let Some(path) = rfd::FileDialog::new().set_title("Open binary").pick_file() {
            self.open_binary(path);
        }
    }

    fn open_package_dialog(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Open .kaiju package")
            .pick_folder()
        {
            self.open_package(path);
        }
    }

    fn save_package_dialog(&mut self) {
        let Some(project) = self.project.as_ref() else {
            self.set_status("No project loaded to save.");
            return;
        };

        let default_name = default_package_file_name(project);
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Save .kaiju package")
            .set_file_name(&default_name)
            .save_file()
        {
            self.save_package(path);
        }
    }

    fn open_binary(&mut self, path: PathBuf) {
        match WorkbenchProject::load(&path, self.options) {
            Ok(project) => {
                let selected_function = default_selected_function(&project.project);
                self.selected_function = selected_function;
                self.selected_address = selected_function.or(project.project.binary.entrypoint);
                self.remember_recent(RecentKind::Binary, path.clone());
                self.set_status(format!("Opened binary {}", path.display()));
                self.project = Some(project);
                self.active_view = ActiveView::Project;
            }
            Err(error) => {
                self.set_status(format!("Open binary failed: {error}"));
                self.project = None;
                self.selected_function = None;
                self.selected_address = None;
            }
        }
    }

    fn open_package(&mut self, path: PathBuf) {
        match WorkbenchProject::load_package(&path, self.options) {
            Ok(project) => {
                let selected_function = default_selected_function(&project.project);
                self.selected_function = selected_function;
                self.selected_address = selected_function.or(project.project.binary.entrypoint);
                self.remember_recent(RecentKind::Package, path.clone());
                self.set_status(format!("Opened package {}", path.display()));
                self.project = Some(project);
                self.active_view = ActiveView::Project;
            }
            Err(error) => {
                self.set_status(format!("Open package failed: {error}"));
                self.project = None;
                self.selected_function = None;
                self.selected_address = None;
            }
        }
    }

    fn save_package(&mut self, mut path: PathBuf) {
        if path.extension().is_none() {
            path.set_extension("kaiju");
        }

        let Some(project) = self.project.as_ref() else {
            self.set_status("No project loaded to save.");
            return;
        };

        match save_project_package(&project.project, &path) {
            Ok(()) => {
                self.remember_recent(RecentKind::Package, path.clone());
                self.set_status(format!("Saved package {}", path.display()));
            }
            Err(error) => {
                self.set_status(format!("Save package failed: {error}"));
            }
        }
    }

    fn load_recent(&mut self, item: RecentItem) {
        match item.kind {
            RecentKind::Binary => self.open_binary(item.path),
            RecentKind::Package => self.open_package(item.path),
        }
    }

    fn remember_recent(&mut self, kind: RecentKind, path: PathBuf) {
        self.recent_items
            .retain(|item| item.kind != kind || item.path != path);
        self.recent_items.insert(0, RecentItem { kind, path });
        self.recent_items.truncate(MAX_RECENT_ITEMS);
        if let Err(error) = save_recent_items(&self.recent_items) {
            self.log(format!("Recent list was not saved: {error}"));
        }
    }

    fn set_status(&mut self, status: impl Into<String>) {
        let status = status.into();
        self.status = status.clone();
        self.log(status);
    }

    fn log(&mut self, message: impl Into<String>) {
        self.logs.push(message.into());
        if self.logs.len() > MAX_LOG_ITEMS {
            let overflow = self.logs.len() - MAX_LOG_ITEMS;
            self.logs.drain(0..overflow);
        }
    }

    fn apply_action(&mut self, action: WorkbenchAction) {
        match action {
            WorkbenchAction::SelectFunction(address) => {
                self.selected_function = Some(address);
                self.selected_address = Some(address);
                self.set_status(format!("Selected function {address}"));
            }
            WorkbenchAction::SelectAddress(address) => {
                self.selected_address = Some(address);
                if let Some(project) = self.project.as_ref() {
                    if let Some(function) = function_containing_address(&project.project, address) {
                        self.selected_function = Some(function);
                    }
                }
                self.set_status(format!("Selected address {address}"));
            }
        }
    }
}

impl eframe::App for KaijuWorkbenchApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        apply_theme(ctx);

        let mut actions = Vec::new();

        egui::TopBottomPanel::top("menu")
            .exact_height(28.0)
            .show(ctx, |ui| {
                render_menu_bar(ui, ctx, self);
            });

        egui::TopBottomPanel::top("toolbar")
            .exact_height(72.0)
            .show(ctx, |ui| {
                render_topbar(ui, self);
            });

        egui::SidePanel::left("browser")
            .resizable(true)
            .default_width(286.0)
            .width_range(240.0..=420.0)
            .show(ctx, |ui| {
                render_browser(
                    ui,
                    self.project.as_ref(),
                    self.selected_function,
                    self.selected_address,
                    &mut actions,
                );
            });

        if self.show_diagnostics {
            egui::SidePanel::right("diagnostics")
                .resizable(true)
                .default_width(320.0)
                .width_range(260.0..=460.0)
                .show(ctx, |ui| {
                    render_diagnostics(ui, self.project.as_ref());
                });
        }

        if self.show_log {
            egui::TopBottomPanel::bottom("log")
                .resizable(true)
                .default_height(130.0)
                .height_range(84.0..=260.0)
                .show(ctx, |ui| {
                    render_log_panel(ui, &self.status, &self.logs);
                });
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            render_tabs(ui, &mut self.active_view);
            ui.add_space(10.0);
            match self.project.as_ref() {
                Some(project) => render_active_view(
                    ui,
                    self.active_view,
                    project,
                    self.selected_function,
                    self.selected_address,
                    self.options,
                    &mut actions,
                ),
                None => render_empty_state(ui),
            }
        });

        for action in actions {
            self.apply_action(action);
        }
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

fn render_menu_bar(ui: &mut egui::Ui, ctx: &egui::Context, app: &mut KaijuWorkbenchApp) {
    egui::menu::bar(ui, |ui| {
        ui.menu_button("File", |ui| {
            if ui.button("Open Binary...").clicked() {
                ui.close_menu();
                app.open_binary_dialog();
            }
            if ui.button("Open Package...").clicked() {
                ui.close_menu();
                app.open_package_dialog();
            }
            ui.separator();
            let save_enabled = app.project.is_some();
            if ui
                .add_enabled(save_enabled, egui::Button::new("Save As Package..."))
                .clicked()
            {
                ui.close_menu();
                app.save_package_dialog();
            }
            ui.separator();
            ui.menu_button("Recent", |ui| {
                if app.recent_items.is_empty() {
                    ui.label("No recent items.");
                } else {
                    for item in app.recent_items.clone() {
                        let label = format!("{}  {}", item.kind.label(), item.path.display());
                        if ui.button(label).clicked() {
                            ui.close_menu();
                            app.load_recent(item);
                        }
                    }
                }
            });
            ui.separator();
            if ui.button("Quit").clicked() {
                ui.close_menu();
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        });

        ui.menu_button("View", |ui| {
            ui.checkbox(&mut app.show_diagnostics, "Diagnostics");
            ui.checkbox(&mut app.show_log, "Log");
            if ui.button("Project").clicked() {
                app.active_view = ActiveView::Project;
                ui.close_menu();
            }
            if ui.button("Disassembly").clicked() {
                app.active_view = ActiveView::Disassembly;
                ui.close_menu();
            }
            if ui.button("Strings").clicked() {
                app.active_view = ActiveView::Strings;
                ui.close_menu();
            }
            if ui.button("CFG").clicked() {
                app.active_view = ActiveView::Cfg;
                ui.close_menu();
            }
            if ui.button("IR").clicked() {
                app.active_view = ActiveView::Ir;
                ui.close_menu();
            }
        });

        ui.menu_button("Selection", |ui| {
            if ui.button("Clear").clicked() {
                app.selected_function = None;
                app.selected_address = None;
                app.set_status("Selection cleared.");
                ui.close_menu();
            }
        });
    });
}

fn render_topbar(ui: &mut egui::Ui, app: &mut KaijuWorkbenchApp) {
    ui.horizontal_centered(|ui| {
        ui.vertical(|ui| {
            render_kaiju_logo(ui, app.logo_svg.clone());
        });

        ui.separator();
        if ui.button("Open Binary").clicked() {
            app.open_binary_dialog();
        }
        if ui.button("Open Package").clicked() {
            app.open_package_dialog();
        }
        if ui
            .add_enabled(app.project.is_some(), egui::Button::new("Save Package"))
            .clicked()
        {
            app.save_package_dialog();
        }

        ui.separator();
        ui.vertical(|ui| {
            ui.label(egui::RichText::new(&app.status).color(egui::Color32::LIGHT_GRAY));
            if let Some(project) = app.project.as_ref() {
                ui.monospace(project.source.display_name());
            } else {
                ui.label("No project loaded.");
            }
        });
    });
}

fn render_kaiju_logo(ui: &mut egui::Ui, logo_svg: Arc<[u8]>) {
    ui.add(
        egui::Image::from_bytes(KAIJU_LOGO_URI, logo_svg)
            .fit_to_exact_size(egui::vec2(112.0, 47.0)),
    );
}

fn render_browser(
    ui: &mut egui::Ui,
    project: Option<&WorkbenchProject>,
    selected_function: Option<Address>,
    selected_address: Option<Address>,
    actions: &mut Vec<WorkbenchAction>,
) {
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
    ui.heading("Selection");
    ui.separator();
    browser_pair(
        ui,
        "Function",
        &selected_function.map_or_else(|| "-".to_string(), |address| address.to_string()),
    );
    browser_pair(
        ui,
        "Address",
        &selected_address.map_or_else(|| "-".to_string(), |address| address.to_string()),
    );

    ui.add_space(14.0);
    ui.heading("Functions");
    ui.separator();
    egui::ScrollArea::vertical().show(ui, |ui| {
        if project.project.functions().is_empty() {
            ui.label("-");
        } else {
            for function in project.project.functions().values() {
                let label = function_label(function.start, function.name.as_deref());
                if ui
                    .selectable_label(selected_function == Some(function.start), label)
                    .clicked()
                {
                    actions.push(WorkbenchAction::SelectFunction(function.start));
                }
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

fn render_active_view(
    ui: &mut egui::Ui,
    active: ActiveView,
    project: &WorkbenchProject,
    selected_function: Option<Address>,
    selected_address: Option<Address>,
    options: WorkbenchOptions,
    actions: &mut Vec<WorkbenchAction>,
) {
    match active {
        ActiveView::Project => render_project_view(ui, project, actions),
        ActiveView::Disassembly => {
            render_disassembly_view(ui, project, selected_function, selected_address, options)
        }
        ActiveView::Strings => render_strings_view(ui, project, selected_address, actions),
        ActiveView::Cfg => render_cfg_view(ui, project, selected_function, options, actions),
        ActiveView::Ir => render_ir_view(ui, project, selected_function, selected_address),
    }
}

fn render_empty_state(ui: &mut egui::Ui) {
    ui.vertical_centered(|ui| {
        ui.add_space(120.0);
        ui.heading("No project loaded");
        ui.label("Use File -> Open Binary or File -> Open Package.");
    });
}

fn render_project_view(
    ui: &mut egui::Ui,
    project: &WorkbenchProject,
    actions: &mut Vec<WorkbenchAction>,
) {
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

        if let Some(package) = project.package.as_ref() {
            ui.add_space(18.0);
            ui.heading("Package");
            egui::Grid::new("package-summary")
                .num_columns(2)
                .striped(true)
                .show(ui, |ui| {
                    grid_pair(ui, "Directory", &package.directory.display().to_string());
                    grid_pair(ui, "Source", &package.source_path.display().to_string());
                    grid_pair(ui, "Snapshot Functions", &package.functions.to_string());
                    grid_pair(ui, "Snapshot Blocks", &package.blocks.to_string());
                    grid_pair(ui, "Snapshot IR", &package.ir_functions.to_string());
                    grid_pair(ui, "Snapshot Xrefs", &package.xrefs.to_string());
                });
        }

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
                    address_button(ui, xref.from, actions);
                    address_button(ui, xref.to, actions);
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

fn render_disassembly_view(
    ui: &mut egui::Ui,
    project: &WorkbenchProject,
    selected_function: Option<Address>,
    selected_address: Option<Address>,
    options: WorkbenchOptions,
) {
    let Some(function_start) = selected_function_or_default(&project.project, selected_function)
    else {
        render_text_view(ui, "Entrypoint Disassembly", &project.disassembly);
        return;
    };

    let title = format!("Disassembly: {function_start}");
    match disassembly_for_function(project, function_start, options) {
        ViewText::Warning(message) => {
            ui.heading(title);
            ui.colored_label(egui::Color32::from_rgb(255, 57, 57), message);
        }
        ViewText::Ready(text) => {
            ui.heading(title);
            render_selectable_text_lines(ui, &text, selected_address);
        }
    }
}

fn render_ir_view(
    ui: &mut egui::Ui,
    project: &WorkbenchProject,
    selected_function: Option<Address>,
    selected_address: Option<Address>,
) {
    let Some(function_start) = selected_function_or_default(&project.project, selected_function)
    else {
        render_text_view(ui, "IR", &project.ir);
        return;
    };

    let title = format!("IR: {function_start}");
    match ir_for_function(project, function_start) {
        ViewText::Warning(message) => {
            ui.heading(title);
            ui.colored_label(egui::Color32::from_rgb(255, 57, 57), message);
        }
        ViewText::Ready(text) => {
            ui.heading(title);
            render_selectable_text_lines(ui, &text, selected_address);
        }
    }
}

fn render_selectable_text_lines(ui: &mut egui::Ui, text: &str, selected_address: Option<Address>) {
    let selected_prefix = selected_address.map(|address| format!("{:016x}", address.value()));
    egui::ScrollArea::both().show(ui, |ui| {
        for line in text.lines() {
            if selected_prefix
                .as_deref()
                .is_some_and(|prefix| line.trim_start().starts_with(prefix))
            {
                ui.colored_label(
                    egui::Color32::from_rgb(255, 57, 57),
                    egui::RichText::new(line).monospace(),
                );
            } else {
                ui.monospace(line);
            }
        }
    });
}

fn render_strings_view(
    ui: &mut egui::Ui,
    project: &WorkbenchProject,
    selected_address: Option<Address>,
    actions: &mut Vec<WorkbenchAction>,
) {
    ui.heading("Strings");
    egui::ScrollArea::both().show(ui, |ui| {
        egui::Grid::new("strings")
            .num_columns(5)
            .striped(true)
            .show(ui, |ui| {
                header_row(ui, &["Offset", "Address", "Encoding", "Length", "Value"]);
                for string in project.project.strings() {
                    ui.monospace(format!("0x{:x}", string.file_offset));
                    if let Some(address) = string.virtual_address {
                        if ui
                            .selectable_label(
                                selected_address == Some(address),
                                address.to_string(),
                            )
                            .clicked()
                        {
                            actions.push(WorkbenchAction::SelectAddress(address));
                        }
                    } else {
                        ui.label("-");
                    }
                    ui.label(project_string_encoding_name(&string.encoding));
                    ui.label(string.char_len.to_string());
                    ui.label(&string.value);
                    ui.end_row();
                }
            });
    });
}

fn render_cfg_view(
    ui: &mut egui::Ui,
    project: &WorkbenchProject,
    selected_function: Option<Address>,
    options: WorkbenchOptions,
    actions: &mut Vec<WorkbenchAction>,
) {
    let selected_cfg = selected_function_or_default(&project.project, selected_function)
        .map(|function_start| cfg_for_function(project, function_start, options));
    let cfg = selected_cfg.as_ref().unwrap_or(&project.cfg);

    ui.heading("Control Flow Graph");
    match cfg {
        CfgView::Warning(message) => {
            ui.colored_label(egui::Color32::from_rgb(255, 57, 57), message);
        }
        CfgView::Ready { graph, text } => {
            ui.columns(2, |columns| {
                render_cfg_text(&mut columns[0], text, actions);
                egui::ScrollArea::both().show(&mut columns[1], |ui| {
                    draw_cfg(ui, graph, actions);
                });
            });
        }
    }
}

fn render_cfg_text(ui: &mut egui::Ui, text: &str, actions: &mut Vec<WorkbenchAction>) {
    egui::ScrollArea::both().show(ui, |ui| {
        for line in text.lines() {
            if let Some(address) = parse_leading_address(line) {
                if ui.button(line).clicked() {
                    actions.push(WorkbenchAction::SelectAddress(address));
                }
            } else {
                ui.monospace(line);
            }
        }
    });
}

fn render_diagnostics(ui: &mut egui::Ui, project: Option<&WorkbenchProject>) {
    ui.heading("Diagnostics");
    ui.separator();

    let Some(project) = project else {
        ui.label("No project loaded.");
        return;
    };

    if project.project.binary.diagnostics.is_empty()
        && project
            .reports
            .iter()
            .all(|report| report.warnings.is_empty())
    {
        ui.label("No diagnostics.");
        return;
    }

    egui::ScrollArea::vertical().show(ui, |ui| {
        if !project.project.binary.diagnostics.is_empty() {
            ui.heading("Loader");
            for diagnostic in &project.project.binary.diagnostics {
                let color = diagnostic_color(diagnostic.severity);
                ui.colored_label(
                    color,
                    format!(
                        "{}: {}",
                        diagnostic_severity_name(diagnostic.severity),
                        diagnostic.message
                    ),
                );
            }
        }

        ui.add_space(12.0);
        ui.heading("Analysis");
        for report in &project.reports {
            if report.warnings.is_empty() {
                ui.label(format!("{}: ok", report.pass_name));
            } else {
                for warning in &report.warnings {
                    ui.colored_label(
                        egui::Color32::from_rgb(255, 196, 87),
                        format!("{}: {warning}", report.pass_name),
                    );
                }
            }
        }
    });
}

fn render_log_panel(ui: &mut egui::Ui, status: &str, logs: &[String]) {
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Status").strong());
        ui.monospace(status);
    });
    ui.separator();
    egui::ScrollArea::vertical()
        .stick_to_bottom(true)
        .show(ui, |ui| {
            for entry in logs {
                ui.monospace(entry);
            }
        });
}

fn grid_pair(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.label(egui::RichText::new(label).color(egui::Color32::GRAY));
    ui.monospace(value);
    ui.end_row();
}

fn address_button(ui: &mut egui::Ui, address: Address, actions: &mut Vec<WorkbenchAction>) {
    if ui.button(address.to_string()).clicked() {
        actions.push(WorkbenchAction::SelectAddress(address));
    }
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

fn draw_cfg(ui: &mut egui::Ui, graph: &ControlFlowGraph, actions: &mut Vec<WorkbenchAction>) {
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

    let mut block_hits = Vec::new();
    for (index, block) in graph.blocks.iter().enumerate() {
        let min = rect.min + egui::vec2(20.0, 20.0 + index as f32 * (block_height + row_gap));
        let block_rect = egui::Rect::from_min_size(min, egui::vec2(block_width, block_height));
        block_hits.push((block_rect, block.start));
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

    let pointer = ui.input(|input| input.pointer.clone());
    if pointer.any_click() {
        if let Some(position) = pointer.interact_pos() {
            for (block_rect, address) in block_hits {
                if block_rect.contains(position) {
                    actions.push(WorkbenchAction::SelectAddress(address));
                    break;
                }
            }
        }
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

fn default_selected_function(project: &Project) -> Option<Address> {
    project
        .functions()
        .keys()
        .next()
        .copied()
        .or(project.binary.entrypoint)
}

fn selected_function_or_default(project: &Project, selected: Option<Address>) -> Option<Address> {
    selected
        .filter(|address| {
            project.function(*address).is_some() || project.binary.entrypoint == Some(*address)
        })
        .or_else(|| default_selected_function(project))
}

fn function_containing_address(project: &Project, address: Address) -> Option<Address> {
    for function in project.functions().values() {
        if function.start == address {
            return Some(function.start);
        }
        for block_start in &function.block_starts {
            let Some(block) = project.basic_block(*block_start) else {
                continue;
            };
            if address >= block.start && address < block.end {
                return Some(function.start);
            }
        }
    }
    None
}

fn function_label(address: Address, name: Option<&str>) -> String {
    match name {
        Some(name) => format!("{address}  {name}"),
        None => address.to_string(),
    }
}

fn default_package_file_name(project: &WorkbenchProject) -> String {
    let summary = project.project.summary();
    let stem = Path::new(&summary.path)
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("kaiju-project");
    format!("{stem}.kaiju")
}

fn disassembly_for_function(
    project: &WorkbenchProject,
    function_start: Address,
    options: WorkbenchOptions,
) -> ViewText {
    match disassemble_function(project, function_start, options) {
        Ok(instructions) if instructions.is_empty() => {
            ViewText::warning("No instructions were decoded for the selected function.")
        }
        Ok(instructions) => ViewText::ready(format_disassembly(&instructions)),
        Err(error) => ViewText::warning(format!("Disassembly unavailable: {error}")),
    }
}

fn disassemble_function(
    project: &WorkbenchProject,
    function_start: Address,
    options: WorkbenchOptions,
) -> Result<Vec<Instruction>> {
    let disassembler = disassembler_for_architecture(project.project.binary.arch)?;
    let Some(function) = project.project.function(function_start) else {
        return disassemble_from_address(&project.project.binary, function_start, options);
    };

    if function.block_starts.is_empty() {
        return disassemble_from_address(&project.project.binary, function_start, options);
    }

    let mut instructions = Vec::new();
    for block_start in &function.block_starts {
        let Some(block) = project.project.basic_block(*block_start) else {
            continue;
        };
        if block.instruction_count == 0 || block.end <= block.start {
            continue;
        }
        let len = usize::try_from(block.end.value() - block.start.value()).map_err(|_| {
            KaijuError::new(
                KaijuErrorKind::AnalysisLimitExceeded,
                "basic block byte range does not fit in memory",
            )
        })?;
        let bytes = project
            .project
            .binary
            .memory_map
            .read_range(block.start, len)?;
        instructions.extend(disassembler.disassemble_block(
            &bytes,
            block.start,
            block.instruction_count,
        )?);
    }

    Ok(instructions)
}

fn disassemble_from_address(
    binary: &LoadedBinary,
    address: Address,
    options: WorkbenchOptions,
) -> Result<Vec<Instruction>> {
    let bytes = read_instruction_window(binary, address, options.instruction_count)?;
    let disassembler = disassembler_for_architecture(binary.arch)?;
    disassembler.disassemble_block(&bytes, address, options.instruction_count)
}

fn cfg_for_function(
    project: &WorkbenchProject,
    function_start: Address,
    options: WorkbenchOptions,
) -> CfgView {
    match build_cfg(&project.project.binary, function_start, options.cfg_options) {
        Ok(graph) if graph.blocks.is_empty() => {
            CfgView::warning("CFG unavailable: no basic blocks were discovered.")
        }
        Ok(graph) => CfgView::ready(graph),
        Err(error) => CfgView::warning(format!("CFG unavailable: {error}")),
    }
}

fn ir_for_function(project: &WorkbenchProject, function_start: Address) -> ViewText {
    let Some(function) = project.project.ir_function(function_start) else {
        return ViewText::warning("IR unavailable: no project IR summary for this function.");
    };

    let mut output = String::new();
    let name = function.name.as_deref().unwrap_or("-");
    writeln!(
        output,
        "fn {} ({}) instructions={} unknowns={}",
        name, function.start, function.instruction_count, function.unknown_count
    )
    .expect("write IR");
    for block in &function.blocks {
        writeln!(output).expect("write IR");
        writeln!(output, "{}:", block.label).expect("write IR");
        for instruction in &block.instructions {
            let suffix = if instruction.unknown {
                "  ; unknown"
            } else {
                ""
            };
            writeln!(
                output,
                "{:016x}  {}{}",
                instruction.address.value(),
                instruction.text,
                suffix
            )
            .expect("write IR");
        }
    }
    ViewText::ready(output)
}

fn parse_leading_address(line: &str) -> Option<Address> {
    let token = line
        .split_whitespace()
        .next()?
        .trim_end_matches(':')
        .split("..")
        .next()?;
    parse_address_token(token)
}

fn parse_address_token(token: &str) -> Option<Address> {
    let hex = token.strip_prefix("0x").unwrap_or(token);
    u64::from_str_radix(hex, 16).ok().map(Address::new)
}

fn diagnostic_severity_name(severity: DiagnosticSeverity) -> &'static str {
    match severity {
        DiagnosticSeverity::Note => "note",
        DiagnosticSeverity::Warning => "warning",
        DiagnosticSeverity::Error => "error",
    }
}

fn diagnostic_color(severity: DiagnosticSeverity) -> egui::Color32 {
    match severity {
        DiagnosticSeverity::Note => egui::Color32::LIGHT_GRAY,
        DiagnosticSeverity::Warning => egui::Color32::from_rgb(255, 196, 87),
        DiagnosticSeverity::Error => egui::Color32::from_rgb(255, 57, 57),
    }
}

fn recent_store_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from).map(|home| {
        home.join(".cache")
            .join("kaiju-workbench")
            .join("recent.txt")
    })
}

fn load_recent_items() -> Vec<RecentItem> {
    let Some(path) = recent_store_path() else {
        return Vec::new();
    };
    let Ok(contents) = fs::read_to_string(path) else {
        return Vec::new();
    };

    contents
        .lines()
        .filter_map(|line| {
            let (kind, path) = line.split_once('\t')?;
            Some(RecentItem {
                kind: RecentKind::parse(kind)?,
                path: PathBuf::from(path),
            })
        })
        .take(MAX_RECENT_ITEMS)
        .collect()
}

fn save_recent_items(items: &[RecentItem]) -> std::io::Result<()> {
    let Some(path) = recent_store_path() else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut contents = String::new();
    for item in items.iter().take(MAX_RECENT_ITEMS) {
        writeln!(contents, "{}\t{}", item.kind.as_str(), item.path.display())
            .expect("write recent item");
    }
    fs::write(path, contents)
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

    #[test]
    fn saves_and_reopens_project_package() {
        let binary_path = temp_file("kaiju-workbench-package.bin");
        let package_path = temp_file("kaiju-workbench-package.kaiju");
        fs::write(&binary_path, b"Kaiju package fixture").expect("write fixture");

        let workbench = WorkbenchProject::load(&binary_path, WorkbenchOptions::default())
            .expect("load workbench project");
        save_project_package(&workbench.project, &package_path).expect("save package");

        let inspection = inspect_project_package(&package_path).expect("inspect package");
        assert_eq!(inspection.source_path, binary_path);
        assert_eq!(inspection.format, "Raw");
        assert_eq!(inspection.functions, 0);

        let reopened = WorkbenchProject::load_package(&package_path, WorkbenchOptions::default())
            .expect("reopen package");
        assert!(matches!(reopened.source, WorkbenchSource::Package { .. }));
        assert!(reopened.package.is_some());
        assert_eq!(reopened.project.strings().len(), 1);

        let _ = fs::remove_file(binary_path);
        let _ = fs::remove_dir_all(package_path);
    }

    fn temp_file(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{name}-{unique}"))
    }
}
