#![forbid(unsafe_code)]

use kaiju_core::{Address, ArchitectureId, Result};
use kaiju_loader::LoadedBinary;
use kaiju_project::{AnalysisFact, Project};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub description: String,
    pub capabilities: Vec<PluginCapability>,
}

impl PluginMetadata {
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        description: impl Into<String>,
        capabilities: Vec<PluginCapability>,
    ) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            description: description.into(),
            capabilities,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginCapability {
    AnalysisPass,
    Loader,
    Architecture,
    Command,
}

pub trait KaijuPlugin {
    fn metadata(&self) -> PluginMetadata;

    fn register(&self, registrar: &mut dyn PluginRegistrar) -> Result<()>;
}

pub trait PluginRegistrar {
    fn register_analysis_pass(&mut self, pass: Box<dyn PluginAnalysisPass>);
}

pub trait PluginAnalysisPass {
    fn name(&self) -> &'static str;

    fn run(&self, project: &mut Project) -> Result<PluginAnalysisReport>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginAnalysisReport {
    pub pass_name: String,
    pub facts_added: usize,
    pub warnings: Vec<String>,
}

impl PluginAnalysisReport {
    #[must_use]
    pub fn new(pass_name: impl Into<String>) -> Self {
        Self {
            pass_name: pass_name.into(),
            facts_added: 0,
            warnings: Vec::new(),
        }
    }

    #[must_use]
    pub const fn with_facts(mut self, facts_added: usize) -> Self {
        self.facts_added = facts_added;
        self
    }
}

pub trait LoaderPlugin {
    fn name(&self) -> &'static str;

    fn can_load(&self, bytes: &[u8]) -> bool;

    fn load(&self, binary: &LoadedBinary) -> Result<LoadedBinary>;
}

pub trait ArchitecturePlugin {
    fn architecture(&self) -> ArchitectureId;

    fn display_name(&self) -> &'static str;
}

pub trait CommandPlugin {
    fn name(&self) -> &'static str;

    fn summary(&self) -> &'static str;
}

#[derive(Default)]
pub struct PluginRegistry {
    plugins: Vec<PluginMetadata>,
    analysis_passes: Vec<Box<dyn PluginAnalysisPass>>,
}

impl PluginRegistry {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            plugins: Vec::new(),
            analysis_passes: Vec::new(),
        }
    }

    pub fn register_plugin(&mut self, plugin: &dyn KaijuPlugin) -> Result<()> {
        let metadata = plugin.metadata();
        plugin.register(self)?;
        self.plugins.push(metadata);
        Ok(())
    }

    #[must_use]
    pub fn plugins(&self) -> &[PluginMetadata] {
        &self.plugins
    }

    #[must_use]
    pub fn analysis_passes(&self) -> &[Box<dyn PluginAnalysisPass>] {
        &self.analysis_passes
    }

    pub fn run_analysis_passes(&self, project: &mut Project) -> Result<Vec<PluginAnalysisReport>> {
        let mut reports = Vec::new();
        for pass in &self.analysis_passes {
            reports.push(pass.run(project)?);
        }
        Ok(reports)
    }
}

impl PluginRegistrar for PluginRegistry {
    fn register_analysis_pass(&mut self, pass: Box<dyn PluginAnalysisPass>) {
        self.analysis_passes.push(pass);
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ExampleBuiltinPlugin;

impl KaijuPlugin for ExampleBuiltinPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata::new(
            "example-builtin",
            "0.1.0",
            "Example in-process plugin used to validate the plugin API skeleton.",
            vec![PluginCapability::AnalysisPass],
        )
    }

    fn register(&self, registrar: &mut dyn PluginRegistrar) -> Result<()> {
        registrar.register_analysis_pass(Box::new(ExampleBuiltinAnalysisPass));
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ExampleBuiltinAnalysisPass;

impl PluginAnalysisPass for ExampleBuiltinAnalysisPass {
    fn name(&self) -> &'static str {
        "example-builtin-analysis"
    }

    fn run(&self, project: &mut Project) -> Result<PluginAnalysisReport> {
        project.add_analysis_fact(AnalysisFact::new(
            self.name(),
            "binary-entrypoint",
            project
                .binary
                .entrypoint
                .unwrap_or(Address::ZERO)
                .to_string(),
        ));
        Ok(PluginAnalysisReport::new(self.name()).with_facts(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaiju_core::{Endian, MemoryMap, MemoryRegion, Permissions};
    use kaiju_loader::{BinaryFormat, LoadedBinary};
    use std::path::PathBuf;

    #[test]
    fn registers_example_builtin_analysis_pass() {
        let mut registry = PluginRegistry::new();

        registry
            .register_plugin(&ExampleBuiltinPlugin)
            .expect("register plugin");

        assert_eq!(registry.plugins().len(), 1);
        assert_eq!(registry.analysis_passes().len(), 1);
        assert_eq!(registry.plugins()[0].name, "example-builtin");
    }

    #[test]
    fn runs_registered_analysis_pass() {
        let mut registry = PluginRegistry::new();
        registry
            .register_plugin(&ExampleBuiltinPlugin)
            .expect("register plugin");
        let mut project = Project::from_loaded_binary(test_binary());

        let reports = registry
            .run_analysis_passes(&mut project)
            .expect("run plugin passes");

        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].pass_name, "example-builtin-analysis");
        assert!(project
            .analysis_facts()
            .iter()
            .any(|fact| fact.namespace == "example-builtin-analysis"));
    }

    fn test_binary() -> LoadedBinary {
        let mut memory_map = MemoryMap::new();
        memory_map.add_region(MemoryRegion::new(
            "raw",
            Address::ZERO,
            Some(0),
            Permissions::read_only(),
            b"kaiju".to_vec(),
        ));

        LoadedBinary {
            path: PathBuf::from("raw.bin"),
            file_size: 5,
            bytes: b"kaiju".to_vec(),
            format: BinaryFormat::Raw,
            arch: ArchitectureId::Unknown,
            endian: Endian::Unknown,
            entrypoint: None,
            memory_map,
            sections: Vec::new(),
            symbols: Vec::new(),
            imports: Vec::new(),
            diagnostics: Vec::new(),
        }
    }
}
