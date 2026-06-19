#![forbid(unsafe_code)]

use std::path::PathBuf;

use eframe::egui;
use kaiju_workbench::{KaijuWorkbenchApp, WorkbenchLoadRequest};

fn main() -> eframe::Result<()> {
    let initial_path = std::env::args_os().nth(1).map(PathBuf::from);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Kaiju Workbench")
            .with_inner_size([1320.0, 860.0])
            .with_min_inner_size([980.0, 640.0]),
        ..eframe::NativeOptions::default()
    };

    eframe::run_native(
        "Kaiju Workbench",
        options,
        Box::new(move |cc| {
            egui_extras::install_image_loaders(&cc.egui_ctx);
            let request = initial_path.map(WorkbenchLoadRequest::Path);
            Box::new(KaijuWorkbenchApp::new(request))
        }),
    )
}
