#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use kaiju_loader::load_path;

fn main() -> ExitCode {
    match run(env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run(mut args: impl Iterator<Item = String>) -> Result<(), String> {
    let path = args
        .next()
        .ok_or_else(|| "usage: kaiju-example-basic-load <file>".to_string())?;
    if let Some(extra) = args.next() {
        return Err(format!("unexpected extra argument: {extra}"));
    }

    let binary = load_path(PathBuf::from(path)).map_err(|error| error.to_string())?;
    let entrypoint = binary
        .entrypoint
        .map_or_else(|| "None".to_string(), |address| address.to_string());

    println!("Path: {}", binary.path.display());
    println!("Format: {}", binary.format);
    println!("Architecture: {}", binary.arch);
    println!("Endian: {}", binary.endian);
    println!("Entrypoint: {entrypoint}");
    println!("Regions:");
    for region in binary.memory_map.regions() {
        let offset = region
            .file_offset
            .map_or_else(|| "-".to_string(), |offset| format!("0x{offset:x}"));
        println!(
            "  {} {} size={} offset={} perms={}",
            region.name, region.address, region.size, offset, region.permissions
        );
    }

    Ok(())
}
