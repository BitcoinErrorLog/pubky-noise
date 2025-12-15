use camino::Utf8Path;
use std::path::PathBuf;
use uniffi_bindgen::{
    library_mode::generate_bindings,
    EmptyCrateConfigSupplier,
    bindings::{SwiftBindingGenerator, KotlinBindingGenerator},
};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    // Parse arguments manually
    let mut library_path: Option<PathBuf> = None;
    let mut language: Option<String> = None;
    let mut out_dir: Option<PathBuf> = None;
    
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "generate" => {}
            "--library" => {
                i += 1;
                if i < args.len() {
                    library_path = Some(PathBuf::from(&args[i]));
                }
            }
            "--language" => {
                i += 1;
                if i < args.len() {
                    language = Some(args[i].clone());
                }
            }
            "--out-dir" => {
                i += 1;
                if i < args.len() {
                    out_dir = Some(PathBuf::from(&args[i]));
                }
            }
            _ => {}
        }
        i += 1;
    }

    let library = library_path.expect("Missing --library argument");
    let lang = language.expect("Missing --language argument");
    let output = out_dir.expect("Missing --out-dir argument");

    let lib_path = Utf8Path::from_path(&library)
        .ok_or_else(|| anyhow::anyhow!("Invalid UTF-8 in library path"))?;
    let out_path = Utf8Path::from_path(&output)
        .ok_or_else(|| anyhow::anyhow!("Invalid UTF-8 in output path"))?;

    match lang.to_lowercase().as_str() {
        "swift" => {
            generate_bindings(
                lib_path,
                None,
                &SwiftBindingGenerator,
                &EmptyCrateConfigSupplier,
                None,
                out_path,
                false,
            )?;
        }
        "kotlin" => {
            generate_bindings(
                lib_path,
                None,
                &KotlinBindingGenerator,
                &EmptyCrateConfigSupplier,
                None,
                out_path,
                false,
            )?;
        }
        other => panic!("Unsupported language: {}", other),
    }

    println!("Bindings generated successfully at {:?}", output);
    Ok(())
}
