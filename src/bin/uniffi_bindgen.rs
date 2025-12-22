//! UniFFI binding generator CLI for pubky-noise.
//!
//! Generates Swift or Kotlin bindings from the compiled library.
//!
//! # Usage
//!
//! ```bash
//! cargo run --bin uniffi_bindgen -- generate \
//!     --library target/debug/libpubky_noise.dylib \
//!     --language swift \
//!     --out-dir ./generated
//! ```

use camino::Utf8Path;
use std::path::PathBuf;
use uniffi_bindgen::{
    bindings::{KotlinBindingGenerator, SwiftBindingGenerator},
    library_mode::generate_bindings,
    EmptyCrateConfigSupplier,
};

const USAGE: &str = r#"UniFFI Binding Generator for pubky-noise

USAGE:
    uniffi_bindgen generate --library <PATH> --language <LANG> --out-dir <DIR>

ARGUMENTS:
    --library <PATH>    Path to the compiled library (.dylib, .so, or .a)
    --language <LANG>   Target language: 'swift' or 'kotlin'
    --out-dir <DIR>     Output directory for generated bindings

OPTIONS:
    -h, --help          Show this help message

EXAMPLES:
    # Generate Swift bindings
    cargo run --bin uniffi_bindgen -- generate \
        --library target/debug/libpubky_noise.dylib \
        --language swift \
        --out-dir ./platforms/ios/Sources

    # Generate Kotlin bindings
    cargo run --bin uniffi_bindgen -- generate \
        --library target/debug/libpubky_noise.so \
        --language kotlin \
        --out-dir ./platforms/android/src/main/kotlin
"#;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    // Check for help flag
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{}", USAGE);
        return Ok(());
    }

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

    let library = library_path.ok_or_else(|| {
        eprintln!("Error: Missing --library argument\n");
        eprintln!("{}", USAGE);
        anyhow::anyhow!("Missing --library argument")
    })?;

    let lang = language.ok_or_else(|| {
        eprintln!("Error: Missing --language argument\n");
        eprintln!("{}", USAGE);
        anyhow::anyhow!("Missing --language argument")
    })?;

    let output = out_dir.ok_or_else(|| {
        eprintln!("Error: Missing --out-dir argument\n");
        eprintln!("{}", USAGE);
        anyhow::anyhow!("Missing --out-dir argument")
    })?;

    let lib_path = Utf8Path::from_path(&library)
        .ok_or_else(|| anyhow::anyhow!("Invalid UTF-8 in library path: {:?}", library))?;
    let out_path = Utf8Path::from_path(&output)
        .ok_or_else(|| anyhow::anyhow!("Invalid UTF-8 in output path: {:?}", output))?;

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
        other => {
            eprintln!("Error: Unsupported language '{}'\n", other);
            eprintln!("Supported languages: swift, kotlin");
            return Err(anyhow::anyhow!(
                "Unsupported language '{}'. Use 'swift' or 'kotlin'.",
                other
            ));
        }
    }

    println!("Bindings generated successfully at {:?}", output);
    Ok(())
}
