fn main() {
    uniffi_build::generate_scaffolding("src/pubky_noise.udl").unwrap();
    println!("cargo::rustc-check-cfg=cfg(loom)");
}
