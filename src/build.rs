fn main() {
    if std::env::var("CARGO_FEATURE_HOOKED_MODULE").is_ok() {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let manifest_path = std::path::Path::new(&manifest_dir).join("Cargo.toml");
        let manifest_content = std::fs::read_to_string(manifest_path).unwrap();

        if let Some(line) = manifest_content.lines().find(|l| l.contains("module_name")) {
            if let Some(value) = line.split('=').nth(1) {
                let module_name = value.split('#').next().unwrap().trim().trim_matches('"');
                println!("cargo:rustc-env=module_name={}", module_name);
            }
        }

        if let Some(line) = manifest_content
            .lines()
            .find(|l| l.contains("library_name"))
        {
            if let Some(value) = line.split('=').nth(1) {
                let library_name = value.split('#').next().unwrap().trim().trim_matches('"');
                println!("cargo:rustc-env=library_name={}", library_name);
            }
        }

        if let Some(line) = manifest_content
            .lines()
            .find(|l| l.contains("function_name"))
        {
            if let Some(value) = line.split('=').nth(1) {
                let function_name = value.split('#').next().unwrap().trim().trim_matches('"');
                println!("cargo:rustc-env=function_name={}", function_name);
            }
        }
    }

    // Tell Cargo to re-run this script if Cargo.toml changes
    println!("cargo:rerun-if-changed=Cargo.toml");
}
