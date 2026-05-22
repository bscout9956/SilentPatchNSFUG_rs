// Helper function to extract a value from Cargo.toml
fn get_manifest_var(manifest: &str, key: &str) -> Option<String> {
    manifest
        .lines()
        // Find the line that starts with our key (ignoring leading spaces)
        .find(|l| l.trim().starts_with(key))
        // Split by '=' and get the right side
        .and_then(|line| line.split('=').nth(1))
        // Remove comments (#), trim spaces, and remove quotes
        .map(|val| {
            val.split('#')
                .next()
                .unwrap()
                .trim()
                .trim_matches('"')
                .to_string()
        })
}

fn main() {
    println!("cargo:rerun-if-changed=Cargo.toml");

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let manifest_path = std::path::Path::new(&manifest_dir).join("Cargo.toml");
    let manifest_content = std::fs::read_to_string(manifest_path).unwrap();

    if let Some(module_name) = get_manifest_var(&manifest_content, "module_name") {
        println!("cargo:rustc-env=module_name={}", module_name);
    }
    if let Some(library_name) = get_manifest_var(&manifest_content, "library_name") {
        println!("cargo:rustc-env=library_name={}", library_name);
    }
    if let Some(function_name) = get_manifest_var(&manifest_content, "function_name") {
        println!("cargo:rustc-env=function_name={}", function_name);
    }
    if let Some(revision_id) = get_manifest_var(&manifest_content, "revision_id") {
        println!("cargo:rustc-env=revision_id={}", revision_id);
    }
    if let Some(build_id) = get_manifest_var(&manifest_content, "build_id") {
        println!("cargo:rustc-env=build_id={}", build_id);
    }

    // Read the signature from the environment
    let signature = get_manifest_var(&manifest_content, "function_signature")
        .expect("ERROR: Could not find 'function_signature' in Cargo.toml!");

    let out_dir = std::env::var_os("OUT_DIR").unwrap();
    let dest_path = std::path::Path::new(&out_dir).join("generated_hook.rs");

    // Generate the macro call dynamically
    let generated_code = format!("define_winapi_hook!(wrapped_function, {});", signature);

    std::fs::write(&dest_path, generated_code).unwrap();
}
