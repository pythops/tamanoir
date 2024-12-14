use std::{env, path::Path, process::Command};
fn build(crate_path: &str) {
    // Path to the other crate
    let other_crate_path = crate_path;

    // Output directory for compiled binaries
    let out_dir = env::var("OUT_DIR").unwrap();
    let target_binary_path = Path::new(&out_dir).join("other_crate_binary");

    // Compile the other crate
    let status = Command::new("cargo")
        .args(&["build", "--release"])
        .current_dir(crate_path)
        .status()
        .expect("Failed to build the other crate");
    assert!(status.success(), "Building other crate failed");

    // Copy the compiled binary to the OUT_DIR
    let compiled_binary = Path::new(crate_path)
        .join("target")
        .join("release")
        .join("other_crate_binary");
    std::fs::copy(compiled_binary, &target_binary_path).expect("Failed to copy binary");

    // Print an instruction for the main program to embed the binary
    println!(
        "cargo:rerun-if-changed={}",
        target_binary_path.to_str().unwrap()
    );
}
