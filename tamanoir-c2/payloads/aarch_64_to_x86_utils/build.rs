use std::process::Command;

fn main() {
    // Trigger re-build if build.rs is changed.
    println!("cargo:rerun-if-changed=build.rs");
    let target_arch =
        std::env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH not set");
    let binary_name = std::env::var("CARGO_PKG_NAME").expect("CARGO_PKG_NAME not set");
    let elf_path = format!(
        "target/{}-unknown-linux-gnu/release/{}",
        target_arch, binary_name
    );
    let bin_path = format!("target/release/{}_x86.bin", binary_name);

    let output = Command::new("x86_64-linux-gnu-strip")
        .arg("-s")
        .arg("--strip-unneeded")
        .arg(&elf_path)
        .output()
        .expect("Failed to run strip");

    if !output.status.success() {
        panic!(
            "strip failed with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let output = Command::new("x86_64-linux-gnu-objcopy")
        .arg("-O")
        .arg("binary")
        .arg(&elf_path)
        .arg(&bin_path)
        .output()
        .expect("Failed to run objcopy");
    if !output.status.success() {
        panic!(
            "objcopy failed with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
    }
}
