use std::process::Command;

fn main() {
    let binary_name = std::env::var("CARGO_PKG_NAME").expect("CARGO_PKG_NAME not set");
    let target_arch =
        std::env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH not set");
    let base_path = format!("target/{}-unknown-linux-gnu/release", target_arch);
    let elf_path = format!("{}/{}", base_path, binary_name);
    let bin_path = format!("{}/{}_{}.bin", base_path, binary_name, target_arch);

    let output = Command::new(format!("{}-linux-gnu-strip", target_arch))
        .arg("-s")
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
    let output = Command::new(format!("{}-linux-gnu-objcopy", target_arch))
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
