pub mod utils;
use std::{
    fs::{create_dir, File},
    io::Write,
};

use log::info;
use tempfile::TempDir;
use utils::{init_utils_files, UTILS_FILES};

use crate::Cmd;

pub fn test_bin(bin_path: String) -> Result<(), String> {
    let tmp_dir = TempDir::new().map_err(|_| "Error creating temp dir")?;
    init_utils_files()?;
    copy_rce_tester(&tmp_dir)?;

    info!("start test of binary {}", &bin_path);
    let cmd = Cmd {
        shell: "/bin/bash".into(),
        stdout: true,
    };
    let build_vars = format!("SHELLCODE_PATH={}", bin_path);
    let cmd0 = format!(
        "cd {} && {}  cargo run --release",
        tmp_dir.path().to_string_lossy(),
        build_vars
    );
    cmd.exec(cmd0)?;
    info!("test completed!");
    Ok(())
}

pub fn copy_rce_tester(temp_dir: &TempDir) -> Result<(), String> {
    let cargo_toml = UTILS_FILES
        .get()
        .unwrap()
        .get("Cargo.toml")
        .cloned()
        .unwrap();
    let base_path = temp_dir.path().to_string_lossy();
    let out_path = format!("{}/{}", base_path, "Cargo.toml");
    File::create(&out_path)
        .map_err(|_| format!("Couldn't create {}", &out_path))?
        .write_all(cargo_toml.as_bytes())
        .map_err(|_| format!("Couldn't create {}", &out_path))?;

    let main_rs = UTILS_FILES.get().unwrap().get("main.rs").cloned().unwrap();
    let out_path = format!("{}/{}", base_path, "src");
    create_dir(&out_path).map_err(|_| format!("Couldn't create {}", &out_path))?;
    let out_path = format!("{}/{}", base_path, "src/main.rs");
    File::create(&out_path)
        .map_err(|_| format!("Couldn't create {}", &out_path))?
        .write_all(main_rs.as_bytes())
        .map_err(|_| format!("Couldn't create {}", &out_path))?;
    Ok(())
}
