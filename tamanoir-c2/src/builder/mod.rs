pub mod utils;

use std::{env, fs::File, io::Write, str::FromStr};

use log::{info, log_enabled, Level};
use tempfile::{Builder, TempDir};
use utils::{
    cross_build_base_cmd, format_build_vars_for_cross, init_utils_files, parse_package_name,
    UTILS_FILES,
};

use crate::{Cmd, Engine, TargetArch};

pub fn build(
    crate_path: String,
    engine: Engine,
    target: TargetArch,
    build_vars: String,
    out_dir: String,
) -> Result<(), String> {
    let current_arch = env::consts::ARCH;
    let crate_path = crate_path;
    let should_x_compile = TargetArch::from_str(current_arch).unwrap() != target;
    let tmp_dir = Builder::new()
        .prefix("tamanoir-rce")
        .tempdir()
        .map_err(|_| "Error creating temp dir")?;
    if should_x_compile {
        x_compile(
            engine,
            crate_path.clone(),
            target,
            build_vars,
            tmp_dir,
            out_dir,
        )?
    } else {
        compile(crate_path, build_vars, tmp_dir, out_dir)?
    };

    Ok(())
}
pub fn x_compile(
    engine: Engine,
    crate_path: String,
    target: TargetArch,
    build_vars: String,
    tmp_dir: TempDir,
    out_dir: String,
) -> Result<(), String> {
    let cmd = Cmd {
        shell: "/bin/bash".into(),
        stdout: log_enabled!(Level::Debug),
    };
    init_utils_files()?;
    let build_vars_formatted = format_build_vars_for_cross(build_vars)?;
    let bin_name = parse_package_name(crate_path.clone())?;
    let tmp_path = tmp_dir.path().to_string_lossy().to_string();
    info!("installing dependencies");
    let cmd0 = format!(
        "cargo install cross --git https://github.com/cross-rs/cross; cp  -r {}/[^.]* {}",
        crate_path, tmp_path
    );
    cmd.exec(cmd0)?;
    info!("start x compilation with cross to target {}", target);
    if let Some(cross_conf) = UTILS_FILES
        .get()
        .unwrap()
        .get(&format!("Cross_{}.toml", target))
        .cloned()
    {
        let out_path = format!("{}/Cross.toml", tmp_path);
        File::create(&out_path)
            .map_err(|_| format!("Couldn't create {}", &out_path))?
            .write_all(cross_conf.as_bytes())
            .map_err(|_| format!("Couldn't create {}", &out_path))?;
    }

    let cmd1 = cross_build_base_cmd(
        tmp_path.clone(),
        engine,
        build_vars_formatted,
        target.clone(),
    );
    cmd.exec(cmd1.clone())?;

    info!("run post install scripts with cross");
    let post_build_script = UTILS_FILES.get().unwrap().get("build.rs").cloned().unwrap();
    let out_path = format!("{}/build.rs", tmp_path);
    File::create(&out_path)
        .map_err(|_| format!("Couldn't create {}", &out_path))?
        .write_all(post_build_script.as_bytes())
        .map_err(|_| format!("Couldn't create {}", &out_path))?;
    cmd.exec(cmd1)?;

    let cmd3 = format!(
        "cp  {}/target/{}-unknown-linux-gnu/release/{}_{}.bin {}/{}_{}.bin",
        tmp_path, target, bin_name, target, out_dir, bin_name, target
    );
    cmd.exec(cmd3)?;

    Ok(())
}

pub fn compile(
    crate_path: String,
    build_vars: String,
    tmp_dir: TempDir,
    out_dir: String,
) -> Result<(), String> {
    let bin_name = parse_package_name(crate_path.clone())?;
    let cmd = Cmd {
        shell: "/bin/bash".into(),
        stdout: log_enabled!(Level::Debug),
    };

    info!("start compilation of {}", bin_name);
    let tmp_path = tmp_dir.path().to_string_lossy();
    let cmd0 = format!(
        "cp -r {}/[^.]* {} && cd {} && {}  cargo build --release",
        crate_path, tmp_path, tmp_path, build_vars
    );
    cmd.exec(cmd0)?;

    info!("start post-build opertaions");
    let cmd1 = format!(
        "strip -s --strip-unneeded {}/target/release/{}",
        tmp_path, bin_name
    );
    let cmd2 = format!(
        "objcopy -O binary {}/target/release/{}  {}/{}_{}.bin",
        tmp_path,
        bin_name,
        out_dir,
        bin_name,
        env::consts::ARCH
    );
    cmd.exec(cmd1)?;
    cmd.exec(cmd2)?;

    Ok(())
}
