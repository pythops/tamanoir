pub mod utils;

use std::{env, str::FromStr};

use log::info;
use utils::{
    clean_cmd, cross_build_base_cmd, format_build_vars_for_cross, parse_package_name, Cmd,
};

use crate::{Engine, TargetArch};

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
    if should_x_compile {
        let _ = x_compile(engine, crate_path, target, build_vars, out_dir)?;
    } else {
        let _ = compile(crate_path, build_vars, out_dir)?;
    }
    Ok(())
}
pub fn x_compile(
    engine: Engine,
    crate_path: String,
    target: TargetArch,
    build_vars: String,
    out_dir: String,
) -> Result<(), String> {
    let cmd = Cmd {
        shell: "/bin/bash".into(),
    };

    let build_vars_formatted = format_build_vars_for_cross(build_vars)?;
    let bin_name = parse_package_name(crate_path.clone())?;

    info!("installing dependencies");
    let cmd0 = format!("cargo install cross --git https://github.com/cross-rs/cross;if [ -e ./x_build_utils/Cross_{}.toml ];then cp ./x_build_utils/Cross_{}.toml {}/Cross.toml;fi",target,target,crate_path);
    cmd.exec(cmd0)?;
    info!("start x compilation with cross to target {}", target);
    let cmd1 = cross_build_base_cmd(
        crate_path.clone(),
        engine,
        build_vars_formatted,
        target.clone(),
    );
    cmd.exec(cmd1.clone())?;

    info!("run post install scripts with cross");
    let cmd2 = format!("cp ./x_build_utils/build.rs {} && {}", crate_path, cmd1);
    cmd.exec(cmd2)?;

    let cmd3 = format!(
        "cp  {}/target/{}-unknown-linux-gnu/release/{}_{}.bin {}/{}_{}.bin",
        crate_path, target, bin_name, target, out_dir, bin_name, target
    );
    cmd.exec(cmd3)?;

    Ok(())
}

pub fn compile(crate_path: String, build_vars: String, out_dir: String) -> Result<(), String> {
    let bin_name = parse_package_name(crate_path.clone())?;
    let cmd = Cmd {
        shell: "/bin/bash".into(),
    };

    info!("start  compilation of {}", bin_name);
    let cmd0 = format!("cd {} && {}  cargo build --release", crate_path, build_vars);
    cmd.exec(cmd0).unwrap();

    info!("start  post-build opertaions");
    let cmd1 = format!(
        "strip -s --strip-unneeded {}/target/release/{}",
        crate_path, bin_name
    );
    let cmd2 = format!(
        "objcopy -O binary {}/target/release/{}  {}/{}_{}.bin",
        crate_path,
        bin_name,
        out_dir,
        bin_name,
        env::consts::ARCH
    );
    cmd.exec(cmd1)?;
    cmd.exec(cmd2)?;

    info!("cleaning");
    let cmd3 = clean_cmd(crate_path);

    cmd.exec(cmd3)?;
    Ok(())
}
