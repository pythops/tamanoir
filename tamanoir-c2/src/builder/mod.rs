pub mod commands;

use std::env;

use commands::{clean_cmd, cross_build_base_cmd, Cmd};
use log::info;

use crate::{Engine, TargetArch};

pub fn format_env_arg(s: &str) -> Result<String, String> {
    if let Some(eq_pos) = s.find('=') {
        let (key, value) = s.split_at(eq_pos);
        if !key.is_empty() && !value.is_empty() {
            return Err(format!("{} should follow key=value pattern", s));
        } else {
            return Ok(format!("--env {}={}", key.trim(), value.trim()));
        }
    }
    Err(format!("{} should follow key=value pattern", s))
}

pub fn x_compile(
    engine: Engine,
    crate_path: String,
    target: TargetArch,
    build_vars: String,
) -> Result<(), String> {
    let cmd = Cmd {
        shell: "/bin/bash".into(),
    };

    info!("installing dependencies");
    let cmd0 = format!("cargo install cross --git https://github.com/cross-rs/cross;if [ -e ./x_build_utils/Cross_{}.toml ];then cp ./x_build_utils/Cross_{}.toml {}/Cross.toml;fi",target,target,crate_path);
    cmd.exec(cmd0)?;

    info!("start x compilation with cross to target {}", target);
    let build_vars: Result<Vec<_>, _> = build_vars.split_whitespace().map(format_env_arg).collect();

    let build_vars_formatted = build_vars
        .map_err(|e| format!("build_vars: {}", e))?
        .join(" ");

    let cmd1 = cross_build_base_cmd(crate_path.clone(), engine, build_vars_formatted, target);
    cmd.exec(cmd1.clone())?;

    info!("run post install scripts with cross");
    let cmd2 = format!("cp ./x_build_utils/build.rs {} && {}", crate_path, cmd1);
    cmd.exec(cmd2)?;

    Ok(())
}

pub fn compile(crate_path: String, build_vars: String) -> Result<(), String> {
    let bin_name = "toto";
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
        "objcopy -O binary {}/target/release/{} ./src/bins/{}_{}.bin",
        crate_path,
        bin_name,
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
