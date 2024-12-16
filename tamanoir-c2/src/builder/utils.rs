use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process::Command,
};

use serde::Deserialize;

use crate::{Engine, TargetArch};

pub struct Cmd {
    pub shell: String,
}

impl Cmd {
    pub fn exec(&self, cmd: String) -> Result<(), String> {
        let mut program = Command::new(&self.shell);
        let prog: &mut Command = program.arg("-c").arg(&cmd);

        let output = prog
            .output()
            .map_err(|_| format!("Failed to run {}", cmd))?;
        io::stdout().write_all(&output.stdout).unwrap();
        io::stderr().write_all(&output.stderr).unwrap();
        if !output.status.success() {
            return Err(format!(
                "{} failed with status {}: {}",
                cmd,
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(())
    }
}
#[derive(Debug, Deserialize)]
struct CargoMetadata {
    package: Option<PackageMetadata>,
}

#[derive(Debug, Deserialize)]
struct PackageMetadata {
    name: String,
}

pub fn parse_package_name(crate_path: String) -> Result<String, String> {
    let cargo_toml_path: PathBuf = Path::new(&crate_path).join("Cargo.toml");
    let cargo_toml_content = fs::read_to_string(cargo_toml_path)
        .expect(&format!("Failed to read {}/Cargo.toml", crate_path));
    let metadata: CargoMetadata = toml::from_str(&cargo_toml_content)
        .expect(&format!("Failed to parse {}/Cargo.toml", crate_path));
    if let Some(package) = metadata.package {
        Ok(package.name)
    } else {
        Err(format!("Failed to parse {}/Cargo.toml", crate_path))
    }
}
pub fn format_env_arg(s: &str) -> Result<String, String> {
    if let Some(eq_pos) = s.find('=') {
        let (key, value) = s.split_at(eq_pos);
        if key.is_empty() || value.is_empty() {
            return Err(format!("{} should follow key=value pattern", s));
        } else {
            return Ok(format!("--env {}={}", key.trim(), value.trim()));
        }
    }
    Err(format!("{} should follow key=value pattern", s))
}
pub fn format_build_vars_for_cross(build_vars: String) -> Result<String, String> {
    let build_vars: Result<Vec<_>, _> = build_vars.split_whitespace().map(format_env_arg).collect();
    let build_vars_formatted = build_vars
        .map_err(|e| format!("build_vars: {}", e))?
        .join(" ");
    Ok(build_vars_formatted)
}

pub fn cross_build_base_cmd(
    crate_path: String,
    engine: Engine,
    build_vars_fmt: String,
    target: TargetArch,
) -> String {
    format!("cd {} && CROSS_CONFIGCROSS_CONTAINER_ENGINE={} CROSS_CONTAINER_OPTS=\"{}\"  cross build --target {}-unknown-linux-gnu --release",crate_path,engine,build_vars_fmt,target)
}

pub fn clean_cmd(crate_path: String) -> String {
    format!(
        "rm -rf {}/target && rm -f {}/build.rs && rm -f {}/Cross.toml",
        crate_path, crate_path, crate_path
    )
}
