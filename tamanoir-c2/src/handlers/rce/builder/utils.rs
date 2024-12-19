use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::OnceLock,
};

use crate::{CargoMetadata, Engine, TargetArch};

pub static UTILS_FILES: OnceLock<HashMap<String, &str>> = OnceLock::new();
const BUILD_RS: &str = include_str!("../../../../../assets/x_build_utils/build.rs");
const CROSS_X86_64_TOML: &str =
    include_str!("../../../../../assets/x_build_utils/Cross_x86_64.toml");

pub fn init_utils_files() -> Result<(), String> {
    let mut map = HashMap::<String, &str>::new();
    map.insert("build.rs".into(), BUILD_RS);
    map.insert("Cross_x86_64.toml".into(), CROSS_X86_64_TOML);
    UTILS_FILES
        .set(map)
        .map_err(|_| "Error initializing UTILS_FILES")?;
    Ok(())
}

pub fn parse_package_name(crate_path: String) -> Result<String, String> {
    let cargo_toml_path: PathBuf = Path::new(&crate_path).join("Cargo.toml");
    let cargo_toml_content = fs::read_to_string(cargo_toml_path)
        .unwrap_or_else(|_| panic!("Failed to read {}/Cargo.toml", crate_path));
    let metadata: CargoMetadata = toml::from_str(&cargo_toml_content)
        .unwrap_or_else(|_| panic!("Failed to parse {}/Cargo.toml", crate_path));
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
        .map_err(|e| format!("--build-vars: {}", e))?
        .join(" ");
    Ok(build_vars_formatted)
}

pub fn cross_build_base_cmd(
    crate_path: String,
    engine: Engine,
    build_vars_fmt: String,
    target: TargetArch,
) -> String {
    format!("cd {} && CROSS_CONFIGCROSS_CONTAINER_ENGINE={} CROSS_CONTAINER_OPTS=\"{}\"  cross build --target {}-unknown-linux-gnu --release -v",crate_path,engine,build_vars_fmt,target)
}
