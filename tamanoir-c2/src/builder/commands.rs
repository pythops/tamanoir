use std::process::Command;

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
