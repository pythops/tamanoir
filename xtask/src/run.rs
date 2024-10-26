use std::{ffi::OsString, process::Command};

use anyhow::{bail, Context as _, Result};
use clap::Parser;
use xtask::AYA_BUILD_EBPF;

#[derive(Debug, Parser)]
pub struct Options {
    /// Build and run the release target.
    #[clap(long)]
    release: bool,
    /// The command used to wrap your application.
    #[clap(short, long, default_value = "sudo -E")]
    runner: String,
    /// Arguments to pass to your application.
    #[clap(global = true, last = true)]
    run_args: Vec<OsString>,
}

/// Build and run the project.
pub fn run(opts: Options) -> Result<()> {
    let Options {
        release,
        runner,
        run_args,
    } = opts;

    let mut cmd = Command::new("cargo");
    cmd.env(AYA_BUILD_EBPF, "true");
    cmd.args(["run", "--package", "tamanoir", "--config"]);
    if release {
        cmd.arg(format!("target.\"cfg(all())\".runner=\"{}\"", runner));
        cmd.arg("--release");
    } else {
        cmd.arg(format!("target.\"cfg(all())\".runner=\"{}\"", runner));
    }
    if !run_args.is_empty() {
        cmd.arg("--").args(run_args);
    }
    let status = cmd
        .status()
        .with_context(|| format!("failed to run {cmd:?}"))?;
    if status.code() != Some(0) {
        bail!("{cmd:?} failed: {status:?}")
    }
    Ok(())
}
