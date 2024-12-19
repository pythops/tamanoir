use std::net::Ipv4Addr;

use clap::{Parser, Subcommand};

use crate::{Engine, TargetArch};

#[derive(Debug, Parser)]
pub struct Opt {
    #[clap(subcommand)]
    pub command: Command,
}
#[derive(Debug, Subcommand)]
pub enum Command {
    #[clap(subcommand)]
    #[command(about = "Build/test Remote Control Execution shell codes")]
    Rce(RceCommand),
    #[command(about = "Start the dns proxy / c2 server")]
    Start {
        #[clap(short, long, default_value = "53")]
        port: u16,
        #[clap(long, default_value = "8.8.8.8")]
        dns_ip: Ipv4Addr,
        #[clap(long, default_value = "8")]
        payload_len: usize,
        #[clap(long, default_value = "hello")]
        rce: String,
        #[clap(long, default_value = "x86_64")]
        target_arch: TargetArch,
    },
}

#[derive(Debug, Subcommand)]
pub enum RceCommand {
    #[command(about = "Build shell code payload for specified architecture")]
    Build {
        #[clap(short,long, default_value = "x86_64",help=format!("Target architecture (supported are {:#?} )",TargetArch::ALL.into_iter().map(|t|t.to_string()).collect::<Vec<_>>()))]
        target_arch: TargetArch,
        #[clap(
            short,
            long,
            default_value = "docker",
            help = "cross build engine (docker and podman supported)"
        )]
        engine: Engine,
        #[clap(
            short,
            long,
            default_value = "",
            help = "key=value, space-separated env vars required for your shellcode, if needed"
        )]
        build_vars: String,
        #[clap(short, long)]
        crate_path: String,
        #[clap(short, long)]
        out_dir: String,
    },
    #[command(about = "Build shell code payload for all available aritectures")]
    BuildAll {
        #[clap(short, long, default_value = "docker")]
        engine: Engine,
        #[clap(short, long, default_value = "")]
        build_vars: String,
        #[clap(short, long)]
        crate_path: String,
        #[clap(short, long)]
        out_dir: String,
    },
    #[command(about = "Test a shellcode against current architecture")]
    Test {
        #[clap(short, long)]
        bin_path: String,
    },
}
