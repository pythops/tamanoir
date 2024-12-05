use std::{collections::HashMap, net::Ipv4Addr, sync::Arc};

use clap::Parser;
use log::{debug, info};
use tamanoir_proxy::handlers::{forward_req, init_keymaps, mangle, Session};
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

    loop {
        let mut buf = [0u8; 512];
        let (len, addr) = sock.recv_from(&mut buf).await?;
        debug!("{:?} bytes received from {:?}", len, addr);
        let data = mangle(&buf[..len], addr, payload_len, sessions.clone())
            .await
            .unwrap();
        if let Ok(data) = forward_req(data, dns_ip).await {
            let len = sock.send_to(&data, addr).await?;
            debug!("{:?} bytes sent", len);
        }
    }
}
