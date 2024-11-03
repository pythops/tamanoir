use aya_ebpf::{
    cty::c_long,
    helpers::{bpf_skb_load_bytes, bpf_skb_store_bytes},
    macros::map,
    maps::Queue,
    programs::TcContext,
};
use aya_log_ebpf::{error, info};
use network_types::{eth::EthHdr, ip::Ipv4Hdr};

#[no_mangle]
pub static TARGET_IP: u32 = 0;

#[no_mangle]
pub static HIJACK_IP: u32 = 0;

pub const IP_OFFSET: usize = EthHdr::LEN;
pub const IP_TOT_LEN_OFFSET: usize = IP_OFFSET + 2;
pub const IP_CSUM_OFFSET: usize = IP_OFFSET + 10;
pub const IP_SRC_ADDR_OFFSET: usize = IP_OFFSET + 12;
pub const IP_DEST_ADDR_OFFSET: usize = IP_OFFSET + 16;
pub const UDP_OFFSET: usize = IP_OFFSET + Ipv4Hdr::LEN;
pub const UDP_DEST_PORT_OFFSET: usize = UDP_OFFSET + 2;
pub const UDP_LEN_OFFSET: usize = UDP_OFFSET + 4;
pub const UDP_CSUM_OFFSET: usize = UDP_OFFSET + 6;
pub const DNS_QUERY_OFFSET: usize = UDP_OFFSET + 8;

pub const BPF_ADJ_ROOM_NET: u32 = 0;

pub const BPF_F_PSEUDO_HDR: u64 = 16;
pub const BPF_F_MARK_ENFORCE: u64 = 64;

#[map]
pub static DATA: Queue<u32> = Queue::with_max_entries(4096, 0);

pub fn log_csums(ctx: &TcContext) {
    info!(
        ctx,
        "=> ipcsum: {}  udpcsum: {}",
        u16::from_be(ctx.load::<u16>(IP_CSUM_OFFSET).unwrap()),
        u16::from_be(ctx.load::<u16>(UDP_CSUM_OFFSET).unwrap())
    );
}

pub enum UpdateType {
    Src,
    Dst,
}

pub fn calculate_udp_checksum(
    ctx: &TcContext,
    src_ip: u32,
    dst_ip: u32,
    udp_header: &[u8],
    payload: &[u8],
    payload_max_len: usize,
    payload_len: usize,
) -> u16 {
    // Pseudo header array (12 bytes)
    let src_ip_bytes = src_ip.to_be_bytes();
    let dst_ip_bytes = dst_ip.to_be_bytes();
    log_csums(ctx);
    let pseudo_header = [
        src_ip_bytes[0],
        src_ip_bytes[1],
        src_ip_bytes[2],
        src_ip_bytes[3], // Source IP
        dst_ip_bytes[0],
        dst_ip_bytes[1],
        dst_ip_bytes[2],
        dst_ip_bytes[3],                                 // Destination IP
        0,                                               // Zero byte
        17,                                              // Protocol (UDP is 17)
        ((udp_header.len() + payload.len()) >> 8) as u8, // UDP length (high byte)
        (udp_header.len() + payload.len()) as u8,        // UDP length (low byte)
    ];

    // 1. Calculate the sum of pseudo header, UDP header, and payload

    let mut sum = 0u32;

    let payload_len = payload_len & (payload_max_len - 1); //mask to avoid verifier ou of bounds error

    if payload_len == 0 {
        return 0;
    }

    for bytes_slice in [&pseudo_header, udp_header, &payload[..payload_len]] {
        let len = bytes_slice.len();

        //info!(ctx, "=> udpcsum: {}", sum);
        for i in 0..len / 2 {
            sum = sum.wrapping_add(
                u16::from_be_bytes([bytes_slice[2 * i], bytes_slice[2 * i + 1]]) as u32,
            );
            //info!(ctx, "pseudo+udp=> udpcsum: ({}){}", i, sum);
        }
        if len % 2 != 0 {
            if let Some(byte) = bytes_slice.last() {
                sum = sum.wrapping_add((*byte as u32) << 8);
            }
            //info!(ctx, "pseudo+udp=> udpcsum: (odd){}", sum);
        }
    }
    // // 2. Fold 32-bit sum to 16-bit and apply one's complement
    let sum = (sum & 0xFFFF) + (sum >> 16);

    let sum = (sum & 0xFFFF) + (sum >> 16);

    !(sum as u16) // One's complement
}

pub fn update_addr(
    ctx: &mut TcContext,
    old_be: &u32,
    new_be: &u32,
    update_type: UpdateType,
) -> Result<(), ()> {
    let offset = match update_type {
        UpdateType::Src => {
            info!(ctx, "updating src addr:");
            IP_SRC_ADDR_OFFSET
        }
        UpdateType::Dst => {
            info!(ctx, "updating dst addr:");
            IP_DEST_ADDR_OFFSET
        }
    };
    ctx.store(offset, new_be, 0).map_err(|_| {
        error!(ctx, "error writing new address ");
    })?;

    ctx.l4_csum_replace(
        UDP_CSUM_OFFSET,
        *old_be as u64,
        *new_be as u64,
        4 + BPF_F_PSEUDO_HDR + BPF_F_MARK_ENFORCE,
    )
    .map_err(|_| {
        error!(ctx, "error: l4_csum_replace");
    })?;
    ctx.l3_csum_replace(IP_CSUM_OFFSET, *old_be as u64, *new_be as u64, 4)
        .map_err(|_| {
            error!(ctx, "error: l3_csum_replace");
        })?;

    log_csums(ctx);
    Ok(())
}

pub fn update_port(
    ctx: &mut TcContext,
    old_be: &u16,
    new_be: &u16,
    update_type: UpdateType,
) -> Result<(), ()> {
    let offset = match update_type {
        UpdateType::Src => {
            info!(ctx, "updating src port");
            UDP_OFFSET
        }
        UpdateType::Dst => {
            info!(ctx, "updating dst port");
            UDP_DEST_PORT_OFFSET
        }
    };

    ctx.store(offset, new_be, 0).map_err(|_| {
        error!(ctx, "error writing new port");
    })?;
    ctx.l4_csum_replace(
        UDP_CSUM_OFFSET,
        *old_be as u64,
        *new_be as u64,
        2 + BPF_F_PSEUDO_HDR + BPF_F_MARK_ENFORCE,
    )
    .map_err(|_| {
        error!(ctx, "error: l4_csum_replace");
    })?;

    //log_csums(ctx);
    Ok(())
}

pub fn update_udp_hdr_len(ctx: &mut TcContext, new_be: &u16) -> Result<(), ()> {
    info!(ctx, "updating udphdr len:");
    ctx.store(UDP_LEN_OFFSET, new_be, 0).map_err(|_| {
        error!(ctx, "error writing new udp hdr len ");
    })?;
    //log_csums(ctx);
    Ok(())
}

pub fn update_ip_hdr_tot_len(ctx: &mut TcContext, old_be: &u16, new_be: &u16) -> Result<(), ()> {
    info!(ctx, "updating iphdr tot len:");
    ctx.store(IP_TOT_LEN_OFFSET, new_be, 0).map_err(|_| {
        error!(ctx, "error writing iphdr tot len ");
    })?;
    ctx.l3_csum_replace(IP_CSUM_OFFSET, *old_be as u64, *new_be as u64, 4)
        .map_err(|_| {
            error!(ctx, "error: l3_csum_replace");
        })?;

    log_csums(ctx);
    Ok(())
}

pub fn inject_keys(ctx: &mut TcContext, offset: usize, payload: [u32; 4]) -> Result<(), ()> {
    info!(
        ctx,
        "injecting keys [{},{},{},{}] @ {}", payload[0], payload[1], payload[2], payload[3], offset
    );
    ctx.store(offset, &payload[0].to_be(), 0).map_err(|_| {
        error!(ctx, "error injecting payload");
    })?;
    ctx.store(offset + 4, &payload[1].to_be(), 0).map_err(|_| {
        error!(ctx, "error injecting payload");
    })?;
    ctx.store(offset + 8, &payload[2].to_be(), 0).map_err(|_| {
        error!(ctx, "error injecting payload");
    })?;
    ctx.store(offset + 12, &payload[3].to_be(), 0)
        .map_err(|_| {
            error!(ctx, "error injecting payload");
        })?;
    Ok(())
}

pub fn load_bytes(ctx: &mut TcContext, offset: usize, dst: &mut [u8]) -> Result<usize, c_long> {
    let len = usize::try_from(ctx.skb.len()).map_err(|core::num::TryFromIntError { .. }| -1)?;
    let len = len.checked_sub(offset).ok_or(-1)?;
    let len = len.min(dst.len());
    if len == 0 {
        return Err(-1);
    }
    info!(ctx, "loading {} bytes", len);

    let len_u32 = u32::try_from(len).map_err(|core::num::TryFromIntError { .. }| -1)?;
    let ret = unsafe {
        bpf_skb_load_bytes(
            ctx.skb.skb as *const _,
            offset as u32,
            dst.as_mut_ptr() as *mut _,
            len_u32,
        )
    };
    if ret == 0 {
        Ok(len)
    } else {
        Err(ret)
    }
}

pub fn store_bytes(
    ctx: &mut TcContext,
    offset: usize,
    src: &[u8],
    flags: u64,
) -> Result<usize, c_long> {
    let len = usize::try_from(ctx.skb.len()).map_err(|core::num::TryFromIntError { .. }| -1)?;
    let len = len.checked_sub(offset).ok_or(-1)?;
    let len = len.min(src.len());

    let mut len_u32 = u32::try_from(len).map_err(|core::num::TryFromIntError { .. }| -1)?;

    len_u32 &= src.len() as u32 - 1;
    if len_u32 == 0 {
        return Err(-1);
    }
    info!(ctx, "storing {} bytes", len_u32);
    unsafe {
        let ret = bpf_skb_store_bytes(
            ctx.skb.skb as *mut _,
            offset as u32,
            src as *const _ as *const _,
            len_u32,
            flags,
        );
        if ret == 0 {
            Ok(len)
        } else {
            Err(ret)
        }
    }
}
