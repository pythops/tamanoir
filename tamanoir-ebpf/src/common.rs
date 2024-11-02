use aya_ebpf::{cty::c_long, helpers::bpf_skb_load_bytes, programs::TcContext};
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

pub fn calculate_udp_checksum(src_ip: u32, dst_ip: u32, udp_header: &[u8], payload: &[u8]) -> u16 {
    // Pseudo header array (12 bytes)
    let src_ip_bytes = src_ip.to_be_bytes();
    let dst_ip_bytes = dst_ip.to_be_bytes();

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

    for bytes_slice in [&pseudo_header, payload, udp_header] {
        //invalid access to map value, value_size=132 off=132 size=1
        //R3 min value is outside of the allowed memory range
        let len = bytes_slice.len();
        for i in 0..len / 2 {
            sum = sum.wrapping_add(
                u16::from_be_bytes([bytes_slice[2 * i], bytes_slice[2 * i + 1]]) as u32,
            );
        }
        if len % 2 != 0 {
            if let Some(byte) = bytes_slice.last() {
                //payload.last() => math between map_value pointer and register with unbounded min value is not allowed
                sum = sum.wrapping_add((*byte as u32) << 8);
            }
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
        ()
    })?;

    ctx.l4_csum_replace(
        UDP_CSUM_OFFSET,
        *old_be as u64,
        *new_be as u64,
        4 + BPF_F_PSEUDO_HDR + BPF_F_MARK_ENFORCE,
    )
    .map_err(|_| {
        error!(ctx, "error: l4_csum_replace");
        ()
    })?;
    ctx.l3_csum_replace(IP_CSUM_OFFSET, *old_be as u64, *new_be as u64, 4)
        .map_err(|_| {
            error!(ctx, "error: l3_csum_replace");
            ()
        })?;

    log_csums(ctx);
    Ok(())
}

pub fn update_port(ctx: &mut TcContext, new_be: &u16, update_type: UpdateType) -> Result<(), ()> {
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
        ()
    })?;

    //log_csums(ctx);
    Ok(())
}

pub fn update_udp_hdr_len(ctx: &mut TcContext, new_be: &u16) -> Result<(), ()> {
    info!(ctx, "updating udphdr len:");
    ctx.store(UDP_LEN_OFFSET, new_be, 0).map_err(|_| {
        error!(ctx, "error writing new udp hdr len ");
        ()
    })?;
    //log_csums(ctx);
    Ok(())
}

pub fn update_ip_hdr_tot_len(ctx: &mut TcContext, old_be: &u16, new_be: &u16) -> Result<(), ()> {
    info!(ctx, "updating iphdr tot len:");
    ctx.store(IP_TOT_LEN_OFFSET, new_be, 0).map_err(|_| {
        error!(ctx, "error writing iphdr tot len ");
        ()
    })?;
    ctx.l3_csum_replace(IP_CSUM_OFFSET, *old_be as u64, *new_be as u64, 4)
        .map_err(|_| {
            error!(ctx, "error: l3_csum_replace");
            ()
        })?;

    log_csums(ctx);
    Ok(())
}

pub fn inject_udp_payload(ctx: &mut TcContext, offset: usize, new_be: &u32) -> Result<(), ()> {
    info!(ctx, "injecting udp payload @ {}", offset);
    ctx.store(offset, new_be, 0).map_err(|_| {
        error!(ctx, "error injecting payload ");
        ()
    })?;

    //log_csums(ctx);
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
