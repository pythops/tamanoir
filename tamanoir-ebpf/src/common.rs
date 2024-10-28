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
pub const BPF_F_MARK_MANGLED_0: u64 = 32;
pub const BPF_F_MARK_ENFORCE: u64 = 64;
