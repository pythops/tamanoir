#![no_std]
#![no_main]

pub mod kprobe;

pub mod ingress;

pub mod egress;

pub mod common;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}


2066 cf5e 3441 d0c6 37fb 437a 0800 4500 
004e 46a9 0000 4011 8344 c0a8 01b4 02f8 
eb59 d876 0035 003a 4bb2 f802 0120 66dc 
ffff 0001 0000 0000 0001 0667 6f6f 676c 
6502 6672 0000 0100 0100 0029 04d0 0000 
0000 000c 000a 0008 01c5 4879



2066 cf5e 3441 d0c6 37fb 437a 0800 4500 
004e f089 0000 4011 c5b7 c0a8 01b4 0101  
0101 de2e 0035 003a c4a9 e152 0120 0001  
0000 0000 0001 0667 6f6f 676c 6502 6672  
0000 0100 0100 0029 04d0 0000 0000 000c 
000a 0008 c0a5 7310 52df ea63   