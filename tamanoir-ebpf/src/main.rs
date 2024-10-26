#![no_std]
#![no_main]

pub mod kprobe;

pub mod ingress;

pub mod egress;

pub mod common;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
