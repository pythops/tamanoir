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
