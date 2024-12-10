//!
//! The entrypoint of the shellcode is the `_start` function. It will be what is placed at the
//! very beginning of the binary produced by the Makefile. Modify that function to create the
//! shellcode that you want. Make sure to do an objdump of the binary to check and make sure
//! that it is actually placed at the beginning of the shellcode.

#![no_std]
#![no_main]

use core::arch::asm;

#[cfg(target_arch = "x86_64")]
pub unsafe fn write(fd: usize, msg: *const u8, len: usize) -> Result<usize, ()> {
    let sys_nr: usize = 1;
    let ret: isize;
    asm!(
    "syscall",
    in("rax") sys_nr,
    in("rdi") fd,
    in("rsi") msg,
    in("rdx") len,
    lateout("rax") ret,
    );
    match ret {
        -1 => Err(()),
        _ => Ok(ret as usize),
    }
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn exit(ret: usize) -> ! {
    let sys_nr: usize = 60;
    asm!(
    "syscall",
    in("rax") sys_nr,
    in("rdi") ret,
    options(noreturn),
    );
}

#[cfg(target_arch = "aarch64")]
pub unsafe fn write(fd: usize, msg: *const u8, len: usize) -> Result<usize, ()> {
    let sys_nr: usize = 1;
    let ret: isize;
    asm!(
    "svc #0",
    in("x8") sys_nr,
    in("x0") fd,
    in("x1") msg,
    in("x2") len,
    lateout("x0") ret,
    );
    match ret {
        -1 => Err(()),
        _ => Ok(ret as usize),
    }
}

#[cfg(target_arch = "aarch64")]
pub unsafe fn exit(ret: usize) -> ! {
    let sys_nr: usize = 60;
    asm!(
    "svc #0",
    in("x8") sys_nr,
    in("x0") ret,
    options(noreturn),
    );
}

// This is only needed for the experimental asm architectures
// See https://github.com/rust-lang/rust/issues/93335
// Currently oly needed for mips of the suported architectures
// #![feature(asm_experimental_arch)]

/// Entry point of the shellcode
///
/// This is the function that you want to modify. Other functions and modules can be added.
/// Just make sure to check that everything is laid out properly in the binary.
///
/// The size of the generated assembly will be affected by the return value of the function.
/// If it will never return, change the return value to `!` and no function prologue or
/// epilogue will be generated.
///
/// The signature can be changed to whatever you want. It will take and return parameters in
/// the standard sysv c abi.
#[no_mangle]
pub extern "C" fn _start() {
    let message: &str = "Hello, Shellcode!\n";
    unsafe {
        let _ = write(1, message.as_bytes().as_ptr(), message.len());
        exit(0);
    }
}

/// Panic handler
///
/// The Cargo.toml file sets the panic behavior to abort so I don't think this functioin will
/// be used. Just leave it so things compile.
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
