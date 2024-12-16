use std::{ptr, thread};

use libc::{mmap, mprotect, MAP_ANONYMOUS, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE};
use log::{debug, error};

#[no_mangle]
pub fn execute(payload: &[u8]) -> Result<(), u32> {
    let payload = payload.to_vec();
    if payload.len() > 4096 {
        error!("Payload is too long! (>4096 bytes)");
        return Err(0u32);
    }
    let size = 4096; // Allocate 1 page of memory
    thread::spawn({
        move || {
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
                    error!("ERROR");
                    panic!("Failed to allocate memory");
                }
                //Write payload inside
                ptr::copy_nonoverlapping(payload.as_ptr(), addr as *mut u8, payload.len());

                // Mark the region as readable and executable
                if mprotect(addr, size, PROT_READ | PROT_EXEC) != 0 {
                    error!("ERROR");
                    panic!("Failed to set memory as executable");
                }
                debug!("Executable memory allocated at: {:?}", addr);
                assert!(!addr.is_null(), "exec_mem is NULL!");
                //Cast the memory address to a callable function pointer
                let func: extern "C" fn() -> u32 = std::mem::transmute(addr);

                //Call the function
                let _ = func();
            }
        }
    });
    Ok(())
}
