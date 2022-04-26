use std::ffi::c_void;

use windows_sys::Win32::{
    Foundation::HANDLE,
    System::{
        Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
        Memory::{
            VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
        },
    },
};

/// Kept for legacy purposes.

pub fn get_aob(h_process: HANDLE, ptr: *const c_void, n: usize) -> Vec<u8> {
    let mut read = 0;
    let mut buffer: Vec<u8> = vec![0; n];

    unsafe {
        ReadProcessMemory(
            h_process,
            ptr as *const c_void,
            buffer.as_mut_ptr() as *mut c_void,
            n,
            &mut read,
        );
    }

    assert_eq!(n, read, "get_aob isn't the requested size");

    buffer
}

pub fn write_aob(h_process: HANDLE, ptr: usize, source: &[u8]) -> usize {
    let mut protection_bytes: u32 = 0x0;
    let c_addr = ptr;
    let size = source.len();
    let mut written = 0;

    unsafe {
        VirtualProtectEx(
            h_process,
            c_addr as *const c_void,
            size,
            PAGE_EXECUTE_READWRITE,
            &mut protection_bytes as _,
        );

        WriteProcessMemory(
            h_process,
            c_addr as *const c_void,
            source[..].as_ptr() as *const c_void,
            size,
            &mut written,
        );

        VirtualProtectEx(
            h_process,
            c_addr as *const c_void,
            size,
            protection_bytes,
            &mut protection_bytes as _,
        );
    }

    assert_eq!(
        written,
        source.len(),
        "write_aob didn't write the correct number of bytes"
    );

    written
}

pub fn write_nops(h_process: HANDLE, ptr: usize, n: usize) {
    let nops: Vec<u8> = vec![0x90; n];
    write_aob(h_process, ptr, &nops);
}

pub fn hook_function(h_process: HANDLE, to_hook: usize, f: usize, len: usize) {
    assert!(len >= 5, "Not enough space to inject the shellcode");

    let mut current_protection: u32 = 0x0;

    unsafe {
        VirtualProtectEx(
            h_process,
            to_hook as *const c_void,
            len,
            PAGE_EXECUTE_READWRITE,
            &mut current_protection as _,
        );
    }

    // just in case, we nop the space where we are injecting stuff
    let nops = vec![0x90; len];
    write_aob(h_process, to_hook, &nops);

    let _diff = f as i64 - to_hook as i64;
    let relative_address: u32 = (_diff as u32 - 5) as u32;
    let relative_aob: [u8; 4] = relative_address.to_le_bytes();

    let mut instructions: Vec<u8> = vec![0xE8];
    instructions.extend_from_slice(&relative_aob[..]);

    let written = write_aob(h_process, to_hook, &instructions);
    assert_eq!(written, 5);

    unsafe {
        VirtualProtectEx(
            h_process,
            to_hook as *const c_void,
            len,
            current_protection,
            &mut current_protection as _,
        );
    }
}

/// This function injects a
/// shellcode on a desired address.
/// # Safety
/// This function is highly unsafe because it will
/// change assembly code of the target program, so
/// be aware of the crashing, wrong-results, etc.
pub unsafe fn inject_shellcode(
    h_process: HANDLE,
    module_base_address: usize,
    entry_point: *const c_void,
    instruction_size: usize,
    f_start: *const u8,
    f_end: *const u8,
) -> *const c_void {
    let f_size = f_end as usize - f_start as usize;
    // get the aob of the function
    let shellcode_bytes: &'static [u8] = std::slice::from_raw_parts(f_start, f_size);

    let mut shellcode_space: *const c_void = std::ptr::null();
    // try to allocate near module
    for i in 1..1000 {
        let current_address = module_base_address - (0x1000 * i);
        shellcode_space = VirtualAllocEx(
            h_process,
            current_address as _,
            0x1000_usize,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        );

        if !shellcode_space.is_null() {
            break;
        }
    }

    let written = write_aob(h_process, shellcode_space as _, &shellcode_bytes.to_vec());
    assert_eq!(written, f_size, "The size of the injection doesnt match");

    let module_injection_address = module_base_address + (entry_point as usize);
    hook_function(
        h_process,
        module_injection_address,
        shellcode_space as _,
        instruction_size,
    );

    shellcode_space
}
