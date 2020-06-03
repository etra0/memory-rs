use winapi::shared::basetsd::DWORD_PTR;
use winapi::shared::minwindef::{DWORD, LPCVOID, LPVOID, PDWORD};
use winapi::um::memoryapi::{
    ReadProcessMemory, VirtualAllocEx, VirtualProtectEx, WriteProcessMemory,
};
use winapi::um::winnt::{HANDLE, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};

pub fn get_aob(h_process: HANDLE, ptr: DWORD_PTR, n: usize) -> Vec<u8> {
    let mut read = 0;
    let mut buffer: Vec<u8> = vec![0; n];

    unsafe {
        ReadProcessMemory(
            h_process,
            ptr as LPCVOID,
            buffer.as_mut_ptr() as LPVOID,
            n,
            &mut read,
        );
    }

    println!("{:x}, {:x?}", ptr, buffer);
    assert_eq!(n, read, "get_aob isn't the requested size");

    buffer
}

pub fn write_aob(h_process: HANDLE, ptr: DWORD_PTR, source: &Vec<u8>) -> usize {
    let mut protection_bytes: DWORD = 0x0;
    let c_addr = ptr;
    let size = source.len();
    let mut written = 0;

    unsafe {
        VirtualProtectEx(
            h_process,
            c_addr as LPVOID,
            size,
            PAGE_EXECUTE_READWRITE,
            &mut protection_bytes as PDWORD,
        );

        WriteProcessMemory(
            h_process,
            c_addr as LPVOID,
            source[..].as_ptr() as LPVOID,
            size,
            &mut written,
        );

        VirtualProtectEx(
            h_process,
            c_addr as LPVOID,
            size,
            protection_bytes,
            &mut protection_bytes as PDWORD,
        );
    }

    assert_eq!(
        written,
        source.len(),
        "write_aob didn't write the correct number of bytes"
    );

    written
}

pub fn write_nops(h_process: HANDLE, ptr: DWORD_PTR, n: usize) {
    let nops: Vec<u8> = vec![0x90; n];
    write_aob(h_process, ptr, &nops);
}

pub fn hook_function(h_process: HANDLE, to_hook: DWORD_PTR, f: DWORD_PTR, len: usize) {
    use std::mem::transmute;

    assert!(len > 5, "Not enough space to inject the shellcode");

    let mut current_protection: DWORD = 0x0;

    unsafe {
        VirtualProtectEx(
            h_process,
            to_hook as LPVOID,
            len,
            PAGE_EXECUTE_READWRITE,
            &mut current_protection as PDWORD,
        );
    }

    // just in case, we nop the space where we are injecting stuff
    let nops = vec![0x90; len];
    write_aob(h_process, to_hook, &nops);

    let _diff = f as i64 - to_hook as i64;
    let relative_address: DWORD = (_diff as DWORD - 5) as DWORD;
    let relative_aob: [u8; 4] = unsafe { transmute::<DWORD, [u8; 4]>(relative_address.to_le()) };

    let mut instructions: Vec<u8> = Vec::new();
    instructions.push(0xE8);
    instructions.extend_from_slice(&relative_aob[..]);

    let written = write_aob(h_process, to_hook, &instructions);
    assert_eq!(written, 5);

    unsafe {
        VirtualProtectEx(
            h_process,
            to_hook as LPVOID,
            len,
            current_protection,
            &mut current_protection as PDWORD,
        );
    }
}

pub fn inject_shellcode(
    h_process: HANDLE,
    module_base_address: DWORD_PTR,
    entry_point: DWORD_PTR,
    instruction_size: usize,
    f_start: *const u8,
    f_end: *const u8,
) -> DWORD_PTR {
    let f_size = f_end as usize - f_start as usize;
    // get the aob of the function
    let shellcode_bytes: &'static [u8] = unsafe { std::slice::from_raw_parts(f_start, f_size) };

    let mut shellcode_space: DWORD_PTR = 0x0;
    // try to allocate near module
    for i in 1..1000 {
        let current_address = module_base_address - (0x1000 * i);
        shellcode_space = unsafe {
            VirtualAllocEx(
                h_process,
                current_address as LPVOID,
                0x1000 as usize,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_EXECUTE_READWRITE,
            ) as DWORD_PTR
        };

        if shellcode_space != 0 {
            break;
        }
    }

    let written = write_aob(h_process, shellcode_space, &shellcode_bytes.to_vec());
    assert_eq!(written, f_size, "The size of the injection doesnt match");

    let module_injection_address = module_base_address + entry_point;
    hook_function(
        h_process,
        module_injection_address,
        shellcode_space,
        instruction_size,
    );

    shellcode_space
}
