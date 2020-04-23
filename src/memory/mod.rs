use winapi::shared::basetsd::{DWORD_PTR};
use winapi::shared::minwindef::{LPVOID, LPCVOID, DWORD, PDWORD};
use winapi::um::winnt::{HANDLE, PAGE_EXECUTE_READWRITE};
use winapi::um::memoryapi::{ReadProcessMemory, WriteProcessMemory, VirtualProtectEx};
use std::mem;

pub fn get_aob(h_process: HANDLE, ptr: DWORD_PTR, target: &mut Vec<u8>, n: usize) {
    let mut c_addr = ptr;
    let mut c_value: u8 = 0x0;
    for _ in 0..n {
        unsafe {
            ReadProcessMemory(
                h_process,
                c_addr as LPCVOID,
                (&mut c_value as *mut u8) as LPVOID,
                mem::size_of::<u8>(),
                std::ptr::null_mut()
            );
        }
        target.push(c_value);
        c_addr += 1;
    }
}

pub fn write_aob(h_process: HANDLE, ptr: DWORD_PTR, source: &Vec<u8>) -> usize {
    let mut protection_bytes: DWORD = 0x0;
    let c_addr = ptr;
    let size = source.len();
    let mut written = 0;

    println!("writing into {:x}", ptr);

    unsafe { 
        VirtualProtectEx(
            h_process,
            c_addr as LPVOID,
            size,
            PAGE_EXECUTE_READWRITE,
            &mut protection_bytes as PDWORD
        );

        WriteProcessMemory(
            h_process,
            c_addr as LPVOID,
            source[..].as_ptr() as LPVOID,
            size,
            &mut written
        );

        VirtualProtectEx(
            h_process,
            c_addr as LPVOID,
            size,
            protection_bytes,
            &mut protection_bytes as PDWORD
        );
    }

    written
}

pub fn write_nops(h_process: HANDLE, ptr: DWORD_PTR, n: usize) {
    let nops: Vec<u8> = vec![0x90; n];
    write_aob(h_process, ptr, &nops);
}

pub fn hook_function(h_process: HANDLE, to_hook: DWORD_PTR,
    f: DWORD_PTR, len: usize) {

    use std::mem::transmute;

    if len < 5 {
        panic!("Not enough space to inject");
    }

    let mut current_protection: DWORD = 0x0;

    unsafe {
        VirtualProtectEx(h_process, to_hook as LPVOID, len,
            PAGE_EXECUTE_READWRITE, &mut current_protection as PDWORD);
    }

    let nops = vec![0x90; len];
    write_aob(h_process, to_hook, &nops);

    let relative_address: DWORD = ((f - to_hook) - 5) as DWORD;
    let relative_aob: [u8; 4] = unsafe { transmute::<DWORD, [u8; 4]>(
        relative_address.to_le()) };

    let mut instructions: Vec<u8> = Vec::new();
    instructions.push(0xE9);
    instructions.extend_from_slice(&relative_aob[..]);

    let written = write_aob(h_process, to_hook, &instructions);
    assert_eq!(written, 5);

    unsafe {
        VirtualProtectEx(h_process, to_hook as LPVOID, len,
            current_protection, &mut current_protection as PDWORD);
    }
}
