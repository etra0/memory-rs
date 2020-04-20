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