use winapi::shared::basetsd::{DWORD_PTR};
use winapi::um::handleapi;
use winapi::shared::minwindef::{LPVOID, LPCVOID, DWORD};
use winapi::um::winnt::{HANDLE, PAGE_EXECUTE_READWRITE};
use winapi::um::tlhelp32;
use winapi::um::memoryapi::{ReadProcessMemory, WriteProcessMemory, VirtualProtectEx};
use std::mem;

pub fn get_aob(h_process: HANDLE, ptr: DWORD_PTR, target: &mut Vec<u8>, n: i32) {
    let mut c_addr = ptr;
    let mut c_value: u8 = 0x0;
    for i in 0..n {
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

pub fn write_aob(h_process: HANDLE, ptr: DWORD_PTR, source: &Vec<u8>) {
    let mut protection_bytes: DWORD = 0x0;
    let mut c_addr = ptr;
    let size = source.len();
    let arr = [0x90, 0x90, 0x90];

    println!("writing into {:x}", ptr);

    unsafe { 
        VirtualProtectEx(h_process, (&mut c_addr as *mut DWORD_PTR) as LPVOID, size, PAGE_EXECUTE_READWRITE, &mut protection_bytes);
        WriteProcessMemory(h_process, (&mut c_addr as *mut DWORD_PTR) as LPVOID, arr.as_ptr() as LPVOID, size, std::ptr::null_mut());
        VirtualProtectEx(h_process, (&mut c_addr as *mut DWORD_PTR) as LPVOID, size, protection_bytes, &mut protection_bytes);
    }
}